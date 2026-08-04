import os
import json
import urllib.request
import re
import tarfile
import gzip
import shutil
import ipaddress
from datetime import datetime, timezone

# ==================== 1. 全局数据源配置 ====================
RULES_CONFIG = {
    "domain": {
        "china": [
            "https://github.com/MissToT/Picture/raw/Meta/Rules/domain/China.mrs",
            "https://github.com/QuixoticHeart/rule-set/raw/ruleset/meta/domain/cn.mrs",
            "https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/cn.mrs"
        ],
        "proxy": [
            "https://github.com/MissToT/Picture/raw/Meta/Rules/domain/Proxy.mrs",
            "https://github.com/QuixoticHeart/rule-set/raw/ruleset/meta/domain/proxy.mrs"
        ],
        "adblock": [
            "https://github.com/privacy-protection-tools/anti-ad.github.io/raw/master/docs/mihomo.mrs",
            "https://github.com/MissToT/Picture/raw/Meta/Rules/domain/reject.mrs"
        ],
        "japan": [
            "https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/dlsite.mrs",
            "https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/dmm.mrs",
            "https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/pixiv.mrs",
            "https://github.com/MissToT/Picture/raw/Meta/Rules/domain/Japan.mrs"
        ],
        "taiwan": [
            "https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/bahamut.mrs",
            "https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/manhuagui.mrs",
            "https://github.com/MissToT/Picture/raw/Meta/Rules/domain/Taiwan.mrs"
        ]
    },
    "ipcidr": {
        "china": [
            "https://github.com/QuixoticHeart/rule-set/raw/ruleset/meta/ipcidr/cn.mrs",
            "https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geoip/cn.mrs"
        ],
        "proxy": [
            "https://github.com/QuixoticHeart/rule-set/raw/ruleset/meta/ipcidr/proxy.mrs"
        ]
    }
}

PREV_SNAPSHOT_DIR = "prev_mihomo"

# ==================== 2. 核心功能函数 ====================

def get_latest_stable_asset_url(repo, pattern):
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    req = urllib.request.Request(url, headers={'User-Agent': 'GitHub-Actions-Script'})
    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            for asset in data.get('assets', []):
                if re.search(pattern, asset['name'], re.IGNORECASE):
                    return asset['browser_download_url']
    except Exception as e:
        print(f"[-] 获取 {repo} 最新版本失败，回退至默认版本: {e}")
    return None

def setup_binaries():
    print("[*] 正在准备编译内核...")

    sb_url = get_latest_stable_asset_url("SagerNet/sing-box", r"linux-amd64.*\.tar\.gz") or \
             "https://github.com/SagerNet/sing-box/releases/download/v1.13.14/sing-box-1.13.14-linux-amd64.tar.gz"
    urllib.request.urlretrieve(sb_url, "sing-box.tar.gz")
    with tarfile.open("sing-box.tar.gz", "r:gz") as tar:
        for member in tar.getmembers():
            if member.name.endswith("/sing-box"):
                with open("sing-box", "wb") as out_f:
                    out_f.write(tar.extractfile(member).read())
    os.chmod("sing-box", 0o755)

    mihomo_url = get_latest_stable_asset_url("MetaCubeX/mihomo", r"linux-amd64.*\.gz") or \
                 "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.27/mihomo-linux-amd64-v1.19.27.gz"
    urllib.request.urlretrieve(mihomo_url, "mihomo.gz")
    with gzip.open("mihomo.gz", "rb") as f_in:
        with open("mihomo", "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
    os.chmod("mihomo", 0o755)

def download_file(url, filename):
    print(f"  -> 下载源: {url}")
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req) as response:
        with open(filename, 'wb') as f:
            f.write(response.read())

def read_text_rules(filename):
    if not os.path.exists(filename):
        return set()
    rules = set()
    with open(filename, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                rules.add(line)
    return rules

def fetch_prev_rules(rule_type, rule_name):
    subdir = "geoip" if rule_type == "ipcidr" else "geosite"
    yaml_path = os.path.join(PREV_SNAPSHOT_DIR, "geo", subdir, f"{rule_name}.yaml")
    if not os.path.exists(yaml_path):
        return None
    rules = set()
    with open(yaml_path, 'r', encoding='utf-8') as f:
        for line in f:
            s = line.strip()
            if s.startswith("- '") and s.endswith("'"):
                rules.add(s[3:-1])
    print(f"  -> 历史快照 [{rule_name}]: {len(rules)} 条")
    return rules

def optimize_ip_rules(rules_set):
    """
    对 IP CIDR 规则进行智能化简与范围去重：
    1. 区分 IPv4 和 IPv6 规则。
    2. 使用 ipaddress.collapse_addresses 自动执行“大包小”及相邻网段合并。
    """
    v4_nets = []
    v6_nets = []
    other_rules = set()

    for item in rules_set:
        item_clean = item.strip()
        if not item_clean:
            continue
        try:
            net = ipaddress.ip_network(item_clean, strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                v4_nets.append(net)
            elif isinstance(net, ipaddress.IPv6Network):
                v6_nets.append(net)
        except ValueError:
            other_rules.add(item_clean)

    v4_collapsed = [str(net) for net in ipaddress.collapse_addresses(v4_nets)]
    v6_collapsed = [str(net) for net in ipaddress.collapse_addresses(v6_nets)]

    return v4_collapsed, v6_collapsed, sorted(list(other_rules))

def export_all_formats(rule_name, rules_list, rule_type):
    """导出 YAML, JSON, TXT, MRS, SRS 文件"""
    is_ip = (rule_type == "ipcidr")
    mihomo_dir  = f"mihomo_out/geo/{'geoip' if is_ip else 'geosite'}"
    singbox_dir = f"singbox_out/geo/{'geoip' if is_ip else 'geosite'}"
    bypass_dir  = "bypass_out"

    os.makedirs(mihomo_dir,  exist_ok=True)
    os.makedirs(singbox_dir, exist_ok=True)
    os.makedirs(bypass_dir,  exist_ok=True)

    sorted_rules = sorted(rules_list)

    # 1. YAML (Mihomo)
    with open(f"{mihomo_dir}/{rule_name}.yaml", 'w', encoding='utf-8') as f:
        f.write("payload:\n")
        for rule in sorted_rules:
            f.write(f"  - '{rule}'\n")

    # 2. JSON (Sing-box)
    with open(f"{singbox_dir}/{rule_name}.json", 'w', encoding='utf-8') as f:
        if is_ip:
            json.dump({"version": 2, "rules": [{"ip_cidr": sorted_rules}]},
                      f, indent=2, ensure_ascii=False)
        else:
            domains, suffixes = [], []
            for r in sorted_rules:
                if r.startswith('+.'):
                    suffixes.append(r[2:])
                elif r.startswith('.'):
                    suffixes.append(r[1:])
                else:
                    domains.append(r)
            json.dump({"version": 2, "rules": [{"domain": domains, "domain_suffix": suffixes}]},
                      f, indent=2, ensure_ascii=False)

    # 3. TXT (纯文本)
    txt_content = "\n".join(sorted_rules) + "\n"
    with open(f"{mihomo_dir}/{rule_name}.txt", 'w', encoding='utf-8') as f:
        f.write(txt_content)
    with open(f"{singbox_dir}/{rule_name}.txt", 'w', encoding='utf-8') as f:
        f.write(txt_content)
    with open(f"{bypass_dir}/{rule_name}.txt", 'w', encoding='utf-8') as f:
        f.write(txt_content)

    # 4. MRS & SRS 二进制编译
    temp_txt_path = f"temp_workspace/merged_{rule_name}_{rule_type}.txt"
    with open(temp_txt_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(sorted_rules))
    os.system(f"./mihomo convert-ruleset {rule_type} text {temp_txt_path} {mihomo_dir}/{rule_name}.mrs")
    os.system(f"./sing-box rule-set compile --output {singbox_dir}/{rule_name}.srs {singbox_dir}/{rule_name}.json")

def record_change_log(change_log, rule_type, rule_name, rules_set, prev_rules):
    """记录变更统计"""
    if prev_rules is not None:
        added   = sorted(rules_set - prev_rules)
        removed = sorted(prev_rules - rules_set)
        print(f"  -> [{rule_name}] 差异：新增 {len(added)} 条，移除 {len(removed)} 条")
    else:
        added, removed = [], []

    change_log[f"{rule_type}/{rule_name}"] = {
        "total":      len(rules_set),
        "prev_total": len(prev_rules) if prev_rules is not None else None,
        "added":      added,
        "removed":    removed,
    }

def generate_change_report(all_changes):
    """生成 CHANGES.md 报告及各个分支专属的提交日志"""
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # 仅提取真正发生变动（有新增/删除或首次初始化）的文件
    changed_items = {}
    for key, data in all_changes.items():
        if data["prev_total"] is None or data["added"] or data["removed"]:
            changed_items[key] = data

    # 1. 生成 CHANGES.md（仅记录修改的文件）
    lines = [f"# 规则变更记录\n\n**更新时间：** {now_str}\n\n---\n\n"]
    if not changed_items:
        lines.append("本次更新无任何规则变动。\n")
    else:
        for key in sorted(changed_items.keys()):
            data = changed_items[key]
            total      = data["total"]
            prev_total = data["prev_total"]
            added      = data["added"]
            removed    = data["removed"]

            lines.append(f"## `{key}`\n\n")

            if prev_total is None:
                lines.append(f"> 首次生成，共 **{total}** 条规则\n\n")
            else:
                diff = total - prev_total
                sign = (f"+{diff}" if diff >= 0 else str(diff))
                lines.append(f"- 规则总数：**{total}**（{sign}）\n")

                if added:
                    lines.append(
                        f"\n<details><summary>✅ 新增 {len(added)} 条（点击展开）</summary>\n\n```\n"
                    )
                    for r in added[:50]:
                        lines.append(f"{r}\n")
                    if len(added) > 50:
                        lines.append(f"... 以及其他 {len(added) - 50} 条\n")
                    lines.append("```\n</details>\n")

                if removed:
                    lines.append(
                        f"\n<details><summary>❌ 移除 {len(removed)} 条（点击展开）</summary>\n\n```\n"
                    )
                    for r in removed[:50]:
                        lines.append(f"{r}\n")
                    if len(removed) > 50:
                        lines.append(f"... 以及其他 {len(removed) - 50} 条\n")
                    lines.append("```\n</details>\n")

            lines.append("\n")

    report = "".join(lines)

    for out_dir in ["mihomo_out", "singbox_out", "bypass_out"]:
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, "CHANGES.md"), "w", encoding="utf-8") as f:
            f.write(report)

    # 2. 分别为各个分支单独生成针对修改文件的提交提示
    branch_configs = {
        "mihomo": (
            "mihomo_commit_msg.txt", 
            lambda rtype, rname: f"geo/{'geoip' if rtype=='ipcidr' else 'geosite'}/{rname}.mrs"
        ),
        "singbox": (
            "singbox_commit_msg.txt", 
            lambda rtype, rname: f"geo/{'geoip' if rtype=='ipcidr' else 'geosite'}/{rname}.srs"
        ),
        "bypass": (
            "bypass_commit_msg.txt", 
            lambda rtype, rname: f"{rname}.txt"
        ),
    }

    for branch_name, (msg_filename, formatter) in branch_configs.items():
        summary_parts = []
        for key, data in sorted(changed_items.items()):
            rtype, rname = key.split("/")
            file_path = formatter(rtype, rname)

            if data["prev_total"] is None:
                summary_parts.append(f"{file_path} init:{data['total']}")
            else:
                summary_parts.append(f"{file_path} +{len(data['added'])}/-{len(data['removed'])}")

        if summary_parts:
            commit_msg = f"sync({now_str}): " + " | ".join(summary_parts)
        else:
            commit_msg = f"sync({now_str}): no changes"

        with open(msg_filename, "w", encoding="utf-8") as f:
            f.write(commit_msg)

        print(f"[*] [{branch_name}] 专属提交信息：{commit_msg}")

# ==================== 3. 主处理流程 ====================

def process_rules(rule_type, rules_dict):
    print(f"\n[*] 开始批量构建 [{rule_type.upper()}] 分流规则...")
    change_log = {}

    for rule_name, urls in rules_dict.items():
        print(f"\n[+] 处理规则集: {rule_name}")

        merged_rules = set()
        for i, url in enumerate(urls):
            temp_mrs = f"temp_workspace/{rule_name}_{i}.mrs"
            temp_txt = f"temp_workspace/{rule_name}_{i}.txt"
            download_file(url, temp_mrs)
            os.system(f"./mihomo convert-ruleset {rule_type} mrs {temp_mrs} {temp_txt}")
            merged_rules |= read_text_rules(temp_txt)

        if rule_type == "ipcidr":
            print("  -> 正在进行 CIDR 范围化简与去重...")
            v4_rules, v6_rules, other_rules = optimize_ip_rules(merged_rules)
            combined_rules = v4_rules + v6_rules + other_rules

            if rule_name == "china":
                print("  -> 导出独立分支规则: [cn-ip-v4] 与 [cn-ip-v6]...")

                # cn-ip-v4
                prev_v4 = fetch_prev_rules(rule_type, "cn-ip-v4")
                export_all_formats("cn-ip-v4", v4_rules, rule_type)
                record_change_log(change_log, rule_type, "cn-ip-v4", set(v4_rules), prev_v4)

                # cn-ip-v6
                prev_v6 = fetch_prev_rules(rule_type, "cn-ip-v6")
                export_all_formats("cn-ip-v6", v6_rules, rule_type)
                record_change_log(change_log, rule_type, "cn-ip-v6", set(v6_rules), prev_v6)
            else:
                prev_rules = fetch_prev_rules(rule_type, rule_name)
                export_all_formats(rule_name, combined_rules, rule_type)
                record_change_log(change_log, rule_type, rule_name, set(combined_rules), prev_rules)
        else:
            prev_rules = fetch_prev_rules(rule_type, rule_name)
            export_all_formats(rule_name, sorted(list(merged_rules)), rule_type)
            record_change_log(change_log, rule_type, rule_name, merged_rules, prev_rules)

    return change_log

def main():
    setup_binaries()
    os.makedirs("temp_workspace", exist_ok=True)

    all_changes = {}
    for rule_type, rules_dict in RULES_CONFIG.items():
        changes = process_rules(rule_type, rules_dict)
        all_changes.update(changes)

    generate_change_report(all_changes)

    print("\n[*] 正在清理临时工作区...")
    shutil.rmtree("temp_workspace", ignore_errors=True)

    print("\n[√] 任务全部完成，所有规则集均已生成完毕！")

if __name__ == "__main__":
    main()