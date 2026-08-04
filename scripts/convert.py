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
    """通过 GitHub API 自动匹配并获取最新稳定版内核资产"""
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    req = urllib.request.Request(url, headers={'User-Agent': 'GitHub-Actions-Script'})
    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            for asset in data.get('assets', []):
                if re.search(pattern, asset['name'], re.IGNORECASE):
                    return asset['browser_download_url']
    except Exception as e:
        print(f"[-] 获取 {repo} 最新稳定版本失败，将回退至默认版本: {e}")
    return None

def setup_binaries():
    """下载并解压 Sing-box 和 Mihomo 编译内核"""
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
    """带有基础伪装的下载器"""
    print(f"  -> 下载源: {url}")
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req) as response:
        with open(filename, 'wb') as f:
            f.write(response.read())

def read_text_rules(filename):
    """读取文本规则，自动过滤注释及空行，利用 Set 结构进行绝对去重"""
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
    """从 CI 预先克隆的本地快照读取上次规则（用于差异比对）"""
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

def export_bypass_txt_files(rules_set):
    """将 ipcidr/china 的 IP 转换为 cn-ip-v4.txt 和 cn-ip-v6.txt 并进行包含关系去重与网段合并"""
    v4_nets = []
    v6_nets = []

    for item in rules_set:
        clean_item = item.strip()
        if not clean_item:
            continue
        try:
            net = ipaddress.ip_network(clean_item, strict=False)
            if net.version == 4:
                v4_nets.append(net)
            elif net.version == 6:
                v6_nets.append(net)
        except ValueError:
            continue

    # collapse_addresses 剔除被更大网段包含的子网段，并进行连贯网段合并
    v4_collapsed = sorted(ipaddress.collapse_addresses(v4_nets))
    v6_collapsed = sorted(ipaddress.collapse_addresses(v6_nets))

    for out_dir in ["mihomo_out", "singbox_out"]:
        bypass_dir = os.path.join(out_dir, "bypass")
        os.makedirs(bypass_dir, exist_ok=True)

        with open(os.path.join(bypass_dir, "cn-ip-v4.txt"), "w", encoding="utf-8") as f:
            for net in v4_collapsed:
                f.write(f"{net}\n")

        with open(os.path.join(bypass_dir, "cn-ip-v6.txt"), "w", encoding="utf-8") as f:
            for net in v6_collapsed:
                f.write(f"{net}\n")

    print(f"  -> 已生成 bypass 格式文件: IPv4 ({len(v4_collapsed)}条), IPv6 ({len(v6_collapsed)}条)")

def export_four_formats(rule_name, rules_set, rule_type):
    """根据规则类型 (domain/ipcidr) 导出 YAML, JSON, MRS, SRS 四种格式"""
    is_ip = (rule_type == "ipcidr")
    mihomo_dir  = f"mihomo_out/geo/{'geoip' if is_ip else 'geosite'}"
    singbox_dir = f"singbox_out/geo/{'geoip' if is_ip else 'geosite'}"
    os.makedirs(mihomo_dir,  exist_ok=True)
    os.makedirs(singbox_dir, exist_ok=True)

    # 1. YAML (Mihomo)
    with open(f"{mihomo_dir}/{rule_name}.yaml", 'w', encoding='utf-8') as f:
        f.write("payload:\n")
        for rule in sorted(rules_set):
            f.write(f"  - '{rule}'\n")

    # 2. JSON (Sing-box)
    with open(f"{singbox_dir}/{rule_name}.json", 'w', encoding='utf-8') as f:
        if is_ip:
            json.dump({"version": 2, "rules": [{"ip_cidr": sorted(list(rules_set))}]},
                      f, indent=2, ensure_ascii=False)
        else:
            domains, suffixes = [], []
            for r in sorted(rules_set):
                if r.startswith('+.'):
                    suffixes.append(r[2:])
                elif r.startswith('.'):
                    suffixes.append(r[1:])
                else:
                    domains.append(r)
            json.dump({"version": 2, "rules": [{"domain": domains, "domain_suffix": suffixes}]},
                      f, indent=2, ensure_ascii=False)

    # 3. MRS & SRS（二进制）
    temp_txt_path = f"temp_workspace/merged_{rule_name}_{rule_type}.txt"
    with open(temp_txt_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(sorted(rules_set)))
    os.system(f"./mihomo convert-ruleset {rule_type} text {temp_txt_path} {mihomo_dir}/{rule_name}.mrs")
    os.system(f"./sing-box rule-set compile --output {singbox_dir}/{rule_name}.srs {singbox_dir}/{rule_name}.json")

def generate_change_report(all_changes):
    """生成 CHANGES.md 差异报告并写入输出目录"""
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [f"# 规则变更记录\n\n**更新时间：** {now_str}\n\n---\n\n"]
    summary_parts = []

    for key in sorted(all_changes.keys()):
        data       = all_changes[key]
        total      = data["total"]
        prev_total = data["prev_total"]
        added      = data["added"]
        removed    = data["removed"]

        lines.append(f"## `{key}`\n\n")

        if prev_total is None:
            lines.append(f"> 首次生成，共 **{total}** 条规则\n\n")
            summary_parts.append(f"{key}: 初始化 {total} 条")
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

            if not added and not removed:
                lines.append("- 无变化\n")
            else:
                summary_parts.append(f"{key} +{len(added)}/-{len(removed)}")

        lines.append("\n")

    report = "".join(lines)

    for out_dir in ["mihomo_out", "singbox_out"]:
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, "CHANGES.md"), "w", encoding="utf-8") as f:
            f.write(report)

# ==================== 3. 主处理流程 ====================

def process_rules(rule_type, rules_dict):
    """通用的规则处理引擎：下载 -> 解编 -> 去重合并 -> 差异比对 -> 导出格式"""
    print(f"\n[*] 开始批量构建 [{rule_type.upper()}] 分流规则...")
    change_log = {}

    for rule_name, urls in rules_dict.items():
        print(f"\n[+] 处理规则集: {rule_name}")

        prev_rules = fetch_prev_rules(rule_type, rule_name)

        merged_rules = set()
        for i, url in enumerate(urls):
            temp_mrs = f"temp_workspace/{rule_name}_{i}.mrs"
            temp_txt = f"temp_workspace/{rule_name}_{i}.txt"
            download_file(url, temp_mrs)
            os.system(f"./mihomo convert-ruleset {rule_type} mrs {temp_mrs} {temp_txt}")
            merged_rules |= read_text_rules(temp_txt)

        print(f"  -> 已完成去重合并，共计 {len(merged_rules)} 条规则，正在执行编译...")

        # 若处理的是 ipcidr 且规则集名为 china，导出新增的 bypass txt 文件
        if rule_type == "ipcidr" and rule_name == "china":
            export_bypass_txt_files(merged_rules)

        export_four_formats(rule_name, merged_rules, rule_type)

        if prev_rules is not None:
            added   = sorted(merged_rules - prev_rules)
            removed = sorted(prev_rules - merged_rules)
            print(f"  -> 差异：新增 {len(added)} 条，移除 {len(removed)} 条")
        else:
            added, removed = [], []

        change_log[f"{rule_type}/{rule_name}"] = {
            "total":      len(merged_rules),
            "prev_total": len(prev_rules) if prev_rules is not None else None,
            "added":      added,
            "removed":    removed,
        }

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