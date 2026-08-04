import os
import json
import urllib.request
import re
import tarfile
import gzip
import shutil
import ipaddress
from datetime import datetime, timezone, timedelta

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
PREV_BYPASS_DIR = "prev_bypass"

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
        print(f"[-] 获取 {repo} 最新稳定版本失败，将回退至默认版本: {e}")
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

def export_bypass_txt_files(v4_collapsed, v6_collapsed, commit_msgs):
    """提取 IPv4 和 IPv6，去重后导出到独立的 bypass_out 目录生成极简分支"""
    os.makedirs("bypass_out", exist_ok=True)
    now = datetime.now(timezone(timedelta(hours=8)))
    time_str = f"{now.year}年{now.month}月{now.day}日{now.strftime('%H:%M:%S')}"

    def process_bypass_file(filename, collapsed_nets):
        filepath = os.path.join("bypass_out", filename)
        new_rules = set(str(n) for n in collapsed_nets)
        
        with open(filepath, "w", encoding="utf-8") as f:
            for rule in sorted(new_rules):
                f.write(f"{rule}\n")
        
        prev_path = os.path.join(PREV_BYPASS_DIR, filename)
        prev_rules = None
        if os.path.exists(prev_path):
            with open(prev_path, "r", encoding="utf-8") as f:
                prev_rules = set(line.strip() for line in f if line.strip())

        added = sorted(new_rules - prev_rules) if prev_rules is not None else []
        removed = sorted(prev_rules - new_rules) if prev_rules is not None else []
        add_cnt = len(added) if prev_rules is not None else len(new_rules)
        rm_cnt = len(removed) if prev_rules is not None else 0
        
        commit_msgs[filename] = f"{time_str} - 更新 {filename}: 新增 {add_cnt} 条，移除 {rm_cnt} 条"
        
        return {
            "total": len(new_rules),
            "prev_total": len(prev_rules) if prev_rules is not None else None,
            "added": added,
            "removed": removed
        }

    v4_res = process_bypass_file("cn-ip-v4.txt", v4_collapsed)
    v6_res = process_bypass_file("cn-ip-v6.txt", v6_collapsed)

    # 专门为 Bypass 独立生成纯净的 README.md
    lines = [f"# Bypass 规则变更记录\n\n**更新时间：** {time_str}\n\n---\n\n"]
    for key, data in [("cn-ip-v4.txt", v4_res), ("cn-ip-v6.txt", v6_res)]:
        lines.append(f"## `{key}`\n\n")
        if data["prev_total"] is None:
            lines.append(f"> 首次生成，共 **{data['total']}** 条规则\n\n")
        else:
            diff = data["total"] - data["prev_total"]
            sign = (f"+{diff}" if diff >= 0 else str(diff))
            lines.append(f"- 规则总数：**{data['total']}**（{sign}）\n")

            if data["added"]:
                lines.append(f"\n<details><summary>✅ 新增 {len(data['added'])} 条（点击展开）</summary>\n\n```text\n")
                for r in data["added"][:50]: lines.append(f"{r}\n")
                if len(data["added"]) > 50: lines.append(f"... 等等\n")
                lines.append("```\n</details>\n")

            if data["removed"]:
                lines.append(f"\n<details><summary>❌ 移除 {len(data['removed'])} 条（点击展开）</summary>\n\n```text\n")
                for r in data["removed"][:50]: lines.append(f"{r}\n")
                if len(data["removed"]) > 50: lines.append(f"... 等等\n")
                lines.append("```\n</details>\n")

            if not data["added"] and not data["removed"]:
                lines.append("- 无变化\n")
        lines.append("\n")

    with open(os.path.join("bypass_out", "README.md"), "w", encoding="utf-8") as f:
        f.write("".join(lines))
    print(f"  -> 已生成 bypass 独立目录文件: IPv4 ({v4_res['total']}条), IPv6 ({v6_res['total']}条)")

def export_four_formats(rule_name, rules_set, rule_type):
    is_ip = (rule_type == "ipcidr")
    mihomo_dir  = f"mihomo_out/geo/{'geoip' if is_ip else 'geosite'}"
    singbox_dir = f"singbox_out/geo/{'geoip' if is_ip else 'geosite'}"
    os.makedirs(mihomo_dir,  exist_ok=True)
    os.makedirs(singbox_dir, exist_ok=True)

    with open(f"{mihomo_dir}/{rule_name}.yaml", 'w', encoding='utf-8') as f:
        f.write("payload:\n")
        for rule in sorted(rules_set):
            f.write(f"  - '{rule}'\n")

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

    temp_txt_path = f"temp_workspace/merged_{rule_name}_{rule_type}.txt"
    with open(temp_txt_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(sorted(rules_set)))
    os.system(f"./mihomo convert-ruleset {rule_type} text {temp_txt_path} {mihomo_dir}/{rule_name}.mrs")
    os.system(f"./sing-box rule-set compile --output {singbox_dir}/{rule_name}.srs {singbox_dir}/{rule_name}.json")

def generate_change_report(all_changes, commit_msgs):
    """分发并隔离 Mihomo 和 Sing-box 的 Markdown 报告"""
    now = datetime.now(timezone(timedelta(hours=8)))
    time_str = f"{now.year}年{now.month}月{now.day}日{now.strftime('%H:%M:%S')}"
    
    configs = [
        ("Mihomo", "mihomo_out", "(.yaml / .mrs)"),
        ("Sing-box", "singbox_out", "(.json / .srs)")
    ]
    
    for branch, out_dir, ext in configs:
        lines = [f"# {branch} 规则变更记录\n\n**更新时间：** {time_str}\n\n---\n\n"]
        for key in sorted(all_changes.keys()):
            data = all_changes[key]
            lines.append(f"## `{key}` {ext}\n\n")
            if data["prev_total"] is None:
                lines.append(f"> 首次生成，共 **{data['total']}** 条规则\n\n")
            else:
                diff = data["total"] - data["prev_total"]
                sign = (f"+{diff}" if diff >= 0 else str(diff))
                lines.append(f"- 规则总数：**{data['total']}**（{sign}）\n")

                if data["added"]:
                    lines.append(f"\n<details><summary>✅ 新增 {len(data['added'])} 条（点击展开）</summary>\n\n```text\n")
                    for r in data["added"][:50]: lines.append(f"{r}\n")
                    if len(data["added"]) > 50: lines.append(f"... 等等\n")
                    lines.append("```\n</details>\n")

                if data["removed"]:
                    lines.append(f"\n<details><summary>❌ 移除 {len(data['removed'])} 条（点击展开）</summary>\n\n```text\n")
                    for r in data["removed"][:50]: lines.append(f"{r}\n")
                    if len(data["removed"]) > 50: lines.append(f"... 等等\n")
                    lines.append("```\n</details>\n")

                if not data["added"] and not data["removed"]:
                    lines.append("- 无变化\n")
            lines.append("\n")

        report = "".join(lines)
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, "README.md"), "w", encoding="utf-8") as f:
            f.write(report)
            
    # 因为每个分支生成的 CHANGES 逻辑基本都在同一时间线，给根目录分配统一的提交信息
    commit_msgs["README.md"] = f"{time_str} - 更新 README.md"

# ==================== 3. 主处理流程 ====================

def process_rules(rule_type, rules_dict, global_commit_msgs):
    print(f"\n[*] 开始批量构建 [{rule_type.upper()}] 分流规则...")
    change_log = {}

    now = datetime.now(timezone(timedelta(hours=8)))
    time_str = f"{now.year}年{now.month}月{now.day}日{now.strftime('%H:%M:%S')}"

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

        # 无论是否是 bypass，只要是 ipcidr，全部过一次子网合并去重
        if rule_type == "ipcidr":
            v4_nets = []
            v6_nets = []
            for item in merged_rules:
                item_clean = item.strip()
                if not item_clean:
                    continue
                try:
                    net = ipaddress.ip_network(item_clean, strict=False)
                    if net.version == 4:
                        v4_nets.append(net)
                    elif net.version == 6:
                        v6_nets.append(net)
                except ValueError:
                    continue
                    
            v4_collapsed = sorted(ipaddress.collapse_addresses(v4_nets))
            v6_collapsed = sorted(ipaddress.collapse_addresses(v6_nets))
            
            # 刷新合并规则池，这步保证后续四种格式导出时的完美去重
            merged_rules = set(str(n) for n in (v4_collapsed + v6_collapsed))

            # 仅在遇到 china 时隔离执行 Bypass 脚本
            if rule_name == "china":
                export_bypass_txt_files(v4_collapsed, v6_collapsed, global_commit_msgs)

        print(f"  -> 已完成去重合并，共计 {len(merged_rules)} 条规则，正在执行编译...")
        export_four_formats(rule_name, merged_rules, rule_type)

        if prev_rules is not None:
            added = sorted(merged_rules - prev_rules)
            removed = sorted(prev_rules - merged_rules)
            add_cnt = len(added)
            rm_cnt = len(removed)
            print(f"  -> 差异：新增 {add_cnt} 条，移除 {rm_cnt} 条")
        else:
            added, removed = [], []
            add_cnt = len(merged_rules)
            rm_cnt = 0

        # 对标 CHANGES 的严格中文提交消息样式
        msg = f"{time_str} - 更新 {rule_type}/{rule_name}: 新增 {add_cnt} 条，移除 {rm_cnt} 条"
        geo_dir = 'geoip' if rule_type == 'ipcidr' else 'geosite'
        
        global_commit_msgs[f"geo/{geo_dir}/{rule_name}.yaml"] = msg
        global_commit_msgs[f"geo/{geo_dir}/{rule_name}.mrs"]  = msg
        global_commit_msgs[f"geo/{geo_dir}/{rule_name}.json"] = msg
        global_commit_msgs[f"geo/{geo_dir}/{rule_name}.srs"]  = msg

        change_log[f"{rule_type}/{rule_name}"] = {
            "total": len(merged_rules),
            "prev_total": len(prev_rules) if prev_rules is not None else None,
            "added": added,
            "removed": removed,
        }

    return change_log

def main():
    setup_binaries()
    os.makedirs("temp_workspace", exist_ok=True)

    all_changes = {}
    global_commit_msgs = {}

    for rule_type, rules_dict in RULES_CONFIG.items():
        changes = process_rules(rule_type, rules_dict, global_commit_msgs)
        all_changes.update(changes)

    generate_change_report(all_changes, global_commit_msgs)

    with open("commit_msgs.json", "w", encoding="utf-8") as f:
        json.dump(global_commit_msgs, f, ensure_ascii=False, indent=2)

    print("\n[*] 正在清理临时工作区...")
    shutil.rmtree("temp_workspace", ignore_errors=True)
    print("\n[√] 任务全部完成，所有规则集均已生成完毕！")

if __name__ == "__main__":
    main()