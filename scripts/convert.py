import os
import json
import urllib.request
import re
import tarfile
import gzip
import shutil
import ipaddress
from datetime import datetime, timezone, timedelta

# 加载独立配置文件
def load_config():
    if os.path.exists("config.json"):
        with open("config.json", "r", encoding="utf-8") as f:
            return json.load(f)
    return {"domain": {}, "ipcidr": {}, "classical": {}}

RULES_CONFIG = load_config()

PREV_SNAPSHOT_DIR = "prev_mihomo"
PREV_BYPASS_DIR = "prev_bypass"

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
        print(f"[-] 获取 {repo} 最新稳定版本失败: {e}")
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

def setup_custom_rule_dirs():
    for action in ["add", "remove"]:
        for rule_type in ["domain", "ipcidr", "classical"]:
            rules_dict = RULES_CONFIG.get(rule_type, {})
            dir_path = os.path.join("rules", action, rule_type)
            os.makedirs(dir_path, exist_ok=True)
            for rule_name in rules_dict.keys():
                file_path = os.path.join(dir_path, f"{rule_name}.txt")
                if not os.path.exists(file_path):
                    with open(file_path, 'w', encoding='utf-8') as f:
                        op = "新增" if action == "add" else "移除"
                        f.write(f"# 在此写入需要【{op}】的 {rule_name} ({rule_type}) 规则\n")
    print("[*] 已初始化自定义规则目录 (rules/add / rules/remove)")

def download_file(url, filename):
    print(f"  -> 下载源: {url}")
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req) as response:
        with open(filename, 'wb') as f:
            f.write(response.read())

def parse_mixed_rules_to_buckets(filename):
    """
    精准解析：
    - 显式指定的 DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, IP-CIDR, IP-CIDR6 原样提取。
    - 对于没有前缀的纯文本行：
      * 如果能解析为 IP，则归入 ipcidr。
      * 如果不包含点号 '.' 或者明显是纯关键词的（如 speedtest、ookla），自动加上关键字格式或作为关键字处理；
        （在 mihomo/sing-box 语法中，如果写成纯文本且无点号， Mihomo 默认常常当 keyword 或完整 domain，
         但按照你的实际需求，无前缀纯字符串应直接作为 DOMAIN-KEYWORD 处理，或者带上 DOMAIN-KEYWORD 前缀输出）。
    """
    domain_set = set()
    ipcidr_set = set()
    
    if not os.path.exists(filename):
        return domain_set, ipcidr_set

    with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if line.startswith("'") and line.endswith("'"): line = line[1:-1]
            if line.startswith('"') and line.endswith('"'): line = line[1:-1]
            if line.startswith('- '):
                line = line[2:].strip()
                if line.startswith("'") and line.endswith("'"): line = line[1:-1]
                if line.startswith('"') and line.endswith('"'): line = line[1:-1]
            if line == 'payload:':
                continue

            # 处理带逗号的格式
            if ',' in line:
                parts = [p.strip() for p in line.split(',')]
                pfx = parts[0].upper()
                
                if pfx in ('IP-CIDR', 'IP-CIDR6'):
                    for p in parts[1:]:
                        try:
                            net = ipaddress.ip_network(p, strict=False)
                            ipcidr_set.add(str(net))
                            break
                        except ValueError:
                            continue
                    continue
                elif pfx in ('DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD'):
                    val = parts[1] if len(parts) > 1 else ''
                    if val:
                        # 核心修改：如果是 DOMAIN-KEYWORD，或者用户输入了这类没有点号的，保留其语义
                        if pfx == 'DOMAIN-KEYWORD':
                            domain_set.add(f"DOMAIN-KEYWORD,{val}")
                        else:
                            domain_set.add(line) # 或者是标准输出
                        continue
                else:
                    continue

            # 尝试直接解析为 IP 网段
            try:
                net = ipaddress.ip_network(line, strict=False)
                ipcidr_set.add(str(net))
                continue
            except ValueError:
                pass

            # 如果没有前缀、没有逗号，且是一行纯文本：
            # 如果不包含 '.' 且像 speedtest/ookla 这种，直接存为 DOMAIN-KEYWORD 格式以便精准识别
            if line:
                if '.' not in line:
                    domain_set.add(f"DOMAIN-KEYWORD,{line}")
                else:
                    domain_set.add(line)

    return domain_set, ipcidr_set

def export_four_formats(rule_name, rules_set, rule_type):
    is_ip = (rule_type == "ipcidr")
    mihomo_dir  = f"mihomo_out/geo/{'geoip' if is_ip else 'geosite'}"
    singbox_dir = f"singbox_out/geo/{'geoip' if is_ip else 'geosite'}"
    os.makedirs(mihomo_dir,  exist_ok=True)
    os.makedirs(singbox_dir, exist_ok=True)

    with open(f"{mihomo_dir}/{rule_name}.yaml", 'w', encoding='utf-8') as f:
        f.write("payload:\n")
        for rule in sorted(rules_set):
            # 如果带有逗号（如 DOMAIN-KEYWORD,xxx），yaml 输出时需要正确带上或按 Mihomo 规范格式化
            if ',' in rule:
                f.write(f"  - '{rule}'\n")
            else:
                f.write(f"  - '{rule}'\n")

    with open(f"{singbox_dir}/{rule_name}.json", 'w', encoding='utf-8') as f:
        if is_ip:
            json.dump({"version": 2, "rules": [{"ip_cidr": sorted(list(rules_set))}]}, f, indent=2, ensure_ascii=False)
        else:
            domains, suffixes, keywords = [], [], []
            for r in sorted(rules_set):
                if ',' in r:
                    pfx, val = r.split(',', 1)
                    pfx = pfx.strip().upper()
                    val = val.strip()
                    if pfx == 'DOMAIN-KEYWORD':
                        keywords.append(val)
                    elif pfx == 'DOMAIN-SUFFIX':
                        suffixes.append(val)
                    elif pfx == 'DOMAIN':
                        domains.append(val)
                else:
                    if r.startswith('+.'): suffixes.append(r[2:])
                    elif r.startswith('.'): suffixes.append(r[1:])
                    else: domains.append(r)
            
            rule_obj = {}
            if domains: rule_obj["domain"] = domains
            if suffixes: rule_obj["domain_suffix"] = suffixes
            if keywords: rule_obj["domain_keyword"] = keywords
            json.dump({"version": 2, "rules": [rule_obj]}, f, indent=2, ensure_ascii=False)

    temp_txt_path = f"temp_workspace/merged_{rule_name}_{rule_type}.txt"
    with open(temp_txt_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(sorted(rules_set)))
    os.system(f"./mihomo convert-ruleset {rule_type} text {temp_txt_path} {mihomo_dir}/{rule_name}.mrs")
    os.system(f"./sing-box rule-set compile --output {singbox_dir}/{rule_name}.srs {singbox_dir}/{rule_name}.json")

def generate_change_report(all_changes, commit_msgs):
    now = datetime.now(timezone(timedelta(hours=8)))
    time_str = f"{now.year}年{now.month}月{now.day}日{now.strftime('%H:%M:%S')}"
    
    configs = [("Mihomo", "mihomo_out", "(.yaml / .mrs)"), ("Sing-box", "singbox_out", "(.json / .srs)")]
    for branch, out_dir, ext in configs:
        lines = [f"# {branch} 规则变更记录\n\n**更新时间：** {time_str}\n\n---\n\n"]
        for key in sorted(all_changes.keys()):
            data = all_changes[key]
            lines.append(f"## `{key}` {ext}\n- 规则总数：**{data['total']}**\n\n")
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, "README.md"), "w", encoding="utf-8") as f:
            f.write("".join(lines))
    commit_msgs["README.md"] = f"{time_str} - 更新 README.md"

def main():
    setup_binaries()
    setup_custom_rule_dirs()
    
    os.makedirs("temp_workspace", exist_ok=True)
    os.makedirs("bypass_out", exist_ok=True)
    os.makedirs("mihomo_out", exist_ok=True)
    os.makedirs("singbox_out", exist_ok=True)

    all_changes = {}
    global_commit_msgs = {}
    now = datetime.now(timezone(timedelta(hours=8)))
    time_str = f"{now.year}年{now.month}月{now.day}日{now.strftime('%H:%M:%S')}"

    # 1. 处理 domain 和 ipcidr 常规规则
    for rule_type in ["domain", "ipcidr"]:
        rules_dict = RULES_CONFIG.get(rule_type, {})
        print(f"\n[*] 开始批量构建 [{rule_type.upper()}] 分流规则...")

        all_rule_names = set(rules_dict.keys())
        for action in ["add", "remove"]:
            action_dir = os.path.join("rules", action, rule_type)
            if os.path.exists(action_dir):
                for filename in os.listdir(action_dir):
                    if filename.endswith(".txt"):
                        all_rule_names.add(filename[:-4])

        for rule_name in sorted(all_rule_names):
            print(f"\n[+] 处理规则集: {rule_name}")
            merged_rules = set()

            urls = rules_dict.get(rule_name, [])
            for i, url in enumerate(urls):
                temp_dl = f"temp_workspace/{rule_name}_{i}.dl"
                temp_txt = f"temp_workspace/{rule_name}_{i}.txt"
                download_file(url, temp_dl)
                
                if url.lower().endswith('.mrs'):
                    ret = os.system(f"./mihomo convert-ruleset {rule_type} mrs {temp_dl} {temp_txt}")
                    if ret != 0 or not os.path.exists(temp_txt):
                        shutil.copy(temp_dl, temp_txt)
                else:
                    shutil.copy(temp_dl, temp_txt)
                
                d_set, ip_set = parse_mixed_rules_to_buckets(temp_txt)
                if rule_type == "ipcidr":
                    merged_rules |= ip_set
                else:
                    merged_rules |= d_set

            for action in ["remove", "add"]:
                custom_file = os.path.join("rules", action, rule_type, f"{rule_name}.txt")
                if os.path.exists(custom_file):
                    d_set, ip_set = parse_mixed_rules_to_buckets(custom_file)
                    target_set = ip_set if rule_type == "ipcidr" else d_set
                    if action == "remove":
                        merged_rules -= target_set
                    else:
                        merged_rules |= target_set

            if rule_type == "ipcidr":
                v4_nets, v6_nets = [], []
                for item in merged_rules:
                    try:
                        net = ipaddress.ip_network(item.strip(), strict=False)
                        if net.version == 4: v4_nets.append(net)
                        else: v6_nets.append(net)
                    except ValueError:
                        continue
                v4_collapsed = sorted(ipaddress.collapse_addresses(v4_nets))
                v6_collapsed = sorted(ipaddress.collapse_addresses(v6_nets))
                merged_rules = set(str(n) for n in (v4_collapsed + v6_collapsed))

            export_four_formats(rule_name, merged_rules, rule_type)

            geo_dir = 'geoip' if rule_type == 'ipcidr' else 'geosite'
            msg = f"{time_str} - 更新 {rule_type}/{rule_name}: 共 {len(merged_rules)} 条"
            global_commit_msgs[f"geo/{geo_dir}/{rule_name}.yaml"] = msg
            global_commit_msgs[f"geo/{geo_dir}/{rule_name}.mrs"]  = msg
            global_commit_msgs[f"geo/{geo_dir}/{rule_name}.json"] = msg
            global_commit_msgs[f"geo/{geo_dir}/{rule_name}.srs"]  = msg

            all_changes[f"{rule_type}/{rule_name}"] = {"total": len(merged_rules)}

    # 2. 处理 classical 混合格式：自动提取并直接放到对应名字的域名/IP规则集中，不加额外后缀
    classical_dict = RULES_CONFIG.get("classical", {})
    if classical_dict:
        print(f"\n[*] 开始处理 [CLASSICAL] 混合规则自动分离...")
        for rule_name, urls in classical_dict.items():
            mixed_domain_set = set()
            mixed_ip_set = set()

            for i, url in enumerate(urls):
                temp_dl = f"temp_workspace/classical_{rule_name}_{i}.dl"
                download_file(url, temp_dl)
                d_set, ip_set = parse_mixed_rules_to_buckets(temp_dl)
                mixed_domain_set |= d_set
                mixed_ip_set |= ip_set

            for action in ["remove", "add"]:
                custom_file = os.path.join("rules", action, "classical", f"{rule_name}.txt")
                if os.path.exists(custom_file):
                    d_set, ip_set = parse_mixed_rules_to_buckets(custom_file)
                    if action == "remove":
                        mixed_domain_set -= d_set
                        mixed_ip_set -= ip_set
                    else:
                        mixed_domain_set |= d_set
                        mixed_ip_set |= ip_set

            if mixed_domain_set:
                export_four_formats(rule_name, mixed_domain_set, "domain")
                msg = f"{time_str} - 更新 domain/{rule_name}: 共 {len(mixed_domain_set)} 条"
                global_commit_msgs[f"geo/geosite/{rule_name}.yaml"] = msg
                global_commit_msgs[f"geo/geosite/{rule_name}.mrs"]  = msg
                global_commit_msgs[f"geo/geosite/{rule_name}.json"] = msg
                global_commit_msgs[f"geo/geosite/{rule_name}.srs"]  = msg
                all_changes[f"domain/{rule_name}"] = {"total": len(mixed_domain_set)}

            if mixed_ip_set:
                v4_nets = [ipaddress.ip_network(x, strict=False) for x in mixed_ip_set if ipaddress.ip_network(x, strict=False).version == 4]
                v4_collapsed = sorted(ipaddress.collapse_addresses(v4_nets))
                mixed_ip_set = set(str(n) for n in v4_collapsed)
                export_four_formats(rule_name, mixed_ip_set, "ipcidr")
                msg = f"{time_str} - 更新 ipcidr/{rule_name}: 共 {len(mixed_ip_set)} 条"
                global_commit_msgs[f"geo/geoip/{rule_name}.yaml"] = msg
                global_commit_msgs[f"geo/geoip/{rule_name}.mrs"]  = msg
                global_commit_msgs[f"geo/geoip/{rule_name}.json"] = msg
                global_commit_msgs[f"geo/geoip/{rule_name}.srs"]  = msg
                all_changes[f"ipcidr/{rule_name}"] = {"total": len(mixed_ip_set)}

    generate_change_report(all_changes, global_commit_msgs)
    with open("commit_msgs.json", "w", encoding="utf-8") as f:
        json.dump(global_commit_msgs, f, ensure_ascii=False, indent=2)

    shutil.rmtree("temp_workspace", ignore_errors=True)
    print("\n[√] 所有任务及 classical 分离已全部完成！")

if __name__ == "__main__":
    main()