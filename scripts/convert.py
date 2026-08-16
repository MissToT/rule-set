import os
import json
import urllib.request
import re
import tarfile
import gzip
import shutil
import ipaddress
from datetime import datetime, timezone, timedelta

# ==================== 1. 全局配置读取 ====================
CONFIG_FILE = "config.json"
if not os.path.exists(CONFIG_FILE):
    DEFAULT_CONFIG = {"domain": {}, "ipcidr": {}, "classical": {}}
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(DEFAULT_CONFIG, f, indent=2)
    RULES_CONFIG = DEFAULT_CONFIG
else:
    with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
        RULES_CONFIG = json.load(f)

PREV_SNAPSHOT_DIR = "prev_mihomo"
PREV_BYPASS_DIR = "prev_bypass"

# ==================== 2. 核心规则解析器 (含通配符适配) ====================

def parse_rule_line(line, default_type):
    """
    智能解析单行规则，严格限制只提取 3 种域名和 2 种 IP 规则，
    并对 DOMAIN、DOMAIN-SUFFIX、DOMAIN-KEYWORD 的各种通配符写法进行完美适配与清洗。
    """
    line = line.strip()
    if not line or line.startswith('#'):
        return None
        
    if line.startswith("'") and line.endswith("'"): line = line[1:-1]
    if line.startswith('"') and line.endswith('"'): line = line[1:-1]
    
    # 严格限定只接受这 5 种前缀
    valid_prefixes = ['DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN',
                      'IP-CIDR6', 'IP-CIDR']
    
    upper_line = line.upper()
    for prefix in valid_prefixes:
        if upper_line.startswith(prefix + ','):
            value = line[len(prefix)+1:].strip()
            
            # --- 显式前缀的通配符清洗 ---
            if prefix == 'DOMAIN-SUFFIX':
                if value.startswith('*.'):
                    value = value[2:]
                elif value.startswith('*'):
                    value = value[1:]
            elif prefix == 'DOMAIN':
                if value.startswith('*.'):
                    return ('DOMAIN-SUFFIX', value[2:])
                elif value.startswith('*'):
                    return ('DOMAIN-SUFFIX', value[1:].lstrip('.'))
            elif prefix == 'DOMAIN-KEYWORD':
                # 清理 DOMAIN-KEYWORD 前后可能自带的星号 (*abc* -> abc)
                value = value.strip('*')
                    
            return (prefix, value)
            
    # --- 无前缀行的通配符适配 ---
    if line.startswith('*.'):
        return ('DOMAIN-SUFFIX', line[2:])
    elif line.startswith('*') and line.endswith('*') and len(line) > 2:
        # 识别形如 *keyword* 的无前缀行为关键词匹配
        return ('DOMAIN-KEYWORD', line[1:-1].strip())
    elif line.startswith('*'):
        return ('DOMAIN-SUFFIX', line[1:].lstrip('.'))
    elif line.startswith('+.'):
        return ('DOMAIN-SUFFIX', line[2:])
    elif line.startswith('.'):
        return ('DOMAIN-SUFFIX', line[1:])
        
    # 根据默认类型兜底
    if default_type == 'domain':
        return ('DOMAIN', line)
    elif default_type == 'ipcidr':
        return ('IP-CIDR6' if ':' in line else 'IP-CIDR', line)
    elif default_type == 'classical':
        if '/' in line:
            return ('IP-CIDR6' if ':' in line else 'IP-CIDR', line)
        else:
            return ('DOMAIN', line)
            
    return None

def rule_to_str(rule_tuple, rule_type):
    pfx, val = rule_tuple
    if rule_type == 'domain':
        if pfx == 'DOMAIN-SUFFIX': return f".{val}"
        elif pfx == 'DOMAIN': return val
        else: return f"{pfx},{val}"
    elif rule_type == 'ipcidr':
        return val
    else:
        return f"{pfx},{val}"

def fetch_and_parse(url, rule_type, temp_dir="temp_workspace"):
    print(f"  -> 下载源: {url}")
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    try:
        with urllib.request.urlopen(req) as response:
            content_bytes = response.read()
    except Exception as e:
        print(f"[-] 下载失败: {e}")
        return set()
        
    rules = set()
    is_mrs = False
    
    if url.lower().endswith('.mrs'):
        is_mrs = True
    else:
        try:
            content_str = content_bytes.decode('utf-8')
        except UnicodeDecodeError:
            is_mrs = True

    if is_mrs:
        temp_mrs = os.path.join(temp_dir, "temp_dl.mrs")
        temp_txt = os.path.join(temp_dir, "temp_dl.txt")
        with open(temp_mrs, 'wb') as f:
            f.write(content_bytes)
        os.system(f"./mihomo convert-ruleset {rule_type} mrs {temp_mrs} {temp_txt}")
        if os.path.exists(temp_txt):
            with open(temp_txt, 'r', encoding='utf-8') as f:
                for line in f:
                    r = parse_rule_line(line, rule_type)
                    if r: rules.add(r)
        return rules

    if 'payload:' in content_str[:100] or url.endswith('.yaml') or url.endswith('.yml'):
        for line in content_str.splitlines():
            line = line.strip()
            if line.startswith("- '") and line.endswith("'"):
                r = parse_rule_line(line[3:-1], rule_type)
                if r: rules.add(r)
            elif line.startswith('- "') and line.endswith('"'):
                r = parse_rule_line(line[3:-1], rule_type)
                if r: rules.add(r)
            elif line.startswith('- '):
                val = line[2:]
                if val != 'payload:':
                    r = parse_rule_line(val, rule_type)
                    if r: rules.add(r)
        return rules

    for line in content_str.splitlines():
        r = parse_rule_line(line, rule_type)
        if r: rules.add(r)
        
    return rules

def read_text_rules(filename, rule_type):
    if not os.path.exists(filename):
        return set()
    rules = set()
    with open(filename, 'r', encoding='utf-8') as f:
        for line in f:
            r = parse_rule_line(line, rule_type)
            if r: rules.add(r)
    return rules

def fetch_prev_rules(rule_type, rule_name):
    geo_dir = 'rule-set' if rule_type == 'classical' else ('geoip' if rule_type == 'ipcidr' else 'geosite')
    yaml_path = os.path.join(PREV_SNAPSHOT_DIR, "geo", geo_dir, f"{rule_name}.yaml")
    
    if not os.path.exists(yaml_path):
        return None
    rules_str_set = set()
    with open(yaml_path, 'r', encoding='utf-8') as f:
        for line in f:
            s = line.strip()
            if s.startswith("- '") and s.endswith("'"):
                rules_str_set.add(s[3:-1])
            elif s.startswith("- ") and not s.startswith("- '"):
                val = s[2:]
                if val != 'payload:': rules_str_set.add(val)
                
    print(f"  -> 历史快照 [{rule_name}]: {len(rules_str_set)} 条")
    return rules_str_set


# ==================== 3. 基础依赖获取与编译 ====================

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
        print(f"[-] 获取 {repo} 最新版本失败，使用回退版本: {e}")
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
        for rule_type, rules_dict in RULES_CONFIG.items():
            dir_path = os.path.join("rules", action, rule_type)
            os.makedirs(dir_path, exist_ok=True)
            for rule_name in rules_dict.keys():
                file_path = os.path.join(dir_path, f"{rule_name}.txt")
                if not os.path.exists(file_path):
                    with open(file_path, 'w', encoding='utf-8') as f:
                        op = "新增" if action == "add" else "移除"
                        f.write(f"# 在此写入需要【{op}】的 {rule_name} ({rule_type}) 规则\n")
    print("[*] 已初始化 rules 模板文件夹")


# ==================== 4. 导出与处理 ====================

def export_bypass_txt_files(v4_collapsed, v6_collapsed, commit_msgs):
    os.makedirs("bypass_out", exist_ok=True)
    now = datetime.now(timezone(timedelta(hours=8)))
    time_str = f"{now.year}年{now.month}月{now.day}日{now.strftime('%H:%M:%S')}"

    def process_bypass_file(filename, collapsed_nets):
        filepath = os.path.join("bypass_out", filename)
        new_rules = set(str(n) for n in collapsed_nets)
        
        with open(filepath, "w", encoding="utf-8") as f:
            for rule in sorted(new_rules): f.write(f"{rule}\n")
        
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
        
        return {"total": len(new_rules), "prev_total": len(prev_rules) if prev_rules is not None else None, "added": added, "removed": removed}

    v4_res = process_bypass_file("cn-ipv4.txt", v4_collapsed)
    v6_res = process_bypass_file("cn-ipv6.txt", v6_collapsed)

    lines = [f"# Bypass 规则变更记录\n\n**更新时间：** {time_str}\n\n---\n\n"]
    for key, data in [("cn-ipv4.txt", v4_res), ("cn-ipv6.txt", v6_res)]:
        lines.append(f"## `{key}`\n\n")
        if data["prev_total"] is None:
            lines.append(f"> 首次生成，共 **{data['total']}** 条规则\n\n")
        else:
            diff = data["total"] - data["prev_total"]
            sign = (f"+{diff}" if diff >= 0 else str(diff))
            lines.append(f"- 规则总数：**{data['total']}**（{sign}）\n")
        lines.append("\n")

    with open(os.path.join("bypass_out", "README.md"), "w", encoding="utf-8") as f:
        f.write("".join(lines))
    print(f"  -> 已生成 bypass 独立目录文件: IPv4 ({v4_res['total']}条), IPv6 ({v6_res['total']}条)")

def export_four_formats(rule_name, rules_set, rule_type):
    geo_dir = 'rule-set' if rule_type == 'classical' else ('geoip' if rule_type == 'ipcidr' else 'geosite')
    mihomo_dir  = f"mihomo_out/geo/{geo_dir}"
    singbox_dir = f"singbox_out/geo/{geo_dir}"
    os.makedirs(mihomo_dir,  exist_ok=True)
    os.makedirs(singbox_dir, exist_ok=True)

    yaml_path = f"{mihomo_dir}/{rule_name}.yaml"
    with open(yaml_path, 'w', encoding='utf-8') as f:
        f.write("payload:\n")
        for rule_tuple in sorted(rules_set):
            string_val = rule_to_str(rule_tuple, rule_type)
            f.write(f"  - '{string_val}'\n")

    json_path = f"{singbox_dir}/{rule_name}.json"
    sb_rules = []
    
    domains, domain_suffixes, domain_keywords = [], [], []
    ip_cidr = []
    
    for pfx, val in sorted(rules_set):
        if pfx == 'DOMAIN': domains.append(val)
        elif pfx == 'DOMAIN-SUFFIX': domain_suffixes.append(val)
        elif pfx == 'DOMAIN-KEYWORD': domain_keywords.append(val)
        elif pfx in ('IP-CIDR', 'IP-CIDR6'): ip_cidr.append(val)

    if domains or domain_suffixes or domain_keywords:
        r = {}
        if domains: r["domain"] = domains
        if domain_suffixes: r["domain_suffix"] = domain_suffixes
        if domain_keywords: r["domain_keyword"] = domain_keywords
        sb_rules.append(r)
        
    if ip_cidr: 
        sb_rules.append({"ip_cidr": ip_cidr})
        
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump({"version": 2, "rules": sb_rules}, f, indent=2, ensure_ascii=False)

    temp_txt_path = f"temp_workspace/merged_{rule_name}_{rule_type}.txt"
    with open(temp_txt_path, 'w', encoding='utf-8') as f:
        for rule_tuple in sorted(rules_set):
            f.write(f"{rule_to_str(rule_tuple, rule_type)}\n")
            
    os.system(f"./mihomo convert-ruleset {rule_type} text {temp_txt_path} {mihomo_dir}/{rule_name}.mrs")
    os.system(f"./sing-box rule-set compile --output {singbox_dir}/{rule_name}.srs {json_path}")

def generate_change_report(all_changes, commit_msgs):
    now = datetime.now(timezone(timedelta(hours=8)))
    time_str = f"{now.year}年{now.month}月{now.day}日{now.strftime('%H:%M:%S')}"
    
    configs = [("Mihomo", "mihomo_out", "(.yaml / .mrs)"), ("Sing-box", "singbox_out", "(.json / .srs)")]
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
            lines.append("\n")

        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, "README.md"), "w", encoding="utf-8") as f:
            f.write("".join(lines))
            
    commit_msgs["README.md"] = f"{time_str} - 更新 README.md"

# ==================== 5. 主处理流程 ====================

def process_rules(rule_type, rules_dict, global_commit_msgs):
    print(f"\n[*] 开始批量构建 [{rule_type.upper()}] 分流规则...")
    change_log = {}

    now = datetime.now(timezone(timedelta(hours=8)))
    time_str = f"{now.year}年{now.month}月{now.day}日{now.strftime('%H:%M:%S')}"

    all_rule_names = set(rules_dict.keys())
    for action in ["add", "remove"]:
        action_dir = os.path.join("rules", action, rule_type)
        if os.path.exists(action_dir):
            for filename in os.listdir(action_dir):
                if filename.endswith(".txt"):
                    r_name = filename[:-4]
                    add_file = os.path.join("rules", "add", rule_type, filename)
                    if r_name in rules_dict or len(read_text_rules(add_file, rule_type)) > 0:
                        all_rule_names.add(r_name)

    for rule_name in sorted(all_rule_names):
        print(f"\n[+] 处理规则集: {rule_name}")

        prev_rules_str = fetch_prev_rules(rule_type, rule_name)

        merged_rules = set()
        urls = rules_dict.get(rule_name, [])
        for i, url in enumerate(urls):
            fetched = fetch_and_parse(url, rule_type, "temp_workspace")
            merged_rules |= fetched

        add_file = os.path.join("rules", "add", rule_type, f"{rule_name}.txt")
        remove_file = os.path.join("rules", "remove", rule_type, f"{rule_name}.txt")

        if os.path.exists(remove_file):
            remove_set = read_text_rules(remove_file, rule_type)
            original_len = len(merged_rules)
            merged_rules -= remove_set
            print(f"  -> [自定义] 移除了 {original_len - len(merged_rules)} 条规则")

        if os.path.exists(add_file):
            add_set = read_text_rules(add_file, rule_type)
            original_len = len(merged_rules)
            merged_rules |= add_set
            print(f"  -> [自定义] 新增了 {len(merged_rules) - original_len} 条规则")

        v4_nets, v6_nets = [], []
        other_rules = set()
        for pfx, val in merged_rules:
            if pfx in ('IP-CIDR', 'IP-CIDR6'):
                try:
                    net = ipaddress.ip_network(val, strict=False)
                    if net.version == 4: v4_nets.append(net)
                    else: v6_nets.append(net)
                except ValueError:
                    other_rules.add((pfx, val))
            else:
                other_rules.add((pfx, val))
                
        v4_collapsed = sorted(ipaddress.collapse_addresses(v4_nets))
        v6_collapsed = sorted(ipaddress.collapse_addresses(v6_nets))
        
        final_rules = other_rules.copy()
        for net in v4_collapsed: final_rules.add(('IP-CIDR', str(net)))
        for net in v6_collapsed: final_rules.add(('IP-CIDR6', str(net)))

        if rule_type == "ipcidr" and rule_name == "china":
            export_bypass_txt_files(v4_collapsed, v6_collapsed, global_commit_msgs)

        print(f"  -> 已完成去重合并，共计 {len(final_rules)} 条规则，正在执行编译...")
        export_four_formats(rule_name, final_rules, rule_type)

        merged_strs = {rule_to_str(r, rule_type) for r in final_rules}
        if prev_rules_str is not None:
            added = sorted(merged_strs - prev_rules_str)
            removed = sorted(prev_rules_str - merged_strs)
            add_cnt = len(added)
            rm_cnt = len(removed)
            print(f"  -> 差异：总计新增 {add_cnt} 条，移除 {rm_cnt} 条")
        else:
            added, removed = [], []
            add_cnt = len(merged_strs)
            rm_cnt = 0

        msg = f"{time_str} - 更新 {rule_type}/{rule_name}: 新增 {add_cnt} 条, 移除 {rm_cnt} 条"
        geo_dir = 'rule-set' if rule_type == 'classical' else ('geoip' if rule_type == 'ipcidr' else 'geosite')
        
        global_commit_msgs[f"geo/{geo_dir}/{rule_name}.yaml"] = msg
        global_commit_msgs[f"geo/{geo_dir}/{rule_name}.mrs"]  = msg
        global_commit_msgs[f"geo/{geo_dir}/{rule_name}.json"] = msg
        global_commit_msgs[f"geo/{geo_dir}/{rule_name}.srs"]  = msg

        change_log[f"{rule_type}/{rule_name}"] = {
            "total": len(merged_strs),
            "prev_total": len(prev_rules_str) if prev_rules_str is not None else None,
            "added": added,
            "removed": removed,
        }

    return change_log

def main():
    setup_binaries()
    setup_custom_rule_dirs()
    
    os.makedirs("temp_workspace", exist_ok=True)
    os.makedirs("bypass_out", exist_ok=True)
    os.makedirs("mihomo_out", exist_ok=True)
    os.makedirs("singbox_out", exist_ok=True)

    all_changes = {}
    global_commit_msgs = {}

    for rule_type, rules_dict in RULES_CONFIG.items():
        if not isinstance(rules_dict, dict): continue
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