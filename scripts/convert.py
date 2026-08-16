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

# ==================== 2. 核心规则解析器 (严格白名单与拦截无效规则) ====================

def parse_rule_line(line, default_type):
    """
    智能解析单行规则：
    1. 严格只提取 DOMAIN、DOMAIN-SUFFIX、DOMAIN-KEYWORD、IP-CIDR、IP-CIDR6。
    2. 遇到 PROCESS-NAME、DST-PORT、GEOIP 等非法前缀直接丢弃，绝不盲目降级。
    3. 完美适配各类通配符。
    """
    line = line.strip()
    if not line or line.startswith('#'):
        return None
        
    if line.startswith("'") and line.endswith("'"): line = line[1:-1]
    if line.startswith('"') and line.endswith('"'): line = line[1:-1]
    
    # 检查是否包含逗号（即带前缀的规则）
    if ',' in line:
        parts = line.split(',', 1)
        pfx = parts[0].strip().upper()
        val = parts[1].strip()
        
        # 严格白名单校验
        if pfx == 'DOMAIN-SUFFIX':
            if val.startswith('*.'): val = val[2:]
            elif val.startswith('*'): val = val[1:]
            return ('DOMAIN-SUFFIX', val)
        elif pfx == 'DOMAIN':
            if val.startswith('*.'): return ('DOMAIN-SUFFIX', val[2:])
            elif val.startswith('*'): return ('DOMAIN-SUFFIX', val[1:].lstrip('.'))
            return ('DOMAIN', val)
        elif pfx == 'DOMAIN-KEYWORD':
            val = val.strip('*')
            return ('DOMAIN-KEYWORD', val)
        elif pfx in ('IP-CIDR', 'IP-CIDR6'):
            return (pfx, val)
        else:
            # 遇到诸如 PROCESS-NAME, DST-PORT, GEOIP 等不在白名单内的规则，直接安全丢弃！
            return None

    # 无逗号的纯文本行（无前缀适配）
    # 尝试判断是否为 IP 或 CIDR
    if '/' in line or any(c.isdigit() for c in line) and ('::' in line or '.' in line):
        try:
            ipaddress.ip_network(line, strict=False)
            return ('IP-CIDR6' if ':' in line else 'IP-CIDR', line)
        except ValueError:
            pass

    # 无前缀域名的通配符适配
    if line.startswith('*.'):
        return ('DOMAIN-SUFFIX', line[2:])
    elif line.startswith('*') and line.endswith('*') and len(line) > 2:
        return ('DOMAIN-KEYWORD', line[1:-1].strip())
    elif line.startswith('*'):
        return ('DOMAIN-SUFFIX', line[1:].lstrip('.'))
    elif line.startswith('+.'):
        return ('DOMAIN-SUFFIX', line[2:])
    elif line.startswith('.'):
        return ('DOMAIN-SUFFIX', line[1:])
        
    # 根据上下文类型兜底解析为纯域名或 IP
    if default_type == 'domain':
        return ('DOMAIN', line)
    elif default_type == 'ipcidr':
        return ('IP-CIDR6' if ':' in line else 'IP-CIDR', line)
    elif default_type == 'classical':
        return ('DOMAIN', line)
            
    return None

def rule_to_str(rule_tuple):
    pfx, val = rule_tuple
    if pfx == 'DOMAIN-SUFFIX': return f".{val}"
    elif pfx == 'DOMAIN': return val
    elif pfx == 'DOMAIN-KEYWORD': return f"DOMAIN-KEYWORD,{val}"
    else: return val

def fetch_and_parse(url, rule_type, temp_dir="temp_workspace"):
    print(f"  -> 下载源 [{rule_type}]: {url}")
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
        with open(temp_mrs, 'wb' ) as f:
            f.write(content_bytes)
        # 统一利用 mihomo 将二进制 mrs 转为文本
        os.system(f"./mihomo convert-ruleset domain mrs {temp_mrs} {temp_txt}")
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

def fetch_prev_rules(geo_dir, rule_name):
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
    return rules_str_set


# ==================== 3. 基础依赖获取与初始化 ====================

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
        print(f"[-] 获取 {repo} 最新版本失败: {e}")
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
            dir_path = os.path.join("rules", action, rule_type)
            os.makedirs(dir_path, exist_ok=True)
            rules_dict = RULES_CONFIG.get(rule_type, {})
            for rule_name in rules_dict.keys():
                file_path = os.path.join(dir_path, f"{rule_name}.txt")
                if not os.path.exists(file_path):
                    with open(file_path, 'w', encoding='utf-8') as f:
                        op = "新增" if action == "add" else "移除"
                        f.write(f"# 在此写入需要【{op}】的 {rule_name} 规则\n")
    print("[*] 已初始化 rules 模板文件夹")


# ==================== 4. 导出与处理核心 ====================

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
        commit_msgs[filename] = f"{time_str} - 更新 {filename}: 新增 {len(added)} 条，移除 {len(removed)} 条"
        return {"total": len(new_rules), "prev_total": len(prev_rules) if prev_rules is not None else None}

    process_bypass_file("cn-ipv4.txt", v4_collapsed)
    process_bypass_file("cn-ipv6.txt", v6_collapsed)

def export_rule_set(rule_name, rules_set, geo_dir, rule_type_for_convert):
    """
    统一导出 geosite 或 geoip 的四种格式文件 (.yaml, .mrs, .json, .srs)
    """
    mihomo_dir  = f"mihomo_out/geo/{geo_dir}"
    singbox_dir = f"singbox_out/geo/{geo_dir}"
    os.makedirs(mihomo_dir,  exist_ok=True)
    os.makedirs(singbox_dir, exist_ok=True)

    # 1. 导出 Mihomo YAML
    yaml_path = f"{mihomo_dir}/{rule_name}.yaml"
    with open(yaml_path, 'w', encoding='utf-8') as f:
        f.write("payload:\n")
        for rule_tuple in sorted(rules_set):
            string_val = rule_to_str(rule_tuple)
            f.write(f"  - '{string_val}'\n")

    # 2. 导出 Sing-box JSON
    json_path = f"{singbox_dir}/{rule_name}.json"
    sb_rules = []
    
    if geo_dir == "geosite":
        domains, domain_suffixes, domain_keywords = [], [], []
        for pfx, val in sorted(rules_set):
            if pfx == 'DOMAIN': domains.append(val)
            elif pfx == 'DOMAIN-SUFFIX': domain_suffixes.append(val)
            elif pfx == 'DOMAIN-KEYWORD': domain_keywords.append(val)
        
        r = {}
        if domains: r["domain"] = domains
        if domain_suffixes: r["domain_suffix"] = domain_suffixes
        if domain_keywords: r["domain_keyword"] = domain_keywords
        if r: sb_rules.append(r)
    else:
        ip_cidr = [val for pfx, val in sorted(rules_set) if pfx in ('IP-CIDR', 'IP-CIDR6')]
        if ip_cidr:
            sb_rules.append({"ip_cidr": ip_cidr})

    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump({"version": 2, "rules": sb_rules}, f, indent=2, ensure_ascii=False)

    # 3. 编译二进制 .mrs 和 .srs
    temp_txt_path = f"temp_workspace/merged_{rule_name}_{geo_dir}.txt"
    with open(temp_txt_path, 'w', encoding='utf-8') as f:
        for rule_tuple in sorted(rules_set):
            f.write(f"{rule_to_str(rule_tuple)}\n")
            
    os.system(f"./mihomo convert-ruleset {rule_type_for_convert} text {temp_txt_path} {mihomo_dir}/{rule_name}.mrs")
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


# ==================== 5. 主处理流程 (实现同名合并与 Classical 拆分) ====================

def main():
    setup_binaries()
    setup_custom_rule_dirs()
    
    os.makedirs("temp_workspace", exist_ok=True)
    os.makedirs("bypass_out", exist_ok=True)
    os.makedirs("mihomo_out", exist_ok=True)
    os.makedirs("singbox_out", exist_ok=True)

    master_domains = {}  # {rule_name: set of domain rules}
    master_ipcidrs = {}  # {rule_name: set of ip rules}

    def add_rule(name, rule_tuple):
        pfx, val = rule_tuple
        if pfx in ('DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD'):
            if name not in master_domains: master_domains[name] = set()
            master_domains[name].add((pfx, val))
        elif pfx in ('IP-CIDR', 'IP-CIDR6'):
            if name not in master_ipcidrs: master_ipcidrs[name] = set()
            master_ipcidrs[name].add((pfx, val))

    # 1. 抓取 domain 配置
    for name, urls in RULES_CONFIG.get('domain', {}).items():
        for url in urls:
            for r in fetch_and_parse(url, "domain"): add_rule(name, r)

    # 2. 抓取 ipcidr 配置
    for name, urls in RULES_CONFIG.get('ipcidr', {}).items():
        for url in urls:
            for r in fetch_and_parse(url, "ipcidr"): add_rule(name, r)

    # 3. 抓取 classical 配置（自动按类型拆分，同名会自动与上方 domain/ipcidr 合并去重）
    for name, urls in RULES_CONFIG.get('classical', {}).items():
        for url in urls:
            for r in fetch_and_parse(url, "classical"): add_rule(name, r)

    # 4. 处理自定义 add / remove 文件夹
    for action in ["add", "remove"]:
        for t in ["domain", "ipcidr", "classical"]:
            dir_path = os.path.join("rules", action, t)
            if os.path.exists(dir_path):
                for filename in os.listdir(dir_path):
                    if filename.endswith(".txt"):
                        name = filename[:-4]
                        custom_rules = read_text_rules(os.path.join(dir_path, filename), t)
                        if action == "add":
                            for r in custom_rules: add_rule(name, r)
                        elif action == "remove":
                            for r in custom_rules:
                                if name in master_domains: master_domains[name].discard(r)
                                if name in master_ipcidrs: master_ipcidrs[name].discard(r)

    global_commit_msgs = {}
    all_changes = {}
    now = datetime.now(timezone(timedelta(hours=8)))
    time_str = f"{now.year}年{now.month}月{now.day}日{now.strftime('%H:%M:%S')}"

    # ==================== 6. 导出 Geosite 规则集 ====================
    print("\n[*] 正在导出 Geosite 域名规则集...")
    for rule_name, rules_set in sorted(master_domains.items()):
        print(f" [+] geosite/{rule_name}: 共 {len(rules_set)} 条")
        prev = fetch_prev_rules("geosite", rule_name)
        
        rule_strs = {rule_to_str(r) for r in rules_set}
        add_cnt = len(rule_strs - prev) if prev is not None else len(rule_strs)
        rm_cnt = len(prev - rule_strs) if prev is not None else 0

        export_rule_set(rule_name, rules_set, "geosite", "domain")

        msg = f"{time_str} - 更新 geosite/{rule_name}: 新增 {add_cnt} 条, 移除 {rm_cnt} 条"
        global_commit_msgs[f"geo/geosite/{rule_name}.yaml"] = msg
        global_commit_msgs[f"geo/geosite/{rule_name}.mrs"]  = msg
        global_commit_msgs[f"geo/geosite/{rule_name}.json"] = msg
        global_commit_msgs[f"geo/geosite/{rule_name}.srs"]  = msg

        all_changes[f"geosite/{rule_name}"] = {
            "total": len(rule_strs),
            "prev_total": len(prev) if prev is not None else None
        }

    # ==================== 7. 导出 Geoip 规则集 (含 IP CIDR 合并) ====================
    print("\n[*] 正在导出 Geoip IP规则集...")
    for rule_name, rules_set in sorted(master_ipcidrs.items()):
        # IP 合并网段折叠逻辑
        v4_nets, v6_nets = [], []
        other_ip_rules = set()
        for pfx, val in rules_set:
            try:
                net = ipaddress.ip_network(val, strict=False)
                if net.version == 4: v4_nets.append(net)
                else: v6_nets.append(net)
            except ValueError:
                other_ip_rules.add((pfx, val))

        v4_collapsed = sorted(ipaddress.collapse_addresses(v4_nets))
        v6_collapsed = sorted(ipaddress.collapse_addresses(v6_nets))
        
        final_ip_rules = other_ip_rules.copy()
        for net in v4_collapsed: final_ip_rules.add(('IP-CIDR', str(net)))
        for net in v6_collapsed: final_ip_rules.add(('IP-CIDR6', str(net)))

        print(f" [+] geoip/{rule_name}: 共 {len(final_ip_rules)} 条")
        prev = fetch_prev_rules("geoip", rule_name)

        rule_strs = {rule_to_str(r) for r in final_ip_rules}
        add_cnt = len(rule_strs - prev) if prev is not None else len(rule_strs)
        rm_cnt = len(prev - rule_strs) if prev is not None else 0

        export_rule_set(rule_name, final_ip_rules, "geoip", "ipcidr")

        if rule_name == "china":
            export_bypass_txt_files(v4_collapsed, v6_collapsed, global_commit_msgs)

        msg = f"{time_str} - 更新 geoip/{rule_name}: 新增 {add_cnt} 条, 移除 {rm_cnt} 条"
        global_commit_msgs[f"geo/geoip/{rule_name}.yaml"] = msg
        global_commit_msgs[f"geo/geoip/{rule_name}.mrs"]  = msg
        global_commit_msgs[f"geo/geoip/{rule_name}.json"] = msg
        global_commit_msgs[f"geo/geoip/{rule_name}.srs"]  = msg

        all_changes[f"geoip/{rule_name}"] = {
            "total": len(rule_strs),
            "prev_total": len(prev) if prev is not None else None
        }

    generate_change_report(all_changes, global_commit_msgs)

    with open("commit_msgs.json", "w", encoding="utf-8") as f:
        json.dump(global_commit_msgs, f, ensure_ascii=False, indent=2)

    print("\n[*] 正在清理临时工作区...")
    shutil.rmtree("temp_workspace", ignore_errors=True)
    print("\n[√] 任务全部完成！")

if __name__ == "__main__":
    main()