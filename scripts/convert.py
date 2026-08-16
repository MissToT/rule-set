import os
import json
import urllib.request
import re
import tarfile
import gzip
import shutil
import ipaddress
from datetime import datetime, timezone, timedelta

def load_config():
    if os.path.exists("config.json"):
        with open("config.json", "r", encoding="utf-8") as f:
            return json.load(f)
    return {"settings": {}, "domain": {}, "ipcidr": {}, "classical": {}}

RULES_CONFIG = load_config()

def normalize_url(url):
    if "github.com" in url and "/blob/" in url:
        url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
    return url

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

def curl_download(url, output):
    normalized_url = normalize_url(url)
    cmd = f"curl -L -s -A 'Mozilla/5.0' -o {output} '{normalized_url}'"
    ret = os.system(cmd)
    if ret != 0 or not os.path.exists(output) or os.path.getsize(output) == 0:
        raise Exception(f"下载过程异常或文件为空")
    
    try:
        with open(output, 'rb') as f:
            header_snippet = f.read(200).lower()
            if b'<html' in header_snippet or b'<!doctype' in header_snippet:
                raise Exception(f"下载内容为 HTML 网页（触发防爬/CDN拦截）")
    except Exception as e:
        if "HTML" in str(e):
            raise e
        pass

def setup_binaries():
    print("[*] 正在准备编译内核...")
    sb_url = get_latest_stable_asset_url("SagerNet/sing-box", r"linux-amd64.*\.tar\.gz") or \
             "https://github.com/SagerNet/sing-box/releases/download/v1.13.14/sing-box-1.13.14-linux-amd64.tar.gz"
    
    curl_download(sb_url, "sing-box.tar.gz")
    with tarfile.open("sing-box.tar.gz", "r:gz") as tar:
        for member in tar.getmembers():
            if member.name.endswith("/sing-box"):
                with open("sing-box", "wb") as out_f:
                    out_f.write(tar.extractfile(member).read())
    os.chmod("sing-box", 0o755)

    mihomo_url = get_latest_stable_asset_url("MetaCubeX/mihomo", r"linux-amd64.*\.gz") or \
                 "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.27/mihomo-linux-amd64-v1.19.27.gz"
    
    curl_download(mihomo_url, "mihomo.gz")
    with gzip.open("mihomo.gz", "rb") as f_in:
        with open("mihomo", "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
    os.chmod("mihomo", 0o755)
    print("[*] 内核准备完毕并已赋权。")

def setup_custom_rule_dirs():
    for action in ["include", "exclude"]:
        for rule_type in ["domain", "ipcidr", "classical"]:
            dir_path = os.path.join("rules", action, rule_type)
            os.makedirs(dir_path, exist_ok=True)
            
            rule_names = RULES_CONFIG.get(rule_type, {}).keys()
            for rule_name in rule_names:
                file_path = os.path.join(dir_path, f"{rule_name}.txt")
                if not os.path.exists(file_path):
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(f"# 自定义本地 {rule_type} 覆写规则 ({action}): {rule_name}\n")
                        f.write(f"# 每行一条规则，支持 Mihomo / Sing-box 格式\n")
                        
    print("[*] 已自动为所有规则生成对应的本地覆写（include/exclude）模板文件。")

def parse_mixed_rules_to_buckets(filename):
    domain_set = set()
    ipcidr_set = set()
    domain_regex_set = set()
    
    if not os.path.exists(filename) or os.path.getsize(filename) == 0:
        return domain_set, ipcidr_set, domain_regex_set

    try:
        with open(filename, 'rb') as f:
            chunk = f.read(512)
            if b'\x00' in chunk or sum(1 for b in chunk if b < 32 and b not in (9, 10, 13)) > 20:
                return domain_set, ipcidr_set, domain_regex_set
    except Exception:
        pass

    try:
        with open(filename, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if isinstance(data, dict) and "rules" in data:
                for rule_obj in data["rules"]:
                    domains = rule_obj.get("domain", [])
                    if isinstance(domains, str): domains = [domains]
                    for d in domains:
                        if d: domain_set.add(d)

                    suffixes = rule_obj.get("domain_suffix", [])
                    if isinstance(suffixes, str): suffixes = [suffixes]
                    for ds in suffixes:
                        if ds:
                            clean_ds = ds.lstrip('+').lstrip('.')
                            domain_set.add(f"+.{clean_ds}")

                    keywords = rule_obj.get("domain_keyword", [])
                    if isinstance(keywords, str): keywords = [keywords]
                    for dk in keywords:
                        if dk: domain_set.add(f"*{dk}*")

                    regexes = rule_obj.get("domain_regex", [])
                    if isinstance(regexes, str): regexes = [regexes]
                    for dr in regexes:
                        if dr: domain_regex_set.add(dr)

                    ip_cidrs = rule_obj.get("ip_cidr", [])
                    if isinstance(ip_cidrs, str): ip_cidrs = [ip_cidrs]
                    for ip in ip_cidrs:
                        if ip:
                            try:
                                net = ipaddress.ip_network(ip, strict=False)
                                ipcidr_set.add(str(net))
                            except ValueError:
                                continue
                return domain_set, ipcidr_set, domain_regex_set
    except json.JSONDecodeError:
        pass
    except Exception:
        pass

    with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'): continue
            if line.startswith("'") and line.endswith("'"): line = line[1:-1]
            if line.startswith('"') and line.endswith('"'): line = line[1:-1]
            if line.startswith('- '):
                line = line[2:].strip()
                if line.startswith("'") and line.endswith("'"): line = line[1:-1]
                if line.startswith('"') and line.endswith('"'): line = line[1:-1]
            if line == 'payload:': continue

            if ',' in line:
                parts = [p.strip() for p in line.split(',')]
                pfx = parts[0].upper()
            elif ':' in line:
                parts = [p.strip() for p in line.split(':')]
                pfx = parts[0].upper()
            else:
                parts = [line]
                pfx = ""

            if pfx in ('IP-CIDR', 'IP-CIDR6'):
                for p in parts[1:]:
                    try:
                        net = ipaddress.ip_network(p, strict=False)
                        ipcidr_set.add(str(net))
                        break
                    except ValueError:
                        continue
                continue
            elif pfx == 'DOMAIN-REGEX':
                val = parts[1] if len(parts) > 1 else ''
                if val:
                    domain_regex_set.add(val)
                    continue
            elif pfx == 'DOMAIN-SUFFIX':
                val = parts[1] if len(parts) > 1 else ''
                if val:
                    clean_val = val.lstrip('+').lstrip('.')
                    domain_set.add(f"+.{clean_val}")
                    continue
            elif pfx in ('DOMAIN', 'DOMAIN-KEYWORD'):
                val = parts[1] if len(parts) > 1 else ''
                if val:
                    if pfx == 'DOMAIN-KEYWORD': domain_set.add(f"*{val}*")
                    else: domain_set.add(val)
                    continue

            if line.startswith('+.'):
                domain_set.add(line)
                continue
            elif line.startswith('.'):
                clean_val = line.lstrip('.')
                domain_set.add(f"+.{clean_val}")
                continue

            try:
                net = ipaddress.ip_network(line, strict=False)
                ipcidr_set.add(str(net))
                continue
            except ValueError:
                pass

            if line:
                if line.startswith('*') and line.endswith('*'):
                    domain_set.add(line)
                elif '.' not in line:
                    domain_set.add(f"*{line}*")
                else:
                    domain_set.add(line)

    return domain_set, ipcidr_set, domain_regex_set

def export_bypass_txt_files(v4_collapsed, v6_collapsed, commit_msgs):
    os.makedirs("bypass_out", exist_ok=True)
    now = datetime.now(timezone(timedelta(hours=8)))
    time_str = f"{now.year}年{now.month}月{now.day}日{now.strftime('%H:%M:%S')}"

    def process_bypass_file(filename, collapsed_nets):
        filepath = os.path.join("bypass_out", filename)
        new_rules = set(str(n) for n in collapsed_nets)
        
        with open(filepath, "w", encoding="utf-8") as f:
            for rule in sorted(new_rules):
                f.write(f"{rule}\n")
        
        commit_msgs[filename] = f"{time_str} - 更新 {filename}: 共 {len(new_rules)} 条"
        return {"total": len(new_rules)}

    v4_res = process_bypass_file("cn-ipv4.txt", v4_collapsed)
    v6_res = process_bypass_file("cn-ipv6.txt", v6_collapsed)

    lines = [
        "# 🚀 IP 绕过规则概览\n\n",
        "> 持续更新中国大陆 IP CIDR 优化分流列表。\n",
        f"> **更新时间：** {time_str}\n\n",
        "| 规则文件 | 下载地址 | 规则数量 |\n",
        "| :--- | :--- | :---: |\n"
    ]
    for key, data in [("cn-ipv4.txt", v4_res), ("cn-ipv6.txt", v6_res)]:
        lines.append(f"| `{key}` | [TXT]({key}) | **{data['total']}** |\n")

    with open(os.path.join("bypass_out", "README.md"), "w", encoding="utf-8") as f:
        f.write("".join(lines))

def export_rule_files(rule_name, rules_set, rule_type, formats, domain_regex_set=None):
    if domain_regex_set is None:
        domain_regex_set = set()
    is_ip = (rule_type == "ipcidr")
    mihomo_dir  = f"mihomo_out/geo/{'geoip' if is_ip else 'geosite'}"
    singbox_dir = f"singbox_out/geo/{'geoip' if is_ip else 'geosite'}"
    os.makedirs(mihomo_dir,  exist_ok=True)
    os.makedirs(singbox_dir, exist_ok=True)

    fmt_lower = [f.lower() for f in formats]

    mihomo_files = {
        "yaml": f"{mihomo_dir}/{rule_name}.yaml",
        "mrs": f"{mihomo_dir}/{rule_name}.mrs"
    }
    singbox_files = {
        "json": f"{singbox_dir}/{rule_name}.json",
        "srs": f"{singbox_dir}/{rule_name}.srs"
    }

    if "yaml" in fmt_lower:
        with open(mihomo_files["yaml"], 'w', encoding='utf-8') as f:
            f.write("payload:\n")
            for rule in sorted(rules_set):
                f.write(f"  - '{rule}'\n")

    if "mrs" in fmt_lower:
        yaml_path = mihomo_files["yaml"]
        temp_yaml_created = False
        if not os.path.exists(yaml_path):
            with open(yaml_path, 'w', encoding='utf-8') as f:
                f.write("payload:\n")
                for rule in sorted(rules_set):
                    f.write(f"  - '{rule}'\n")
            temp_yaml_created = True
        
        os.system(f"./mihomo convert-ruleset {rule_type} yaml {yaml_path} {mihomo_files['mrs']}")
        
        if temp_yaml_created and "yaml" not in fmt_lower:
            if os.path.exists(yaml_path):
                os.remove(yaml_path)

    if "json" in fmt_lower:
        with open(singbox_files["json"], 'w', encoding='utf-8') as f:
            if is_ip:
                json.dump({"version": 2, "rules": [{"ip_cidr": sorted(list(rules_set))}]}, f, indent=2, ensure_ascii=False)
            else:
                domains, suffixes, keywords = [], [], []
                for r in sorted(rules_set):
                    if r.startswith('*') and r.endswith('*'):
                        keywords.append(r[1:-1])
                    elif r.startswith('+.'):
                        suffixes.append(r[2:])
                    elif r.startswith('.'):
                        suffixes.append(r[1:])
                    else:
                        domains.append(r)
                
                rule_obj = {}
                if domains: rule_obj["domain"] = domains
                if suffixes: rule_obj["domain_suffix"] = suffixes
                if keywords: rule_obj["domain_keyword"] = keywords
                if domain_regex_set: rule_obj["domain_regex"] = sorted(list(domain_regex_set))
                
                json.dump({"version": 2, "rules": [rule_obj]}, f, indent=2, ensure_ascii=False)

    if "srs" in fmt_lower:
        json_path = singbox_files["json"]
        temp_json_created = False
        if not os.path.exists(json_path):
            if is_ip:
                with open(json_path, 'w', encoding='utf-8') as f:
                    json.dump({"version": 2, "rules": [{"ip_cidr": sorted(list(rules_set))}]}, f, indent=2, ensure_ascii=False)
            else:
                domains, suffixes, keywords = [], [], []
                for r in sorted(rules_set):
                    if r.startswith('*') and r.endswith('*'): keywords.append(r[1:-1])
                    elif r.startswith('+.'): suffixes.append(r[2:])
                    elif r.startswith('.'): suffixes.append(r[1:])
                    else: domains.append(r)
                rule_obj = {}
                if domains: rule_obj["domain"] = domains
                if suffixes: rule_obj["domain_suffix"] = suffixes
                if keywords: rule_obj["domain_keyword"] = keywords
                if domain_regex_set: rule_obj["domain_regex"] = sorted(list(domain_regex_set))
                with open(json_path, 'w', encoding='utf-8') as f:
                    json.dump({"version": 2, "rules": [rule_obj]}, f, indent=2, ensure_ascii=False)
            temp_json_created = True

        os.system(f"./sing-box rule-set compile --output {singbox_files['srs']} {singbox_files['json']}")

        if temp_json_created and "json" not in fmt_lower:
            if os.path.exists(json_path):
                os.remove(json_path)

    for ext, path in mihomo_files.items():
        if ext not in fmt_lower and os.path.exists(path):
            os.remove(path)

    for ext, path in singbox_files.items():
        if ext not in fmt_lower and os.path.exists(path):
            os.remove(path)

def generate_change_report(mihomo_items, singbox_items, commit_msgs):
    now = datetime.now(timezone(timedelta(hours=8)))
    time_str = f"{now.year}年{now.month}月{now.day}日{now.strftime('%H:%M:%S')}"
    
    def build_markdown_report(title, items, client_type):
        lines = [
            f"# 🛡️ {title} 代理规则集\n\n",
            f"> 自动化构建的多格式代理规则订阅源。\n",
            f"> **更新时间：** {time_str}\n\n"
        ]
        
        geosite_items = [x for x in items if x['category'] == 'geosite']
        geoip_items = [x for x in items if x['category'] == 'geoip']
        
        if geosite_items:
            lines.append("## 📂 GeoSite 域名规则\n\n")
            lines.append("| 规则名称 | 下载地址与格式 | 规则数量 |\n")
            lines.append("| :--- | :--- | :---: |\n")
            for item in sorted(geosite_items, key=lambda x: x['name']):
                name = item['name']
                total = item['total']
                active_formats = [f.lower() for f in item['formats'] if f.lower() in ('yaml', 'mrs', 'json', 'srs')]
                
                if client_type == 'mihomo':
                    valid = [f for f in active_formats if f in ('yaml', 'mrs')]
                    links = [f"[{f.upper()}](geo/geosite/{name}.{f})" for f in valid]
                else:
                    valid = [f for f in active_formats if f in ('json', 'srs')]
                    links = [f"[{f.upper()}](geo/geosite/{name}.{f})" for f in valid]
                
                link_str = " · ".join(links) if links else "无"
                lines.append(f"| `{name}` | {link_str} | **{total}** |\n")
            lines.append("\n")
            
        if geoip_items:
            lines.append("## 📂 GeoIP IP 规则\n\n")
            lines.append("| 规则名称 | 下载地址与格式 | 规则数量 |\n")
            lines.append("| :--- | :--- | :---: |\n")
            for item in sorted(geoip_items, key=lambda x: x['name']):
                name = item['name']
                total = item['total']
                active_formats = [f.lower() for f in item['formats'] if f.lower() in ('yaml', 'mrs', 'json', 'srs')]
                
                if client_type == 'mihomo':
                    valid = [f for f in active_formats if f in ('yaml', 'mrs')]
                    links = [f"[{f.upper()}](geo/geoip/{name}.{f})" for f in valid]
                else:
                    valid = [f for f in active_formats if f in ('json', 'srs')]
                    links = [f"[{f.upper()}](geo/geoip/{name}.{f})" for f in valid]
                
                link_str = " · ".join(links) if links else "无"
                lines.append(f"| `{name}` | {link_str} | **{total}** |\n")
            lines.append("\n")
            
        return "".join(lines)

    os.makedirs("mihomo_out", exist_ok=True)
    with open(os.path.join("mihomo_out", "README.md"), "w", encoding="utf-8") as f:
        f.write(build_markdown_report("Mihomo", mihomo_items, "mihomo"))

    os.makedirs("singbox_out", exist_ok=True)
    with open(os.path.join("singbox_out", "README.md"), "w", encoding="utf-8") as f:
        f.write(build_markdown_report("Sing-box", singbox_items, "singbox"))
        
    commit_msgs["README.md"] = f"{time_str} - 更新 README.md 概览页面"

def parse_rule_config(rule_config, global_enable_local, global_formats):
    include_urls = []
    exclude_urls = []
    inline_inc = []
    inline_exc = []
    final_enable_local = global_enable_local
    formats = global_formats

    if isinstance(rule_config, dict):
        final_enable_local = rule_config.get("enable_local", global_enable_local)
        formats = rule_config.get("formats", global_formats)
        
        inc_val = rule_config.get("include", [])
        if isinstance(inc_val, list):
            include_urls = inc_val
        elif isinstance(inc_val, dict):
            include_urls = inc_val.get("urls", [])
            inline_inc.extend(inc_val.get("inline", []))
        
        exc_val = rule_config.get("exclude", [])
        if isinstance(exc_val, list):
            exclude_urls = exc_val
        elif isinstance(exc_val, dict):
            exclude_urls = exc_val.get("urls", [])
            inline_exc.extend(exc_val.get("inline", []))
        
        if "inline_include" in rule_config:
            inline_inc.extend(rule_config.get("inline_include", []))
        if "inline_exclude" in rule_config:
            inline_exc.extend(rule_config.get("inline_exclude", []))
            
    elif isinstance(rule_config, list):
        include_urls = rule_config
        
    inline_inc = list(dict.fromkeys(inline_inc))
    inline_exc = list(dict.fromkeys(inline_exc))
    
    return include_urls, exclude_urls, final_enable_local, formats, inline_inc, inline_exc

def main():
    setup_binaries()
    setup_custom_rule_dirs()
    
    os.makedirs("temp_workspace", exist_ok=True)
    os.makedirs("bypass_out", exist_ok=True)
    os.makedirs("mihomo_out", exist_ok=True)
    os.makedirs("singbox_out", exist_ok=True)

    mihomo_items = []
    singbox_items = []
    global_commit_msgs = {}
    now = datetime.now(timezone(timedelta(hours=8)))
    time_str = f"{now.year}年{now.month}月{now.day}日{now.strftime('%H:%M:%S')}"

    settings = RULES_CONFIG.get("settings", {})
    global_enable_local = settings.get("enable_local", True)
    global_formats = settings.get("formats", ["mrs", "yaml", "srs", "json"])

    rule_cache = {}
    all_rule_defs = []
    
    for rule_type in ["domain", "ipcidr", "classical"]:
        type_dict = RULES_CONFIG.get(rule_type, {})
        rule_names = set(type_dict.keys())
        for action in ["include", "exclude"]:
            dir_path = os.path.join("rules", action, rule_type)
            if os.path.exists(dir_path):
                for filename in os.listdir(dir_path):
                    if filename.endswith(".txt"):
                        rule_names.add(filename[:-4])
        
        for rule_name in sorted(rule_names):
            rule_config = type_dict.get(rule_name, {})
            all_rule_defs.append((rule_type, rule_name, rule_config))

    print(f"\n[*] 开始第一阶段：下载与解析所有基础规则源...")

    for rule_type, rule_name, rule_config in all_rule_defs:
        include_urls, exclude_urls, final_enable_local, formats, inline_inc, inline_exc = parse_rule_config(
            rule_config, global_enable_local, global_formats
        )

        if not include_urls and not exclude_urls and not final_enable_local and not inline_inc:
            continue

        base_domain_set = set()
        base_ip_set = set()
        base_domain_regex = set()

        for action_type, url_list in [("include", include_urls), ("exclude", exclude_urls)]:
            for i, url in enumerate(url_list):
                try:
                    temp_dl = f"temp_workspace/{rule_type}_{rule_name}_{action_type}_{i}.dl"
                    temp_txt = f"temp_workspace/{rule_type}_{rule_name}_{action_type}_{i}.txt"
                    
                    curl_download(url, temp_dl)
                    
                    url_lower = url.lower()
                    if url_lower.endswith('.mrs'):
                        t_str = "ipcidr" if rule_type == "ipcidr" else "domain"
                        ret = os.system(f"./mihomo convert-ruleset {t_str} mrs {temp_dl} {temp_txt}")
                        if ret != 0 or not os.path.exists(temp_txt):
                            raise Exception("Mihomo 转换 mrs 失败")
                    elif url_lower.endswith('.srs'):
                        temp_json = f"temp_workspace/{rule_type}_{rule_name}_{action_type}_{i}.json"
                        ret = os.system(f"./sing-box rule-set decompile {temp_dl} --output {temp_json}")
                        if ret != 0 or not os.path.exists(temp_json) or os.path.getsize(temp_json) == 0:
                            raise Exception("Sing-box 反编译 srs 失败")
                        temp_txt = temp_json
                    else:
                        shutil.copy(temp_dl, temp_txt)
                    
                    d_set, ip_set, dr_set = parse_mixed_rules_to_buckets(temp_txt)
                    
                    if action_type == "include":
                        base_domain_set |= d_set
                        base_ip_set |= ip_set
                        base_domain_regex |= dr_set
                    else:
                        base_domain_set -= d_set
                        base_ip_set -= ip_set
                        base_domain_regex -= dr_set
                except Exception as e:
                    print(f"[-] 警告：处理规则源跳过 [{rule_type}/{rule_name}] | {url} -> {e}")
                    continue

        if final_enable_local:
            for action in ["exclude", "include"]:
                custom_file = os.path.join("rules", action, rule_type, f"{rule_name}.txt")
                if os.path.exists(custom_file):
                    d_set, ip_set, dr_set = parse_mixed_rules_to_buckets(custom_file)
                    if action == "exclude":
                        base_domain_set -= d_set
                        base_ip_set -= ip_set
                        base_domain_regex -= dr_set
                    else:
                        base_domain_set |= d_set
                        base_ip_set |= ip_set
                        base_domain_regex |= dr_set

        cache_key = (rule_type, rule_name)
        rule_cache[cache_key] = {
            "type": rule_type,
            "domain": base_domain_set,
            "ip": base_ip_set,
            "regex": base_domain_regex,
            "formats": formats,
            "inline_include": inline_inc,
            "inline_exclude": inline_exc
        }

    print(f"\n[*] 开始第二阶段：解析内联引用 (inline_include / inline_exclude)...")

    for rule_type, rule_name, rule_config in all_rule_defs:
        cache_key = (rule_type, rule_name)
        if cache_key not in rule_cache:
            continue
        
        current = rule_cache[cache_key]

        for target_name in current["inline_include"]:
            target_key = (rule_type, target_name)
            if target_key in rule_cache:
                target_data = rule_cache[target_key]
                current["domain"] |= target_data["domain"]
                current["ip"] |= target_data["ip"]
                current["regex"] |= target_data["regex"]

        for target_name in current["inline_exclude"]:
            target_key = (rule_type, target_name)
            if target_key in rule_cache:
                target_data = rule_cache[target_key]
                current["domain"] -= target_data["domain"]
                current["ip"] -= target_data["ip"]
                current["regex"] -= target_data["regex"]

    print(f"\n[*] 开始第三阶段：优化CIDR并导出最终多格式规则文件...")

    for rule_type, rule_name, rule_config in all_rule_defs:
        cache_key = (rule_type, rule_name)
        if cache_key not in rule_cache:
            continue
        
        data = rule_cache[cache_key]
        formats = data["formats"]

        if rule_type == "domain":
            merged_rules = data["domain"]
            merged_regex = data["regex"]
            
            if not merged_rules and not merged_regex:
                continue

            export_rule_files(rule_name, merged_rules, "domain", formats, merged_regex)

            singbox_total_set = set(merged_rules)
            if merged_regex:
                singbox_total_set |= {f"REGEX:{r}" for r in merged_regex}

            msg = f"{time_str} - 更新 domain/{rule_name}: 共 {len(singbox_total_set)} 条"
            for fmt in [f.lower() for f in formats]:
                if fmt == "yaml": global_commit_msgs[f"geo/geosite/{rule_name}.yaml"] = msg
                elif fmt == "mrs": global_commit_msgs[f"geo/geosite/{rule_name}.mrs"] = msg
                elif fmt == "json": global_commit_msgs[f"geo/geosite/{rule_name}.json"] = msg
                elif fmt == "srs": global_commit_msgs[f"geo/geosite/{rule_name}.srs"] = msg

            mihomo_items.append({"category": "geosite", "name": rule_name, "formats": formats, "total": len(merged_rules)})
            singbox_items.append({"category": "geosite", "name": rule_name, "formats": formats, "total": len(singbox_total_set)})

        elif rule_type == "ipcidr":
            raw_ips = data["ip"]
            if not raw_ips:
                continue

            v4_nets, v6_nets = [], []
            for item in raw_ips:
                try:
                    net = ipaddress.ip_network(item.strip(), strict=False)
                    if net.version == 4: v4_nets.append(net)
                    else: v6_nets.append(net)
                except ValueError:
                    continue
            v4_collapsed = sorted(ipaddress.collapse_addresses(v4_nets))
            v6_collapsed = sorted(ipaddress.collapse_addresses(v6_nets))
            merged_rules = set(str(n) for n in (v4_collapsed + v6_collapsed))

            if rule_name == "china":
                export_bypass_txt_files(v4_collapsed, v6_collapsed, global_commit_msgs)

            export_rule_files(rule_name, merged_rules, "ipcidr", formats)

            msg = f"{time_str} - 更新 ipcidr/{rule_name}: 共 {len(merged_rules)} 条"
            for fmt in [f.lower() for f in formats]:
                if fmt == "yaml": global_commit_msgs[f"geo/geoip/{rule_name}.yaml"] = msg
                elif fmt == "mrs": global_commit_msgs[f"geo/geoip/{rule_name}.mrs"] = msg
                elif fmt == "json": global_commit_msgs[f"geo/geoip/{rule_name}.json"] = msg
                elif fmt == "srs": global_commit_msgs[f"geo/geoip/{rule_name}.srs"] = msg

            mihomo_items.append({"category": "geoip", "name": rule_name, "formats": formats, "total": len(merged_rules)})
            singbox_items.append({"category": "geoip", "name": rule_name, "formats": formats, "total": len(merged_rules)})

        elif rule_type == "classical":
            mixed_domain_set = data["domain"]
            mixed_ip_set = data["ip"]
            mixed_regex_set = data["regex"]

            if mixed_domain_set or mixed_regex_set:
                export_rule_files(rule_name, mixed_domain_set, "domain", formats, mixed_regex_set)

                singbox_domain_set = set(mixed_domain_set)
                if mixed_regex_set:
                    singbox_domain_set |= {f"REGEX:{r}" for r in mixed_regex_set}

                msg = f"{time_str} - 更新 domain/{rule_name}: 共 {len(singbox_domain_set)} 条"
                for fmt in [f.lower() for f in formats]:
                    if fmt == "yaml": global_commit_msgs[f"geo/geosite/{rule_name}.yaml"] = msg
                    elif fmt == "mrs": global_commit_msgs[f"geo/geosite/{rule_name}.mrs"] = msg
                    elif fmt == "json": global_commit_msgs[f"geo/geosite/{rule_name}.json"] = msg
                    elif fmt == "srs": global_commit_msgs[f"geo/geosite/{rule_name}.srs"] = msg

                mihomo_items.append({"category": "geosite", "name": rule_name, "formats": formats, "total": len(mixed_domain_set)})
                singbox_items.append({"category": "geosite", "name": rule_name, "formats": formats, "total": len(singbox_domain_set)})

            if mixed_ip_set:
                v4_nets = [ipaddress.ip_network(x, strict=False) for x in mixed_ip_set if ipaddress.ip_network(x, strict=False).version == 4]
                v4_collapsed = sorted(ipaddress.collapse_addresses(v4_nets))
                collapsed_ip_set = set(str(n) for n in v4_collapsed)

                export_rule_files(rule_name, collapsed_ip_set, "ipcidr", formats)

                msg = f"{time_str} - 更新 ipcidr/{rule_name}: 共 {len(collapsed_ip_set)} 条"
                for fmt in [f.lower() for f in formats]:
                    if fmt == "yaml": global_commit_msgs[f"geo/geoip/{rule_name}.yaml"] = msg
                    elif fmt == "mrs": global_commit_msgs[f"geo/geoip/{rule_name}.mrs"] = msg
                    elif fmt == "json": global_commit_msgs[f"geo/geoip/{rule_name}.json"] = msg
                    elif fmt == "srs": global_commit_msgs[f"geo/geoip/{rule_name}.srs"] = msg

                mihomo_items.append({"category": "geoip", "name": rule_name, "formats": formats, "total": len(collapsed_ip_set)})
                singbox_items.append({"category": "geoip", "name": rule_name, "formats": formats, "total": len(collapsed_ip_set)})

    generate_change_report(mihomo_items, singbox_items, global_commit_msgs)
    
    with open("commit_msgs.json", "w", encoding="utf-8") as f:
        json.dump(global_commit_msgs, f, indent=2, ensure_ascii=False)

if __name__ == "__main__":
    main()