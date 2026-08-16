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
    return {"domain": {}, "ipcidr": {}, "classical": {}}

RULES_CONFIG = load_config()

PREV_MIHOMO_DIR = "prev_mihomo"
PREV_SINGBOX_DIR = "prev_singbox"
PREV_BYPASS_DIR = "prev_bypass"

def normalize_url(url):
    """自动将 GitHub blob 网页链接转换为 raw 直链，防止下载到 HTML 源码"""
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
    """使用 curl 稳定下载文件"""
    normalized_url = normalize_url(url)
    cmd = f"curl -L -s -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36' -o {output} '{normalized_url}'"
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
    for action in ["add", "remove"]:
        for rule_type in ["domain", "ipcidr", "classical"]:
            rules_dict = RULES_CONFIG.get(rule_type, {})
            dir_path = os.path.join("rules", action, rule_type)
            if os.path.exists(dir_path):
                valid_names = set(rules_dict.keys())
                for filename in os.listdir(dir_path):
                    if filename.endswith(".txt"):
                        rule_name = filename[:-4]
                        if rule_name not in valid_names:
                            file_path = os.path.join(dir_path, filename)
                            try:
                                os.remove(file_path)
                                print(f"[*] 已清理 config.json 中已删除规则的本地残留文件: {file_path}")
                            except Exception as e:
                                print(f"[-] 清理文件 {file_path} 失败: {e}")

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
    print("[*] 已同步并初始化自定义规则目录 (rules/add / rules/remove)")

def parse_mixed_rules_to_buckets(filename):
    domain_set = set()
    ipcidr_set = set()
    domain_regex_set = set()
    
    if not os.path.exists(filename) or os.path.getsize(filename) == 0:
        return domain_set, ipcidr_set, domain_regex_set

    # 安全防护：检查是否为二进制文件
    try:
        with open(filename, 'rb') as f:
            chunk = f.read(512)
            if b'\x00' in chunk or sum(1 for b in chunk if b < 32 and b not in (9, 10, 13)) > 20:
                print(f"[-] 警告: 发现文件 {filename} 包含二进制数据，跳过文本解析。")
                return domain_set, ipcidr_set, domain_regex_set
    except Exception:
        pass

    # 1. 尝试作为 sing-box JSON 解析
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
    except Exception:
        pass

    # 2. 文本逐行解析
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
                if '.' not in line: domain_set.add(f"*{line}*")
                else: domain_set.add(line)

    return domain_set, ipcidr_set, domain_regex_set

def load_prev_mihomo_rules(geo_subfolder, rule_name):
    prev_yaml = os.path.join(PREV_MIHOMO_DIR, "geo", geo_subfolder, f"{rule_name}.yaml")
    if os.path.exists(prev_yaml):
        rules = set()
        try:
            with open(prev_yaml, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("- "):
                        val = line[2:].strip()
                        if val.startswith("'") and val.endswith("'"): val = val[1:-1]
                        if val.startswith('"') and val.endswith('"'): val = val[1:-1]
                        if val:
                            if val.startswith('.') and not val.startswith('+.'):
                                val = f"+.{val.lstrip('.')}"
                            rules.add(val)
            return rules
        except Exception:
            pass
    return None

def load_prev_singbox_rules(geo_subfolder, rule_name):
    prev_json = os.path.join(PREV_SINGBOX_DIR, "geo", geo_subfolder, f"{rule_name}.json")
    if os.path.exists(prev_json):
        try:
            d_set, ip_set, dr_set = parse_mixed_rules_to_buckets(prev_json)
            if geo_subfolder == "geoip":
                return ip_set
            else:
                return d_set | {f"REGEX:{r}" for r in dr_set}
        except Exception:
            pass
    return None

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

def export_four_formats(rule_name, rules_set, rule_type, domain_regex_set=None):
    if domain_regex_set is None:
        domain_regex_set = set()
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

    temp_txt_path = f"temp_workspace/merged_{rule_name}_{rule_type}.txt"
    with open(temp_txt_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(sorted(rules_set)))
    os.system(f"./mihomo convert-ruleset {rule_type} text {temp_txt_path} {mihomo_dir}/{rule_name}.mrs")
    os.system(f"./sing-box rule-set compile --output {singbox_dir}/{rule_name}.srs {singbox_dir}/{rule_name}.json")

def generate_change_report(mihomo_changes, singbox_changes, commit_msgs):
    now = datetime.now(timezone(timedelta(hours=8)))
    time_str = f"{now.year}年{now.month}月{now.day}日{now.strftime('%H:%M:%S')}"
    
    configs = [
        ("Mihomo", "mihomo_out", "(.yaml / .mrs)", mihomo_changes), 
        ("Sing-box", "singbox_out", "(.json / .srs)", singbox_changes)
    ]
    for branch, out_dir, ext, changes_data in configs:
        lines = [f"# {branch} 规则变更记录\n\n**更新时间：** {time_str}\n\n---\n\n"]
        for key in sorted(changes_data.keys()):
            data = changes_data[key]
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

    mihomo_changes = {}
    singbox_changes = {}
    global_commit_msgs = {}
    now = datetime.now(timezone(timedelta(hours=8)))
    time_str = f"{now.year}年{now.month}月{now.day}日{now.strftime('%H:%M:%S')}"

    # 1. 处理 domain 和 ipcidr 常规规则
    for rule_type in ["domain", "ipcidr"]:
        rules_dict = RULES_CONFIG.get(rule_type, {})
        if not rules_dict: continue
        print(f"\n[*] 开始批量构建 [{rule_type.upper()}] 分流规则...")

        for rule_name in sorted(rules_dict.keys()):
            print(f"\n[+] 处理规则集: {rule_name}")
            merged_rules = set()
            merged_domain_regex = set()

            urls = rules_dict.get(rule_name, [])
            for i, url in enumerate(urls):
                try:
                    temp_dl = f"temp_workspace/{rule_name}_{i}.dl"
                    temp_txt = f"temp_workspace/{rule_name}_{i}.txt"
                    
                    # 下载文件，如果失败会抛出异常跳转到 except
                    curl_download(url, temp_dl)
                    
                    url_lower = url.lower()
                    if url_lower.endswith('.mrs'):
                        ret = os.system(f"./mihomo convert-ruleset {rule_type} mrs {temp_dl} {temp_txt}")
                        if ret != 0 or not os.path.exists(temp_txt):
                            raise Exception("Mihomo 转换 mrs 失败")
                    elif url_lower.endswith('.srs'):
                        temp_json = f"temp_workspace/{rule_name}_{i}.json"
                        ret = os.system(f"./sing-box rule-set decompile {temp_dl} --output {temp_json}")
                        if ret != 0 or not os.path.exists(temp_json) or os.path.getsize(temp_json) == 0:
                            raise Exception("Sing-box 反编译 srs 失败")
                        temp_txt = temp_json
                    else:
                        shutil.copy(temp_dl, temp_txt)
                    
                    d_set, ip_set, dr_set = parse_mixed_rules_to_buckets(temp_txt)
                    if rule_type == "ipcidr":
                        merged_rules |= ip_set
                    else:
                        merged_rules |= d_set
                        merged_domain_regex |= dr_set

                except Exception as e:
                    print(f"[-] 警告：处理规则源跳过 | {url} -> {e}")
                    continue  # 核心：发生任何错误都不中断程序，继续处理下一个链接

            for action in ["remove", "add"]:
                custom_file = os.path.join("rules", action, rule_type, f"{rule_name}.txt")
                if os.path.exists(custom_file):
                    d_set, ip_set, dr_set = parse_mixed_rules_to_buckets(custom_file)
                    target_set = ip_set if rule_type == "ipcidr" else d_set
                    if action == "remove":
                        merged_rules -= target_set
                        if rule_type != "ipcidr":
                            merged_domain_regex -= dr_set
                    else:
                        merged_rules |= target_set
                        if rule_type != "ipcidr":
                            merged_domain_regex |= dr_set

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

                if rule_name == "china":
                    export_bypass_txt_files(v4_collapsed, v6_collapsed, global_commit_msgs)

            export_four_formats(rule_name, merged_rules, rule_type, merged_domain_regex if rule_type != "ipcidr" else None)

            geo_dir = 'geoip' if rule_type == 'ipcidr' else 'geosite'
            
            prev_mihomo_rules = load_prev_mihomo_rules(geo_dir, rule_name)
            mihomo_new_set = set(merged_rules)
            m_added = sorted(mihomo_new_set - prev_mihomo_rules) if prev_mihomo_rules is not None else []
            m_removed = sorted(prev_mihomo_rules - mihomo_new_set) if prev_mihomo_rules is not None else []

            prev_singbox_rules = load_prev_singbox_rules(geo_dir, rule_name)
            singbox_new_set = set(merged_rules)
            if rule_type != "ipcidr" and merged_domain_regex:
                singbox_new_set |= {f"REGEX:{r}" for r in merged_domain_regex}
            
            s_added = sorted(singbox_new_set - prev_singbox_rules) if prev_singbox_rules is not None else []
            s_removed = sorted(prev_singbox_rules - singbox_new_set) if prev_singbox_rules is not None else []

            msg = f"{time_str} - 更新 {rule_type}/{rule_name}: 共 {len(singbox_new_set)} 条"
            global_commit_msgs[f"geo/{geo_dir}/{rule_name}.yaml"] = msg
            global_commit_msgs[f"geo/{geo_dir}/{rule_name}.mrs"]  = msg
            global_commit_msgs[f"geo/{geo_dir}/{rule_name}.json"] = msg
            global_commit_msgs[f"geo/{geo_dir}/{rule_name}.srs"]  = msg

            mihomo_changes[f"{rule_type}/{rule_name}"] = {
                "total": len(mihomo_new_set),
                "prev_total": len(prev_mihomo_rules) if prev_mihomo_rules is not None else None,
                "added": m_added,
                "removed": m_removed
            }
            singbox_changes[f"{rule_type}/{rule_name}"] = {
                "total": len(singbox_new_set),
                "prev_total": len(prev_singbox_rules) if prev_singbox_rules is not None else None,
                "added": s_added,
                "removed": s_removed
            }

    # 2. 处理 classical 混合格式
    classical_dict = RULES_CONFIG.get("classical", {})
    if classical_dict:
        print(f"\n[*] 开始处理 [CLASSICAL] 混合规则自动分离...")
        for rule_name, urls in classical_dict.items():
            mixed_domain_set = set()
            mixed_ip_set = set()
            mixed_domain_regex_set = set()

            for i, url in enumerate(urls):
                try:
                    temp_dl = f"temp_workspace/classical_{rule_name}_{i}.dl"
                    temp_txt = f"temp_workspace/classical_{rule_name}_{i}.txt"
                    
                    curl_download(url, temp_dl)
                    
                    url_lower = url.lower()
                    if url_lower.endswith('.mrs'):
                        ret = os.system(f"./mihomo convert-ruleset domain mrs {temp_dl} {temp_txt}")
                        if ret != 0 or not os.path.exists(temp_txt):
                            raise Exception("Mihomo 转换 mrs 失败")
                    elif url_lower.endswith('.srs'):
                        temp_json = f"temp_workspace/classical_{rule_name}_{i}.json"
                        ret = os.system(f"./sing-box rule-set decompile {temp_dl} --output {temp_json}")
                        if ret != 0 or not os.path.exists(temp_json) or os.path.getsize(temp_json) == 0:
                            raise Exception("Sing-box 反编译 srs 失败")
                        temp_txt = temp_json
                    else:
                        shutil.copy(temp_dl, temp_txt)

                    d_set, ip_set, dr_set = parse_mixed_rules_to_buckets(temp_txt)
                    mixed_domain_set |= d_set
                    mixed_ip_set |= ip_set
                    mixed_domain_regex_set |= dr_set
                    
                except Exception as e:
                    print(f"[-] 警告：处理规则源跳过 | {url} -> {e}")
                    continue  # 同样地，这里如果某条混合规则出问题，直接跳过并继续

            for action in ["remove", "add"]:
                custom_file = os.path.join("rules", action, "classical", f"{rule_name}.txt")
                if os.path.exists(custom_file):
                    d_set, ip_set, dr_set = parse_mixed_rules_to_buckets(custom_file)
                    if action == "remove":
                        mixed_domain_set -= d_set
                        mixed_ip_set -= ip_set
                        mixed_domain_regex_set -= dr_set
                    else:
                        mixed_domain_set |= d_set
                        mixed_ip_set |= ip_set
                        mixed_domain_regex_set |= dr_set

            if mixed_domain_set or mixed_domain_regex_set:
                export_four_formats(rule_name, mixed_domain_set, "domain", mixed_domain_regex_set)
                
                prev_mihomo_rules = load_prev_mihomo_rules("geosite", rule_name)
                mihomo_new_set = set(mixed_domain_set)
                m_added = sorted(mihomo_new_set - prev_mihomo_rules) if prev_mihomo_rules is not None else []
                m_removed = sorted(prev_mihomo_rules - mihomo_new_set) if prev_mihomo_rules is not None else []

                prev_singbox_rules = load_prev_singbox_rules("geosite", rule_name)
                singbox_new_set = set(mixed_domain_set)
                if mixed_domain_regex_set:
                    singbox_new_set |= {f"REGEX:{r}" for r in mixed_domain_regex_set}

                s_added = sorted(singbox_new_set - prev_singbox_rules) if prev_singbox_rules is not None else []
                s_removed = sorted(prev_singbox_rules - singbox_new_set) if prev_singbox_rules is not None else []

                msg = f"{time_str} - 更新 domain/{rule_name}: 共 {len(singbox_new_set)} 条"
                global_commit_msgs[f"geo/geosite/{rule_name}.yaml"] = msg
                global_commit_msgs[f"geo/geosite/{rule_name}.mrs"]  = msg
                global_commit_msgs[f"geo/geosite/{rule_name}.json"] = msg
                global_commit_msgs[f"geo/geosite/{rule_name}.srs"]  = msg

                mihomo_changes[f"domain/{rule_name}"] = {
                    "total": len(mihomo_new_set),
                    "prev_total": len(prev_mihomo_rules) if prev_mihomo_rules is not None else None,
                    "added": m_added,
                    "removed": m_removed
                }
                singbox_changes[f"domain/{rule_name}"] = {
                    "total": len(singbox_new_set),
                    "prev_total": len(prev_singbox_rules) if prev_singbox_rules is not None else None,
                    "added": s_added,
                    "removed": s_removed
                }

            if mixed_ip_set:
                v4_nets = [ipaddress.ip_network(x, strict=False) for x in mixed_ip_set if ipaddress.ip_network(x, strict=False).version == 4]
                v4_collapsed = sorted(ipaddress.collapse_addresses(v4_nets))
                mixed_ip_set = set(str(n) for n in v4_collapsed)
                export_four_formats(rule_name, mixed_ip_set, "ipcidr")
                
                prev_mihomo_rules = load_prev_mihomo_rules("geoip", rule_name)
                mihomo_new_set = set(mixed_ip_set)
                m_added = sorted(mihomo_new_set - prev_mihomo_rules) if prev_mihomo_rules is not None else []
                m_removed = sorted(prev_mihomo_rules - mihomo_new_set) if prev_mihomo_rules is not None else []

                prev_singbox_rules = load_prev_singbox_rules("geoip", rule_name)
                singbox_new_set = set(mixed_ip_set)
                s_added = sorted(singbox_new_set - prev_singbox_rules) if prev_singbox_rules is not None else []
                s_removed = sorted(prev_singbox_rules - singbox_new_set) if prev_singbox_rules is not None else []

                msg = f"{time_str} - 更新 ipcidr/{rule_name}: 共 {len(singbox_new_set)} 条"
                global_commit_msgs[f"geo/geoip/{rule_name}.yaml"] = msg
                global_commit_msgs[f"geo/geoip/{rule_name}.mrs"]  = msg
                global_commit_msgs[f"geo/geoip/{rule_name}.json"] = msg
                global_commit_msgs[f"geo/geoip/{rule_name}.srs"]  = msg

                mihomo_changes[f"ipcidr/{rule_name}"] = {
                    "total": len(mihomo_new_set),
                    "prev_total": len(prev_mihomo_rules) if prev_mihomo_rules is not None else None,
                    "added": m_added,
                    "removed": m_removed
                }
                singbox_changes[f"ipcidr/{rule_name}"] = {
                    "total": len(singbox_new_set),
                    "prev_total": len(prev_singbox_rules) if prev_singbox_rules is not None else None,
                    "added": s_added,
                    "removed": s_removed
                }

    generate_change_report(mihomo_changes, singbox_changes, global_commit_msgs)
    with open("commit_msgs.json", "w", encoding="utf-8") as f:
        json.dump(global_commit_msgs, f, ensure_ascii=False, indent=2)

    shutil.rmtree("temp_workspace", ignore_errors=True)
    print("\n[√] 所有任务完成：已支持错误捕获与容错跳过！")

if __name__ == "__main__":
    main()