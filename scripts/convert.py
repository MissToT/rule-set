import os
import sys
import json
import urllib.request
import re
import tarfile
import gzip
import shutil

# ==================== 配置区 ====================
# 1. 基础规则源
URL_MISSTOT_CHINA_DOMAIN = "https://github.com/MissToT/Picture/raw/Meta/Rules/domain/China.mrs"
URL_MISSTOT_PROXY_DOMAIN = "https://github.com/MissToT/Picture/raw/Meta/Rules/domain/Proxy.mrs"
URL_QUIXOTIC_CN_DOMAIN = "https://github.com/QuixoticHeart/rule-set/raw/ruleset/meta/domain/cn.mrs"
URL_QUIXOTIC_PROXY_DOMAIN = "https://github.com/QuixoticHeart/rule-set/raw/ruleset/meta/domain/proxy.mrs"
URL_QUIXOTIC_CN_IP = "https://github.com/QuixoticHeart/rule-set/raw/ruleset/meta/ipcidr/cn.mrs"
URL_QUIXOTIC_PROXY_IP = "https://raw.githubusercontent.com/QuixoticHeart/rule-set/ruleset/meta/ipcidr/proxy.mrs"

# 2. 自定义规则集配置
RULES_CONFIG = {
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
}

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
        print(f"获取 {repo} 最新稳定版本失败: {e}")
    return None

def setup_binaries():
    print("[-] 正在准备 sing-box 和 mihomo 最新稳定版编译内核...")
    sb_url = get_latest_stable_asset_url("SagerNet/sing-box", r"linux-amd64.*\.tar\.gz") or "https://github.com/SagerNet/sing-box/releases/download/v1.18.0/sing-box-1.18.0-linux-amd64.tar.gz"
    urllib.request.urlretrieve(sb_url, "sing-box.tar.gz")
    with tarfile.open("sing-box.tar.gz", "r:gz") as tar:
        for member in tar.getmembers():
            if member.name.endswith("/sing-box"):
                with open("sing-box", "wb") as out_f: out_f.write(tar.extractfile(member).read())
    os.chmod("sing-box", 0o755)
    
    mihomo_url = get_latest_stable_asset_url("MetaCubeX/mihomo", r"linux-amd64.*\.gz") or "https://github.com/MetaCubeX/mihomo/releases/download/v1.18.3/mihomo-linux-amd64-v1.18.3.gz"
    urllib.request.urlretrieve(mihomo_url, "mihomo.gz")
    with gzip.open("mihomo.gz", "rb") as f_in:
        with open("mihomo", "wb") as f_out: shutil.copyfileobj(f_in, f_out)
    os.chmod("mihomo", 0o755)

def download_file(url, filename):
    print(f"[-] 下载: {url}")
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req) as response:
        with open(filename, 'wb') as f: f.write(response.read())

def read_text_rules(filename):
    if not os.path.exists(filename): return set()
    rules = set()
    with open(filename, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'): rules.add(line)
    return rules

def generate_formats(name, rules_set, is_ip=False):
    """为指定规则集生成 YAML, JSON, MRS, SRS"""
    # 路径配置
    base_dir = "mihomo_out/geo/geoip" if is_ip else "mihomo_out/geo/geosite"
    sb_dir = "singbox_out/geo/geoip" if is_ip else "singbox_out/geo/geosite"
    os.makedirs(base_dir, exist_ok=True); os.makedirs(sb_dir, exist_ok=True)
    
    # 1. YAML (Mihomo)
    with open(f"{base_dir}/{name}.yaml", 'w', encoding='utf-8') as f:
        f.write("payload:\n")
        for rule in sorted(rules_set): f.write(f"  - '{rule}'\n")
        
    # 2. JSON (Sing-box)
    with open(f"{sb_dir}/{name}.json", 'w', encoding='utf-8') as f:
        if is_ip:
            json.dump({"version": 2, "rules": [{"ip_cidr": sorted(list(rules_set))}]}, f, indent=2, ensure_ascii=False)
        else:
            domains, suffixes = [], []
            for r in sorted(rules_set):
                if r.startswith('+.'): suffixes.append(r[2:])
                elif r.startswith('.'): suffixes.append(r[1:])
                else: domains.append(r)
            json.dump({"version": 2, "rules": [{"domain": domains, "domain_suffix": suffixes}]}, f, indent=2, ensure_ascii=False)
            
    # 3. MRS & SRS (Binary)
    txt_path = f"temp_{name}.txt"
    with open(txt_path, 'w', encoding='utf-8') as f: f.write("\n".join(sorted(rules_set)))
    type_arg = "ipcidr" if is_ip else "domain"
    os.system(f"./mihomo convert-ruleset {type_arg} text {txt_path} {base_dir}/{name}.mrs")
    os.system(f"./sing-box rule-set compile --output {sb_dir}/{name}.srs {sb_dir}/{name}.json")

def main():
    setup_binaries()
    
    # 基础 Domain 处理
    download_file(URL_MISSTOT_CHINA_DOMAIN, "m1.mrs"); download_file(URL_QUIXOTIC_CN_DOMAIN, "m2.mrs")
    os.system("./mihomo convert-ruleset domain mrs m1.mrs t1.txt"); os.system("./mihomo convert-ruleset domain mrs m2.mrs t2.txt")
    generate_formats("china", read_text_rules("t1.txt") | read_text_rules("t2.txt"))
    
    download_file(URL_MISSTOT_PROXY_DOMAIN, "m3.mrs"); download_file(URL_QUIXOTIC_PROXY_DOMAIN, "m4.mrs")
    os.system("./mihomo convert-ruleset domain mrs m3.mrs t3.txt"); os.system("./mihomo convert-ruleset domain mrs m4.mrs t4.txt")
    generate_formats("proxy", read_text_rules("t3.txt") | read_text_rules("t4.txt"))
    
    # 基础 IP 处理
    download_file(URL_QUIXOTIC_CN_IP, "m5.mrs"); download_file(URL_QUIXOTIC_PROXY_IP, "m6.mrs")
    os.system("./mihomo convert-ruleset ipcidr mrs m5.mrs t5.txt"); os.system("./mihomo convert-ruleset ipcidr mrs m6.mrs t6.txt")
    generate_formats("china", read_text_rules("t5.txt"), is_ip=True)
    generate_formats("proxy", read_text_rules("t6.txt"), is_ip=True)
    
    # 自定义规则处理
    for name, urls in RULES_CONFIG.items():
        merged = set()
        for i, url in enumerate(urls):
            download_file(url, f"c_{name}_{i}.mrs")
            os.system(f"./mihomo convert-ruleset domain mrs c_{name}_{i}.mrs c_{name}_{i}.txt")
            merged |= read_text_rules(f"c_{name}_{i}.txt")
        generate_formats(name, merged)

    print("\n[√] 任务全部完成，所有规则集已生成 4 种格式并去重。")

if __name__ == "__main__":
    main()