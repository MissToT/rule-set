import os
import sys
import json
import urllib.request
import re
import tarfile
import gzip
import shutil

# 规则源配置
URL_MISSTOT_CHINA = "https://v6.gh-proxy.org/github.com/MissToT/Picture/raw/Meta/Rules/domain/China.mrs"
URL_MISSTOT_PROXY = "https://v6.gh-proxy.org/github.com/MissToT/Picture/raw/Meta/Rules/domain/Proxy.mrs"
URL_QUIXOTIC_CN_MRS = "https://v6.gh-proxy.org/github.com/QuixoticHeart/rule-set/raw/ruleset/meta/domain/cn.mrs"
URL_QUIXOTIC_PROXY_MRS = "https://v6.gh-proxy.org/github.com/QuixoticHeart/rule-set/raw/ruleset/meta/domain/proxy.mrs"

def get_latest_asset_url(repo, pattern):
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    req = urllib.request.Request(url, headers={'User-Agent': 'GitHub-Actions-Script'})
    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            for asset in data.get('assets', []):
                if re.search(pattern, asset['name'], re.IGNORECASE):
                    return asset['browser_download_url']
    except Exception as e:
        print(f"获取 {repo} 最新版本失败: {e}")
    return None

def setup_binaries():
    print("[-] 正在准备 sing-box 和 mihomo 编译内核...")
    
    # 准备 sing-box
    sb_url = get_latest_asset_url("SagerNet/sing-box", r"linux-amd64.*\.tar\.gz")
    if not sb_url:
        sb_url = "https://github.com/SagerNet/sing-box/releases/download/v1.11.2/sing-box-1.11.2-linux-amd64.tar.gz"
    urllib.request.urlretrieve(sb_url, "sing-box.tar.gz")
    with tarfile.open("sing-box.tar.gz", "r:gz") as tar:
        for member in tar.getmembers():
            if member.name.endswith("/sing-box"):
                f = tar.extractfile(member)
                if f:
                    with open("sing-box", "wb") as out_f:
                        out_f.write(f.read())
    os.chmod("sing-box", 0o755)
    
    # 准备 mihomo
    mihomo_url = get_latest_asset_url("MetaCubeX/mihomo", r"linux-amd64.*\.gz")
    if not mihomo_url:
        mihomo_url = "https://github.com/MetaCubeX/mihomo/releases/download/v1.18.3/mihomo-linux-amd64-v1.18.3.gz"
    urllib.request.urlretrieve(mihomo_url, "mihomo.gz")
    with gzip.open("mihomo.gz", "rb") as f_in:
        with open("mihomo", "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
    os.chmod("mihomo", 0o755)

def download_file(url, filename):
    print(f"[-] 下载规则源: {url} -> {filename}")
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response:
            with open(filename, 'wb') as f:
                f.write(response.read())
    except Exception as e:
        print(f"下载失败 {url}: {e}")
        sys.exit(1)

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

def write_text_rules(rules_set, filename):
    with open(filename, 'w', encoding='utf-8') as f:
        for rule in sorted(rules_set):
            f.write(f"{rule}\n")

def main():
    setup_binaries()
    
    # 构建严谨的 geo/geosite 和 geo/geoip 目录树结构
    os.makedirs("mihomo_out/geo/geosite", exist_ok=True)
    os.makedirs("mihomo_out/geo/geoip", exist_ok=True)
    os.makedirs("singbox_out/geo/geosite", exist_ok=True)
    os.makedirs("singbox_out/geo/geoip", exist_ok=True)

    # 下载所需文件（移除了 json 文件的下载）
    download_file(URL_MISSTOT_CHINA, "misstot_china.mrs")
    download_file(URL_MISSTOT_PROXY, "misstot_proxy.mrs")
    download_file(URL_QUIXOTIC_CN_MRS, "quixotic_cn.mrs")
    download_file(URL_QUIXOTIC_PROXY_MRS, "quixotic_proxy.mrs")

    # 解编二进制 .mrs 到明文文本
    print("[-] 解析 .mrs 二进制规则文件...")
    os.system("./mihomo convert-ruleset domain mrs misstot_china.mrs misstot_china.txt")
    os.system("./mihomo convert-ruleset domain mrs misstot_proxy.mrs misstot_proxy.txt")
    os.system("./mihomo convert-ruleset domain mrs quixotic_cn.mrs quixotic_cn.txt")
    os.system("./mihomo convert-ruleset domain mrs quixotic_proxy.mrs quixotic_proxy.txt")

    # ==================== 一、Mihomo Geosite 规则处理 ====================
    print("[-] 处理 Task 1: geo/geosite/china.mrs")
    china_rules = read_text_rules("misstot_china.txt").union(read_text_rules("quixotic_cn.txt"))
    write_text_rules(china_rules, "merged_china_mihomo.txt")
    os.system("./mihomo convert-ruleset domain text merged_china_mihomo.txt mihomo_out/geo/geosite/china.mrs")

    print("[-] 处理 Task 2: geo/geosite/proxy.mrs")
    proxy_rules = read_text_rules("misstot_proxy.txt").union(read_text_rules("quixotic_proxy.txt"))
    write_text_rules(proxy_rules, "merged_proxy_mihomo.txt")
    os.system("./mihomo convert-ruleset domain text merged_proxy_mihomo.txt mihomo_out/geo/geosite/proxy.mrs")

    # ==================== 二、Sing-box Geosite 规则处理 ====================
    print("[-] 处理 Task 3: geo/geosite/china.srs")
    merged_china_list = sorted(list(read_text_rules("misstot_china.txt").union(read_text_rules("quixotic_cn.txt"))))
    sb_china = {
        "version": 1,
        "rules": [
            {
                "domain": merged_china_list,
                "domain_suffix": merged_china_list
            }
        ]
    }
    with open("merged_china_sb.json", 'w', encoding='utf-8') as f:
        json.dump(sb_china, f, indent=2, ensure_ascii=False)
    os.system("./sing-box rule-set compile --output singbox_out/geo/geosite/china.srs merged_china_sb.json")

    print("[-] 处理 Task 4: geo/geosite/proxy.srs")
    merged_proxy_list = sorted(list(read_text_rules("misstot_proxy.txt").union(read_text_rules("quixotic_proxy.txt"))))
    sb_proxy = {
        "version": 1,
        "rules": [
            {
                "domain": merged_proxy_list,
                "domain_suffix": merged_proxy_list
            }
        ]
    }
    with open("merged_proxy_sb.json", 'w', encoding='utf-8') as f:
        json.dump(sb_proxy, f, indent=2, ensure_ascii=False)
    os.system("./sing-box rule-set compile --output singbox_out/geo/geosite/proxy.srs merged_proxy_sb.json")

    # ==================== 三、GeoIP 占位符结构生成 ====================
    print("[-] 构建 geoip 占位文件 (保持目录结构)...")
    open("mihomo_out/geo/geoip/.keep", 'w').close()
    open("singbox_out/geo/geoip/.keep", 'w').close()
    
    print("[+] 所有规则与目录结构处理完毕！")

if __name__ == "__main__":
    main()