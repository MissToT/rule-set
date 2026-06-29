import os
import sys
import json
import urllib.request
import re
import tarfile
import gzip
import shutil

# ==================== 1. 全局数据源配置 ====================
# 将所有规则抽象为字典，分为 domain (Geosite) 和 ipcidr (GeoIP)
# 后续增加任何新规则，只需在此处追加，无需修改下方任何执行代码。
RULES_CONFIG = {
    "domain": {
        "china": [
            "https://v6.gh-proxy.org/github.com/MissToT/Picture/raw/Meta/Rules/domain/China.mrs",
            "https://v6.gh-proxy.org/github.com/QuixoticHeart/rule-set/raw/ruleset/meta/domain/cn.mrs",
            "https://v6.gh-proxy.org/github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/cn.mrs" # [新增] MetaCubeX 中国域名
        ],
        "proxy": [
            "https://v6.gh-proxy.org/github.com/MissToT/Picture/raw/Meta/Rules/domain/Proxy.mrs",
            "https://v6.gh-proxy.org/github.com/QuixoticHeart/rule-set/raw/ruleset/meta/domain/proxy.mrs"
        ],
        "adblock": [
            "https://v6.gh-proxy.org/github.com/privacy-protection-tools/anti-ad.github.io/raw/master/docs/mihomo.mrs",
            "https://v6.gh-proxy.org/github.com/MissToT/Picture/raw/Meta/Rules/domain/reject.mrs"
        ],
        "japan": [
            "https://v6.gh-proxy.org/github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/dlsite.mrs",
            "https://v6.gh-proxy.org/github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/dmm.mrs",
            "https://v6.gh-proxy.org/github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/pixiv.mrs",
            "https://v6.gh-proxy.org/github.com/MissToT/Picture/raw/Meta/Rules/domain/Japan.mrs"
        ],
        "taiwan": [
            "https://v6.gh-proxy.org/github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/bahamut.mrs",
            "https://v6.gh-proxy.org/github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/manhuagui.mrs",
            "https://v6.gh-proxy.org/github.com/MissToT/Picture/raw/Meta/Rules/domain/Taiwan.mrs"
        ]
    },
    "ipcidr": {
        "china": [
            "https://v6.gh-proxy.org/github.com/QuixoticHeart/rule-set/raw/ruleset/meta/ipcidr/cn.mrs",
            "https://v6.gh-proxy.org/github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geoip/cn.mrs" # [新增] MetaCubeX 中国IP
        ],
        "proxy": [
            "https://raw.githubusercontent.com/QuixoticHeart/rule-set/ruleset/meta/ipcidr/proxy.mrs"
        ]
    }
}

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
    
    # 准备 sing-box
    sb_url = get_latest_stable_asset_url("SagerNet/sing-box", r"linux-amd64.*\.tar\.gz") or "https://github.com/SagerNet/sing-box/releases/download/v1.18.0/sing-box-1.18.0-linux-amd64.tar.gz"
    urllib.request.urlretrieve(sb_url, "sing-box.tar.gz")
    with tarfile.open("sing-box.tar.gz", "r:gz") as tar:
        for member in tar.getmembers():
            if member.name.endswith("/sing-box"):
                with open("sing-box", "wb") as out_f: 
                    out_f.write(tar.extractfile(member).read())
    os.chmod("sing-box", 0o755)
    
    # 准备 mihomo
    mihomo_url = get_latest_stable_asset_url("MetaCubeX/mihomo", r"linux-amd64.*\.gz") or "https://github.com/MetaCubeX/mihomo/releases/download/v1.18.3/mihomo-linux-amd64-v1.18.3.gz"
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

def export_four_formats(rule_name, rules_set, rule_type):
    """根据规则类型 (domain/ipcidr) 导出 YAML, JSON, MRS, SRS 四种格式"""
    is_ip = (rule_type == "ipcidr")
    
    # 设定输出路径映射
    mihomo_dir = f"mihomo_out/geo/{'geoip' if is_ip else 'geosite'}"
    singbox_dir = f"singbox_out/geo/{'geoip' if is_ip else 'geosite'}"
    os.makedirs(mihomo_dir, exist_ok=True)
    os.makedirs(singbox_dir, exist_ok=True)
    
    # 1. 导出 YAML (Mihomo 规范)
    with open(f"{mihomo_dir}/{rule_name}.yaml", 'w', encoding='utf-8') as f:
        f.write("payload:\n")
        for rule in sorted(rules_set): 
            f.write(f"  - '{rule}'\n")
            
    # 2. 导出 JSON (Sing-box 规范，处理精细分离)
    with open(f"{singbox_dir}/{rule_name}.json", 'w', encoding='utf-8') as f:
        if is_ip:
            json.dump({"version": 2, "rules": [{"ip_cidr": sorted(list(rules_set))}]}, f, indent=2, ensure_ascii=False)
        else:
            domains, suffixes = [], []
            for r in sorted(rules_set):
                if r.startswith('+.'): 
                    suffixes.append(r[2:])
                elif r.startswith('.'): 
                    suffixes.append(r[1:])
                else: 
                    domains.append(r)
            json.dump({"version": 2, "rules": [{"domain": domains, "domain_suffix": suffixes}]}, f, indent=2, ensure_ascii=False)
            
    # 3. 编译 MRS & SRS (二进制规范)
    temp_txt_path = f"temp_workspace/merged_{rule_name}_{rule_type}.txt"
    with open(temp_txt_path, 'w', encoding='utf-8') as f: 
        f.write("\n".join(sorted(rules_set)))
    
    os.system(f"./mihomo convert-ruleset {rule_type} text {temp_txt_path} {mihomo_dir}/{rule_name}.mrs")
    os.system(f"./sing-box rule-set compile --output {singbox_dir}/{rule_name}.srs {singbox_dir}/{rule_name}.json")


# ==================== 3. 主处理流程 ====================

def process_rules(rule_type, rules_dict):
    """通用的规则处理引擎：下载 -> 解编 -> 去重合并 -> 导出格式"""
    print(f"\n[*] 开始批量构建 [{rule_type.upper()}] 分流规则...")
    for rule_name, urls in rules_dict.items():
        print(f"\n[+] 处理规则集: {rule_name}")
        merged_rules = set()
        
        for i, url in enumerate(urls):
            temp_mrs = f"temp_workspace/{rule_name}_{i}.mrs"
            temp_txt = f"temp_workspace/{rule_name}_{i}.txt"
            
            download_file(url, temp_mrs)
            # 使用 Mihomo 将下载的二进制转为明文文本
            os.system(f"./mihomo convert-ruleset {rule_type} mrs {temp_mrs} {temp_txt}")
            merged_rules |= read_text_rules(temp_txt)
            
        print(f"  -> 已完成去重合并，共计 {len(merged_rules)} 条规则，正在执行编译...")
        export_four_formats(rule_name, merged_rules, rule_type)

def main():
    # 1. 环境初始化
    setup_binaries()
    os.makedirs("temp_workspace", exist_ok=True)
    
    # 2. 数据驱动执行规则构建
    for rule_type, rules_dict in RULES_CONFIG.items():
        process_rules(rule_type, rules_dict)

    # 3. 清理临时环境
    print("\n[*] 正在清理临时工作区...")
    shutil.rmtree("temp_workspace", ignore_errors=True)
    
    print("\n[√] 任务全部完成，所有规则集均已生成完毕！")

if __name__ == "__main__":
    main()