<div align="center">

# 📦 Rule Set

**自动同步的 Mihomo / Sing-box 双格式规则集**

每日自动从多个上游仓库拉取 `.mrs` 规则，去重合并后编译为 Mihomo 与 Sing-box 四种格式

[![Update](https://github.com/MissToT/rule-set/actions/workflows/update.yml/badge.svg)](https://github.com/MissToT/rule-set/actions/workflows/update.yml)
![GitHub last commit](https://img.shields.io/github/last-commit/MissToT/rule-set?label=最近更新)
![GitHub repo size](https://img.shields.io/github/repo-size/MissToT/rule-set?label=仓库大小)

</div>

---

## 📋 规则集列表

### 域名规则（Geosite）

| 规则集 | 说明 | Mihomo | Sing-box |
|--------|------|:-:|:-:|
| `china` | 国内域名 | [yaml](https://raw.githubusercontent.com/MissToT/rule-set/mihomo/geo/geosite/china.yaml) / [mrs](https://raw.githubusercontent.com/MissToT/rule-set/mihomo/geo/geosite/china.mrs) | [json](https://raw.githubusercontent.com/MissToT/rule-set/singbox/geo/geosite/china.json) / [srs](https://raw.githubusercontent.com/MissToT/rule-set/singbox/geo/geosite/china.srs) |
| `proxy` | 代理域名 | [yaml](https://raw.githubusercontent.com/MissToT/rule-set/mihomo/geo/geosite/proxy.yaml) / [mrs](https://raw.githubusercontent.com/MissToT/rule-set/mihomo/geo/geosite/proxy.mrs) | [json](https://raw.githubusercontent.com/MissToT/rule-set/singbox/geo/geosite/proxy.json) / [srs](https://raw.githubusercontent.com/MissToT/rule-set/singbox/geo/geosite/proxy.srs) |
| `adblock` | 广告域名 | [yaml](https://raw.githubusercontent.com/MissToT/rule-set/mihomo/geo/geosite/adblock.yaml) / [mrs](https://raw.githubusercontent.com/MissToT/rule-set/mihomo/geo/geosite/adblock.mrs) | [json](https://raw.githubusercontent.com/MissToT/rule-set/singbox/geo/geosite/adblock.json) / [srs](https://raw.githubusercontent.com/MissToT/rule-set/singbox/geo/geosite/adblock.srs) |

### IP 段规则（GeoIP）

| 规则集 | 说明 | Mihomo | Sing-box |
|--------|------|:-:|:-:|
| `china` | 国内 IP | [yaml](https://raw.githubusercontent.com/MissToT/rule-set/mihomo/geo/geoip/china.yaml) / [mrs](https://raw.githubusercontent.com/MissToT/rule-set/mihomo/geo/geoip/china.mrs) | [json](https://raw.githubusercontent.com/MissToT/rule-set/singbox/geo/geoip/china.json) / [srs](https://raw.githubusercontent.com/MissToT/rule-set/singbox/geo/geoip/china.srs) |
| `proxy` | 代理 IP | [yaml](https://raw.githubusercontent.com/MissToT/rule-set/mihomo/geo/geoip/proxy.yaml) / [mrs](https://raw.githubusercontent.com/MissToT/rule-set/mihomo/geo/geoip/proxy.mrs) | [json](https://raw.githubusercontent.com/MissToT/rule-set/singbox/geo/geoip/proxy.json) / [srs](https://raw.githubusercontent.com/MissToT/rule-set/singbox/geo/geoip/proxy.srs) |

---

## 🚀 使用方法

### Mihomo（Clash Meta）

在配置文件中引用 `.mrs` 格式（推荐）或 `.yaml` 格式：

```yaml
rule-providers:
  proxy-domain:
    type: http
    behavior: domain
    format: mrs
    url: "https://raw.githubusercontent.com/MissToT/rule-set/mihomo/geo/geosite/proxy.mrs"
    interval: 86400

  china-ip:
    type: http
    behavior: ipcidr
    format: mrs
    url: "https://raw.githubusercontent.com/MissToT/rule-set/mihomo/geo/geoip/china.mrs"
    interval: 86400
```

在 `rules` 中引用：

```yaml
rules:
  - RULE-SET,proxy-domain,🚀 节点选择
  - RULE-SET,china-ip,🇨🇳 直连
```

---

### Sing-box

**第一步：声明规则集**

```json
{
  "rule_set": [
    {
      "tag": "geosite-proxy",
      "type": "remote",
      "format": "binary",
      "url": "https://raw.githubusercontent.com/MissToT/rule-set/singbox/geo/geosite/proxy.srs"
    },
    {
      "tag": "geosite-china",
      "type": "remote",
      "format": "binary",
      "url": "https://raw.githubusercontent.com/MissToT/rule-set/singbox/geo/geosite/china.srs"
    },
    {
      "tag": "geoip-china",
      "type": "remote",
      "format": "binary",
      "url": "https://raw.githubusercontent.com/MissToT/rule-set/singbox/geo/geoip/china.srs"
    }
  ]
}
```

**第二步：在路由中引用**

```json
{
  "route": {
    "rules": [
      {
        "rule_set": ["geosite-proxy"],
        "outbound": "proxy"
      },
      {
        "rule_set": ["geosite-china", "geoip-china"],
        "outbound": "direct"
      }
    ]
  }
}
```

---

## 📡 数据来源

规则从以下上游仓库下载并合并，脚本本身不修改任何规则内容：

[QuixoticHeart/rule-set](https://github.com/QuixoticHeart/rule-set) / [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat) / [privacy-protection-tools/anti-ad](https://github.com/privacy-protection-tools/anti-AD)

---

<div align="center">

规则数据来源于各上游仓库 · 仅做格式转换与去重合并，不修改规则内容

</div>
