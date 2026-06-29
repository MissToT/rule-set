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

| 规则集 | 说明 | Mihomo `.yaml` | Mihomo `.mrs` | Sing-box `.json` | Sing-box `.srs` |
|--------|------|:-:|:-:|:-:|:-:|
| `china` | 国内域名直连 | [yaml](https://raw.githubusercontent.com/MissToT/rule-set/mihomo/geo/geosite/china.yaml) | [mrs](https://raw.githubusercontent.com/MissToT/rule-set/mihomo/geo/geosite/china.mrs) | [json](https://raw.githubusercontent.com/MissToT/rule-set/singbox/geo/geosite/china.json) | [srs](https://raw.githubusercontent.com/MissToT/rule-set/singbox/geo/geosite/china.srs) |
| `proxy` | 代理域名规则 | [yaml](https://raw.githubusercontent.com/MissToT/rule-set/mihomo/geo/geosite/proxy.yaml) | [mrs](https://raw.githubusercontent.com/MissToT/rule-set/mihomo/geo/geosite/proxy.mrs) | [json](https://raw.githubusercontent.com/MissToT/rule-set/singbox/geo/geosite/proxy.json) | [srs](https://raw.githubusercontent.com/MissToT/rule-set/singbox/geo/geosite/proxy.srs) |
| `adblock` | 广告拦截规则 | [yaml](https://raw.githubusercontent.com/MissToT/rule-set/mihomo/geo/geosite/adblock.yaml) | [mrs](https://raw.githubusercontent.com/MissToT/rule-set/mihomo/geo/geosite/adblock.mrs) | [json](https://raw.githubusercontent.com/MissToT/rule-set/singbox/geo/geosite/adblock.json) | [srs](https://raw.githubusercontent.com/MissToT/rule-set/singbox/geo/geosite/adblock.srs) |
| `japan` | 日本流媒体 / 内容平台 | [yaml](https://raw.githubusercontent.com/MissToT/rule-set/mihomo/geo/geosite/japan.yaml) | [mrs](https://raw.githubusercontent.com/MissToT/rule-set/mihomo/geo/geosite/japan.mrs) | [json](https://raw.githubusercontent.com/MissToT/rule-set/singbox/geo/geosite/japan.json) | [srs](https://raw.githubusercontent.com/MissToT/rule-set/singbox/geo/geosite/japan.srs) |
| `taiwan` | 台湾流媒体 / 内容平台 | [yaml](https://raw.githubusercontent.com/MissToT/rule-set/mihomo/geo/geosite/taiwan.yaml) | [mrs](https://raw.githubusercontent.com/MissToT/rule-set/mihomo/geo/geosite/taiwan.mrs) | [json](https://raw.githubusercontent.com/MissToT/rule-set/singbox/geo/geosite/taiwan.json) | [srs](https://raw.githubusercontent.com/MissToT/rule-set/singbox/geo/geosite/taiwan.srs) |

### IP 段规则（GeoIP）

| 规则集 | 说明 | Mihomo `.yaml` | Mihomo `.mrs` | Sing-box `.json` | Sing-box `.srs` |
|--------|------|:-:|:-:|:-:|:-:|
| `china` | 国内 IP 直连 | [yaml](https://raw.githubusercontent.com/MissToT/rule-set/mihomo/geo/geoip/china.yaml) | [mrs](https://raw.githubusercontent.com/MissToT/rule-set/mihomo/geo/geoip/china.mrs) | [json](https://raw.githubusercontent.com/MissToT/rule-set/singbox/geo/geoip/china.json) | [srs](https://raw.githubusercontent.com/MissToT/rule-set/singbox/geo/geoip/china.srs) |
| `proxy` | 代理 IP 段规则 | [yaml](https://raw.githubusercontent.com/MissToT/rule-set/mihomo/geo/geoip/proxy.yaml) | [mrs](https://raw.githubusercontent.com/MissToT/rule-set/mihomo/geo/geoip/proxy.mrs) | [json](https://raw.githubusercontent.com/MissToT/rule-set/singbox/geo/geoip/proxy.json) | [srs](https://raw.githubusercontent.com/MissToT/rule-set/singbox/geo/geoip/proxy.srs) |

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

## 🔄 更新机制

```
多个上游 .mrs 文件
    │
    ▼
Mihomo 解码为明文文本
    │
    ▼
Set 结构跨源去重合并
    │
    ├──► Mihomo 编译  ──►  .yaml / .mrs  ──►  推送至 mihomo 分支
    │
    └──► Sing-box 编译 ──►  .json / .srs  ──►  推送至 singbox 分支
```

- 自动运行时间：每天 **北京时间凌晨 4:00**（UTC 20:00）
- 支持手动在 Actions 页面触发 `workflow_dispatch`
- 每次运行自动获取最新稳定版 sing-box 与 mihomo 内核进行编译

---

## 📂 输出目录结构

规则集分别推送至两个独立分支：

**`mihomo` 分支**（Mihomo / Clash Meta 格式）
```
geo/
├── geosite/
│   ├── china.yaml / china.mrs
│   ├── proxy.yaml / proxy.mrs
│   ├── adblock.yaml / adblock.mrs
│   ├── japan.yaml  / japan.mrs
│   └── taiwan.yaml / taiwan.mrs
└── geoip/
    ├── china.yaml / china.mrs
    └── proxy.yaml / proxy.mrs
```

**`singbox` 分支**（Sing-box 格式）
```
geo/
├── geosite/
│   ├── china.json / china.srs   ✦
│   ├── proxy.json / proxy.srs   ✦
│   ├── adblock.json / adblock.srs ✦
│   ├── japan.json  / japan.srs  ✦
│   └── taiwan.json / taiwan.srs ✦
└── geoip/
    ├── china.json / china.srs   ✦
    └── proxy.json / proxy.srs   ✦
```

---

## 📡 数据来源

规则从以下上游仓库下载并合并，脚本本身不修改任何规则内容：

| 规则集 | 上游来源 |
|--------|---------|
| `domain/china` | MissToT/Picture · QuixoticHeart/rule-set · MetaCubeX/meta-rules-dat |
| `domain/proxy` | MissToT/Picture · QuixoticHeart/rule-set |
| `domain/adblock` | privacy-protection-tools/anti-ad · MissToT/Picture |
| `domain/japan` | MetaCubeX/meta-rules-dat (dlsite/dmm/pixiv) · MissToT/Picture |
| `domain/taiwan` | MetaCubeX/meta-rules-dat (bahamut/manhuagui) · MissToT/Picture |
| `ipcidr/china` | QuixoticHeart/rule-set · MetaCubeX/meta-rules-dat |
| `ipcidr/proxy` | QuixoticHeart/rule-set |

---

<div align="center">

规则数据来源于各上游仓库 · 仅做格式转换与去重合并，不修改规则内容

</div>
