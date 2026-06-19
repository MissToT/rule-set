<div align="center">

# 📦 Singbox Rule Set

**自动同步的 sing-box 二进制规则集**

每日自动从上游 mihomo 规则仓库拉取，转换并编译为 sing-box `.srs` 格式

[![Update](https://github.com/MissToT/rule-set/actions/workflows/update.yml/badge.svg)](https://github.com/MissToT/rule-set/actions/workflows/update.yml)
![GitHub last commit](https://img.shields.io/github/last-commit/MissToT/rule-set?label=最近更新)
![GitHub repo size](https://img.shields.io/github/repo-size/MissToT/rule-set?label=仓库大小)

</div>

---

## 📋 规则集列表

| 规则集 | 类型 | 说明 | 下载 |
|--------|------|------|------|
| `proxy-domain` | 域名 | 代理域名规则 | [.srs](https://raw.githubusercontent.com/MissToT/rule-set/main/dist/domain/proxy.srs) · [.json](https://raw.githubusercontent.com/MissToT/rule-set/main/dist/domain/proxy.json) |
| `proxy-ipcidr` | IP 段 | 代理 IP 段规则 | [.srs](https://raw.githubusercontent.com/MissToT/rule-set/main/dist/ipcidr/proxy.srs) · [.json](https://raw.githubusercontent.com/MissToT/rule-set/main/dist/ipcidr/proxy.json) |

---

## 🚀 使用方法

### 第一步：声明规则集

```json
{
  "rule_set": [
    {
      "tag": "proxy-domain",
      "type": "remote",
      "format": "binary",
      "url": "https://raw.githubusercontent.com/MissToT/rule-set/main/dist/domain/proxy.srs",
      "download_detour": "direct",
      "update_interval": "1d"
    },
    {
      "tag": "proxy-ipcidr",
      "type": "remote",
      "format": "binary",
      "url": "https://raw.githubusercontent.com/MissToT/rule-set/main/dist/ipcidr/proxy.srs",
      "download_detour": "direct",
      "update_interval": "1d"
    }
  ]
}
```

### 第二步：在路由中引用

```json
{
  "route": {
    "rules": [
      {
        "rule_set": ["proxy-domain", "proxy-ipcidr"],
        "outbound": "proxy"
      }
    ]
  }
}
```

---

## 🔄 更新机制

```
上游 mihomo 规则  ──►  Python 脚本转换  ──►  sing-box 编译  ──►  推送至仓库
(proxy.list)           (→ .json)              (→ .srs)
```

- 自动运行时间：每天 **北京时间 10:00**（UTC 02:00）
- 上游无变化时跳过提交，保持 commit 记录整洁
- 使用 sing-box **1.4.x beta**（支持 `version: 5` 规则集格式）

---

## 📂 目录结构

```
dist/
├── domain/
│   ├── proxy.json    # 人类可读的规则源文件
│   └── proxy.srs     # sing-box 二进制规则集 ✦
└── ipcidr/
    ├── proxy.json
    └── proxy.srs     # sing-box 二进制规则集 ✦
```

---

## 📡 数据来源

上游仓库：[QuixoticHeart/rule-set](https://github.com/QuixoticHeart/rule-set)

| 本仓库规则集 | 上游文件 |
|-------------|---------|
| `proxy-domain` | `meta/domain/proxy.list` |
| `proxy-ipcidr` | `meta/ipcidr/proxy.list` |

---

<div align="center">

规则集数据来源于 [QuixoticHeart/rule-set](https://github.com/QuixoticHeart/rule-set) · 仅做格式转换，不修改规则内容

</div>
