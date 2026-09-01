# Chitanda 协议全模式配置指南 (Mihomo / Clash.Meta & Xray-core Wiki)

本文档提供 **Chitanda (千反田)** 传输协议在 **Mihomo (Clash.Meta)** 客户端与 **Xray-core** 服务端/客户端中的完整配置手册与 4 种传输载荷模式（`h2` / `h3` / `auto` / `h1`）的详细用例。

---

## 1. 传输载荷模式概览 (Transport Matrix)

| 模式 | 传输标识 | 承载机制 (TCP / UDP) | 证书要求 | 典型适用场景 |
| :--- | :--- | :--- | :---: | :--- |
| **H2 多路复用** | `h2` | TLS 1.3 + HTTP/2 流复用 / H3 QUIC Datagram | 必须 (有效 TLS 证书) | **生产环境主线推荐**。高并发池化复用、极低 CPU 开销与成熟抗封锁。 |
| **原生 H3/QUIC** | `h3` | TLS 1.3 + HTTP/3 流复用 / H3 QUIC Datagram | 必须 (有效 TLS 证书) | **弱网/丢包环境**。原生 0 队头阻塞，强抗网络抖动与移动网络切换。 |
| **自适应容灾** | `auto` | 动态 H2 优先 $\leftrightarrow$ 降级自愈 H3 | 必须 (有效 TLS 证书) | **混合网络环境**。主动健康嗅探与 0 阻断故障自动切换。 |
| **纯 IP 实验通道** | `h1` *(plain-h1)* | 纯 IP HTTP/1.1 全双工 AEAD / 原生 `plain-udp` | **免证书 (纯 IP 直连)** | **内网/纯 IP 互联**。零 TLS 开销，抗探测静态伪装为普通 HTTP 二进制流。 |

---

## 2. Mihomo (Clash.Meta) 客户端配置手册

### 2.1 节点参数说明 (Proxy Parameters)

| 字段 | 类型 | 必填 | 默认值 | 详细说明 |
| :--- | :---: | :---: | :---: | :--- |
| `name` | String | 是 | - | 节点自定义显示名称 |
| `type` | String | 是 | - | 代理协议类型，固定为 `chitanda` |
| `server` | String | 是 | - | 服务器域名或 IP 地址 |
| `port` | Integer | 是 | - | 服务器监听端口 (如 `443` 或自定义端口) |
| `psk` | String | 是 | - | 预共享密钥 (Pre-Shared Key，需与服务端完全一致) |
| `path` | String | 否 | `/api/v1/sync` | 伪装请求路径，建议使用常见 API 路径 |
| `transport` | String | 否 | `h2` | 载荷模式：`h2` (默认)、`h3`、`auto`、`h1` (或 `plain-h1`) |
| `sni` | String | 否 | (同 `server`) | TLS SNI 域名；TLS 模式下必填有效域名，`h1` 纯 IP 模式可省略 |
| `skip-cert-verify`| Boolean| 否 | `false` | 是否跳过 TLS 证书合法性校验 (生产环境建议保持 `false`) |
| `pool-size` | Integer | 否 | `4` | TCP 物理连接池容量 (针对 `h2` 模式优化吞吐与抗突发流量) |
| `udp` | Boolean | 否 | `true` | 是否启用 UDP 数据包转发 |
| `interface-name` | String | 否 | - | 出站绑定网卡名称 (支持多网卡策略路由) |
| `routing-mark` | Integer | 否 | `0` | Linux 出站流量的 `fwmark` 路由标记 |
| `ip-version` | String | 否 | `dual` | 解析与连接偏好：`ipv4-prefer`、`ipv6-prefer`、`ipv4-only`、`ipv6-only` |

---

### 2.2 Mihomo 4 种模式节点配置实例

#### ① 模式 1：`h2` (TLS 1.3 + HTTP/2 多路复用 - 默认推荐)
```yaml
- name: "Chitanda-H2-Tokyo"
  type: chitanda
  server: tokyo.yourdomain.com
  port: 443
  psk: "super-secret-pre-shared-key-32bytes-min"
  path: "/api/v1/sync"
  transport: "h2"
  sni: "tokyo.yourdomain.com"
  pool-size: 4
  udp: true
```

#### ② 模式 2：`h3` (原生 HTTP/3 & QUIC 0 队头阻塞)
```yaml
- name: "Chitanda-H3-Tokyo"
  type: chitanda
  server: tokyo.yourdomain.com
  port: 443
  psk: "super-secret-pre-shared-key-32bytes-min"
  path: "/api/v1/sync"
  transport: "h3"
  sni: "tokyo.yourdomain.com"
  udp: true
```

#### ③ 模式 3：`auto` (智能探测与动态 H2 $\leftrightarrow$ H3 容灾切换)
```yaml
- name: "Chitanda-Auto-Tokyo"
  type: chitanda
  server: tokyo.yourdomain.com
  port: 443
  psk: "super-secret-pre-shared-key-32bytes-min"
  path: "/api/v1/sync"
  transport: "auto"
  sni: "tokyo.yourdomain.com"
  pool-size: 4
  udp: true
```

#### ④ 模式 4：`h1` (纯 IP / 免证书 / 全双工 HTTP/1.1 实验通道)
```yaml
- name: "Chitanda-H1-DirectIP"
  type: chitanda
  server: 198.51.100.23
  port: 18200
  psk: "super-secret-pre-shared-key-32bytes-min"
  path: "/gateway/stream/v2"
  transport: "h1"
  udp: true
```

---

### 2.3 Mihomo 完整客户端配置文件示例 (`config.yaml`)

```yaml
port: 7890
socks-port: 7891
allow-lan: false
mode: rule
log-level: info
ipv6: false

dns:
  enable: true
  listen: 0.0.0.0:1053
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - 223.5.5.5
    - 119.29.29.29
  fallback:
    - 8.8.8.8
    - 1.1.1.1

proxies:
  # 1. 主线 H2 节点
  - name: "Tokyo-H2"
    type: chitanda
    server: jp.example.com
    port: 443
    psk: "ch1tanda-auth-key-production-sample"
    path: "/api/v1/sync"
    transport: "h2"
    sni: "jp.example.com"
    pool-size: 4
    udp: true

  # 2. 原生 H3/QUIC 节点
  - name: "Tokyo-H3"
    type: chitanda
    server: jp.example.com
    port: 443
    psk: "ch1tanda-auth-key-production-sample"
    path: "/api/v1/sync"
    transport: "h3"
    sni: "jp.example.com"
    udp: true

  # 3. 智能自愈 Auto 节点
  - name: "Tokyo-Auto"
    type: chitanda
    server: jp.example.com
    port: 443
    psk: "ch1tanda-auth-key-production-sample"
    path: "/api/v1/sync"
    transport: "auto"
    sni: "jp.example.com"
    pool-size: 4
    udp: true

  # 4. 纯 IP 免证书 H1 节点
  - name: "DirectIP-H1"
    type: chitanda
    server: 203.0.113.88
    port: 18200
    psk: "ch1tanda-auth-key-production-sample"
    path: "/gateway/stream/v2"
    transport: "h1"
    udp: true

proxy-groups:
  - name: "PROXIES"
    type: select
    proxies:
      - "AUTO-FALLBACK"
      - "Tokyo-H2"
      - "Tokyo-H3"
      - "Tokyo-Auto"
      - "DirectIP-H1"
      - DIRECT

  - name: "AUTO-FALLBACK"
    type: fallback
    url: "http://www.gstatic.com/generate_204"
    interval: 300
    proxies:
      - "Tokyo-H2"
      - "Tokyo-H3"
      - "Tokyo-Auto"
      - "DirectIP-H1"

rules:
  - GEOIP,CN,DIRECT
  - MATCH,PROXIES
```

---

## 3. Xray-core 服务端与客户端配置手册

在 Xray-core 中，`chitanda` 既可以作为 **Inbound (入站服务端)** 接收解密流量并转发给 Xray 路由分发器，也可以作为 **Outbound (出站客户端)** 连接远端 Chitanda 节点。

### 3.1 Xray 服务端入站参数 (`inbounds.settings`)

| 字段 | 类型 | 必填 | 默认值 | 详细说明 |
| :--- | :---: | :---: | :---: | :--- |
| `psk` | String | 是 | - | 预共享认证密钥 |
| `path` | String | 否 | `/api/v1/sync` | 协议通信认证 Path |
| `transport` | String | 否 | `h2` | 载荷模式 (`h2` / `h3` / `auto` / `h1`) |
| `fallback` | String | 否 | - | 防探测回落目标 (如 `127.0.0.1:8080`、`unix:/run/nginx.sock` 或外部站点) |
| `strict_sni` | String | 否 | - | 严格 SNI 校验域名 (非指定 SNI 强制回落) |

---

### 3.2 Xray 4 种模式服务端入站配置 (`inbounds`)

#### ① 服务端 H2 主线入站 (带 TLS 1.3 与网站回落)
```json
{
  "tag": "chitanda-inbound-h2",
  "port": 443,
  "protocol": "chitanda",
  "settings": {
    "psk": "super-secret-pre-shared-key-32bytes-min",
    "path": "/api/v1/sync",
    "transport": "h2",
    "strict_sni": "jp.example.com",
    "fallback": "127.0.0.1:8080"
  },
  "streamSettings": {
    "security": "tls",
    "tlsSettings": {
      "certificates": [
        {
          "certificateFile": "/etc/ssl/chitanda/fullchain.cer",
          "keyFile": "/etc/ssl/chitanda/private.key"
        }
      ],
      "alpn": ["h2", "http/1.1"]
    }
  }
}
```

#### ② 服务端 H3 / QUIC 原生入站
```json
{
  "tag": "chitanda-inbound-h3",
  "port": 443,
  "protocol": "chitanda",
  "settings": {
    "psk": "super-secret-pre-shared-key-32bytes-min",
    "path": "/api/v1/sync",
    "transport": "h3",
    "strict_sni": "jp.example.com",
    "fallback": "127.0.0.1:8080"
  },
  "streamSettings": {
    "security": "tls",
    "tlsSettings": {
      "certificates": [
        {
          "certificateFile": "/etc/ssl/chitanda/fullchain.cer",
          "keyFile": "/etc/ssl/chitanda/private.key"
        }
      ],
      "alpn": ["h3"]
    }
  }
}
```

#### ③ 服务端 Auto (自愈兼容入站)
```json
{
  "tag": "chitanda-inbound-auto",
  "port": 443,
  "protocol": "chitanda",
  "settings": {
    "psk": "super-secret-pre-shared-key-32bytes-min",
    "path": "/api/v1/sync",
    "transport": "auto",
    "strict_sni": "jp.example.com",
    "fallback": "127.0.0.1:8080"
  },
  "streamSettings": {
    "security": "tls",
    "tlsSettings": {
      "certificates": [
        {
          "certificateFile": "/etc/ssl/chitanda/fullchain.cer",
          "keyFile": "/etc/ssl/chitanda/private.key"
        }
      ],
      "alpn": ["h2", "h3", "http/1.1"]
    }
  }
}
```

#### ④ 服务端 H1 (纯 IP / 免证书 / 0 特征入站)
```json
{
  "tag": "chitanda-inbound-h1",
  "port": 18200,
  "protocol": "chitanda",
  "settings": {
    "psk": "super-secret-pre-shared-key-32bytes-min",
    "path": "/gateway/stream/v2",
    "transport": "h1",
    "fallback": "127.0.0.1:80"
  },
  "streamSettings": {
    "security": "none"
  }
}
```

---

### 3.3 Xray 4 种模式客户端出站配置 (`outbounds`)

```json
{
  "outbounds": [
    {
      "tag": "chitanda-out-h2",
      "protocol": "chitanda",
      "settings": {
        "server": "jp.example.com:443",
        "server_name": "jp.example.com",
        "psk": "super-secret-pre-shared-key-32bytes-min",
        "path": "/api/v1/sync",
        "transport": "h2",
        "pool_size": 4
      }
    },
    {
      "tag": "chitanda-out-h3",
      "protocol": "chitanda",
      "settings": {
        "server": "jp.example.com:443",
        "server_name": "jp.example.com",
        "psk": "super-secret-pre-shared-key-32bytes-min",
        "path": "/api/v1/sync",
        "transport": "h3"
      }
    },
    {
      "tag": "chitanda-out-auto",
      "protocol": "chitanda",
      "settings": {
        "server": "jp.example.com:443",
        "server_name": "jp.example.com",
        "psk": "super-secret-pre-shared-key-32bytes-min",
        "path": "/api/v1/sync",
        "transport": "auto",
        "pool_size": 4
      }
    },
    {
      "tag": "chitanda-out-h1",
      "protocol": "chitanda",
      "settings": {
        "server": "203.0.113.88:18200",
        "psk": "super-secret-pre-shared-key-32bytes-min",
        "path": "/gateway/stream/v2",
        "transport": "h1"
      }
    },
    {
      "tag": "direct",
      "protocol": "freedom"
    }
  ]
}
```

---

### 3.4 Xray 完整服务端生产配置示例 (`server_production.json`)

```json
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "tag": "chitanda-in",
      "port": 443,
      "protocol": "chitanda",
      "settings": {
        "psk": "your-32-byte-secure-pre-shared-key-here",
        "path": "/api/v1/sync",
        "transport": "h2",
        "strict_sni": "status.chitanda.org",
        "fallback": "127.0.0.1:8080"
      },
      "streamSettings": {
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/ssl/chitanda.crt",
              "keyFile": "/etc/ssl/chitanda.key"
            }
          ]
        }
      }
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom"
    },
    {
      "tag": "blocked",
      "protocol": "blackhole"
    }
  ]
}
```

---

## 4. 生产安全与部署最佳实践

1. **PSK 密钥强度**：
   - 务必使用随机生成的强密码（建议使用 `openssl rand -base64 32` 生成 32 字节高熵密钥）。
2. **防探测 Fallback 伪装**：
   - 生产环境中强烈建议配置 `fallback`（如本地运行的 Nginx/Caddy 或反代至真实外部业务门户），未授权的主动探测将获得与普通网站完全一致的响应。
3. **Strict SNI 保护**：
   - 配置 `strict_sni` 防止通过扫描非指定域名或纯 IP 探测出 TLS 证书特征。
