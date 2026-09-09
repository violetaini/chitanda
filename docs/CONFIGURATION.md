# Chitanda 协议全模式配置指南 (Mihomo / Clash.Meta & Xray-core Wiki)

本文档提供 **Chitanda (千反田)** 传输协议在 **Mihomo (Clash.Meta)** 客户端与 **Xray-core** 服务端/客户端中的完整配置手册与 5 种传输载荷模式（`h2` / `stream` / `h3` / `auto` / `h1`）的详细用例。

---

## 1. 传输载荷模式概览 (Transport Matrix)

| 模式 | 传输标识 | 承载机制 (TCP / UDP) | 证书要求 | 典型适用场景 |
| :--- | :--- | :--- | :---: | :--- |
| **H2 多路复用** | `h2` | TLS 1.3 + HTTP/2 流复用 / H3 QUIC Datagram | 必须 (有效 TLS 证书) | **生产环境主线推荐**。高并发池化复用、极低 CPU 开销与成熟抗封锁。 |
| **专线极速流** | `stream` | RawStream TCP (AES-128-GCM) / `plain-udp` 原生 AEAD | **免证书 (专线/纯 IP)** | **IEPL/IPLC 专线与高性能中转**。单线程吞吐超 4000 MB/s，离散握手，0 探测回显。 |
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
| `path` | String | 否 | `/api/v1/sync` | 伪装请求路径，建议使用常见 API 路径 (`stream` 模式无需此项) |
| `transport` | String | 否 | `h2` | 载荷模式：`h2` (默认)、`stream`、`h3`、`auto`、`h1` (或 `plain-h1`) |
| `sni` | String | 否 | (同 `server`) | TLS SNI 域名；TLS 模式下必填有效域名，`stream`/`h1` 纯 IP 模式可省略 |
| `server-id` | String | 否 | - | 服务端节点标识 (绑定节点身份，仅 `stream` 专线模式防跨节点握手重放) |
| `skip-cert-verify`| Boolean| 否 | `false` | 是否跳过 TLS 证书合法性校验 (生产环境建议保持 `false`) |
| `pool-size` | Integer | 否 | `4` | TCP 物理连接池容量 (针对 `h2` 模式优化吞吐与抗突发流量) |
| `udp` | Boolean | 否 | `true` | 是否启用 UDP 数据包转发 |
| `interface-name` | String | 否 | - | 出站绑定网卡名称 (支持多网卡策略路由) |
| `routing-mark` | Integer | 否 | `0` | Linux 出站流量的 `fwmark` 路由标记 |
| `ip-version` | String | 否 | `dual` | 解析与连接偏好：`ipv4-prefer`、`ipv6-prefer`、`ipv4-only`、`ipv6-only` |

---

### 2.2 Mihomo 5 种模式节点配置实例

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

#### ④ 模式 4：`stream` (RawStream 专线与高性能中转)
```yaml
- name: "Chitanda-Stream-Direct"
  type: chitanda
  server: 198.51.100.23
  port: 11323
  psk: "super-secret-pre-shared-key-32bytes-min"
  transport: "stream"
  udp: true
```

#### ⑤ 模式 5：`h1` (纯 IP / 免证书 / 全双工 HTTP/1.1 实验通道)
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

  # 5. 专线极速 Stream 节点
  - name: "Tokyo-Stream"
    type: chitanda
    server: 203.0.113.88
    port: 11323
    psk: "ch1tanda-auth-key-production-sample"
    transport: "stream"
    server-id: "tokyo-node-01"
    udp: true

proxy-groups:
  - name: "PROXIES"
    type: select
    proxies:
      - "AUTO-FALLBACK"
      - "Tokyo-H2"
      - "Tokyo-Stream"
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
      - "Tokyo-Stream"
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
| `transport` | String | 否 | `h2` | 载荷模式 (`h2` / `h3` / `auto` / `stream` / `h1`) |
| `fallback` | String | 否 | - | 防探测回落目标 (如 `127.0.0.1:8080`、`unix:/run/nginx.sock` 或外部站点) |
| `strict_sni` | String | 否 | - | 严格 SNI 校验域名 (非指定 SNI 强制回落) |
| `server_id` | String | 否 | - | 服务端节点标识 (专线/stream 模式跨节点防重放绑定) |
| `replay_file` | String | 否 | - | 持久化防重放缓存文件路径 (如 `/var/log/chitanda/replay.db`) |

---

### 3.2 Xray 5 种模式服务端入站配置 (`inbounds`)

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

#### ④ 服务端 Stream (专线 / 高性能 0 探测入站)
```json
{
  "tag": "chitanda-inbound-stream",
  "port": 11323,
  "protocol": "chitanda",
  "settings": {
    "psk": "super-secret-pre-shared-key-32bytes-min",
    "transport": "stream",
    "server_id": "node-tokyo-01",
    "replay_file": "/var/log/chitanda/stream_replay.db"
  },
  "streamSettings": { "security": "none" }
}
```

#### ⑤ 服务端 H1 (纯 IP / 免证书 / 0 特征入站)
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

### 3.3 Xray 客户端出站参数 (`outbounds.settings`)

| 字段 | 类型 | 必填 | 默认值 | 详细说明 |
| :--- | :---: | :---: | :---: | :--- |
| `server` | String | 是 | - | 服务器地址与端口 (`域名:端口` 或 `IP:端口`) |
| `psk` | String | 是 | - | 预共享认证密钥 (需与服务端一致) |
| `server_name` | String | 否 | (同 `server`) | TLS SNI 校验域名 (TLS 模式) |
| `path` | String | 否 | `/api/v1/sync` | 伪装请求路径 |
| `transport` | String | 否 | `h2` | 载荷模式 (`h2` / `h3` / `auto` / `stream` / `h1`) |
| `pool_size` | Integer | 否 | `4` | TCP 物理复用连接池大小 (仅 `h2` / `auto` 模式有效) |
| `server_id` | String | 否 | - | 服务端标识绑定 (仅 `stream` 模式有效，防跨节点重放) |
| `allow_insecure` | Boolean | 否 | `false` | 是否跳过 TLS 证书校验 (默认 `false` 严格验证；防止自签名测试异常) |

---

### 3.4 Xray 5 种模式客户端出站配置 (`outbounds`)

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
        "pool_size": 4,
        "allow_insecure": false
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
        "transport": "h3",
        "allow_insecure": false
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
        "pool_size": 4,
        "allow_insecure": false
      }
    },
    {
      "tag": "chitanda-out-stream",
      "protocol": "chitanda",
      "settings": {
        "server": "203.0.113.88:11323",
        "psk": "super-secret-pre-shared-key-32bytes-min",
        "server_id": "node-tokyo-01",
        "transport": "stream"
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

---

## 4. 3-xui (Xray-UI) 节点部署与内核热更新运维指南

3-xui (以及各类 Xray-UI 系列面板) 是通过 Web 可视化界面管理 Xray 配置并守护后台 Xray 核心进程的面板程序。3-xui 部署的节点本质上运行在底层 `/usr/local/x-ui/bin/xray-linux-*` 核心二进制之上。

### 4.1 为什么要更新 3-xui 与客户端双端内核？

若您遇到**高频短连接游戏（如《碧蓝档案》/ Blue Archive）、频繁交互的移动端应用经常发生连接卡死、超时断连，或者 OpenClash 软路由 / 客户端运行一段时间后出现端口假死、控制面板无法连接、DNS 超时、必须重启内核**等现象：

- **服务端根因**：旧版服务端在收到目标端响应完成并关闭后，上行方向因未收到客户端显式 FIN 会挂起等待 30 秒超时（或在 H3 模式下无超时无限挂死 QUIC 流）。当游戏短时间内并发大量 HTTP 轮询时，短连接迅速堆积并耗尽服务端的套接字与文件描述符（FD）。
- **客户端根因**：客户端连接池在双向半关闭（Half-Close）时缺乏带内标界，未能及时感应服务端已关闭并回收本地套接字，导致软路由的文件句柄耗尽，进而阻塞 `9090` 等控制端口与 DNS 查询。
- **协同解决方案**：
  1. **服务端**：必须将 3-xui 的底层内核更新为最新的 `xray-chitanda`。服务端引入了 **250ms 快速优雅排空（Downstream-Triggered Drain）** 机制，当目标响应完毕关闭后，立即向客户端发送带内 EOF 并限制排空窗口为 250 毫秒，超时强制断开两端，瞬间回收套接字。
  2. **客户端**：必须将 OpenClash / CMFA / 电脑端核心更新为最新的 `mihomo-chitanda`。支持解析带内 EOF 并完成本地连接池释放。

---

### 4.2 3-xui 内核更新操作步骤

#### 方法一：通过 3-xui Web 界面在线切换升级（推荐）
1. 浏览器打开并登录 3-xui 管理面板。
2. 进入左侧导航栏的 **「Xray 设置」**（或 **「面板设置」**）。
3. 找到 **「切换版本 / 内核版本」** 按钮并点击。
4. 在弹出的版本列表中，选择最新的 **`Chitanda Core`** 构建版本。
5. 点击 **确定更新**，3-xui 会自动下载对应架构二进制并重启后台 Xray 进程。

#### 方法二：通过 SSH 终端手动一键替换更新
如果您使用的是标准 3-xui 且界面未配置在线源，可直接在服务器终端执行如下命令快速替换内核：

```bash
# 1. 检查服务器架构 (x86_64 或 aarch64)
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then
    FILE="Xray-linux-64.zip"
    BIN_NAME="xray-linux-amd64"
elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
    FILE="Xray-linux-arm64-v8a.zip"
    BIN_NAME="xray-linux-arm64"
else
    echo "Unsupported architecture: $ARCH" && exit 1
fi

# 2. 下载 Chitanda 最新编译的 Xray 二进制包
cd /tmp
curl -fsSL -O "https://github.com/violetaini/chitanda/releases/latest/download/${FILE}"

# 3. 停止 x-ui 服务并替换二进制
systemctl stop x-ui
unzip -o "${FILE}" xray -d /tmp/chitanda_xray_bin/
cp -f /tmp/chitanda_xray_bin/xray /usr/local/x-ui/bin/${BIN_NAME}
# 若 3-xui 目录下存在 xray 原名文件，一并同步替换
[ -f /usr/local/x-ui/bin/xray ] && cp -f /tmp/chitanda_xray_bin/xray /usr/local/x-ui/bin/xray
chmod +x /usr/local/x-ui/bin/*

# 4. 清理临时文件并重启 x-ui
rm -rf /tmp/${FILE} /tmp/chitanda_xray_bin
systemctl restart x-ui

# 5. 验证版本
/usr/local/x-ui/bin/${BIN_NAME} version
```

---

### 4.3 3-xui 面板 5 种模式入站节点配置指南

在 3-xui 的 **「入站列表」 $\rightarrow$ 「添加入站」** 中配置 Chitanda 节点：

#### 1. `stream` 模式（专线/高性能纯 IP 首选，免域名证书）
- **协议**：`chitanda`
- **监听端口**：自定义端口（如 `11323`）
- **传输模式 (Transport)**：`stream`
- **预共享密钥 (PSK)**：自定义高熵密钥（如 `openssl rand -base64 32`）
- **Server ID**：填写节点唯一标识（如 `node-shanghai-01`），用于抗跨节点重放攻击。
- **安全设置 (Security)**：`none`（无需配置 TLS 证书，纯 IP 即可连通）

#### 2. `h2` 模式（公网主线推荐，高并发复用抗封锁）
- **协议**：`chitanda`
- **监听端口**：`443` 或自定义端口
- **传输模式 (Transport)**：`h2`
- **预共享密钥 (PSK)**：自定义密钥
- **Path**：伪装 API 路径（如 `/api/v1/sync`）
- **安全设置 (Security)**：`tls`
- **证书路径**：配置有效的 SSL/TLS 证书路径（`.cer` 和 `.key`）
- **Fallback (回落)**：建议填写本地静态 Web 端口（如 `127.0.0.1:8080`）或真实域名反代，未认证探测将回落到伪装网站。

#### 3. `h3` 模式（原生 QUIC 丢包抗性主线）
- **协议**：`chitanda`
- **传输模式 (Transport)**：`h3`
- **安全设置 (Security)**：`tls`（QUIC 强依赖 TLS 证书）
- **ALPN**：必须包含 `h3`。

#### 4. `auto` 模式（智能自愈降级）
- **协议**：`chitanda`
- **传输模式 (Transport)**：`auto`
- **安全设置 (Security)**：`tls`
- **ALPN**：`h2, h3, http/1.1`

#### 5. `h1` 模式（纯 IP 免证书实验模式）
- **协议**：`chitanda`
- **传输模式 (Transport)**：`h1`
- **Path**：`/gateway/stream/v2`
- **安全设置 (Security)**：`none`

---

## 5. 客户端 (OpenClash / Mihomo / CMFA) 内核升级指南

### 5.1 OpenClash 软路由内核升级
1. 进入 OpenWrt 后台 $\to$ 打开 **OpenClash** 插件界面。
2. 进入 **「插件设置」 $\rightarrow$ 「版本更新」**。
3. 检查并点击 **「更新 Meta 内核」**（Chitanda-OpenClash 定制版会自动从 Chitanda Release 获取最新编译的 `mihomo` 内核）。
4. *手动替换方式*：下载最新的 `mihomo-linux-amd64`（或对应软路由架构），改名为 `clash_meta`，上传覆盖至 `/etc/openclash/core/clash_meta`，并执行 `chmod +x /etc/openclash/core/clash_meta`，随后在 OpenClash 界面重启内核。

### 5.2 Clash Meta For Android (CMFA) 安卓端升级
1. 访问 [chitanda-cmfa Releases](https://github.com/violetaini/chitanda-cmfa/releases)。
2. 下载包含最新核心提交的 APK 安装包直接覆盖安装。

### 5.3 桌面客户端 (Mihomo Party / Clash Verge Rev 等)
1. 下载 Release 中的 `mihomo-windows-64.zip` / `mihomo-darwin-*.zip`。
2. 解压并将 `mihomo` 可执行文件替换客户端配置目录中的内核文件，重启客户端。

---

## 6. 高频短连接与游戏场景优化规范 (Half-Close & Blue Archive 案例)

### 6.1 游戏与高频 API 交互时序模型
以《碧蓝档案》（Blue Archive）为例，客户端（手机/模拟器）的每次 UI 点击交互、关卡结算、资源加载都会通过 HTTP/1.1 发起高频突发短请求：

```text
客户端                                     Chitanda 服务端                                  游戏官方服务器
  │                                               │                                               │
  ├─── 1. 发起 POST /game/api 请求 ──────────────>├─── 2. 发起连接并转发请求 ───────────────────>│
  │                                               │                                               │
  │                                               │<── 3. 返回 200 OK 响应数据 ──────────────────┤
  │<── 4. 转发响应数据 ───────────────────────────┤                                               │
  │                                               │<── 5. 业务结束，目标立即发送 FIN/EOF ─────────┤
  │                                               │    (目标连接主动关闭，downloadDone 触发)        │
  │                                               │                                               │
  │                                               │【旧版行为】：服务端等待客户端 30s ！！！       │
  │                                               │【导致后果】：每分钟数百次点击堆积海量挂死连接   │
  │                                               │              OpenClash 句柄爆满、面板假死！     │
  │                                               │                                               │
  │                                               │【现代优化】：立即进入 250ms 快速回收阶段        │
  │<── 6. 发送带内 EOF [0x00,0x00] + TCP FIN ─────┤    (向客户端发送带内 EOF，同时设置 250ms 读保护)│
  │                                               │                                               │
  ├─── 7. 客户端收到 EOF，回收本地套接字 ─────────>│                                               │
  │                                               │─── 8. 250ms 超时强制释放双端套接字 ───────────┤
  ▼                                               ▼                                               ▼
  连接完全销毁 (毫秒级释放，游戏连点 0 句柄残留，0 连接断开，软路由 9090 端口与 DNS 永不卡死！)
```

### 6.2 关键优化指标验证
在真实公网服务器对打测试中（50 个高频连续短突发请求模拟）：
- **旧版表现**：连接堆积持续 30 秒，系统产生 50+ 处于 `CLOSE_WAIT`/`FIN_WAIT` 状态的挂死套接字，OpenClash 外部控制端口超时无响应。
- **最新版本表现**：
  - 单请求端到端生命周期从 30 秒缩短至 **6~15 毫秒**；
  - 50 并发高频短连接在 **325 毫秒** 内全部完成并优雅关闭；
  - `ss -tupan | grep 38300` 检查结果：**0 残留套接字，0 FD 泄漏**！

---

## 7. Mihomo / OpenClash 运行健壮性与零 DefaultResolver 契约

在 OpenClash 软路由及各类 Mihomo (Clash.Meta) 客户端中，为杜绝代理内核绕过 Fake-IP / 内置 DNS 发生真实 IP 泄露，Mihomo 源码（`main.go`）设置了极严格的防御性断言：**严格禁止协议出站适配器在代理建立阶段调用 Go 标准库的系统 DNS 解析器（`net.DefaultResolver`）**。一旦发生违规调用，Mihomo 会立即向 stderr 输出全部 goroutine 堆栈并强行调用 `os.Exit(2)` 终止进程，导致 OpenClash 瞬间暴毙。

为确保软路由与客户端在高频 UDP 游戏与域名节点场景下的极致稳定，Chitanda 协议实现了全方位的**零 DefaultResolver 契约**：

### 7.1 核心防护机制

1. **纯内存 IP 解析器 (`parseUDPAddr`)**：
   - 在数据包接收、目标反向解析链路中，完全采用 Go 原生 `netip.ParseAddrPort` 与 `net.ParseIP` 进行无锁、无分配的内存级字面量 IP 解析；
   - 绝不调用任何操作系统或 Go 运行时的 DNS 解析方法，0 DNS 阻塞开销。
2. **Mihomo 专有域名解析器无缝对接 (`resolveUDPAddr`)**：
   - 当节点配置为域名（例如专线中转 `iepl-tokyo.example.com`）时，Chitanda 出站适配器将域名解析任务通过回调函数完全委托给 Mihomo 的 `resolver.ProxyServerHostResolver`；
   - 解析结果严格遵循 Mihomo 的 DNS 优选策略（`ipv4-prefer` / `ipv6-prefer` 等），并自动与 OpenClash 的 Fake-IP 缓存协同工作。
3. **软路由策略路由与 `fwmark` 强绑定**：
   - 在软路由（OpenWrt）透明代理模式下，内核基于 `fwmark` 标记识别出站流量。Chitanda 在初始化 UDP 监听套接字时，主动向 Mihomo 的 `c.dialer.ListenPacket` 传入已解析的真实服务端目的 IP (`AddrPort`)；
   - 彻底解决 Linux 内核策略路由在未知目的套接字时误匹配默认路由导致的数据包黑洞问题。
4. **泛型 PacketConn 接口解耦**：
   - 解除旧版对 `*net.UDPConn` 底层原生套接字的硬性类型断言约束，抽象为通用的 `net.PacketConn`；
   - 完美兼容 OpenClash / Mihomo 各类装饰层连接（如附带流量统计、自闭合守护及策略绑定的安全包装对象）。

---

## 8. 生产安全与部署最佳实践

1. **PSK 密钥强度**：
   - 务必使用随机生成的强密码（建议使用 `openssl rand -base64 32` 生成 32 字节高熵密钥）。
2. **防探测 Fallback 伪装**：
   - 生产环境中强烈建议配置 `fallback`（如本地运行的 Nginx/Caddy 或反代至真实外部业务门户），未授权的主动探测将获得与普通网站完全一致的响应。
3. **Strict SNI 保护**：
   - 配置 `strict_sni` 防止通过扫描非指定域名或纯 IP 探测出 TLS 证书特征。
