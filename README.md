# Chitanda (千反田) 私有传输协议

Chitanda 是一个面向自有服务端部署的高性能、抗探测 Go 代理传输协议。项目提供模块化服务端、可嵌入的客户端 SDK（提供标准 `net.Conn` 与 `net.PacketConn` 接口）及直连基准测试工具。

当前主线支持 **4 种传输载荷模式（Transport Carriers）**：以 **`h2` (TLS 1.3 + HTTP/2 多路复用)** 作为主线默认推荐，同时提供 **`h3`**、**`auto`** 与免证书纯 IP 模式 **`h1`**（别名 `plain-h1`）。

- 📖 **[完整配置手册与 Wiki 规范](docs/CONFIGURATION.md)**
- 📁 **[示例配置文件目录 (Examples)](examples/)**
- 📦 **[GitHub 自动发布二进制 (Releases)](https://github.com/violetaini/chitanda/releases)**

---

## 1. 传输载荷矩阵 (Transport Carrier Matrix)

```text
                                  业务上层 / 代理内核 / 客户端 SDK
                                                 │
                                           pkg/client SDK
                     ┌───────────────────────────┴───────────────────────────┐
                     ▼                                                       ▼
            【TLS 域名主线模式】                                      【纯 IP / 免证书实验模式】
      h2 (默认) / h3 / auto                                              h1 (plain-h1)
   ┌─────────────────┬──────────────────┐                ┌───────────────────────┬───────────────────────┐
   │ TCP: H2/H3 复用  │ UDP: H3 Datagram │                │ TCP: H1 全双工 AEAD   │ UDP: Plain-UDP Datagram│
   └─────────────────┴──────────────────┘                └───────────────────────┴───────────────────────┘
                     │                                                       │
                     └───────────────────────────┬───────────────────────────┘
                                                 ▼
                                         cmd/chitanda-server
```

| 模式 | TCP 承载机制 | UDP 承载机制 | 0-RTT 支持 | 核心特征与适用场景 |
| :--- | :--- | :--- | :---: | :--- |
| **`h2`** | TLS 1.3 + HTTP/2 流复用 | H3 QUIC Datagram (RFC 9221) | ✅ (连接池流复用 0-RTT) | **默认与主线推荐**。单/多 TCP 物理连接池化复用，吞吐极高，CPU 开销低，抗审查特征成熟。 |
| **`h3`** | TLS 1.3 + QUIC Stream + HTTP/3 | H3 QUIC Datagram (RFC 9221) | ✅ (会话恢复 0-RTT) | 原生 QUIC 0 队头阻塞，强抗丢包与弱网抖动；支持持久化 Session Ticket 0-RTT。 |
| **`auto`** | H2 优先 $\leftrightarrow$ 异常自愈 H3 | H3 QUIC Datagram (RFC 9221) | ✅ | 新建连接动态健康探测；TCP 受阻或丢包劣化时平滑向 H3 容灾。 |
| **`h1`** *(实验, 别名 `plain-h1`)* | 纯 IP HTTP/1.1 全双工 + PSK-AEAD | `plain-udp` 原生 AEAD 数据报 | ✅ (Flight 1 预派生 0-RTT) | **免域名 / 免证书 / 纯 IP 实验模式**。无 TLS 开销，内层 ChaCha20-Poly1305 认证加密；外层为标准全双工 HTTP/1.1。 |

---

## 2. 核心架构与密码学设计

### A. TLS 传输主线 (`h2` / `h3` / `auto`)
- **握手与认证**：TLS 1.3 标准握手（支持配置 Strict SNI 校验）。
- **Transcript V2 HMAC 签名**：请求头携带基于 PSK 与长度前缀域隔离（Domain Separation）的 HMAC-SHA256 签名，绑定 Method、Path、Target、Timestamp 与 Nonce。
- **2ms Group-Commit 组提交防重放**：服务端持久化 Nonce 缓存采用微批次异步刷盘与条件变量唤醒机制，在保障崩溃一致性的同时消除高并发磁盘 I/O 瓶颈。
- **原生 UDP 旁路**：UDP 流量通过独立的 HTTP/3 Extended CONNECT 与 QUIC Datagram 传输，配合 2048 位滑动位图抵御乱序与重放。
- **Wire-Version 双向兼容**：服务端自适应识别现代原始流客户端与携带私有帧标记（`X-Framing: 1`）的客户端，平滑向后兼容。

### B. 无 TLS 纯 IP 实验载荷 (`h1` / `plain-udp`)
- **标准全双工 HTTP/1.1 Carrier**：
  - 外层仅使用标准 `POST <path> HTTP/1.1` 与 `Transfer-Encoding: chunked`；
  - 彻底剥离明文 `X-Session-Target` 与自定义私有 Header，伪装为普通二进制流上传接口；
  - 服务端使用 Go `http.NewResponseController(w).EnableFullDuplex()` 实现双向流式全双工。
- **0-RTT 应用流水线（Flight 1 Pipelining）**：
  - 客户端基于 PSK、时间戳 $T_c$ 与随机数 $N_c$ 派生 $K_{0\text{-rtt}}$；
  - 在第 1 个 TCP 发送包中合并写入：`HTTP Headers` + `Chunk 1 (ClientHello 48B)` + `Chunk 2 (0-RTT OPEN 目标帧 + Early Data)`；
  - 服务端校验时间戳并记录防重放后，**瞬间解密 OPEN 目标并发起上游直连**，达成应用层 0-RTT。
- **静态 PSK 密码学模型 (Static PSK Model)**：
  - 双方通过 HKDF-SHA256 派生双向独立会话密钥 $K_{c \to s}$ 与 $K_{s \to c}$，单调递增 Nonce 流式加密；
  - *注：此模式依赖静态 PSK，未引入临时 ECDHE 交换，不具备前向保密（PFS），敏感主线流量应使用标准 TLS 1.3 载荷。*
- **`plain-udp` 原生 AEAD 数据报与独立防重放**：
  - 格式：$[ T_c \ (8\text{B}) \parallel \text{Seq} \ (8\text{B}) \parallel \text{Nonce} \ (12\text{B}) \parallel \text{ChaCha20-Poly1305}(\text{SOCKS5 Addr} \parallel \text{Payload}) \parallel \text{Tag} \ (16\text{B}) ]$；
  - **严格先验 AEAD 后记 Replay**：解包时先验证密码学 AEAD 认证标签，未认证数据包直接丢弃，彻底杜绝恶意构造极大序号污染防重放窗口；
  - **每会话独立滑动窗口**：每个客户端 IP 拥有独立的 2048 包防重放位图，杜绝多客户端相互碰撞；
  - **异步调度**：服务端目标解析与 DialUDP 采用异步并发分发，避免主读循环被慢 DNS 阻塞。

### C. 多模式防探测回落 (Dynamic Masquerade Fallback)
未通过路径匹配、方法校验或 HMAC 认证的请求，按配置平滑回落：
1. **内置企业 ERP 业务网关**：内置 Vanguard Global Operations Hub (EBG v4.2) 响应式门户与 REST API；
2. **本地静态目录**：托管指定的 HTML/静态资源；
3. **Nginx UDS 反向代理**：通过 `unix:/path/to/nginx.sock` 零网络栈损耗代理本地 Web 服务；
4. **本地端口反向代理**：转发至 `127.0.0.1:8080` 等本地 HTTP 服务。

---

## 3. Go SDK 使用示例

```go
package main

import (
	"context"
	"log"
	"net"
	"time"

	"chitanda/pkg/client"
)

func main() {
	// 默认推荐：h2 (TLS 1.3 多路复用主线)
	cli, err := client.New(client.Config{
		Server:       "server.example.com:443",
		ServerName:   "server.example.com",
		PSK:          []byte("your-32-byte-secure-pre-shared-key-here"),
		Path:         "/api/v1/sync",
		TCPTransport: client.TCPTransportH2, // 模式: "h2", "h3", "auto", "h1"
	})
	if err != nil {
		log.Fatalf("Init client failed: %v", err)
	}
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. TCP 出站拨号 (返回标准 net.Conn)
	tcpConn, err := cli.DialContext(ctx, "tcp", "www.google.com:443")
	if err != nil {
		log.Fatalf("Dial TCP failed: %v", err)
	}
	defer tcpConn.Close()

	// 2. 原生 UDP 出站监听 (返回标准 net.PacketConn)
	udpConn, err := cli.ListenPacket(ctx)
	if err != nil {
		log.Fatalf("Listen UDP failed: %v", err)
	}
	defer udpConn.Close()

	dnsServer, _ := net.ResolveUDPAddr("udp", "1.1.1.1:53")
	dnsQuery := []byte{ /* ... DNS Wire Query ... */ }
	_, _ = udpConn.WriteTo(dnsQuery, dnsServer)
}
```

---

## 4. 客户端与服务端生态配置全示例 (Mihomo & Xray-core)

详细参数手册与生产架构请参阅 **[docs/CONFIGURATION.md](docs/CONFIGURATION.md)**。

### A. Mihomo (Clash.Meta) 客户端 4 种模式节点

在 Mihomo `config.yaml` 的 `proxies` 列表中直接配置：

```yaml
proxies:
  # 模式 1: H2 多路复用主线模式 (TLS 1.3 + HTTP/2 流复用) - 默认推荐
  - name: "Chitanda-H2-Tokyo"
    type: chitanda
    server: jp.example.com
    port: 443
    psk: "your-32-byte-secure-pre-shared-key-here"
    path: "/api/v1/sync"
    transport: "h2"
    sni: "jp.example.com"
    pool-size: 4
    udp: true

  # 模式 2: H3 原生 QUIC 模式 (HTTP/3 0-RTT + 0 队头阻塞)
  - name: "Chitanda-H3-Tokyo"
    type: chitanda
    server: jp.example.com
    port: 443
    psk: "your-32-byte-secure-pre-shared-key-here"
    path: "/api/v1/sync"
    transport: "h3"
    sni: "jp.example.com"
    udp: true

  # 模式 3: Auto 智能探测与自愈容灾模式 (H2 主线 + 嗅探降级 H3)
  - name: "Chitanda-Auto-Tokyo"
    type: chitanda
    server: jp.example.com
    port: 443
    psk: "your-32-byte-secure-pre-shared-key-here"
    path: "/api/v1/sync"
    transport: "auto"
    sni: "jp.example.com"
    pool-size: 4
    udp: true

  # 模式 4: H1 纯 IP 免证书实验模式 (全双工 HTTP/1.1 AEAD + Plain-UDP)
  - name: "Chitanda-H1-DirectIP"
    type: chitanda
    server: 203.0.113.88
    port: 18200
    psk: "your-32-byte-secure-pre-shared-key-here"
    path: "/gateway/stream/v2"
    transport: "h1"
    udp: true
```

完整配置文件模板见 **[examples/mihomo/config.yaml](examples/mihomo/config.yaml)**。

---

### B. Xray-core 服务端与客户端 4 种模式

#### 1) 服务端入站配置 (`inbounds`)
```json
{
  "inbounds": [
    {
      "tag": "chitanda-h2-in",
      "port": 443,
      "protocol": "chitanda",
      "settings": {
        "psk": "your-32-byte-secure-pre-shared-key-here",
        "path": "/api/v1/sync",
        "transport": "h2",
        "strict_sni": "jp.example.com",
        "fallback": "127.0.0.1:8080"
      },
      "streamSettings": {
        "security": "tls",
        "tlsSettings": {
          "certificates": [{ "certificateFile": "/etc/ssl/cert.pem", "keyFile": "/etc/ssl/key.pem" }]
        }
      }
    },
    {
      "tag": "chitanda-h1-in",
      "port": 18200,
      "protocol": "chitanda",
      "settings": {
        "psk": "your-32-byte-secure-pre-shared-key-here",
        "path": "/gateway/stream/v2",
        "transport": "h1",
        "fallback": "127.0.0.1:80"
      },
      "streamSettings": { "security": "none" }
    }
  ]
}
```

#### 2) 客户端出站配置 (`outbounds`)
```json
{
  "outbounds": [
    {
      "tag": "chitanda-h2-out",
      "protocol": "chitanda",
      "settings": {
        "server": "jp.example.com:443",
        "server_name": "jp.example.com",
        "psk": "your-32-byte-secure-pre-shared-key-here",
        "path": "/api/v1/sync",
        "transport": "h2",
        "pool_size": 4
      }
    },
    {
      "tag": "chitanda-h3-out",
      "protocol": "chitanda",
      "settings": {
        "server": "jp.example.com:443",
        "server_name": "jp.example.com",
        "psk": "your-32-byte-secure-pre-shared-key-here",
        "path": "/api/v1/sync",
        "transport": "h3"
      }
    },
    {
      "tag": "chitanda-auto-out",
      "protocol": "chitanda",
      "settings": {
        "server": "jp.example.com:443",
        "server_name": "jp.example.com",
        "psk": "your-32-byte-secure-pre-shared-key-here",
        "path": "/api/v1/sync",
        "transport": "auto",
        "pool_size": 4
      }
    },
    {
      "tag": "chitanda-h1-out",
      "protocol": "chitanda",
      "settings": {
        "server": "203.0.113.88:18200",
        "psk": "your-32-byte-secure-pre-shared-key-here",
        "path": "/gateway/stream/v2",
        "transport": "h1"
      }
    }
  ]
}
```

完整服务端与客户端 JSON 见 **[examples/xray/server_all_modes.json](examples/xray/server_all_modes.json)** 与 **[examples/xray/client_all_modes.json](examples/xray/client_all_modes.json)**。

---

## 5. 自动跟随上游编译流水线 (Automated Upstream CI/CD)

通过本仓库的 GitHub Actions (`.github/workflows/upstream-sync-build.yml`)：
1. **自动监控**：每日自动轮询 `XTLS/Xray-core` 与 `MetaCubeX/mihomo` 的最新 Release Tag；
2. **动态注入**：自动执行 `scripts/inject-xray.py` 与 `scripts/inject-mihomo.py` 完成无侵入适配器挂载；
3. **全平台发布**：自动编译 Windows / Linux / macOS 多架构二进制并直接发布到本仓库的 [GitHub Releases](https://github.com/violetaini/chitanda/releases)。

---

## 6. 构建与验证

```sh
# 运行全量单元测试（包含密码学、重放攻击注入、全双工回环与 UDP 模拟）
go test -count=1 -v ./...

# 编译 Linux ARM64 生产二进制
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o bin/chitanda-server ./cmd/chitanda-server
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o bin/chitanda-client ./cmd/chitanda-client
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o bin/bench-direct ./cmd/bench-direct
```

---

## 7. 技术边界与安全声明 (Threat Model & Limitations)

1. **主线与实验模式定位**：
   - `h2` / `h3` 依托 TLS 1.3 加密与标准 SNI，是审查对抗环境下的**主要生产载荷**；
   - `h1` 虽具备高吞吐与无证书直连能力，但外层为明文 HTTP/1.1，易受时序和流特征分析，**定位为纯 IP / 内网 / 免证书实验通道**，不建议作为高对抗环境下的主路由。
2. **前向保密性说明**：
   - TLS 模式 (`h2` / `h3`) 依托 TLS 1.3 ECDHE 具备完全前向保密（PFS）；
   - 免证书模式 (`h1` / `plain-udp`) 采用预共享密钥（PSK）衍生，不具备前向保密能力。
3. **0-RTT 与重放安全**：
   - `plain-udp` 采用“先 AEAD 校验，后会话滑动窗口防重放”的防御体系，未认证包无法污染防重放状态。
