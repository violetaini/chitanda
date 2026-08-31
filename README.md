# MyXray 私有传输协议

MyXray 是一个面向自有服务端部署的高性能、抗探测 Go 代理传输协议。项目提供模块化服务端、可嵌入的客户端 SDK（提供标准 `net.Conn` 与 `net.PacketConn` 接口）及直连基准测试工具。

当前主线支持 **4 种传输载荷模式（Transport Carriers）**，覆盖标准 TLS/域名环境与极端无证书/纯 IP 敏感场景。

---

## 1. 传输载荷矩阵 (Transport Carrier Matrix)

```text
                                  业务上层 / 代理内核 / 客户端 SDK
                                                 │
                                           pkg/client SDK
                     ┌───────────────────────────┴───────────────────────────┐
                     ▼                                                       ▼
            【TLS 域名模式】                                          【纯 IP / 免证书模式】
      h2 / h3 / auto                                                       plain-h1
   ┌─────────────────┬──────────────────┐                ┌───────────────────────┬───────────────────────┐
   │ TCP: H2/H3 复用  │ UDP: H3 Datagram │                │ TCP: H1 全双工 AEAD   │ UDP: Plain-UDP Datagram│
   └─────────────────┴──────────────────┘                └───────────────────────┴───────────────────────┘
                     │                                                       │
                     └───────────────────────────┬───────────────────────────┘
                                                 ▼
                                         cmd/myxray-server
```

| 模式 | TCP 承载机制 | UDP 承载机制 | 0-RTT 支持 | 核心特征与适用场景 |
| :--- | :--- | :--- | :---: | :--- |
| **`h2`** | TLS 1.3 + HTTP/2 流复用 | H3 QUIC Datagram (RFC 9221) | ✅ (流复用 0-RTT) | **默认推荐**。单/多 TCP 物理连接池化复用，吞吐极高，CPU 开销低。 |
| **`h3`** | TLS 1.3 + QUIC Stream + HTTP/3 | H3 QUIC Datagram (RFC 9221) | ✅ (会话恢复 0-RTT) | 原生 QUIC 0 队头阻塞，强抗丢包与弱网抖动；支持持久化 Session Ticket 0-RTT。 |
| **`auto`** | H2 优先 $\leftrightarrow$ 异常自愈 H3 | H3 QUIC Datagram (RFC 9221) | ✅ | 新建连接动态健康探测；TCP 受阻或丢包劣化时平滑向 H3 容灾。 |
| **`plain-h1`** | 纯 IP HTTP/1.1 Chunked 全双工 + PSK-AEAD | `plain-udp` 原生 AEAD 数据报 | ✅ (Flight 1 0-RTT) | **免域名 / 免证书 / 免 SNI**。纯 IP 直连，无 TLS 开销，内层 ChaCha20-Poly1305 双向认证加密。 |

---

## 2. 核心架构与密码学设计

### A. TLS 传输族 (`h2` / `h3` / `auto`)
- **握手与认证**：TLS 1.3 标准握手（支持配置 Strict SNI 校验）。
- **Transcript V2 HMAC 签名**：请求头携带基于 PSK 与长度前缀域隔离（Domain Separation）的 HMAC-SHA256 签名，绑定 Method、Path、Target、Timestamp 与 Nonce。
- **2ms Group-Commit 组提交防重放**：服务端持久化 Nonce 缓存采用微批次异步刷盘与条件变量唤醒机制，在保障崩溃一致性的同时消除高并发磁盘 I/O 瓶颈。
- **原生 UDP 旁路**：UDP 流量通过独立的 HTTP/3 Extended CONNECT 与 QUIC Datagram 传输，配合 2048 位滑动位图抵御乱序与重放。

### B. 无 TLS 纯 IP 传输族 (`plain-h1` / `plain-udp`)
- **零特征外层 HTTP/1.1 Carrier**：
  - 外层仅使用标准 `POST <path> HTTP/1.1` 与 `Transfer-Encoding: chunked`；
  - 彻底剥离明文 `X-Session-Target` 与自定义私有 Header，伪装为普通二进制流上传接口；
  - 服务端使用 Go `http.NewResponseController(w).EnableFullDuplex()` 实现真正的双向流式全双工。
- **0-RTT 流水线（Flight 1 Pipelining）**：
  - 客户端基于 PSK、时间戳 $T_c$ 与随机数 $N_c$ 派生 $K_{0\text{-rtt}}$；
  - 在第 1 个 TCP 发送包中合并写入：`HTTP Headers` + `Chunk 1 (ClientHello 48B)` + `Chunk 2 (0-RTT OPEN 目标帧 + Early Data)`；
  - 服务端校验防重放后，**无需等待响应往返，立刻解密 OPEN 目标并向目标发起直连**，达成应用层 0-RTT。
- **双向身份证明与 Session KDF**：
  - 服务端在响应首块返回 40 字节 `ServerHello`，包含服务端随机数 $N_s$ 与密码学持有证明 $\text{Auth}_s$；
  - 双方通过 HKDF-SHA256 派生双向独立会话密钥 $K_{c \to s}$ 与 $K_{s \to c}$，单调递增 Nonce 流式加密。
- **`plain-udp` 原生 AEAD 数据报**：
  - 格式：$[ T_c \ (8\text{B}) \parallel \text{Nonce} \ (12\text{B}) \parallel \text{ChaCha20-Poly1305}(\text{SOCKS5 Addr} \parallel \text{Payload}) \parallel \text{Tag} \ (16\text{B}) ]$；
  - 纯 UDP 传输，彻底杜绝 TCP 队头阻塞与重传延迟；
  - 服务端动态维护客户端 NAT 映射表与空闲会话垃圾回收。

### C. 多模式防探测回落 (Dynamic Masquerade Fallback)
未通过路径匹配、方法校验或 HMAC 认证的请求，按配置平滑回落：
1. **内置企业 ERP 业务网关**：内置 Vanguard Global Operations Hub (EBG v4.2) 响应式门户与 REST API，包含动态 TraceID/ClusterID 生成；
2. **本地静态目录**：托管指定的 HTML/静态资源；
3. **Nginx UDS 反向代理**：通过 `unix:/path/to/nginx.sock` 零网络栈损耗代理本地 Web 服务；
4. **本地端口反向代理**：转发至 `127.0.0.1:8080` 等本地 HTTP 服务。

---

## 3. 代码结构与组件

```text
myxray/
├── cmd/
│   ├── myxray-server/       # 服务端主入口（支持 TLS/H2/H3 及 Plain-H1/UDP 模式）
│   ├── myxray-client/       # 客户端运行程序
│   └── bench-direct/        # 绕过 SOCKS5 的直接性能压测工具
├── pkg/
│   ├── client/              # 核心客户端 SDK (DialContext / ListenPacket)
│   │   ├── conn_h1.go       # Plain-H1 0-RTT 全双工连接实现
│   │   ├── conn_plain_udp.go# Plain-UDP 原生 PacketConn 实现
│   │   ├── conn_tcp.go      # H2 TCP 多路复用连接池
│   │   ├── conn_udp.go      # H3 QUIC Datagram UDP 实现
│   │   └── prober.go        # Auto 模式健康探测与自愈调度器
│   └── server/              # 服务端核心逻辑 (ServeHTTP / Plain-H1 / Plain-UDP / Fallback)
└── internal/
    ├── auth/                # Transcript V2 HMAC 签名与 Group-Commit 防重放缓存
    ├── frame/               # QUIC Datagram 封包与滑动重放窗口
    ├── h1session/           # Plain-H1 0-RTT 握手、HKDF 密钥派生与 AEAD 流
    ├── plainudp/            # Plain-UDP 数据报编解码与 ChaCha20-Poly1305 AEAD
    ├── quicconfig/          # QUIC 缓冲区与调优参数
    ├── sessioncache/        # 跨进程持久化 TLS Session Ticket 缓存
    ├── socks5/              # SOCKS5 握手与地址编解码
    └── target/              # 出站目标地址合法性校验与 SSRF 阻断
```

---

## 4. Go SDK 使用示例

```go
package main

import (
	"context"
	"log"
	"net"
	"time"

	"myxray/pkg/client"
)

func main() {
	// 初始化客户端（以 plain-h1 免证书模式为例）
	cli, err := client.New(client.Config{
		Server:       "168.138.209.1:8080",
		PSK:          []byte("your-32-byte-secure-pre-shared-key-here"),
		Path:         "/api/v1/sync",
		TCPTransport: client.TCPTransportPlainH1, // 可选: "h2", "h3", "auto", "plain-h1"
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

## 5. 构建与自动化测试

本项目在 Linux / macOS / Windows 下均支持全量单元测试与跨平台编译：

```sh
# 运行全量单元测试（包含密码学、重放缓存、全双工回环与 UDP 模拟）
go test -count=1 -v ./...

# 编译 Linux ARM64 生产二进制
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o bin/myxray-server ./cmd/myxray-server
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o bin/myxray-client ./cmd/myxray-client
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o bin/bench-direct ./cmd/bench-direct
```

---

## 6. 技术边界与安全声明 (Threat Model & Limitations)

1. **不可观测性假说（Unobservability）**：
   - 协议在密码学上保证了机密性、完整性、前向安全与双向身份认证，且消除明文私有 Header；
   - 但流量时序分析（Timing Analysis）、包长分布（Packet Length Distribution）及极端流量指纹仍然可能作为辅助特征，**不应假设存在数学意义上的“100% 绝对隐形”**。
2. **0-RTT 重放权衡**：
   - 0-RTT 载荷具有内在的可重放窗口风险，本项目通过服务端 $\pm 30$ 秒窗口与持久化 Group Commit 缓存进行防护；在单机重启或宕机瞬间，未落盘的毫秒级窗口可能产生短暂防御失效，高敏感交易类流量建议使用标准 1-RTT。
3. **SSRF 防御边界**：
   - 服务端默认开启公网单播白名单检查，拦截内网（RFC 1918）、环回及保留地址出站，防止代理成为跳板扫描内网。
