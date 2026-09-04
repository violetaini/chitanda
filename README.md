# Chitanda (千反田) 私有传输协议

Chitanda 是一个面向自有服务端部署的高性能、抗探测 Go 代理传输协议。项目提供模块化服务端、可嵌入的客户端 SDK（提供标准 `net.Conn` 与 `net.PacketConn` 接口）及直连基准测试工具。

当前主线支持 **5 种传输载荷模式（Transport Carriers）**：以 **`h2` (TLS 1.3 + HTTP/2 多路复用)** 作为公网主线推荐；针对 IEPL / IPLC 专线提供极限吞吐的 **`stream` (RawStream 自定义 TCP)**；同时提供 **`h3`**、**`auto`** 与纯 IP 模式 **`h1`**（别名 `plain-h1`）。

- 📖 **[完整配置手册与 Wiki 规范](docs/CONFIGURATION.md)**
- 📁 **[示例配置文件目录 (Examples)](examples/)**
- 📦 **[GitHub 自动发布二进制 (Releases)](https://github.com/violetaini/chitanda/releases)**

---

## 1. 传输载荷矩阵 (Transport Carrier Matrix)

```text
                                  业务上层 / 代理内核 / 客户端 SDK
                                                 │
                                           pkg/client SDK
                     ┌───────────────────────────┼───────────────────────────┐
                     ▼                           ▼                           ▼
            【TLS 域名公网主线】              【专线/中转高性能主线】         【纯 IP / 免证书实验模式】
          h2 (默认) / h3 / auto                     stream                         h1 (plain-h1)
   ┌─────────────────┬──────────────────┐ ┌──────────────────────────┐ ┌───────────────────────┬───────────────────────┐
   │ TCP: H2/H3 复用  │ UDP: H3 Datagram │ │ TCP: RawStream (AES-GCM) │ │ TCP: H1 全双工 AEAD   │ UDP: Plain-UDP Datagram│
   └─────────────────┴──────────────────┘ └─────────────┬────────────┘ └───────────────────────┴───────────────────────┘
                     │                                  │                                       │
                     └──────────────────────────────────┼───────────────────────────────────────┘
                                                        ▼
                                               cmd/chitanda-server
```

| 模式 | TCP 承载机制 | UDP 承载机制 | 0-RTT 支持 | 核心特征与适用场景 |
| :--- | :--- | :--- | :---: | :--- |
| **`h2`** | TLS 1.3 + HTTP/2 流复用 | H3 QUIC Datagram (RFC 9221) | ✅ (连接池流复用 0-RTT) | **公网主线推荐**。单/多 TCP 物理连接池化复用，吞吐极高，CPU 开销低，抗审查特征成熟。 |
| **`stream`** | RawStream TCP (AES-128-GCM) | `plain-udp` 原生 AEAD 数据报 | ✅ (0-RTT OPEN 动态填充) | **IEPL/IPLC 专线与高性能中转推荐**。单线程吞吐近 2000 MB/s (0 内存分配)；主动探测免疫（非认证探测立即断开，无 Web 特征）；ServerID 跨节点防重放绑定。 |
| **`h3`** | TLS 1.3 + QUIC Stream + HTTP/3 | H3 QUIC Datagram (RFC 9221) | ✅ (会话恢复 0-RTT) | 原生 QUIC 0 队头阻塞，强抗丢包与弱网抖动；支持持久化 Session Ticket 0-RTT。 |
| **`auto`** | H2 优先 $\leftrightarrow$ 异常自愈 H3 | H3 QUIC Datagram (RFC 9221) | ✅ | 新建连接动态健康探测；TCP 受阻或丢包劣化时平滑向 H3 容灾。 |
| **`h1`** *(别名 `plain-h1`)* | 纯 IP HTTP/1.1 全双工 + PSK-AEAD | `plain-udp` 原生 AEAD 数据报 | ✅ (Flight 1 预派生 0-RTT) | **免域名 / 免证书 / 纯 IP 实验模式**。无 TLS 开销，内层流式认证加密；外层伪装为标准全双工 HTTP/1.1。 |

---

## 2. 核心架构与密码学设计

### A. TLS 传输主线 (`h2` / `h3` / `auto`)
- **握手与认证**：TLS 1.3 标准握手（支持配置 Strict SNI 校验）。
- **Transcript V2 HMAC 签名**：请求头携带基于 PSK 与长度前缀域隔离（Domain Separation）的 HMAC-SHA256 签名，绑定 Method、Path、Target、Timestamp 与 Nonce。
- **2ms Group-Commit 组提交防重放**：服务端持久化 Nonce 缓存采用微批次异步刷盘与条件变量唤醒机制，在保障崩溃一致性的同时消除高并发磁盘 I/O 瓶颈。
- **原生 UDP 旁路**：UDP 流量通过独立的 HTTP/3 Extended CONNECT 与 QUIC Datagram 传输，配合 2048 位滑动位图抵御乱序与重放。
- **Wire-Version 双向兼容**：服务端自适应识别现代原始流客户端与携带私有帧标记（`X-Framing: 1`）的客户端，平滑向后兼容。

### B. 专线极速载荷 (`stream` / Chitanda RawStream)
- **原生高性能 TCP 分帧**：摒弃 Web 封装开销，基于 AES-128-GCM 实现单线程吞吐近 2 GB/s 的零拷贝流式代理。
- **0-RTT 动态混淆首飞**：
  - ClientHello (48B) 携带时间戳与 24B Nonce，绑定 ServerID 域签名；
  - 0-RTT OPEN 目标帧强制填充 32~256 字节的动态随机 Padding，平滑混淆首包长度指纹；
  - 服务端两阶段提交持久化 Nonce 缓存（先验证 ClientHello + 0-RTT 帧解密成功，才执行落盘），杜绝重放污染与跨重启/跨节点重放。
- **傲盾/DPI 主动探测免疫**：
  - 遇到非认证流量（如扫描器发送 `GET / HTTP/1.1` 或垃圾探针）**立即关闭连接，响应 0 字节，绝不返回任何 HTTP/Web 错误特征**；
  - 严格支持 TCP 半关闭（Half-Close），完美兼容长请求与单向流式交互。

### C. 纯 IP 实验载荷 (`h1` / `plain-udp`)
- **标准全双工 HTTP/1.1 Carrier (`h1`)**：
  - 外层仅使用标准 `POST <path> HTTP/1.1` 与 `Transfer-Encoding: chunked`，服务端启用全双工流；
  - 0-RTT OPEN 目标帧随 Flight 1 单包聚合发送，瞬间发起目标直连；
  - 内置严格分块解析上下限校验，根除负数切片越界与未认证超大内存分配（OOM）。
- **`plain-udp` 原生 AEAD 数据报与双向隔离**：
  - **XChaCha20-Poly1305 + 24B Nonce**：采用 24 字节扩展 Nonce（`[8B SessionID] [8B Monotonic Seq] [8B Salt]`），彻底杜绝 Nonce 耗尽与生日碰撞；
  - **双向密钥与防反射**：独立派生 `c2sKey` 与 `s2cKey`，Associated Data (AD) 强制绑定传输方向（`DirClientToServer` / `DirServerToClient`），反射报文解密直接失败；
  - **客户端来源校验与并发安全**：客户端严格校验对端 IP/Port 必须为服务器地址；内部采用独立内存池保证 `net.PacketConn` 线程安全并发调用；
  - **服务端资源有界**：限制全服最大活跃会话数（10,000）与每会话转发目标数（32），防止恶意 UDP 泛洪耗尽系统 FD 与内存。

### D. 多模式防探测回落 (Dynamic Masquerade Fallback)
未通过路径匹配、方法校验或 HMAC 认证的 HTTP 请求，按配置平滑回落：
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

	"github.com/violetaini/chitanda/pkg/client"
)

func main() {
	// 默认推荐：h2 (TLS 1.3 多路复用主线)
	cli, err := client.New(client.Config{
		Server:       "server.example.com:443",
		ServerName:   "server.example.com",
		PSK:          []byte("your-32-byte-secure-pre-shared-key-here"),
		Path:         "/api/v1/sync",
		TCPTransport: client.TCPTransportH2, // 模式: "h2", "stream", "h3", "auto", "h1"
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

### A. Mihomo (Clash.Meta) 客户端 5 种模式节点

在 Mihomo `config.yaml` 的 `proxies` 列表中直接配置：

```yaml
proxies:
  # 模式 1: H2 多路复用主线模式 (TLS 1.3 + HTTP/2 流复用) - 公网主线推荐
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

  # 模式 2: Stream 专线高性能模式 (RawStream TCP + AES-128-GCM + 动态混淆) - 专线推荐
  - name: "Chitanda-Stream-Tokyo"
    type: chitanda
    server: 203.0.113.88
    port: 11323
    psk: "your-32-byte-secure-pre-shared-key-here"
    transport: "stream"
    server-id: "tokyo-node-01"
    udp: true

  # 模式 3: H3 原生 QUIC 模式 (HTTP/3 0-RTT + 0 队头阻塞)
  - name: "Chitanda-H3-Tokyo"
    type: chitanda
    server: jp.example.com
    port: 443
    psk: "your-32-byte-secure-pre-shared-key-here"
    path: "/api/v1/sync"
    transport: "h3"
    sni: "jp.example.com"
    udp: true

  # 模式 4: Auto 智能探测与自愈容灾模式 (H2 主线 + 嗅探降级 H3)
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

  # 模式 5: H1 纯 IP 免证书实验模式 (全双工 HTTP/1.1 AEAD + Plain-UDP)
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
      "tag": "chitanda-stream-in",
      "port": 11323,
      "protocol": "chitanda",
      "settings": {
        "psk": "your-32-byte-secure-pre-shared-key-here",
        "server_id": "tokyo-node-01",
        "transport": "stream"
      },
      "streamSettings": { "security": "none" }
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
      "tag": "chitanda-stream-out",
      "protocol": "chitanda",
      "settings": {
        "server": "203.0.113.88:11323",
        "psk": "your-32-byte-secure-pre-shared-key-here",
        "server_id": "tokyo-node-01",
        "transport": "stream"
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

## 6. 3X-UI 面板定制版一键部署 (3X-UI v2.3.11 with Chitanda Core)

本项目在专有分支 [`3x-ui`](https://github.com/violetaini/chitanda/tree/3x-ui) 中提供了定制版的 **3X-UI (v2.3.11)** 控制面板。该面板锁定了经典稳定的 v2.3.11 架构，同时将内核源与更新接口无缝指向 Chitanda Xray-core。

### 一键安装部署命令

在 Linux 服务器（Ubuntu / Debian / CentOS / AlmaLinux 等）以 root 权限执行：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/violetaini/chitanda/3x-ui/install.sh)
```

### 特性与说明
- **开箱即用**：自动完成 3X-UI 面板安装，并将底层 Xray 内核直接部署为最新的 `xray-chitanda`。
- **在线切换内核**：进入 3X-UI Web 界面后的 **Xray 设置 $\to$ 切换版本** 功能已自动接管，指向本仓库的 GitHub Releases，可直接在线选择和热更新 Chitanda 编译的所有版本内核。
- **多架构适配**：自动识别并适配 Linux AMD64 (`x86_64`) 与 ARM64 (`aarch64`)。

---

## 7. 构建与验证

```sh
# 运行全量单元测试（包含密码学、防反射、重放攻击注入、全双工回环与 UDP 模拟）
go test -count=1 -v ./...

# 运行 RawStream 零拷贝吞吐微基准
go test -bench="." -benchmem github.com/violetaini/chitanda/internal/rawstream

# 编译 Linux 生产二进制
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/chitanda-server ./cmd/chitanda-server
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/chitanda-client ./cmd/chitanda-client
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/bench-direct ./cmd/bench-direct
```

---

## 8. 性能基准 (Micro-Benchmarks)

RawStream 与 AEADStream 在 x86_64 (AES-NI) 硬件环境下的实测基准测试：

| 基准测试项 | 吞吐量 | 单次耗时 | 堆内存分配 | 每次操作分配数 |
| :--- | :---: | :---: | :---: | :---: |
| **`BenchmarkStreamConn_Throughput`** | **1,984.90 MB/s** | 16.5 μs | **0 B/op** | **0 allocs/op** |
| **`BenchmarkAEADStream_Direct`** | **2,194.64 MB/s** | 7.4 μs | **0 B/op** | **0 allocs/op** |
| **`BenchmarkAES128GCM_Direct`** | **2,279.36 MB/s** | 7.1 μs | **0 B/op** | **0 allocs/op** |

*注：全双工流式传输与批处理刷盘完全实现了零堆分配（0 allocs/op），单连接吞吐近 2000 MB/s，逼近硬件总线速度极限。*

---

## 9. 技术边界与安全声明 (Threat Model & Limitations)

1. **载荷定位与网络场景**：
   - `h2` / `h3` 依托 TLS 1.3 加密与标准真实 SNI 伪装，是跨境外公网审查对抗环境下的**主要公网生产载荷**；
   - `stream` (Chitanda RawStream) 彻底去除 HTTP 协议冗余，采用 AES-128-GCM + 动态 Padding，专为 **IEPL / IPLC 商业内网专线与 BGP 中转链路** 打造，具备极高吞吐并防御傲盾等商业防火墙的主动 HTTP 嗅探探测；
   - `h1` 具备免证书直连与伪装能力，定位为纯 IP / 内网穿透通道。
2. **前向保密性说明**：
   - TLS 模式 (`h2` / `h3`) 依托 TLS 1.3 ECDHE 具备完全前向保密（PFS）；
   - 静态 PSK 模式 (`stream` / `h1` / `plain-udp`) 采用预共享密钥衍生会话密钥，不具备临时密钥交换 PFS。敏感公网流量推荐使用 TLS 1.3 载荷。
3. **0-RTT 与防重放安全**：
   - `stream` 采用服务端两阶段提交（Two-Phase Commit）持久化重放缓存，只有认证且解密成功后的 Nonce 才会提交持久化，并绑定 ServerID 杜绝跨节点重放；
   - `plain-udp` 采用 XChaCha20-Poly1305（24 字节 Nonce）、双向分离派生密钥（`c2sKey` / `s2cKey`）与方向标记 AD，彻底杜绝数据包反射攻击与 Nonce 生日碰撞。
