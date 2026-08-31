# MyXray 四种传输模式

MyXray 通过 `TCPTransport` 提供 `h2`、`h3`、`auto`、`plain-h1` 四种 TCP 路由模式。该配置决定 TCP 代理连接使用哪一种载荷 carrier；UDP 流量在 TLS 模式下使用 H3 QUIC Datagram，在免证书模式下使用 `plain-udp` 原生 AEAD 数据报。

本文以 `pkg/client` 与 `pkg/server` 的当前主线实现为准。

---

## 1. 模式总览矩阵

| 配置值 (`TCPTransport`) | TCP 承载机制 | UDP 承载机制 | 0-RTT 特性 | 证书/域名要求 | 默认值 |
| :--- | :--- | :--- | :---: | :---: | :---: |
| **`h2`** | TLS 1.3 / HTTP/2 连接池流复用 | H3 / QUIC Datagram | ✅ (已有连接流复用 0-RTT) | 需要域名与 TLS 证书 | 是 (默认) |
| **`h3`** | TLS 1.3 / QUIC Stream / HTTP/3 | H3 / QUIC Datagram | ✅ (持久化票据 0-RTT) | 需要域名与 TLS 证书 | 否 |
| **`auto`** | H2 优选，按健康状态回退 H3 | H3 / QUIC Datagram | ✅ | 需要域名与 TLS 证书 | 否 |
| **`plain-h1`** (别名 `h1`) | 纯 IP HTTP/1.1 全双工 + PSK-AEAD | `plain-udp` 原生 AEAD 数据报 | ✅ (Flight 1 预派生 0-RTT) | **完全不需要** (纯 IP 直连) | 否 |

---

## 2. 各模式技术细节

### 1. `h2`：固定 HTTP/2 TCP Carrier
- **配置**：`TCPTransport: client.TCPTransportH2`
- **TCP 数据路径**：TLS 1.3 + HTTP/2 `POST`，鉴权后请求/响应体直接流式传输原始 TCP 字节流。
- **连接池**：SDK 默认创建 4 个独立 H2 物理连接（`TCPPoolSize`），动态均衡活跃流。
- **UDP**：由独立的 H3 Transport Manager 建立 QUIC Datagram 关联。

### 2. `h3`：固定 HTTP/3 (QUIC) TCP Carrier
- **配置**：`TCPTransport: client.TCPTransportH3`
- **TCP 数据路径**：TLS 1.3 + QUIC Stream + HTTP/3。
- **抗丢包与 0-RTT**：QUIC 原生消除 TCP 队头阻塞；配置 `SessionCacheFile` 后可跨进程复用 TLS 票据实现 0-RTT。
- **UDP**：复用 QUIC Datagram 传输通道。

### 3. `auto`：动态健康探测与自愈调度
- **配置**：`TCPTransport: client.TCPTransportAuto`
- **机制**：优先使用 H2 快速通道；当连续探测失败或网络发生降级时，新建 TCP 连接自动切换到 H3 QUIC 连接池；后台定期探测 H2 恢复状态。

### 4. `plain-h1`：纯 IP 全双工 + 0-RTT + 原生 Plain-UDP
- **配置**：`TCPTransport: client.TCPTransportPlainH1` 或 `client.TCPTransportH1`
- **无 TLS / 纯 IP**：无需配置 `ServerName` 与证书，直连服务器 IP:Port。
- **0-RTT 流水线机制**：
  - 客户端基于 PSK、时间戳 $T_c$ 与随机数 $N_c$ 派生 $K_{0\text{-rtt}}$；
  - 建立 TCP 连接后，在首个 TCP 数据包（Flight 1）中合并发送 `HTTP Headers` + `Chunk 1 (ClientHello)` + `Chunk 2 (0-RTT OPEN Target)`；
  - 服务端验证防重放后，**无需等待往返响应即可瞬间解密目标并向 Upstream 建连**，达成应用层 0-RTT；
  - 服务端响应首块携带 40 字节 `ServerHello` 与持有证明 $\text{Auth}_s$，双向平滑升级至 1-RTT 密钥 ($K_{c \to s}, K_{s \to c}$)。
- **配套 UDP**：调用 `ListenPacket` 自动返回 `plain-udp` 原生 AEAD 数据报连接，纯 UDP 传输，0 队头阻塞。
