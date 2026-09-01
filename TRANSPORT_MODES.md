# MyXray 四种传输模式规范 (Transport Modes Specification)

MyXray 通过 `TCPTransport` 提供 `h2`、`h3`、`auto`、`plain-h1` 四种传输载荷模式。

本文档详细规范各模式的数据路径、密码学模型、故障切换与安全边界。

---

## 1. 模式总览矩阵

| 配置值 (`TCPTransport`) | TCP 承载机制 | UDP 承载机制 | 0-RTT 特性 | 证书/域名要求 | 建议定位 |
| :--- | :--- | :--- | :---: | :---: | :--- |
| **`h2`** *(默认)* | TLS 1.3 / HTTP/2 连接池流复用 | H3 / QUIC Datagram | ✅ (连接复用 0-RTT) | 必须配置域名与有效证书 | **生产主线推荐**：低 CPU 开销、极高吞吐、主流 TLS 伪装 |
| **`h3`** | TLS 1.3 / QUIC Stream / HTTP/3 | H3 / QUIC Datagram | ✅ (持久化票据 0-RTT) | 必须配置域名与有效证书 | **抗弱网/丢包主线**：原生 QUIC 0 队头阻塞 |
| **`auto`** | H2 优先 $\leftrightarrow$ 迟滞自愈 H3 | H3 / QUIC Datagram | ✅ | 必须配置域名与有效证书 | **自适应容灾**：H2 异常自动降级 H3，网络恢复自动切回 |
| **`plain-h1`** *(别名 `h1`)* | 纯 IP HTTP/1.1 全双工 + PSK-AEAD | `plain-udp` 原生 AEAD 数据报 | ✅ (Flight 1 预派生 0-RTT) | **完全不需要** (纯 IP 直连) | **免证书实验/内网载荷**：极简无 TLS，内层 ChaCha20 加密 |

---

## 2. 各模式技术细节

### 1. `h2`：固定 HTTP/2 TCP Carrier (生产默认推荐)
- **配置方式**：`TCPTransport: client.TCPTransportH2`
- **数据路径**：客户端建立 TLS 1.3 连接，验证服务端证书与 SNI。私有代理流使用 HTTP/2 `POST` 请求，鉴权完成后直接在请求体和响应体中传输原始 TCP 字节流。
- **连接池化**：SDK 维护 `TCPPoolSize`（1-16）个独立 H2 物理连接，动态调度分配到活跃流最少的连接。
- **Wire-Version 向后兼容**：服务端自适应识别旧客户端私有帧标记（`X-Framing: 1`）与现代原始字节流。
- **UDP 路径**：由独立的 H3 Manager 建立 QUIC Datagram 关联通道。

### 2. `h3`：固定 HTTP/3 (QUIC) TCP Carrier
- **配置方式**：`TCPTransport: client.TCPTransportH3`
- **数据路径**：基于 QUIC Stream 与 HTTP/3 传输。每个 TCP 代理连接映射为一个独立的 QUIC bidirectional stream。
- **0-RTT 与抗丢包**：QUIC 原生消除了 TCP 队头阻塞；配置 `SessionCacheFile` 可跨进程复用 TLS 票据实现 0-RTT。
- **UDP 路径**：复用同一 QUIC 栈的 HTTP/3 Extended CONNECT 与 QUIC Datagram (RFC 9221)。

### 3. `auto`：动态健康探测与迟滞自愈 (Hysteresis Failover/Failback)
- **配置方式**：`TCPTransport: client.TCPTransportAuto`
- **工作机制**：
  1. 默认优先使用 H2 快速通道建立出站 TCP；
  2. 后台 Prober 每 3 秒发送轻量探测（`HEAD /` 携带 `X-Carrier-Probe: 1`）；
  3. **快速降级**：连续 2 次探测失败或 RTT > 500ms（约 6 秒内），标记降级，后续新建 TCP 自动走 H3 QUIC 连接池；
  4. **迟滞自愈**：当 H2 连续 10 次探测成功且 RTT <= 500ms（稳定 30 秒），解除降级状态，新建 TCP 自动切回 H2；
  5. 切换仅影响后续新建流，已有在传流保持原有连接直至自然结束。

### 4. `plain-h1` / `plain-udp`：免证书纯 IP 实验载荷
- **配置方式**：`TCPTransport: client.TCPTransportPlainH1`
- **无 TLS / 纯 IP**：无需配置 `ServerName` 与证书，直连服务器 IP:Port。
- **0-RTT 流水线机制**：
  - 客户端基于 PSK、时间戳 $T_c$ 与随机数 $N_c$ 预派生 $K_{0\text{-rtt}}$；
  - 建立 TCP 连接后，在首个 TCP 数据包（Flight 1）中合并发送 `HTTP Headers` + `Chunk 1 (ClientHello 48B)` + `Chunk 2 (0-RTT OPEN Target)`；
  - 服务端验证时间戳与持久化防重放后，**无需等待往返响应即可瞬间解密目标并向 Upstream 建连**，达成应用层 0-RTT。
- **`plain-udp` 原生 AEAD 数据报**：
  - **密文格式**：$[ T_c \ (8\text{B}) \parallel \text{Seq} \ (8\text{B}) \parallel \text{Nonce} \ (12\text{B}) \parallel \text{ChaCha20-Poly1305}(\text{SessionID 8B} \parallel \text{Target} \parallel \text{Payload}) \parallel \text{Tag 16B} ]$；
  - **先验 AEAD、后记 Replay**：未通过 Poly1305 认证的包直接丢弃，不修改任何防重放状态，彻底杜绝防重放窗口投毒；
  - **SessionID 隔离与跨 NAT 防重放**：内层携带加密 SessionID，防重放滑动窗口绑定到 SessionID 而非外部易变的 UDP 源地址；
  - **有界 Worker Pool 调度**：服务端采用 `NumCPU * 2` 的固定 Worker 队列，按 SessionID 哈希派发，实现同会话保序、跨会话并发、0 调度风暴；
  - **实测性能**：全链路 8MB 深度 UDP 内核缓冲与 `sync.Pool` 零堆分配，实测跑满 **405+ Mbps 0.00% 丢包**。
- **安全与威胁模型定位**：
  - 静态 PSK 衍生，**不具备前向保密（PFS）**；
  - 外层为明文 HTTP/1.1，易受时序和包长分析，定位为**纯 IP / 免证书实验或内网通道**，不建议作为对抗强审查环境的主线。
