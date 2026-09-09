# Chitanda 五种传输载荷模式与生命周期规范 (Transport Modes & Lifecycle Specification)

Chitanda (千反田) 核心协议通过 `TCPTransport` 提供 `h2`、`stream`、`h3`、`auto`、`h1` (plain-h1) 共 5 种传输载荷模式。

本文档详细规范各模式的数据路径、密码学模型、故障切换、半关闭（Half-Close）生命周期与安全边界。

---

## 1. 模式总览矩阵

| 配置值 (`TCPTransport`) | TCP 承载机制 | UDP 承载机制 | 0-RTT 特性 | 证书/域名要求 | 建议定位与核心优势 |
| :--- | :--- | :--- | :---: | :---: | :--- |
| **`h2`** *(默认)* | TLS 1.3 / HTTP/2 连接池流复用 | H3 / QUIC Datagram | ✅ (连接复用 0-RTT) | 必须配置域名与有效证书 | **生产公网主线推荐**：低 CPU 开销、极高吞吐、主流成熟 TLS 伪装、RFC 7540 动态 Padding 防指纹 |
| **`stream`** | RawStream TCP (AES-128-GCM) | `plain-udp` 原生 AEAD 数据报 | ✅ (0-RTT OPEN 动态填充) | **完全不需要** (免证书专线/纯 IP) | **IEPL/IPLC 专线与高性能中转推荐**：单线程近 2000 MB/s、离散握手 0 探测指纹、毫秒级快速半关闭 |
| **`h3`** | TLS 1.3 / QUIC Stream / HTTP/3 | H3 / QUIC Datagram | ✅ (持久化票据 0-RTT) | 必须配置域名与有效证书 | **抗弱网/丢包主线**：原生 QUIC 0 队头阻塞、移动端网络切换平滑保活 |
| **`auto`** | H2 优先 $\leftrightarrow$ 迟滞自愈 H3 | H3 / QUIC Datagram | ✅ | 必须配置域名与有效证书 | **自适应容灾**：H2 异常自动降级 H3，网络恢复自动回切 |
| **`h1`** *(别名 `plain-h1`)* | 纯 IP HTTP/1.1 全双工 + PSK-AEAD | `plain-udp` 原生 AEAD 数据报 | ✅ (Flight 1 预派生 0-RTT) | **完全不需要** (纯 IP 直连) | **免证书实验/内网载荷**：极简无 TLS，内层 ChaCha20 加密，外层全双工 HTTP/1.1 伪装 |

---

## 2. 各模式技术细节

### 1. `h2`：固定 HTTP/2 TCP Carrier (生产公网主线推荐)
- **配置方式**：`TCPTransport: "h2"`
- **数据路径**：客户端建立 TLS 1.3 连接，验证服务端证书与 SNI。私有代理流使用 HTTP/2 `POST` 请求，鉴权完成后直接在请求体和响应体中传输原始 TCP 字节流。
- **连接池化**：SDK 维护 `TCPPoolSize`（1-16）个独立 H2 物理连接，动态调度分配到活跃流最少的连接。
- **RFC 7540 协议级动态填充 (Dynamic Frame Padding)**：HEADERS 与 DATA 帧注入 8~64 字节随机长度的原生 RFC 7540 Padding，彻底打破外层 TLS 记录与内层明文的 1:1 统计相关性。
- **Wire-Version 向后兼容**：服务端自适应识别旧客户端私有帧标记（`X-Framing: 1`）与现代原始字节流。
- **UDP 路径**：由独立的 H3 Manager 建立 QUIC Datagram 关联通道。

### 2. `stream`：RawStream TCP Carrier (IEPL/IPLC 专线与中转推荐)
- **配置方式**：`TCPTransport: "stream"`
- **无 TLS / 专线极致性能**：去除 TLS 协议包裹与多路复用开销，直接采用 AES-128-GCM 进行轻量高吞吐流式加解密。
- **多态离散握手 (Polymorphic Discrete Handshake)**：
  - ClientHello 随机长度为 49~113 字节，ServerHello 随机长度为 41~105 字节；
  - 掩码加密时间戳与填充长度，彻底消除 `0x00000000` 明文零值特征；
  - 服务端读取固定首包执行常数时间 HMAC 验证，遇非认证流量响应 0 字节并断开，杜绝主动探测。
- **自适应动态记录分帧 (Dynamic Record Sizing)**：
  - 首包交互/空闲后采用 1,418 字节 MTU 契合分帧，降低 Web/API 交互延迟 > 50%；
  - 持续吞吐突发（>128KB）自适应平滑跃迁至 32KB 分帧，单核吞吐突破 30+ Gbps，零内存分配。
- **ServerID 绑定防跨节点重放**：会话密钥强绑定目标 `server_id`，杜绝节点间凭据重放攻击。

### 3. `h3`：固定 HTTP/3 (QUIC) TCP Carrier
- **配置方式**：`TCPTransport: "h3"`
- **数据路径**：基于 QUIC Stream 与 HTTP/3 传输。每个 TCP 代理连接映射为一个独立的 QUIC bidirectional stream。
- **0-RTT 与抗丢包**：QUIC 原生消除了 TCP 队头阻塞；配置 `SessionCacheFile` 可跨进程复用 TLS 票据实现 0-RTT。
- **UDP 路径**：复用同一 QUIC 栈的 HTTP/3 Extended CONNECT 与 QUIC Datagram (RFC 9221)。

### 4. `auto`：动态健康探测与迟滞自愈 (Hysteresis Failover/Failback)
- **配置方式**：`TCPTransport: "auto"`
- **工作机制**：
  1. 默认优先使用 H2 快速通道建立出站 TCP；
  2. 后台 Prober 每 3 秒发送轻量探测（`HEAD /` 携带 `X-Carrier-Probe: 1`）；
  3. **快速降级**：连续 2 次探测失败或 RTT > 500ms（约 6 秒内），标记降级，后续新建 TCP 自动走 H3 QUIC 连接池；
  4. **迟滞自愈**：当 H2 连续 10 次探测成功且 RTT <= 500ms（稳定 30 秒），解除降级状态，新建 TCP 自动切回 H2；
  5. 切换仅影响后续新建流，已有在传流保持原有连接直至自然结束。

### 5. `h1` (`plain-h1`) / `plain-udp`：免证书纯 IP 实验载荷
- **配置方式**：`TCPTransport: "h1"` (或 `"plain-h1"`)
- **无 TLS / 纯 IP**：无需配置 `ServerName` 与证书，直连服务器 IP:Port。
- **0-RTT 流水线机制**：Flight 1 合并发送 HTTP 请求头 + ClientHello + 0-RTT OPEN Target 帧，服务端解密后立即连接目标，实现应用层 0-RTT。
- **`plain-udp` 原生 AEAD 数据报**：
  - 全密文高熵载荷（香农熵 > 7.996 bits/byte），双向独立密钥（`c2sKey`/`s2cKey`）与 Associated Data 强绑定防反射；
  - 2048 位滑动窗口抗乱序与重放，全服会话上限与每会话并发限制杜绝资源泛洪。

---

## 3. 全模式半关闭与优雅回收生命周期 (Half-Close & Graceful Lifecycle)

在代理手游（如《碧蓝档案》）、短 HTTP/1.1 API 轮询或移动客户端连接池中，通常呈现 **“客户端发起请求 $\rightarrow$ 服务端响应 $\rightarrow$ 目标服务器主动发送 FIN 断开”** 的时序。若双向代理流不能快速闭合空闲上行方向，会导致连接大量挂死、软路由文件描述符（FD）耗尽及代理内核假死。

Chitanda 对全部 5 种载荷模式实施了统一的生命周期与优雅回收控制：

```text
  [客户端 App / 游戏] ──(请求数据)──> [代理客户端] ──(隧道载荷)──> [Chitanda 服务端] ──(请求)──> [目标服务器]
                                                                                             │
                                                                                        (发送响应)
                                                                                             │
  [客户端 App / 游戏] <──(响应数据)── [代理客户端] <──(隧道载荷)── [Chitanda 服务端] <──(返回 200 OK)
                                                                                             │
                                                                                        (目标发送 FIN/EOF)
                                                                                             │
                                                                                    【downloadDone 触发】
                                                                                             │
                                                      ┌──────────────────────────────────────┴──────────────────────────────────────┐
                                                      ▼                                                                             ▼
                                            【stream 专线模式】                                                          【h2 / h3 / h1 模式】
                                    1. 立即调用 closeWriteConn(client)                                             1. h2/h1: 启动 250ms 快速回收定时器
                                       发送带内 WriteEOF() [0x00, 0x00] + TCP FIN                                  2. h3: 启动 250ms 定时器并触发 stream.CancelRead(0)
                                    2. 启动 250ms SetReadDeadline 保护                                             3. 杜绝旧版 30s 漫长等待，连接在毫秒级释放！
                                    3. 空闲客户端在 250ms 内强制释放两端套接字
```

### 关键回收规范：
1. **下行优先回收 (Download-Completion Triggered Drain)**：
   - 目标服务器响应完毕并关闭连接后，服务端认为核心业务交互已完成。
   - 对客户端方向启动 **250 毫秒（250ms）** 优雅排空窗口，允许客户端传输尾随确认或 FIN。
   - 若客户端连接池处于空闲静默状态（未主动发 FIN），250ms 超时将直接唤醒读取协程并安全切断两端套接字，**杜绝旧版代码挂起 30 秒导致的 FD 暴涨**。
2. **握手锁与上游连接解耦 (Handshake Scope Decoupling)**：
   - `stream` 模式的 2 秒握手截止时间与 512 握手信号量仅在 ClientHello/ServerHello 密文握手阶段生效；
   - 密钥协商完毕后立即调用 `releaseHandshake()` 并清空连接超时，海外高延迟目标建连不受握手超时截断。
3. **带内流结束标界 (In-band EOF Marker)**：
   - `StreamConn.CloseWrite()` 同时下发 2 字节 `[0x00, 0x00]` 带内标记与底层 TCP FIN，即使中间路由过滤 FIN，对端 `FramedReader` 仍能准确感知单向流关闭。
