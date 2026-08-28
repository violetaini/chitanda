# MyXray 底层传输协议模式详解 (Transport Modes)

经过深度的物理链路重构与协议解耦，MyXray `pkg/client` 和 `pkg/server` 目前原生支持三种不同的底层代理传输模式。无论是接入 `Mihomo (Clash.Meta)` 还是 `Xray-core`，用户只需通过 `TCPTransport` 参数即可一键切换以下工作模式。

---

## 1. 纯 HTTP/2 模式 (`h2`) —— 千兆测速狂魔

这是追求极致吞吐量（Max Throughput）的专用模式。

* **配置标识**: `-tcp-transport h2` (对应 SDK 参数 `client.TCPTransportH2`)
* **底层承载**: 物理 TCP + TLS 1.3
* **TCP 代理机制**: 原生 TCP over HTTP/2 Stream。
* **UDP 代理机制**: UDP over HTTP/2 (实质为 UDP over TCP)。
* **技术亮点**:
  * **完全零拷贝透传**：客户端服务端剥离了所有的私有双重 Frame 切片，直接使用 1MB 大小（放大 64 倍）的 `io.CopyBuffer` 强行拉通流数据。
  * **满额压榨物理极限**：依赖 Linux 内核级的 TCP/TSO/GRO 硬件卸载，无需占用额外用户态 CPU 时间去处理网络重传，在我们的 2.0GHz ARM 单核压测中，跑满了 **1 Gbps** 物理服务器上限。
* **适用场景**:
  * 专线、内网穿透、IPTV、或者是**网络极好无丢包**的纯下载型代理节点。
* **致命短板**:
  * 由于 UDP 被强制套在 TCP 内部，遇到网络丢包时会产生**严重的 TCP 队头阻塞 (TCP Meltdown)**，打游戏和语音通话延迟会飙升。

---

## 2. 纯 HTTP/3 模式 (`h3`) —— 弱网与抗封锁战神

这是专为跨国网络、严重丢包、高墙阻断设计的抗干扰模式。

* **配置标识**: `-tcp-transport h3` (对应 SDK 参数 `client.TCPTransportH3`)
* **底层承载**: 物理 UDP + QUIC (纯用户态协议栈)
* **TCP 代理机制**: TCP over QUIC Stream。
* **UDP 代理机制**: **真原生** UDP over QUIC Datagrams (遵循 RFC 9221)。
* **技术亮点**:
  * **真·UDP 透传**：Datagrams 直接越过流控逻辑，丢包不重传、无序送达。完美保留了 UDP 数据报的物理特性，**彻底告别队头阻塞**。
  * **极强的丢包自愈力**：即使在物理链路发生 15%~20% 丢包时，QUIC 强大的重传和前向纠错机制依然能保证上层协议无感平滑。
  * **GSO 超级分片**：底层引入了 20 倍 MTU 的批量收发（GSO Batching），大幅消减了系统调用（Syscall）。
* **适用场景**:
  * 电竞游戏代理、WebRTC 实时音视频、晚高峰跨国弱网、针对 TCP 进行 QoS 甚至阻断的严苛网络环境。
* **性能上限**:
  * `quic-go` 运行在 Go 用户态，单 UDP 包需要独立进行 AES-GCM 加密校验，极其消耗 CPU（ARM 单核跑分约为 **500 Mbps**）。

---

## 3. 智能混合模式 (`auto`) —— 完美的究极融合形态（推荐）

这是当今代理架构中最完美的最终解，兼得鱼与熊掌，**也是未来推荐的默认模式**。

* **配置标识**: `-tcp-transport auto` (对应 SDK 参数 `client.TCPTransportAuto`)
* **底层承载**: 客户端在后台**同时维持** HTTP/2(TCP) 和 HTTP/3(UDP) 两套物理连接池，并共享同一套 0-RTT Session Cache。
* **工作机制 (智能分流 + 健康降级)**:
  1. **智能协议分发**：
     * **应用 TCP 请求** ➔ 默认扔进 `HTTP/2` 连接池，跑 1 Gbps 的千兆极速（如下载 4K 视频）。
     * **应用 UDP 请求** ➔ 强行分配给 `HTTP/3 Datagrams` 连接池，享受零阻塞电竞级延迟（如语音和游戏）。
  2. **无特征主动探针 (Health Prober)**：
     * 客户端每 3 秒使用 HTTP/2 发起一次静默的 `GET /` 请求，完美伪装成正常的网站访问。
  3. **无缝断网自愈 (Fallback)**：
     * 当探针发现 TCP(H2) 连接超时或延迟飙升 >500ms（如遭遇 GFW 阻断 TCP 或晚高峰极度拥堵）时，**客户端会自动将所有新的 TCP 请求静默降级到 HTTP/3 池发往远端**，直至 TCP 物理链路恢复健康并稳定至少 30 秒。
* **适用场景**:
  * 满足 99.9% 用户的日常挂机场景，是下一代 Mihomo / Xray 内核集成最核心的路由底座。
