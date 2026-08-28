# MyXray 底层传输协议模式详解 (Transport Modes)

经过对物理链路与协议层的重构，MyXray `pkg/client` 和 `pkg/server` 目前原生支持三种不同的底层传输模式。在接入 `Mihomo (Clash.Meta)` 或 `Xray-core` 框架时，开发者与用户可通过 `TCPTransport` 参数进行指定，以适配不同的网络拓扑与业务需求。

---

## 1. 单一 HTTP/2 模式 (`h2`) —— 高吞吐量导向

此模式以最大化物理层网络吞吐量（Max Throughput）为核心设计目标。

* **配置标识**: `-tcp-transport h2` (对应 SDK 参数 `client.TCPTransportH2`)
* **底层承载**: 物理 TCP + TLS 1.3
* **TCP 代理机制**: 原生 TCP over HTTP/2 Stream。
* **UDP 代理机制**: UDP over HTTP/2 (实质为 UDP over TCP)。
* **技术特征**:
  * **大缓冲区内存池**：移除了传统代理协议中的冗余封装，直接使用 1MB 的 `io.CopyBuffer` 映射流数据。
  * **内核级网络加速**：依赖 Linux 操作系统的 TCP 栈与网卡硬件卸载（TSO/GRO），最小化用户态 CPU 负载。在 2.0GHz ARM 环境压测中，可满载单核达成 1 Gbps 吞吐量。
* **适用场景**:
  * 专线、内网穿透、IPTV 等链路质量极佳、无丢包的场景。
* **架构局限**:
  * 由于 UDP 数据包在此模式下被强制封装于 TCP 报文中，若物理链路发生丢包，将引发严重的 TCP 队头阻塞（TCP Meltdown），从而导致实时流媒体或游戏业务延迟骤增。

---

## 2. 单一 HTTP/3 模式 (`h3`) —— 弱网与高连通性导向

此模式针对跨国链路丢包率高、TCP 协议遭遇 QoS 限制或深度报文检测（DPI）干扰的场景设计。

* **配置标识**: `-tcp-transport h3` (对应 SDK 参数 `client.TCPTransportH3`)
* **底层承载**: 物理 UDP + QUIC (全用户态协议栈)
* **TCP 代理机制**: TCP over QUIC Stream。
* **UDP 代理机制**: UDP over QUIC Datagrams (严格遵循 RFC 9221)。
* **技术特征**:
  * **原生无序传输**：UDP 流量通过 Datagrams 通道直接传输，不保证送达顺序且不触发重传，从物理层面根除队头阻塞问题。
  * **高可用拥塞控制**：利用 QUIC 协议特性，在物理链路发生 10%~20% 丢包时，仍能维持平稳的应用层吞吐。
  * **系统调用优化**：通过开启 GSO (Generic Segmentation Offload) 批量收发，单次 Syscall 最大处理 20 倍 MTU 数据，降低内核交互开销。
* **适用场景**:
  * 实时音视频（WebRTC）、电子竞技，或存在严重 TCP 干扰的劣质网络环境。
* **性能瓶颈**:
  * 由于 `quic-go` 运行于 Go 用户态，需对每个 UDP 分片进行独立的 AES-GCM 加密与 MAC 校验。在缺乏内核旁路支持下，CPU 算力消耗较大（同等环境极限吞吐约为 500 Mbps）。

---

## 3. 智能混合路由模式 (`auto`) —— 生产环境推荐配置

该模式结合了 TCP 的高吞吐优势与 QUIC 的抗丢包特性，为复杂的生产环境提供动态协议适应能力。

* **配置标识**: `-tcp-transport auto` (对应 SDK 参数 `client.TCPTransportAuto`)
* **底层承载**: 客户端在后台并发维持 HTTP/2(TCP) 与 HTTP/3(UDP) 连接池，并共享 0-RTT 状态。
* **核心机制**:
  1. **协议自适应分流**：
     * **TCP 请求** ➔ 默认路由至 `HTTP/2` 连接池，获取最优下载吞吐量。
     * **UDP 请求** ➔ 强制路由至 `HTTP/3 Datagrams` 连接池，确保实时性业务无丢包阻塞。
  2. **主动健康探测 (Active Probing)**：
     * 客户端按 3 秒周期复用现存的 H2 连接池，向远端发起轻量级无验证的 `GET /` 请求，流量特征与正常网页访问完全一致。
  3. **连接灾备与平滑降级 (Graceful Degradation)**：
     * 当探测器监测到 TCP(H2) 连接超时或 RTT 异常波动（>500ms）时，系统判定 TCP 链路受阻。此时，新的 TCP 请求将被自动重定向至 HTTP/3 (QUIC) 备用通道传输。直至 TCP 链路恢复稳定，系统方执行自动回切。
* **适用场景**:
  * 推荐作为默认策略部署。在保证高速率的同时，提供跨层级的网络连通性保障，为 Mihomo 与 Xray 的上层应用提供坚实的路由底座。
