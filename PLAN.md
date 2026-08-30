# MyXray 设计状态与演进计划

本文区分当前已经存在的实现、仍需验证的工程假设和后续路线。协议总览见 [README.md](README.md)，三种 TCP 路由模式的精确定义见 [TRANSPORT_MODES.md](TRANSPORT_MODES.md)。

## 1. 产品定位

MyXray 面向自有服务器与自有客户端部署，目标是在统一服务端上提供：

- TLS/HTTP/2 承载的 TCP 代理路径；
- QUIC/HTTP/3 承载的 TCP 代理路径；
- HTTP/3 Extended CONNECT 与 QUIC Datagram 承载的 UDP 代理路径；
- 不绑定 SOCKS5 的 Go 客户端 SDK；
- 未授权请求到真实 HTTPS 站点的 fallback。

“抗审查”是需要在明确威胁模型下测试的目标，不是当前实现可以保证的属性。项目不声称不可检测，也不把特定节点上的吞吐测量外推为普遍性能承诺。

## 2. 当前主线架构

```text
          [上层调用方 / bench-direct / 后续 outbound adapter]
                               |
                        [pkg/client SDK]
                               |
             +-----------------+-----------------+
             |                                   |
     TCPTransport: h2/h3/auto           UDP: 始终使用 H3
             |                                   |
     H2 request body 或 H3 stream       Extended CONNECT + Datagram
             +-----------------+-----------------+
                               |
                    [cmd/myxray-server]
                TCP/H2 + UDP/H3 同一端口号
```

当前协议权威实现是 `pkg/client` 与 `cmd/myxray-server`。`cmd/myxray-v2-client` 仍复制了一套旧 TCP 帧实现，与当前 raw-stream 服务端尚未重新同步，不能作为三种模式已经端到端通过的证据。

## 3. 当前三种 TCP 模式

| 模式 | TCP 行为 | UDP 行为 |
| --- | --- | --- |
| `h2` | 固定 TLS/H2 | 固定 H3 Datagram |
| `h3` | 固定 QUIC/H3 stream | 固定 H3 Datagram，且与 H3/TCP 使用独立 QUIC 连接 |
| `auto` | H2 优先，建连失败或健康状态降级时为新连接选择 H3 | 固定 H3 Datagram |

`TCPTransport` 不控制 UDP。目前没有 UDP-over-H2，也没有在 H2 与 H3 之间迁移已经建立的 TCP 流。

## 4. 已实现机制

### 4.1 TCP

- H2 使用 `POST` 私有路径，请求体与响应体直接映射 TCP 字节流。
- H3 使用 HTTP/3 request stream 直接映射 TCP 字节流。
- H2 SDK 支持多 transport pool，并按活跃流数量选择 carrier。
- H3 SDK 支持多 QUIC connection pool，并在拨号阶段预占活跃流计数，避免并发请求集中到第一个 carrier。
- `auto` 支持单次 H2 建连失败后的 H3 尝试，以及后台 H2 健康状态切换。

当前主线已经移除 TCP 数据上的 `OPEN`、`DATA`、`HALF_CLOSE` 等自定义双重帧。相关类型仍用于历史客户端代码和 UDP 数据报之外的遗留测试，后续应清理或重新定义边界。

### 4.2 UDP

- 使用 H3 Extended CONNECT 建立 association。
- 使用 HTTP Datagram（RFC 9297）承载于 QUIC DATAGRAM（RFC 9221），发送不可重传数据报。
- 私有 envelope 包含版本、序号、目标地址与载荷。
- 使用 2048 项序号窗口过滤重复及过旧数据报。
- vendored quic-go 当前发送队列为 512，接收队列为 2048。
- vendored CUBIC 当前最小拥塞窗口为 64 包，初始拥塞窗口为 128 包。

### 4.3 鉴权与 fallback

- HMAC-SHA256 覆盖 method、path、target、timestamp 与 nonce。
- 时间窗口为正负 90 秒。
- 服务端在授权上游副作用前持久化 nonce；持久 replay cache 失败时 fail closed。
- 未授权请求移除私有头后转发到真实 HTTPS fallback。
- 上游目标只允许公网单播地址。

### 4.4 H3 会话恢复

- 客户端可选持久 TLS session cache。
- 服务端允许 QUIC 0-RTT，并使用持久 ticket key。
- 只有已取得有效票据的后续连接才可能使用 0-RTT。
- 从未连接过的首次 0-RTT、0-RTT UDP、一次性预密钥和多节点强一致 nonce 消费尚未实现。

## 5. 当前成熟度

| 能力 | 状态 |
| --- | --- |
| 服务端 H2/H3 监听 | 已实现 |
| `pkg/client` 的 H2/H3/auto 路由 | 已实现，H2/H3 均支持 TCP carrier pool，缺少完整端到端回归 |
| H3 Datagram UDP | 已实现，性能与弱网结论依赖部署条件 |
| 独立 SOCKS5 客户端与当前服务端兼容 | 未完成协议同步 |
| 完整 `net.Conn` deadline/half-close 语义 | 未完成 |
| Xray-core adapter | 未实现 |
| Mihomo adapter | 未实现 |
| sing-box adapter | 未实现 |
| 自动化 CI 发布门禁 | 未实现，当前依赖手工脚本 |

## 6. 后续优先级

### P0：恢复单一协议事实源

1. 让 `cmd/myxray-v2-client` 直接复用 `pkg/client`，或同步移除其旧 TCP 帧协议。
2. 删除或改写引用已删除符号的陈旧测试。
3. 为 `server + SDK` 增加 H2、H3、auto 的端到端测试。
4. 修正 H2 建连使用后台 context 的问题，确保调用方取消与 deadline 能中断建连。
5. 覆盖 TCP 双向 EOF、半关闭、取消、deadline、服务端重启和 application bytes 不重放。
6. 覆盖 UDP association 生命周期、重放窗口、MTU 边界和连接关闭唤醒。

验收标准：三个模式的行为矩阵均由自动测试证明，`scripts/verify-release.sh` 在干净 checkout 上通过。

### P1：补全 SDK 契约与上游适配

1. 明确并实现 `DialContext` 对 `network` 参数的校验。
2. 为 H2/H3 `net.Conn` 和 UDP `net.PacketConn` 实现可观察的 deadline 行为。
3. 修正 H3 `CloseWrite`，区分优雅 FIN 与流中止。
4. 将 module path 调整为可由外部仓库正常引用的路径。
5. 在 SDK 契约稳定后分别实现 Xray-core、Mihomo 和 sing-box adapter。

验收标准：通过各上游的真实接口测试，而不只做 Go 编译期类型断言。

### P2：部署与传输增强

1. 建立 Linux/ARM64 与常用 amd64 平台的 CI 测试、race、vet 和交叉编译。
2. 验证 NAT rebinding 与 QUIC connection migration。
3. 评估 UDP-over-H2 是否值得作为可选 fallback，并量化 TCP 队头阻塞代价。
4. 在明确业务模型后评估 FEC、应用优先级和其他拥塞控制策略。
5. 建立包含 RTT、MTU、随机丢包、突发丢包、CPU steal 和长时间稳定性的基准矩阵。
6. 只有替代 QUIC/H3 底层在同机、同链路、同协议语义的 A/B 中同时改善吞吐与 CPU/GB，才考虑引入 Rust/C FFI 或 sidecar；不得以其他项目的峰值替代本项目验证。

验收标准：所有性能结论都能由版本化脚本复现，并同时报告吞吐、丢包、延迟、CPU、内存和失败率。
