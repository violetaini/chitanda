# MyXray 三种传输模式

MyXray 当前通过 `TCPTransport` 提供 `h2`、`h3`、`auto` 三种 TCP 路由模式。该配置只决定 TCP 代理连接使用哪一种 carrier；UDP 在三种模式下都固定使用 HTTP/3 Extended CONNECT 和 QUIC Datagram。

本文以 `pkg/client` 的当前实现为准。命令行使用 `-tcp-transport`，SDK 使用 `client.Config.TCPTransport`。

## 1. 行为总表

| 配置值 | TCP 新连接 | UDP association | 自动切换 | 默认值 |
| --- | --- | --- | --- | --- |
| `h2` | TLS 1.3 / HTTP/2 | H3 / QUIC Datagram | 否 | 是 |
| `h3` | TLS 1.3 / QUIC Stream / HTTP/3 | H3 / QUIC Datagram | 否 | 否 |
| `auto` | H2 优先，按状态回退 H3 | H3 / QUIC Datagram | 仅针对新建 TCP 连接 | 否 |

无论选择哪种模式，UDP 都要求客户端到服务端的 UDP/H3 端口可达。当前没有 UDP-over-H2 fallback。

## 2. `h2`：固定 HTTP/2 TCP carrier

配置方式：

```go
TCPTransport: client.TCPTransportH2
```

```text
TCP application
      |
raw byte stream in HTTP request/response body
      |
HTTP/2 + TLS 1.3 + TCP
```

当前行为：

- TCP 会话使用 HTTP/2 `POST` 请求建立，鉴权后直接传输原始 TCP 字节流。
- SDK 默认创建 4 个 H2 transport，`TCPPoolSize` 最大限制为 16。
- 新连接选择当前活跃流数量最少的 transport。
- `Prewarm` 会并发发起普通 `HEAD /` 请求，使 TLS/H2 连接提前建立；这不是 TLS 0-RTT。
- H2 内部最多尝试两次；仍然失败时向调用方返回错误，不自动改走 H3。
- UDP 仍由独立的 H3 manager 建立 QUIC Datagram association。

适用条件：

- TCP/H2 路径稳定且未被明显限速或阻断。
- 更重视成熟内核 TCP 栈、硬件卸载能力和较低的用户态 QUIC CPU 开销。

需要验证的风险：

- 物理 TCP 丢包会影响同一 H2 carrier 上的多个流。
- 多 carrier 能分散流量，但会增加连接数、TLS 握手和服务端状态。
- 选择 `h2` 不会为 UDP 提供 TCP fallback。

## 3. `h3`：固定 HTTP/3 TCP carrier

配置方式：

```go
TCPTransport: client.TCPTransportH3
```

```text
TCP application                 UDP application
      |                               |
HTTP/3 request stream          HTTP/3 Extended CONNECT
      |                               |
QUIC connection A              QUIC connection B + Datagram
```

当前行为：

- TCP 字节流直接承载于 HTTP/3 request stream，不叠加项目自定义 TCP 数据帧。
- TCP 与 UDP 使用不同的 QUIC 物理连接，避免两类流量直接共享同一个拥塞窗口。
- TLS session cache 可选；只有已经取得并持久化有效会话票据后，后续 H3 连接才可能使用 0-RTT。
- UDP 使用 HTTP Datagram（RFC 9297）承载于 QUIC DATAGRAM（RFC 9221），不提供可靠性、顺序保证或重传。
- H3 内部最多尝试两次；仍然失败时向调用方返回错误，不回退 H2。

适用条件：

- TCP 路径受到限制，而 UDP/QUIC 路径可用。
- 可以接受 quic-go 用户态协议栈带来的额外 CPU 和每包处理成本。

需要验证的风险：

- UDP 被网络完全阻断时，TCP 和 UDP 代理能力都会失败。
- QUIC 的实际吞吐受 CPU、RTT、丢包、MTU、GSO 支持和宿主机调度影响，不能用固定数值概括。
- 0-RTT 不是首次连接能力，也不代表多节点环境已经具备强一致防重放。

## 4. `auto`：H2 优先、H3 回退

配置方式：

```go
TCPTransport: client.TCPTransportAuto
```

`auto` 的决策单位是“新建 TCP 连接”，不是单个数据包，也不是已经建立的 TCP 流。

### 建连路径

1. H2 未被标记为降级时，从 H2 pool 选择活跃流最少的 transport。
2. 如果该次 H2 建连成功，返回 H2 `net.Conn`。
3. 如果 H2 的内部重试仍然失败，在任何应用数据交付前尝试 H3。
4. H2 已被标记为降级时，新建 TCP 连接直接使用 H3。
5. 已建立连接不会在 H2 与 H3 之间迁移；连接中途失败仍由上层处理。

### 后台健康探测

- 探测周期为 3 秒。
- 探测请求复用 H2 transport，访问普通 `GET /` 并读取完整响应体。
- 单次错误或响应耗时超过 500 ms 计为失败。
- HTTP 状态码本身不参与健康判断。
- 连续 2 次失败后将 H2 标记为降级。
- 连续 10 次成功后恢复 H2。

探测访问的是 fallback 根页面，因此结果同时包含 H2 链路、TLS 连接和 fallback origin 的处理时间。fallback 站点变慢也可能触发 H3 回退；它不是只测网络层 RTT 的纯探针。

### UDP 行为

`auto` 不对 UDP 做协议选择。`ListenPacket` 始终建立 H3/QUIC Datagram association，也不会在 UDP/H3 不可用时改走 H2。

## 5. 选择建议

| 网络条件 | 建议起点 | 必须验证 |
| --- | --- | --- |
| TCP 与 UDP 都稳定，TCP 吞吐优先 | `h2` | H2 多流丢包影响、UDP/H3 可达性 |
| TCP 明显受限，UDP/QUIC 稳定 | `h3` | CPU、MTU、UDP QoS 和 QUIC 封锁 |
| TCP 状态会变化且 UDP/H3 可作为备用 | `auto` | 探测阈值、fallback origin 延迟和切换频率 |

项目默认值仍是 `h2`。是否使用 `auto` 应由部署链路的可重复测试决定，而不是把它直接视为所有环境的生产默认值。

SDK 的 `auto` 没有固定 4 秒内完成回退的保证；代码中的 `autoH2ConnectTimeout` 当前未参与 SDK 路由。H2 建连阶段对调用方 context 的继承也不完整，这两项应在依赖严格超时语义前修复。

## 6. 可证伪的模式验证

建议至少进行以下测试：

1. `h2`：阻断客户端到服务端的 TCP 端口，确认 TCP 建连失败而不是隐式切换 H3。
2. `h3`：阻断 UDP 端口，确认 TCP/H3 与 UDP association 均失败。
3. `auto`：保持 UDP 可用、阻断 TCP，确认新 TCP 连接回退 H3；恢复 TCP 后观察连续健康探测带来的回切。
4. 所有模式：分别验证 TCP 双向 EOF/半关闭、超时、服务端重启和连接取消行为。
5. UDP：在不同 MTU、RTT、随机丢包和突发速率下分别记录 delivered rate、loss、jitter、CPU 与队列丢弃。

性能和弱网结论应附带测试节点、CPU、内核、RTT、MTU、负载模型与统计区间。单次峰值不能证明某种模式在其他网络中更优。

## 7. 不随模式变化的协议属性

- 私有请求使用 HMAC-SHA256、时间戳和随机 nonce 鉴权。
- 服务端使用持久 replay cache，持久化失败时拒绝继续授权。
- 未授权请求进入真实 HTTPS fallback，私有请求头在转发前被移除。
- 目标地址经过公网单播过滤。
- 三种模式都不提供“不可检测”保证。
