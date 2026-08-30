# MyXray 私有传输协议

MyXray 是一个面向自有节点部署的 Go 代理传输协议原型。项目同时提供服务端、可嵌入的核心客户端 SDK 和直连压测工具，当前主线支持 `h2`、`h3`、`auto` 三种 TCP 路由模式。

这里的“三种模式”特指 `TCPTransport` 的三个取值。UDP 当前不跟随该选项，统一通过 HTTP/3 Extended CONNECT 和 QUIC Datagram 传输。

## 1. 项目组成

```text
                  业务上层 / 代理内核 / 压测工具
                               |
                        pkg/client SDK
                  +------------+------------+
                  |                         |
          TCP: h2 / h3 / auto       UDP: 固定使用 H3
                  |                         |
                  +------------+------------+
                               |
                      cmd/myxray-server
                 TCP/H2 + UDP/H3 同一端口号
```

| 组件 | 用途 | 当前状态 |
| --- | --- | --- |
| `cmd/myxray-server` | TLS/H2 与 QUIC/H3 服务端 | 当前主线 |
| `pkg/client` | 提供 `DialContext` 和 `ListenPacket` | 当前主线 |
| `cmd/bench-direct` | 绕过 SOCKS5，直接测试 SDK 数据路径 | 当前主线 |
| `cmd/myxray-v2-client` | 本地 SOCKS5 TCP/UDP 客户端 | TCP 路径仍保留旧帧协议，需与当前服务端重新同步 |
| `cmd/myxray-client` | 早期 H2-only SOCKS5 客户端 | 历史实现 |

当前协议行为应以 `pkg/client` 与 `cmd/myxray-server` 为准。在独立客户端完成协议同步前，不应把它与当前服务端的 TCP 互操作性视为已验证能力。

## 2. 三种 TCP 模式

| 模式 | TCP 承载 | UDP 承载 | 主要行为 | 适用方向 |
| --- | --- | --- | --- | --- |
| `h2` | TLS 1.3 + HTTP/2 | H3 QUIC Datagram | TCP 固定走 H2，不自动切换 | TCP 网络稳定、优先吞吐与较低 CPU 开销 |
| `h3` | TLS 1.3 + QUIC Stream + HTTP/3 | H3 QUIC Datagram | TCP 和 UDP 都使用 H3，但使用不同 QUIC 物理连接 | TCP 受限或希望统一使用 UDP/QUIC 承载 |
| `auto` | H2 优先，失败或降级时使用 H3 | H3 QUIC Datagram | 新建 TCP 连接按健康状态在 H2/H3 间选择 | 网络条件变化、需要新连接级回退 |

默认模式是 `h2`。`auto` 模式不会迁移已经建立的 TCP 流，只影响后续新建连接。完整切换规则见 [TRANSPORT_MODES.md](TRANSPORT_MODES.md)。

## 3. 协议数据路径

### TCP over H2

- 客户端连接指定服务器地址，并使用 `ServerName` 完成 SNI 与证书校验。
- 私有会话使用 HTTP/2 `POST` 请求建立。
- 鉴权完成后，请求体和响应体直接承载 TCP 字节流，不再叠加项目自定义 TCP 数据帧。
- SDK 默认创建 4 个 H2 transport，最多允许 16 个，并优先选择活跃流最少的 transport。

### TCP over H3

- TCP 字节流承载于 HTTP/3 request stream。
- 配置持久 TLS session cache 后，可在已有会话票据的后续连接上尝试 QUIC 0-RTT。
- H3/TCP 与 H3/UDP 使用不同的 QUIC 物理连接，避免 UDP 流量直接共享 TCP 代理流的拥塞状态。

### UDP over H3

- 使用 HTTP/3 Extended CONNECT 建立 UDP association。
- 使用 HTTP Datagram（RFC 9297）封装代理数据，并通过 QUIC DATAGRAM（RFC 9221）发送；不保证送达、顺序或重传。
- 私有数据报包含版本、64 位序号、目标地址和载荷；每个方向使用 2048 项窗口过滤重复或过旧的数据报。
- 当前私有 UDP 载荷上限为 1350 字节。未知或较小 MTU 链路应使用更保守的 QUIC initial packet size。

服务端必须显式配置 `-quic-listen` 和 `-ticket-key-file` 才会启用 H3。TCP 与 UDP 可以使用相同端口号，但分别监听 TCP socket 与 UDP socket。

## 4. 鉴权与边界

- 私有请求使用 HMAC-SHA256 签名，签名输入包含 HTTP method、私有路径、目标地址、时间戳和随机 nonce。
- 服务端允许的时钟偏差为正负 90 秒，并将已接受 nonce 持久化；持久层发生错误时拒绝继续接受新 nonce。
- 未通过私有路径、方法或鉴权检查的请求会转发到配置的真实 HTTPS 站点，私有请求头会在 fallback 前移除。
- 服务端只允许访问公网单播目标，拒绝私网、回环、链路本地及已知特殊用途地址。
- PSK 用于请求鉴权，不是额外的载荷加密层；数据机密性来自 TLS 或 QUIC/TLS。

Fallback 能降低未授权探测与正常站点之间的响应差异，但不等于协议不可识别。TLS/H2 设置、QUIC 行为、流量时序及主动端点交互仍然可以形成可观察特征。

## 5. Go SDK

```go
import "myxray/pkg/client"

cli, err := client.New(client.Config{
    Server:           "server.example.com:443",
    ServerName:       "server.example.com",
    PSK:              pskBytes, // 至少 32 字节
    Path:             "/your-private-path",
    TCPTransport:     client.TCPTransportAuto,
    TCPPoolSize:      4,
    SessionCacheFile: "/var/lib/myxray/sessions.json",
})
if err != nil {
    log.Fatal(err)
}
defer cli.Close()

tcpConn, err := cli.DialContext(ctx, "tcp", "example.org:443")

udpConn, err := cli.ListenPacket(ctx)
if err == nil {
    _, err = udpConn.WriteTo(payload, targetUDPAddr)
}
```

SDK 提供了便于上游适配的 `net.Conn` 与 `net.PacketConn` 类型接口，但仓库当前还没有 Xray-core、Mihomo 或 sing-box 的正式 outbound adapter。当前 module path 也是仓库内部名称 `myxray`，对外部模块发布前需要调整。现有包装器的 deadline 语义也尚未完整实现，因此“可以编写适配器”不应表述为“已经无缝集成”。

## 6. 构建与验证

项目声明使用 Go 1.26 工具链，并依赖仓库内经过性能修改的 `vendor`：

```sh
go test -mod=vendor ./...
go test -mod=vendor github.com/quic-go/quic-go github.com/quic-go/quic-go/http3

CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -mod=vendor -o bin/myxray-server-arm64 ./cmd/myxray-server
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -mod=vendor -o bin/myxray-v2-client-arm64 ./cmd/myxray-v2-client
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -mod=vendor -o bin/bench-direct-arm64 ./cmd/bench-direct
```

当前 `main` 的三个 Linux/ARM64 目标可以构建，vendored quic-go 与 HTTP/3 测试可以通过；全量项目测试仍有两处已删除符号的陈旧测试引用需要修复。发布前应以 `scripts/verify-release.sh` 全部通过为准。

## 7. 已知限制

- 尚无正式的 Xray-core、Mihomo、sing-box outbound adapter。
- 尚无 UDP-over-H2；使用 UDP 必须保证服务端 UDP/H3 端口可达。
- `auto` 只对新建 TCP 连接执行选择，不能无损迁移已有连接。
- H2 建连阶段当前没有完整继承 `DialContext` 的调用方 context，取消和超时语义需要修正。
- 从未连接过的首次 0-RTT、0-RTT UDP、一次性预密钥和多节点强一致防重放尚未实现。
- NAT rebinding、连接迁移、FEC 和不同审查环境下的分类结果尚缺少系统验证。
- 性能数据只代表特定硬件、RTT、MTU、丢包和宿主机负载条件，不能视为普遍吞吐保证。

部署记录和历史测量见 [DEPLOYMENT.md](DEPLOYMENT.md) 与 [TEST_REPORT.md](TEST_REPORT.md)。
