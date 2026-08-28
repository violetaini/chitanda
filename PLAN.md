# 私有协议设计与实施计划 (MyXray)

## 1. 产品定位与产品模式 (对标 Hysteria 2)

目标是面向私有部署的高性能、抗审查代理协议，重点对抗 GFW 的首包分类、主动探测、重放探测与弱网劣化。

在产品形态与架构设计上，全面贯彻类似 **Hysteria 2** 的产品模式：

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                           MyXray 产品体系                               │
├───────────────────────────────┬─────────────────────────────────────────┤
│    1. 自身独立可执行文件      │          2. 上游内核集成 SDK            │
│  (Standalone Client & Server) │       (Core Outbound / Transport)       │
├───────────────────────────────┼─────────────────────────────────────────┤
│  • cmd/myxray-server (服务端) │  • pkg/client (Go SDK 统一接口)         │
│  • cmd/myxray-v2-client(客户端)│    - DialContext: 对接 TCP 流量         │
│  • cmd/bench-direct  (直测端) │    - ListenPacket: 对接 UDP 流量        │
│                               │  • 无缝接入 Xray-core / Mihomo / Sing-box│
└───────────────────────────────┴─────────────────────────────────────────┘
```

设计原则：

- **核心纯净化（SDK 化）**：协议传输引擎不内置、不绑定任何本地应用代理层（如 SOCKS5、HTTP 代理），只对外提供标准 Go 网络接口 `DialContext(ctx, "tcp", target)` 与 `ListenPacket(ctx)`。
- **上游内核无缝对接**：
  - **Xray-core**：直接实现 `proxy/myxray` 出站适配器（实现 `proxy.Outbound` 与 `core.OutboundHandler`）。
  - **Mihomo (Clash.Meta)**：直接实现 `adapter/outbound` 中的 `constant.ProxyAdapter`（`DialContext` / `ListenPacketContext`）。
  - **Sing-box**：直接实现 `adapter.Outbound` 适配器。
- **外层标准伪装**：TLS 1.3 / HTTP/2 作为默认 TCP 载体，HTTP/3 / QUIC Datagram 作为原生 UDP 载体，未授权请求静默 Fallback 到真实站点。
- **原生 UDP 抗丢包优化**：借鉴 TUIC / 速率自适应设计，针对不可重传 Datagram 扩容发送队列（512 深度）并设定抗雪崩拥塞退让下限，保障弱网随机丢包下的高速吞吐。
- **严格工程规范**：每次关键变动即时同步项目文档并推送到 GitHub 远端。

---

## 2. 总体架构

```text
               [ 业务上层 / Xray / Mihomo / Standalone CLI ]
                                    │
                         【pkg/client 统一 SDK】
                     ┌──────────────┴──────────────┐
                     ▼                             ▼
           [ TCP: TLS 1.3 / H2 ]         [ UDP: HTTP/3 / QUIC ]
            - 热连接池 / 多路复用          - 独立 QUIC 物理连接
            - 私有帧 / 半关闭 / 0-RTT      - RFC 9221 原生 Datagram
            - 单流达 830+ Mbps            - 队列扩容 / 拥塞抗丢包调优
                     └──────────────┬──────────────┘
                                    ▼
                         [ 公网 TLS 1.3 / QUIC ]
                                    │
                                    ▼
                         【cmd/myxray-server】
            - 统一端口 (TCP/UDP :11322) 监听
            - HMAC-SHA256 签名鉴权 + 防重放拦截
            - 未授权流量 Fallback 到正常 Web API
```

---

## 3. 核心传输机制

### 3.1 TCP 传输 (TLS 1.3 / HTTP/2)
- 默认采用 HTTP/2 全双工长连接，通过 `X-Session-Mode: tcp-h2-framed` 建立私有会话。
- 私有逻辑帧支持 `OPEN`、`DATA`、`HALF_CLOSE`、`RESET`。
- 服务端以数据帧流式返回，客户端透明解码，完整支持 TCP 半关闭与标准 Go `net.Conn` 行为。
- 实测单连接吞吐量突破 **830 Mbps**，4 并发流达到 **882 Mbps**。

### 3.2 UDP 传输 (HTTP/3 / QUIC Datagram)
- TCP 与 UDP 在传输层**完全隔离**（独立的 QUIC 物理连接），彻底避免 UDP 弱网丢包污染 TCP 的拥塞控制窗口。
- 采用 RFC 9221 QUIC Datagram 进行不可重传的原生数据报转发。
- **抗丢包与高吞吐关键优化**：
  1. `maxDatagramSendQueueLen` 从 32 扩容至 512，避免应用层在突发发包时产生毫秒级拥塞阻塞；
  2. 调整 CUBIC 拥塞窗口下限（`minCongestionWindowPackets = 32`, `initialCongestionWindow = 64`），防止弱网随机 1-3% 丢包导致窗口坍缩至 2 MSS；
  3. 服务端/客户端支持 `recvmmsg` / `sendmmsg` 批量收发。
- 实测 UDP 稳态吞吐突破 **157.19 Mbps**（10 秒持续打流 15.7 万包），突发峰值 **175.10 Mbps**。

---

## 4. 纯协议基准测试套件 (`cmd/bench-direct`)

为了彻底杜绝本地 SOCKS5 握手、TCP 控制流解析及回环开销对性能测量的干扰，项目内置了专用的纯协议压测工具：

```bash
# 启动远端测试 Sink / Echo 端
bench-direct -mode echo-server -listen 0.0.0.0:18088

# 客户端直连 SDK 压测 TCP
bench-direct -mode tcp -server 170.9.59.149:11322 -server-name status.chitanda.org \
  -psk-file secrets/psk -path-file secrets/path -target 170.9.59.149:18088 -duration 10s -concurrency 4

# 客户端直连 SDK 压测原生 UDP
bench-direct -mode udp -server 170.9.59.149:11322 -server-name status.chitanda.org \
  -psk-file secrets/psk -path-file secrets/path -target 170.9.59.149:18088 -udp-rate 250 -duration 10s
```

---

## 5. 后续演进路线

1. **内核 Outbound 插件封装**：
   - 编写 `xray-core` 集成模块 `proxy/myxray`；
   - 编写 `mihomo` (Clash.Meta) 集成适配器 `adapter/outbound/myxray.go`。
2. **多径与自适应传输 (BBR / 混合拥塞控制)**：
   - 进一步探索在特定丢包率下的自适应速率控制算法（对标 Hysteria 2 Brutal / TUIC 拥塞策略）。
