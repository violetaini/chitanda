# MyXray Protocol Prototype & Core SDK

MyXray is a high-performance, censorship-resistant proxy protocol designed following the **Hysteria 2 product model**:
- **Self-contained Server & Client Binaries**: `cmd/myxray-server`, `cmd/myxray-v2-client`, and `cmd/bench-direct`.
- **Pure Go Core SDK (`pkg/client`)**: Clean `DialContext(ctx, "tcp", target)` and `ListenPacket(ctx)` interfaces ready for seamless upstream integration into **Xray-core**, **Mihomo (Clash.Meta)**, and **Sing-box** without SOCKS5 coupling.

---

## 1. Product & Architecture Overview

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                           MyXray Architecture                           │
├───────────────────────────────┬─────────────────────────────────────────┤
│    1. Standalone Binaries     │         2. Core Integration SDK         │
├───────────────────────────────┼─────────────────────────────────────────┤
│  • cmd/myxray-server          │  • pkg/client                           │
│  • cmd/myxray-v2-client       │    - DialContext (TCP over TLS/H2)      │
│  • cmd/bench-direct           │    - ListenPacket (UDP over H3/Datagram)│
└───────────────────────────────┴─────────────────────────────────────────┘
```

- **TCP Transport**: Production-grade TLS 1.3 / HTTP/2 full-duplex framing with 0-RTT pre-warmed connection pool and TCP half-close support (measured **882 Mbps** throughput).
- **UDP Transport**: Native RFC 9221 QUIC Datagrams over HTTP/3 with independent physical connection isolation, expanded 512-packet send queue, and loss-tolerant congestion floor (measured **157.19 Mbps** steady-state round-trip throughput).
- **Authentication**: HMAC-SHA256 authenticated header signatures with nonce tracking and persistent replay cache.
- **Fallback**: Unauthenticated requests are silently proxied to real websites.

---

## 2. Using the Go Core SDK (`pkg/client`)

To integrate MyXray into Xray-core (`proxy/myxray`) or Mihomo (`adapter/outbound`):

```go
import "myxray/pkg/client"

// 1. Initialize Client
cli, err := client.New(client.Config{
    Server:           "170.9.59.149:11322",
    ServerName:       "status.chitanda.org",
    PSK:              pskBytes, // 32+ bytes
    Path:             "/your-private-path",
    TCPTransport:     client.TCPTransportH2, // "h2" (default), "auto", or "h3"
})
if err != nil {
    log.Fatal(err)
}
defer cli.Close()

// 2. Dial TCP (returns standard net.Conn)
conn, err := cli.DialContext(ctx, "tcp", "1.1.1.1:443")

// 3. Listen UDP (returns standard net.PacketConn)
pconn, err := cli.ListenPacket(ctx)
_, err = pconn.WriteTo(payload, targetUDPAddr)
```

---

## 3. Direct Native Core Benchmark (`cmd/bench-direct`)

Direct benchmarking tool without any SOCKS5 overhead:

```bash
# 1. Start Echo / Sink Server on remote node
bench-direct -mode echo-server -listen 0.0.0.0:18088

# 2. Run Direct TCP Benchmark from client
bench-direct -mode tcp -server 170.9.59.149:11322 -server-name status.chitanda.org \
  -psk-file secrets/psk -path-file secrets/path -target 170.9.59.149:18088 -duration 10s -concurrency 4

# 3. Run Direct UDP Native Datagram Benchmark from client
bench-direct -mode udp -server 170.9.59.149:11322 -server-name status.chitanda.org \
  -psk-file secrets/psk -path-file secrets/path -target 170.9.59.149:18088 -udp-rate 250 -duration 10s
```

---

## 4. Build & Test

```sh
# Run tests
go test -mod=vendor ./...
go test -mod=vendor github.com/quic-go/quic-go github.com/quic-go/quic-go/http3

# Cross-compile for Linux/ARM64 deployment
GOOS=linux GOARCH=arm64 go build -mod=vendor -o bin/myxray-server-arm64 ./cmd/myxray-server
GOOS=linux GOARCH=arm64 go build -mod=vendor -o bin/myxray-v2-client-arm64 ./cmd/myxray-v2-client
GOOS=linux GOARCH=arm64 go build -mod=vendor -o bin/bench-direct-arm64 ./cmd/bench-direct
```

For live deployment status and detailed performance benchmarks, see `DEPLOYMENT.md` and `TEST_REPORT.md`.
