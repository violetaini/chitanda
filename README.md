# MyXray protocol prototype

This repository contains the V1 and V2 deployable prototypes described in `PLAN.md`.

## Current scope

- V1 real TLS 1.3 + HTTP/2 transport and V2 real HTTP/3 + QUIC transport.
- A private V2 frame layer with `OPEN`, `OPEN_ACK`, `DATA`, `HALF_CLOSE`, `RESET`, and `WINDOW_UPDATE` frame types.
- HMAC authentication with timestamp and replay cache.
- Persistent TLS 1.3 session tickets and optimistic first application data over 0-RTT after ticket provisioning.
- SOCKS5 TCP plus native UDP ASSOCIATE over extended CONNECT and HTTP Datagrams.
- Normal HTTPS fallback for unauthenticated requests.
- Public-target validation to prevent access to loopback and private networks.

This is not the final wire protocol. Never-contacted first-ever 0-RTT, one-time prekeys, early-data forward secrecy, UDP-over-H2 fallback, automatic path migration, traffic-shape rotation, and classifier-resistance validation are not implemented yet.

## Build

```sh
./scripts/verify-release.sh

# Individual commands used by the gate:
go test -mod=vendor ./...
go test -mod=vendor github.com/quic-go/quic-go github.com/quic-go/quic-go/http3
go build -mod=vendor -o bin/myxray-server ./cmd/myxray-server
GOOS=windows GOARCH=amd64 go build -mod=vendor -o bin/myxray-client.exe ./cmd/myxray-client
GOOS=linux GOARCH=arm64 go build -mod=vendor -o bin/myxray-v2-client ./cmd/myxray-v2-client
```

`verify-release.sh` is the release gate: it checks the vendor patch and test templates, formatting, all project tests, the explicit vendored QUIC suites, `go vet`, targeted race tests, and static Linux/ARM64 server and V2 client builds.

V1 uses a vendored HTTP/2 transport with a fixed 16 MiB receive window. V2 uses quic-go with a 2,048-entry QUIC Datagram receive queue, a 256-entry per-HTTP-stream Datagram queue, and a 2,048-packet private replay window. TCP and UDP use separate physical QUIC connections so UDP loss cannot directly reduce the TCP congestion window. The deployed high-throughput profile uses a 1,452-byte QUIC initial packet size and a 1,350-byte private UDP payload cap for the measured IPv4/1500-byte path. On a smaller-MTU path, start both V2 endpoints with `-quic-initial-packet-size 1280`; oversized UDP datagrams are dropped without terminating the association. When updating dependencies, run `scripts/prepare-vendor.sh`; a plain `go mod vendor` removes the tested performance and Datagram-copy patches.

For an isolated QUIC diagnosis, set `QLOGDIR` on both V2 processes before starting them. Both client and server then write per-connection `.sqlog` traces with congestion-window, RTT, loss, and packet events. Qlog output is intentionally verbose and should be disabled for formal throughput measurements and normal service operation.

## Client

```powershell
.\myxray-client.exe `
  -listen 127.0.0.1:2080 `
  -server 23.145.248.44:11322 `
  -server-name probe.chitanda.org `
  -psk-file .\secrets\psk `
  -path-file .\secrets\path
```

The SOCKS5 listener intentionally binds to loopback only. With Clash Verge TUN enabled, add a DIRECT rule for the server IP and domain before measuring latency or censorship behavior.

For the active endpoint, local start/stop commands and verified deployment state, see `DEPLOYMENT.md`.
