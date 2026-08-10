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
go test -mod=vendor ./...
go build -mod=vendor -o bin/myxray-server ./cmd/myxray-server
GOOS=windows GOARCH=amd64 go build -mod=vendor -o bin/myxray-client.exe ./cmd/myxray-client
GOOS=linux GOARCH=arm64 go build -mod=vendor -o bin/myxray-v2-client ./cmd/myxray-v2-client
```

V1 uses a vendored HTTP/2 transport with a fixed 16 MiB receive window. V2 uses quic-go with a 2,048-entry Datagram receive queue and a 2,048-packet private replay window. The deployed high-throughput profile uses a 1,452-byte QUIC initial packet size and a 1,350-byte private UDP payload cap for the measured IPv4/1500-byte path. On a smaller-MTU path, start both V2 endpoints with `-quic-initial-packet-size 1280`; oversized UDP datagrams are dropped without terminating the association. When updating dependencies, run `scripts/prepare-vendor.sh`; a plain `go mod vendor` removes the tested queue, HTTP/2 window, and QUIC datagram-copy patches.

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
