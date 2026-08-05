# MyXray protocol prototype

This repository contains the first deployable prototype of the protocol described in `PLAN.md`.

## Current scope

- Real TLS 1.3 with HTTP/2 transport.
- One HTTP/2 stream per proxied TCP connection.
- HMAC authentication with timestamp and replay cache.
- SOCKS5 client with a prewarmed HTTP/2 connection.
- Normal HTTPS fallback for unauthenticated requests.
- Public-target validation to prevent access to loopback and private networks.

This is not the final wire protocol. V2 one-time prekeys, HTTP/3, QUIC DATAGRAM, traffic-shape rotation and native UDP are not implemented yet.

## Build

```sh
go test ./...
go build -o bin/myxray-server ./cmd/myxray-server
GOOS=windows GOARCH=amd64 go build -o bin/myxray-client.exe ./cmd/myxray-client
```

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
