# Deployment status

## Active endpoint

- Server: `23.145.248.44:11322`
- TLS name: `probe.chitanda.org`
- Local SOCKS5: `127.0.0.1:2080`
- Server service: `myxray-server.service`
- Health endpoint: server-local `127.0.0.1:18122/healthz`

The public endpoint uses TLS 1.3 and HTTP/2. Requests without valid private authentication are forwarded to the existing HTTPS site. The production Nginx listener on port 443 is unchanged.

## Local control

```powershell
.\scripts\start-client.ps1
.\scripts\stop-client.ps1
```

Runtime logs and the PID file are stored under `run/`. Secrets are stored under `secrets/` and excluded by `.gitignore`.

## Clash Verge

The deployment test was run with TUN disabled. Before enabling TUN again, route `23.145.248.44/32` and `probe.chitanda.org` directly; otherwise this client can loop through or be measured through Clash.

## Verified on 2026-08-05

- Unit tests and static checks passed.
- Server health returned HTTP 204.
- Public fallback returned HTTP/2 200 with a valid certificate.
- A local end-to-end SOCKS request returned HTTP 200.
- Five simultaneous SOCKS requests all returned HTTP 200 over one client-to-server TCP connection.

This is the V1 prototype. Native UDP, QUIC/HTTP/3, V2 one-time prekeys and first-connection 0-RTT are not implemented yet. These results prove deployment and multiplexing, not resistance to GFW classification.
