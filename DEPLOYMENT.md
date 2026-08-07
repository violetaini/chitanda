# Deployment status

## V1 endpoint

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

## Isolated performance environment (2026-08-06)

- Service test node: `170.9.59.149:11322` (`myxray-test-replay-170`)
- Client test node: `168.138.209.1:22080` (`myxray-test-client-168`)
- Test origin ports on the service node: `18080`, `18081`, and temporary half-close origin `18083`
- The 154.12.176.212 host was not used for this deployment and has no MyXray test files or service.
- The client node has `chrony` enabled because it initially had no time synchronisation service.

### Active V2 test services (verified 2026-08-07)

- Server: `170.9.59.149:11322` over both TCP/H2 and UDP/H3; V2 service `myxray-test-v2-170`.
- Client: `168.138.209.1`, V2 SOCKS5 TCP/UDP listener `127.0.0.1:22081`; service `myxray-test-v2-client-168`.
- TLS name: `status.chitanda.org`; server ticket key and client session cache persist across service restarts.
- The first application request after restarting both services used accepted TLS 1.3 0-RTT and returned HTTP 200.
- Native UDP was verified through SOCKS UDP ASSOCIATE. Warm 50 Mbps testing received 49.2 Mbps with 0.5% loss; forward saturation was about 93 Mbps with unacceptable loss above the stable range.
- Temporary benchmark bridges were stopped after testing. The production Nginx/Xray listeners and the former `154.12.176.212` host were not modified.

Measured between the two test nodes, whose raw RTT was about 100 ms and iperf3 throughput about 1.3–1.5 Gbps:

| Test | Result |
| --- | --- |
| Single-session 1 GiB download | 122.87 MB/s, about 983 Mbps, one TCP/TLS/H2 connection |
| Single-session 64 MiB upload | 48–91 MB/s across three runs, HTTP 204 |
| Hot-connection 30-request P95 | 0.206 s after durable replay logging |
| Concurrent short streams | 500/500 successful at concurrency 50, one physical connection |
| TCP half-close | 1 MiB and SHA-256 matched exactly |
| Replay inside process | First request 200, exact replay 404 |
| Replay after server restart | Exact replay remained 404 |

The 16 MiB HTTP/2 stream window is intentionally a build-time vendored change. It removes the default 4 MiB long-haul throughput ceiling while leaving TLS and HTTP/2 framing in mature libraries. It is still a visible HTTP/2 setting to a completed active HTTPS probe, so it is a performance/fingerprint tradeoff, not an anti-classification guarantee. See `TEST_REPORT.md` for the full evidence and remaining gaps.
