# MyXray V1 test report

Date: 2026-08-06 (Asia/Shanghai)

## Scope

The isolated test used `170.9.59.149` as the server and `168.138.209.1` as the client. Existing Nginx, Xray, Docker and port 443 services were left unchanged. The former `154.12.176.212` host was not deployed to and is outside this report.

Both test nodes are Debian 13 ARM64 with two Neoverse-N1 vCPUs. The direct path measured about 100 ms RTT and 1.3–1.5 Gbps with iperf3. The client node initially had no NTP service; `chrony` was installed and is now synchronised.

## Functional results

- TLS/H2 private request returned HTTP 200 through the local SOCKS listener.
- A single client-to-server TCP/TLS connection carried concurrent streams; the client did not open one physical connection per short request.
- Normal HTTPS fallback returned the origin status/body shape. Private authentication headers are stripped before fallback forwarding.
- Loopback/private target access was rejected. Special-use ranges including CGNAT and documentation networks are now rejected as well.
- TCP half-close preserved directionality: a 1 MiB payload and SHA-256 matched after the client closed only its write side.
- During an intentional server restart, the client retry added no application-byte replay and restored requests without a permanent SOCKS failure.

## Throughput results

Before window tuning, one H2 stream was limited to roughly 38.6 MB/s download and 9.0 MB/s upload. The limits matched Go HTTP/2's default flow-control windows over a 100 ms path.

The tested build uses a 16 MiB client stream receive window and 64 MiB/connection plus 16 MiB/stream server receive windows. Results after tuning:

| Direction | Direct origin | MyXray, one SOCKS session | Notes |
| --- | ---: | ---: | --- |
| 256 MiB download | 100.8–114.9 MB/s | 89.1–118.0 MB/s | 1 GiB run reached 122.87 MB/s / 983 Mbps |
| 64 MiB upload | 44.8–46.3 MB/s | 48.6–90.8 MB/s | All proxy responses HTTP 204 |

The direct upload origin is a small Python test service and is not a line-rate benchmark; raw iperf3 is the appropriate network ceiling. The proxy result is therefore evidence that the single stream is no longer flow-control limited, not a universal speed promise.

## Latency and load

- 30 one-byte direct requests averaged about 0.302 s total; 30 requests over the hot MyXray connection averaged about 0.212 s with P95 about 0.206 s. One 0.413 s outlier was observed.
- 500 concurrent short requests at concurrency 50 all returned HTTP 200 in 4.85 s. At that point the server peak RSS was about 10.9 MB and the client peak RSS about 17.7 MB.
- The server restart test initially produced one failed request from a stale connection. After adding one retry before any application bytes are sent, a second run had 20/20 successes; one request took 0.531 s during restart.

## Replay and persistence

The replay cache now appends `expiry + nonce`, calls `fsync`, then permits the authenticated upstream dial. It reloads non-expired entries at startup and compacts after 10,000 writes. A live exact replay changed from HTTP 200 to HTTP 404 inside one process and remained HTTP 404 after restarting the service. A disk error fails closed.

This is a single-node durable cache. It is not yet a multi-node strongly consistent consume record, so it does not satisfy the V2 multi-node 0-RTT requirement.

## Not implemented or not proven

- First-connection TLS Early Data with one-time prekeys, crash-safe at-most-once execution and forward secrecy for early data.
- A private application frame layer with independent stream windows, priority, rekeying and DATAGRAM frames. V1 still maps one SOCKS TCP flow to one HTTP/2 request stream.
- Native UDP over QUIC/HTTP/3, NAT rebinding, loss/jitter comparison and H2 fallback for UDP.
- Raw TCP/Noise carrier, dynamic traffic-shape rotation, classifier separation against GFW or 傲盾, and any claim of undetectability.
- The 16 MiB HTTP/2 setting is encrypted on the wire but visible to a probe that completes TLS and inspects HTTP/2 SETTINGS. Its classification tradeoff needs a separate corpus-based measurement.
