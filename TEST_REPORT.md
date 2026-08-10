# MyXray V1/V2 test report

Date: 2026-08-07 (Asia/Shanghai)

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

## V2 HTTP/3 and 0-RTT

V2 was deployed on the same two nodes using TCP and UDP port `11322` on the server and SOCKS5 TCP/UDP port `22081` on the client. It uses HTTP/3 request streams for TCP and extended CONNECT plus HTTP Datagrams for UDP. V1/H2 remained active as a separate fallback during testing.

- The private frame layer round-tripped `OPEN`, `OPEN_ACK`, `DATA`, `HALF_CLOSE`, and reset semantics; one HTTP/3 request stream carries one proxied TCP flow while one QUIC connection multiplexes request streams.
- The persistent TLS session cache, persistent server ticket key, and stale-ticket recovery passed unit and live restart tests.
- After restarting both server and client, the first application request returned HTTP 200 in 0.354 s and logged `used_0rtt=true` and `early_accepted=true`.
- This result requires a previously provisioned TLS ticket. It is not a never-contacted first-ever TLS connection, and early data does not yet have the planned one-time-prekey forward secrecy.

Single TCP stream measurements on the roughly 100 ms path:

| Path | Download | Upload |
| --- | ---: | ---: |
| Direct iperf3 | about 1.68 Gbps | about 1.32 Gbps |
| V1 TLS/H2 | about 723 Mbps | about 1.01 Gbps |
| V2 HTTP/3 | about 392 Mbps | about 388 Mbps |

Increasing V2 QUIC flow-control windows to 32 MiB/stream and 64 MiB/connection did not materially change the roughly 400 Mbps result. The current V2 single-stream implementation is therefore functional but not throughput-optimal on these two-vCPU ARM64 nodes.

## V2 native UDP

The first apparent 1 Mbps ceiling was invalid: the temporary benchmark bridge allowed the SOCKS TCP control connection to become unreachable and garbage-collected after about five seconds, terminating its UDP association. Holding the control connection for the association lifetime removed that artifact.

Valid forward tests used 1,000-byte iperf3 payloads over SOCKS UDP ASSOCIATE and a private HTTP Datagram envelope. QUIC datagrams remain unreliable by design.

| Offered rate | Received rate | Loss | Jitter |
| ---: | ---: | ---: | ---: |
| 20 Mbps | 19.8 Mbps | 0% | 0.069 ms |
| 50 Mbps, warm | 49.2 Mbps | 0.5% | 0.158 ms |
| 75 Mbps | 73.3 Mbps | 1.3% | 0.108 ms |
| 100 Mbps | 89.9 Mbps | 9.1% | 0.085 ms |
| 150 Mbps | 92.9 Mbps | 37% | 0.096 ms |

Warm reverse tests reached 50.0 Mbps with 0.011% loss and 98.8 Mbps with 1.2% loss. A fresh reverse association lost more traffic during the first congestion-window ramp. The defensible current conclusion is about 93 Mbps forward saturation, with roughly 50 Mbps as the stable low-loss operating point on this specific path and hardware.

The Datagram receive queue and private replay window are both 2,048 entries. Raising the replay window reduced false-replay risk under reordering but did not remove the CPU/packet-rate saturation point.

## 2026-08-10 throughput optimization

The two nodes remain Debian 13 ARM64 VMs with two Neoverse-N1 vCPUs. During UDP saturation, `vmstat` measured about 12-22% CPU steal on the client and 9-15% on the server, so single-run rates are noisy and should not be treated as a hardware-independent ceiling.

- The private UDP hot path now reuses frame and SOCKS buffers and caches repeated target addresses. QUIC HTTP Datagram send removes one intermediate copy; QUIC receive removes one redundant copy before the receive queue. Protocol bytes and replay checks are unchanged.
- The private QUIC ACK threshold, Linux receive batch size, and large GSO buffer experiments were reverted after they reduced TCP single-flow throughput. They are not part of the deployed build.
- With a fresh connection and the high-MTU profile, TCP download reached 398 Mbps over the proxy, with stable one-second intervals around 387-406 Mbps. TCP upload reached 199 Mbps in the same test window. The earlier 1.46 Gbps direct iperf3 result remains the path ceiling, not a proxy result.
- At 1,350-byte UDP payloads, 150 Mbps offered reached 120 Mbps with 19% loss on a fresh association. After a 1,200-byte warm-up, the same path reached about 129 Mbps with 13% loss. At 50 Mbps, forward and reverse tests received 48.1 and 48.7 Mbps, with aggregate loss around 2.7-2.9% concentrated partly in startup.
- The deployed `-quic-initial-packet-size 1452` assumes the measured IPv4/1500-byte path. A temporary 1280-byte client correctly dropped an oversized 1,350-byte packet but kept its association and subsequently delivered 1,200-byte packets at 19.1 Mbps. Use 1280 on unknown or smaller-MTU paths.

The optimization reduces per-packet allocations and copies, but the end-to-end UDP improvement is dominated by packet size and the two-vCPU VM's kernel/steal behavior. It does not establish a universal throughput guarantee.

## Remaining gaps

- Never-contacted first-ever 0-RTT with provisioned one-time prekeys, crash-safe multi-node at-most-once consumption, and forward secrecy for early data.
- UDP-over-H2 fallback, verified NAT rebinding/connection migration, application-selectable FEC, and 0-RTT UDP. HTTP Datagrams are sent only after the handshake.
- Application priority and rekeying; `WINDOW_UPDATE` is reserved while QUIC currently provides active flow control.
- Raw TCP/Noise carrier, dynamic traffic-shape rotation, and blind classifier separation against GFW or 傲盾.
- Any claim of undetectability. HTTP/2 settings and HTTP/3/QUIC behavior remain observable to active endpoints, and QUIC can be blocked independently of payload classification.
