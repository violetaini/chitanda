# MyXray V1/V2 test report

Initial test date: 2026-08-07; latest validation: 2026-08-21 (Asia/Shanghai)

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

## 2026-08-18 receive-path and congestion-control validation

The exact route was remeasured before changing the protocol. Direct single-stream TCP reached about 1.59 Gbps. Raw reverse UDP with 1,350-byte payloads reached about 466 Mbps in one iperf3 process; two independent processes reached about 787 Mbps combined. These are different ceilings, so a TCP result is not evidence that one UDP/QUIC flow can carry the same rate.

- CUBIC4 remained the best loss-responsive profile. CUBIC8 was indistinguishable, and a fixed-rate controller delivered 441 Mbps at an 800 Mbps target and 315 Mbps at a 1,600 Mbps target after GRO was enabled.
- Server qlog measured about 100.8 ms RTT, a roughly 6.06 MiB congestion window, and 4,664 packet-loss declarations in 15 seconds. The resulting window/RTT rate matches the observed roughly 480 Mbps plateau.
- A Linux UDP GRO prototype initially looked faster, but its first zero-copy ownership model was not concurrency-safe and was rejected during review. The safe atomic-owner version measured 429/432 Mbps TCP with GRO on/off and 91.4/111 Mbps UDP at 150 Mbps input, so all GRO code was removed from the release candidate.
- A 256-entry per-stream HTTP Datagram queue, batched H3 dequeue, and server-side `sendmmsg` remain. The final no-GRO candidate received about 111 Mbps with 26% loss at 150 Mbps input.
- TCP and UDP now use separate QUIC connections. A UDP-heavy association no longer invalidates or directly reduces the TCP connection's congestion window.
- Same-node Hysteria controls did not reproduce the claimed 2 Gbps result: BBR/aggressive reached 391 Mbps and configured 2 Gbps Brutal reached 269 Mbps. MyXray fresh TCP runs were roughly 430-500 Mbps in the same optimization series.

## 2026-08-20 same-window TCP controls

The route was variable, so the controls were interleaved and use receiver throughput. Direct single-flow TCP measured 1.336 Gbps forward and 1.696 Gbps reverse in the same window. A direct Go TCP bridge using the same generic copy path measured 1.337/1.766 Gbps, ruling out the benchmark bridge as the shared 1 Gbps ceiling.

- Xray VLESS/TLS: forward median 1.014 Gbps versus MyXray H2 median 964 Mbps (about 5%); reverse median 1.028 Gbps versus MyXray H2 1.010 Gbps (about 2%). Neither reproduced 2 Gbps.
- Xray VLESS without TLS: forward median 855 Mbps and reverse median 1.033 Gbps. In a same-window comparison, no-TLS/TLS/direct were 898/1005/1335 Mbps forward and 1021/1027/1103 Mbps reverse. Removing TLS did not improve throughput, so TLS encryption is not the dominant limit on these nodes.
- Xray Shadowsocks 2022 (`2022-blake3-aes-128-gcm`): forward median 935 Mbps versus direct 1.323 Gbps; reverse median 1.029 Gbps versus direct 1.333 Gbps. This exact SS implementation reached about 71%/77% of direct and did not reproduce 2 Gbps.
- Both nodes are two-vCPU 2.0 GHz Neoverse-N1 virtual machines with a single virtio receive/transmit queue. Steal time during saturated runs was commonly 8-23%. This evidence points to proxy forwarding, kernel scheduling and host contention rather than a private-frame-specific 2x penalty.
- Increasing the QUIC outer send queue from 8 to 16 was rejected. Aggregate UDP receive throughput fell about 2.1%; reverse 300 Mbps trials fell from 173/196 to 159/146 Mbps, and aggregate H3 TCP fell about 2.4%.
- A clean current UDP baseline with 1,350-byte payloads delivered 99.9 Mbps at 100 Mbps offered, 147/149 Mbps forward/reverse at 150 Mbps, and 178/183 Mbps at 200 Mbps (about 9-10% loss at 200 Mbps). Direct single-process UDP in the same period saturated around 315 Mbps forward and 443 Mbps reverse, so the tunnel still has a material per-packet processing gap even though TCP's 2 Gbps target is not a valid UDP baseline.
- Increasing the application-data ACK threshold from 2 to 4 was rejected: one 200 Mbps UDP pair improved, but 300 Mbps UDP fell 191 to 171 Mbps and H3 TCP fell 14-18%.
- Expanding H2 copy buffers to 256 KiB and coalescing TLS records reduced CPU/syscall counts but did not raise throughput, so neither experiment is retained.
- The UDP replay-window hot path was changed from an O(window) shift to an O(1) ring bitset (about 29.9 to 3.35 ns/op on ARM64). The reverse SOCKS UDP address builder now caches its encoded destination (about 131.5 to 41.4 ns/op, zero allocations in both cases).

All rates remain observations from shared two-vCPU VMs with substantial steal, not product guarantees. The implementation still does not fill the measured direct TCP path.

## 2026-08-21 release validation

The final candidate was rebuilt from a clean vendor preparation on the ARM64 server. `go test -mod=vendor ./...`, the explicit quic-go and HTTP/3 suites, race tests for the server, client, frame, SOCKS, quic-go and HTTP/3 packages, and static Linux/ARM64 builds all passed. Applying `scripts/vendor-performance.patch` in reverse also passed, so the checked-in vendor tree and the reproducible patch agree.

- Final server SHA-256: `49c3efe0277442debfb3ce1bbb4c5130d80b2efdf19ee5a9ad006ca56d324ef5`.
- Final V2 client SHA-256: `c9d288b1a8496fd7c7e395df890fa964c42acd625b0b645713e1ce92c5ec4104`.
- Same-window direct TCP was 1.34 Gbps forward and 1.49 Gbps reverse. Final H2 was 934 Mbps forward and 1.03 Gbps reverse; final H3 was 462 Mbps forward and 470 Mbps reverse. H2 is in the same range as the measured Xray SS/VLESS controls, but neither the controls nor MyXray filled 2 Gbps on these nodes.
- Final native UDP with 1,350-byte payloads received about 150 Mbps at 150 Mbps offered. At 200 Mbps, forward received 188 Mbps with 5.8% loss; a warmed reverse association received 199 Mbps with 0.32% loss. The formal endpoint's final 50 Mbps smoke test received 50.0 Mbps with 0/46,763 lost and 0.039 ms jitter.
- A fresh H3 connection succeeded without early data. After persisting the ticket and restarting the isolated client, the next request returned HTTP 200 and logged `used_0rtt=true early_accepted=true` against the formal server port.
- Fixed 32-entry metadata arrays were rejected: on ARM64 they forced a 1,408-byte allocation even for a one-datagram batch, and isolated endpoint tests regressed roughly 5-7%. Dynamic slices remain in the release.
- Release review then found and fixed three lifecycle failures before the final build: an authenticated H3 request could dial upstream before its private `OPEN` frame was validated; a broken durable replay cache could fall back to memory-only acceptance after compaction failure; and an HTTP Datagram receiver could remain blocked after the QUIC receive loop stopped. Each now has a regression test and fails closed or wakes waiters as appropriate.

The formal server `myxray-test-v2-170` now runs the final binary through a stable symlink on TCP/UDP `11322`; the formal client `myxray-test-v2-client-168` does the same on `127.0.0.1:22081`. Both are persistent, enabled systemd units rather than transient test units. Experiment services and bridges were stopped after validation. The previous binaries remain installed under their original names for an explicit rollback.

## 2026-08-28 Release 5 Direct Native Benchmark & Core SDK Validation

### Architectural Decoupling (Hysteria 2 Product Model)
- **SOCKS5 Stripped from Core**: Created pure Go Core SDK (`pkg/client`), exporting standard `DialContext(ctx, "tcp", target)` returning `net.Conn` and `ListenPacket(ctx)` returning `net.PacketConn`.
- **Core Integration Surface**: The SDK exposes `DialContext` and `ListenPacket` as adapter building blocks. Xray-core, Mihomo, and sing-box adapters are not yet implemented, and full `net.Conn` deadline semantics still require work.
- **Direct Native Benchmark Tool (`cmd/bench-direct`)**: Built direct benchmark harness that pumps data directly through `pkg/client` (or acts as echo/sink server), completely eliminating SOCKS5 loopback parsing, per-session TCP handshake overhead, and bridge serialization.

### UDP Datagram & Loss-Tolerant Congestion Optimization
- **Queue Expansion**: Enlarged `maxDatagramSendQueueLen` from 32 to 512 in vendored `quic-go/datagram_queue.go`, preventing queue saturation during microsecond packet bursts.
- **Congestion Floor & Warmup**: Set `minCongestionWindowPackets = 64` and `initialCongestionWindow = 128` in `quic-go/internal/congestion/cubic_sender.go`. These are aggressive project-specific defaults and must be evaluated against fairness, queueing delay, and loss on each deployment path.

### Real Remote Node Benchmark Measurements (170 Server <-> 168 Client)

Both nodes running Debian 13 ARM64 (2vCPU, ~100ms cross-region RTT):

#### 1. TCP Direct Core Benchmark (TLS 1.3 / HTTP/2)
| Test Configuration | Measured Throughput | Streams / Failure | Duration |
| :--- | :--- | :--- | :--- |
| Single Stream (Single Carrier) | **830.93 Mbps** (103.87 MB/s) | 1 stream / 0 failed | 5.00s |
| 4 Concurrent Streams (Single Carrier) | **882.02 Mbps** (110.25 MB/s) | 4 streams / 0 failed | 5.06s |
| 4 Concurrent Streams (Pool: 4 Carriers) | **996.47 Mbps** (124.56 MB/s) | 4 streams / 0 failed | 5.11s |
| 8 Concurrent Streams (Pool: 8 Carriers) | **1050.44 Mbps** (131.31 MB/s) | 8 streams / 0 failed | 5.12s |
| 16 Concurrent Streams (Pool: 8 Carriers) | **1079.57 Mbps** (134.95 MB/s) | 16 streams / 0 failed | 10.13s |
| 32 Concurrent Streams (Pool: 12 Carriers) | **1139.02 Mbps** (142.38 MB/s) | 32 streams / 0 failed | 10.16s |
| 64 Concurrent Streams (Pool: 16 Carriers) | **961.20 Mbps** (120.15 MB/s) | 64 streams / 0 failed | 10.25s |

#### 2. Native UDP Datagram Benchmark (RFC 9221 / HTTP/3)
| Offered Target Rate | Packets Sent | Packets Received | Delivered Rate | Loss Rate | Mode |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **100 Mbps** (5s) | 44,435 pkts | 44,435 pkts | **95.97 Mbps** | **0.00%** | Round-Trip Echo |
| **150 Mbps** (5s) | 65,097 pkts | 64,979 pkts | **140.31 Mbps** | **0.18%** | Round-Trip Echo |
| **200 Mbps** (5s) | 80,703 pkts | 69,786 pkts | **150.71 Mbps** | **13.53%** | Round-Trip Echo |
| **200 Mbps** (5s) | 85,555 pkts | 85,549 pkts | **196.19 Mbps** | **0.007%** | Direct Sink Delivery |
| **300 Mbps** (5s) | 126,944 pkts | 114,453 pkts | **264.16 Mbps** | **9.84%** | Direct Sink Delivery |
| **400 Mbps** (5s) | 132,148 pkts | 123,881 pkts | **295.66 Mbps** | **6.26%** | Direct Sink Delivery |

## Remaining gaps

- Never-contacted first-ever 0-RTT with provisioned one-time prekeys, crash-safe multi-node at-most-once consumption, and forward secrecy for early data.
- UDP-over-H2 fallback, verified NAT rebinding/connection migration, application-selectable FEC, and 0-RTT UDP. HTTP Datagrams are sent only after the handshake.
- Application priority and rekeying; `WINDOW_UPDATE` is reserved while QUIC currently provides active flow control.
- Raw TCP/Noise carrier, dynamic traffic-shape rotation, and blind classifier separation against GFW or 傲盾.
- Any claim of undetectability. HTTP/2 settings and HTTP/3/QUIC behavior remain observable to active endpoints, and QUIC can be blocked independently of payload classification.
