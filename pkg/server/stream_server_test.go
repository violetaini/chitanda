package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/violetaini/chitanda/internal/auth"
	"github.com/violetaini/chitanda/internal/rawstream"
	"github.com/violetaini/chitanda/pkg/client"
)

func TestStreamServer_EchoTCP(t *testing.T) {
	psk := []byte("01234567890123456789012345678901")

	// 1. Upstream Echo Server
	echoL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	defer echoL.Close()

	go func() {
		for {
			c, err := echoL.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	// 2. StreamServer
	srvL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	defer srvL.Close()

	srv := NewStreamServer(psk, "", nil, func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	})
	defer srv.Close()

	go func() {
		_ = srv.Serve(srvL)
	}()

	// 3. Client dialing through StreamServer
	cli, err := client.New(client.Config{
		Server:       srvL.Addr().String(),
		PSK:          psk,
		TCPTransport: client.TCPTransportStream,
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := cli.DialContext(ctx, "tcp", echoL.Addr().String())
	if err != nil {
		t.Fatalf("DialContext stream failed: %v", err)
	}
	defer conn.Close()

	message := []byte("Hello Chitanda RawStream over IEPL!")
	if _, err := conn.Write(message); err != nil {
		t.Fatalf("conn.Write: %v", err)
	}

	buf := make([]byte, len(message))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("io.ReadFull: %v", err)
	}

	if !bytes.Equal(buf, message) {
		t.Fatalf("echo mismatch: got %q, want %q", buf, message)
	}
}

func TestStreamServer_AntiProbe_AodunHTTPScan(t *testing.T) {
	psk := []byte("01234567890123456789012345678901")

	srvL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	defer srvL.Close()

	srv := NewStreamServer(psk, "", nil, nil)
	defer srv.Close()

	go func() {
		_ = srv.Serve(srvL)
	}()

	// Simulate Aodun or domestic IDC compliance scanner sending HTTP GET
	conn, err := net.Dial("tcp", srvL.Addr().String())
	if err != nil {
		t.Fatalf("scanner dial: %v", err)
	}
	defer conn.Close()

	probeReq := []byte("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: AodunScanner/2.0\r\nAccept: */*\r\n\r\n")
	if _, err := conn.Write(probeReq); err != nil {
		t.Fatalf("scanner write: %v", err)
	}

	// Read response: Must immediately receive EOF and ZERO bytes!
	recvBuf := make([]byte, 1024)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, readErr := conn.Read(recvBuf)

	if n > 0 {
		t.Fatalf("AntiProbe failed: server replied with %d bytes: %q. Expected 0 bytes!", n, recvBuf[:n])
	}
	if readErr == nil {
		t.Fatalf("expected EOF or connection closed, got nil error")
	}
}

func TestStreamServer_AntiProbe_RandomJunk(t *testing.T) {
	psk := []byte("01234567890123456789012345678901")

	srvL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	defer srvL.Close()

	srv := NewStreamServer(psk, "", nil, nil)
	defer srv.Close()

	go func() {
		_ = srv.Serve(srvL)
	}()

	conn, err := net.Dial("tcp", srvL.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	junk := bytes.Repeat([]byte{0xDE, 0xAD, 0xBE, 0xEF}, 16) // 64 bytes
	if _, err := conn.Write(junk); err != nil {
		t.Fatalf("write junk: %v", err)
	}

	recvBuf := make([]byte, 1024)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, readErr := conn.Read(recvBuf)

	if n > 0 {
		t.Fatalf("AntiProbe failed on junk: server replied with %d bytes: %q", n, recvBuf[:n])
	}
	if readErr == nil {
		t.Fatalf("expected EOF on junk probe, got nil")
	}
}

func TestStreamServer_NativeUDP_Echo(t *testing.T) {
	psk := []byte("01234567890123456789012345678901")

	// 1. Upstream UDP Echo Server
	echoUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("echo UDP listen: %v", err)
	}
	defer echoUDP.Close()

	go func() {
		buf := make([]byte, 2048)
		for {
			n, rAddr, err := echoUDP.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = echoUDP.WriteTo(buf[:n], rAddr)
		}
	}()

	// 2. StreamServer with Native UDP attached
	srvTCP, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tcp listen: %v", err)
	}
	defer srvTCP.Close()

	tcpPort := srvTCP.Addr().(*net.TCPAddr).Port
	srvUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: tcpPort})
	if err != nil {
		t.Fatalf("udp listen on same port: %v", err)
	}
	defer srvUDP.Close()

	srv := NewStreamServer(psk, "", nil, nil)
	defer srv.Close()

	if err := srv.AttachUDP(srvUDP); err != nil {
		t.Fatalf("AttachUDP failed: %v", err)
	}
	srv.UDPServer().SetResolveUDPForTest(func(ctx context.Context, address string) (*net.UDPAddr, error) {
		return net.ResolveUDPAddr("udp", address)
	})

	go func() {
		_ = srv.Serve(srvTCP)
	}()

	// 3. Client using ListenPacket (Native PlainUDP)
	cli, err := client.New(client.Config{
		Server:       srvTCP.Addr().String(),
		PSK:          psk,
		TCPTransport: client.TCPTransportStream,
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	packetConn, err := cli.ListenPacket(ctx)
	if err != nil {
		t.Fatalf("ListenPacket failed: %v", err)
	}
	defer packetConn.Close()

	echoAddr, err := net.ResolveUDPAddr("udp", echoUDP.LocalAddr().String())
	if err != nil {
		t.Fatalf("resolve echo addr: %v", err)
	}

	udpMsg := []byte("Fast Native UDP Datagram for Gaming/Discord")
	if _, err := packetConn.WriteTo(udpMsg, echoAddr); err != nil {
		t.Fatalf("packetConn.WriteTo: %v", err)
	}

	recvBuf := make([]byte, 2048)
	_ = packetConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, rAddr, err := packetConn.ReadFrom(recvBuf)
	if err != nil {
		t.Fatalf("packetConn.ReadFrom: %v", err)
	}

	if !bytes.Equal(recvBuf[:n], udpMsg) {
		t.Fatalf("UDP echo mismatch: got %q, want %q", recvBuf[:n], udpMsg)
	}
	if rAddr.String() != echoAddr.String() {
		t.Fatalf("expected remote addr %s, got %s", echoAddr.String(), rAddr.String())
	}
}

func TestStreamServer_AntiReplay(t *testing.T) {
	psk := []byte("01234567890123456789012345678901")

	echoL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	defer echoL.Close()

	go func() {
		for {
			c, err := echoL.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	srvL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	defer srvL.Close()

	srv := NewStreamServer(psk, "", nil, func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", echoL.Addr().String())
	})
	defer srv.Close()

	go func() {
		_ = srv.Serve(srvL)
	}()

	// 1. Build a valid ClientHello + 0-RTT frame
	now := time.Now()
	clientHello, clientNonce, ts, err := rawstream.CreatePolymorphicClientHello(psk, "", now)
	if err != nil {
		t.Fatalf("create polymorphic client hello: %v", err)
	}

	k0RTT, err := rawstream.Derive0RTTKey(psk, "", ts, clientNonce)
	if err != nil {
		t.Fatalf("derive 0-rtt key: %v", err)
	}

	openFramePlaintext, err := rawstream.Encode0RTTOpenFrame("1.1.1.1:80", nil, 32, 64)
	if err != nil {
		t.Fatalf("encode 0-rtt open frame: %v", err)
	}

	encrypted0RTT, err := rawstream.Encrypt0RTTChunk(k0RTT, openFramePlaintext)
	if err != nil {
		t.Fatalf("encrypt 0-rtt chunk: %v", err)
	}

	wireLen := len(encrypted0RTT)
	flight1 := make([]byte, 0, len(clientHello)+2+wireLen)
	flight1 = append(flight1, clientHello...)
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(wireLen))
	flight1 = append(flight1, lenBuf[:]...)
	flight1 = append(flight1, encrypted0RTT...)

	// 2. First connection: send flight 1 -> should succeed and receive polymorphic ServerHello
	conn1, err := net.Dial("tcp", srvL.Addr().String())
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}

	if _, err := conn1.Write(flight1); err != nil {
		_ = conn1.Close()
		t.Fatalf("write flight 1: %v", err)
	}

	if _, err := rawstream.ReadAndVerifyPolymorphicServerHello(conn1, psk, "", ts, clientNonce); err != nil {
		_ = conn1.Close()
		t.Fatalf("read server hello: %v", err)
	}
	_ = conn1.Close()

	// 3. Second connection (Replay attack): send EXACT same flight 1
	conn2, err := net.Dial("tcp", srvL.Addr().String())
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	defer conn2.Close()

	if _, err := conn2.Write(flight1); err != nil {
		t.Fatalf("replay flight 1: %v", err)
	}

	// Must be dropped immediately with 0 bytes response
	recvBuf := make([]byte, 256)
	_ = conn2.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, readErr := conn2.Read(recvBuf)
	if n > 0 {
		t.Fatalf("AntiReplay failed: server responded with %d bytes to replayed handshake!", n)
	}
	if readErr == nil {
		t.Fatalf("expected EOF or closed connection on replayed handshake, got nil error")
	}
}

func TestStreamServer_TCPHalfClose(t *testing.T) {
	psk := []byte("01234567890123456789012345678901")

	// Upstream Echo Server that only finishes responding when client sends EOF
	echoL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	defer echoL.Close()

	go func() {
		for {
			c, err := echoL.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	srvL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	defer srvL.Close()

	srv := NewStreamServer(psk, "", nil, func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	})
	defer srv.Close()

	go func() {
		_ = srv.Serve(srvL)
	}()

	cli, err := client.New(client.Config{
		Server:       srvL.Addr().String(),
		PSK:          psk,
		TCPTransport: client.TCPTransportStream,
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := cli.DialContext(ctx, "tcp", echoL.Addr().String())
	if err != nil {
		t.Fatalf("DialContext failed: %v", err)
	}
	defer conn.Close()

	// Send data, then CloseWrite
	payload := bytes.Repeat([]byte("HalfCloseTestData12345"), 500) // 11KB
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("conn.Write: %v", err)
	}

	// Call CloseWrite on stream conn
	cw, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		t.Fatalf("expected conn to implement CloseWrite")
	}
	if err := cw.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite failed: %v", err)
	}

	// Verify we can read the entire payload back after CloseWrite!
	respBuf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		t.Fatalf("ReadFull after CloseWrite failed: %v", err)
	}

	if !bytes.Equal(respBuf, payload) {
		t.Fatalf("echo payload mismatch after CloseWrite")
	}
}

func TestStreamServer_PersistentReplay_SurvivesRestart(t *testing.T) {
	psk := []byte("01234567890123456789012345678901")
	cacheFile := filepath.Join(t.TempDir(), "replay.log")

	// 1. First server session
	replays1, err := auth.OpenReplayCache(cacheFile, time.Now())
	if err != nil {
		t.Fatalf("OpenReplayCache 1: %v", err)
	}

	echoL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	defer echoL.Close()

	go func() {
		for {
			c, err := echoL.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	srvL1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("server listen 1: %v", err)
	}
	defer srvL1.Close()

	srv1 := NewStreamServer(psk, "", replays1, func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", echoL.Addr().String())
	})

	go func() {
		_ = srv1.Serve(srvL1)
	}()

	// Build Flight 1
	now := time.Now()
	clientHello, clientNonce, ts, err := rawstream.CreatePolymorphicClientHello(psk, "", now)
	if err != nil {
		t.Fatalf("create polymorphic client hello: %v", err)
	}
	k0RTT, _ := rawstream.Derive0RTTKey(psk, "", ts, clientNonce)
	openFramePlaintext, _ := rawstream.Encode0RTTOpenFrame("1.1.1.1:80", nil, 32, 64)
	encrypted0RTT, _ := rawstream.Encrypt0RTTChunk(k0RTT, openFramePlaintext)

	wireLen := len(encrypted0RTT)
	flight1 := make([]byte, 0, len(clientHello)+2+wireLen)
	flight1 = append(flight1, clientHello...)
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(wireLen))
	flight1 = append(flight1, lenBuf[:]...)
	flight1 = append(flight1, encrypted0RTT...)

	// Connect to server 1
	conn1, err := net.Dial("tcp", srvL1.Addr().String())
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}
	if _, err := conn1.Write(flight1); err != nil {
		t.Fatalf("write flight 1: %v", err)
	}
	if _, err := rawstream.ReadAndVerifyPolymorphicServerHello(conn1, psk, "", ts, clientNonce); err != nil {
		t.Fatalf("read server hello: %v", err)
	}
	_ = conn1.Close()

	// "Restart" server: close srv1 (which syncs and closes replays1)
	_ = srv1.Close()

	// 2. Second server session: load from existing cacheFile
	replays2, err := auth.OpenReplayCache(cacheFile, time.Now())
	if err != nil {
		t.Fatalf("OpenReplayCache 2: %v", err)
	}

	srvL2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = replays2.Close()
		t.Fatalf("server listen 2: %v", err)
	}
	defer srvL2.Close()

	srv2 := NewStreamServer(psk, "", replays2, func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", echoL.Addr().String())
	})

	go func() {
		_ = srv2.Serve(srvL2)
	}()

	// Connect to server 2 and REPLAY flight 1
	conn2, err := net.Dial("tcp", srvL2.Addr().String())
	if err != nil {
		_ = srv2.Close()
		t.Fatalf("dial 2: %v", err)
	}
	defer conn2.Close()

	if _, err := conn2.Write(flight1); err != nil {
		_ = srv2.Close()
		t.Fatalf("write replay flight: %v", err)
	}

	_ = conn2.SetReadDeadline(time.Now().Add(2 * time.Second))
	respBuf := make([]byte, 128)
	n, readErr := conn2.Read(respBuf)
	if n > 0 {
		_ = srv2.Close()
		t.Fatalf("REPLAY ATTACK SUCCEEDED after restart! Server returned %d bytes: %x", n, respBuf[:n])
	}
	if readErr == nil {
		_ = srv2.Close()
		t.Fatalf("expected EOF or reset on replayed connection, got nil error")
	}
	_ = srv2.Close()
}

func TestStreamServer_CrossNodeReplay_DifferentServerID(t *testing.T) {
	psk := []byte("01234567890123456789012345678901")

	srvL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	defer srvL.Close()

	// Server configured with ServerID "node-tokyo"
	srv := NewStreamServer(psk, "node-tokyo", nil, nil)
	defer srv.Close()

	go func() {
		_ = srv.Serve(srvL)
	}()

	// Attacker sends ClientHello crafted for "node-singapore" (sharing the same PSK)
	clientHello, _, _, err := rawstream.CreatePolymorphicClientHello(psk, "node-singapore", time.Now())
	if err != nil {
		t.Fatalf("CreatePolymorphicClientHello: %v", err)
	}

	conn, err := net.Dial("tcp", srvL.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write(clientHello); err != nil {
		t.Fatalf("write: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 100)
	n, readErr := conn.Read(buf)
	if n > 0 {
		t.Fatalf("Cross-node attack succeeded! Server replied with %d bytes: %x", n, buf[:n])
	}
	if readErr == nil {
		t.Fatalf("expected EOF/closed on cross-node mismatch, got nil")
	}
}

func TestStreamServer_HandshakeConcurrencyLimit(t *testing.T) {
	psk := []byte("01234567890123456789012345678901")

	srvL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	defer srvL.Close()

	srv := NewStreamServer(psk, "", nil, nil)
	srv.SetHandshakeLimit(2) // limit to 2 concurrent handshakes
	defer srv.Close()

	go func() {
		_ = srv.Serve(srvL)
	}()

	// Hold 2 concurrent handshakes open
	conns := make([]net.Conn, 2)
	for i := 0; i < 2; i++ {
		c, err := net.Dial("tcp", srvL.Addr().String())
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		conns[i] = c
		defer c.Close()
		// write only 1 byte to keep handshake pending
		_, _ = c.Write([]byte{0x01})
	}

	time.Sleep(50 * time.Millisecond)

	// 3rd connection attempts to connect -> must be shed immediately
	c3, err := net.Dial("tcp", srvL.Addr().String())
	if err != nil {
		t.Fatalf("dial 3: %v", err)
	}
	defer c3.Close()

	_ = c3.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 10)
	n, readErr := c3.Read(buf)
	if n > 0 {
		t.Fatalf("expected 3rd connection to be closed immediately, but got %d bytes", n)
	}
	if readErr == nil {
		t.Fatalf("expected EOF or reset on shed connection, got nil")
	}
}

func TestClient_DialRawStream_ContextTimeoutAndCancellation(t *testing.T) {
	psk := []byte("01234567890123456789012345678901")

	// Blackhole listener: accepts connection but never responds
	blackholeL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("blackhole listen: %v", err)
	}
	defer blackholeL.Close()

	go func() {
		for {
			c, err := blackholeL.Accept()
			if err != nil {
				return
			}
			// Keep conn open, never write anything (simulating silent blackhole)
			defer c.Close()
		}
	}()

	cli, err := client.New(client.Config{
		Server:       blackholeL.Addr().String(),
		PSK:          psk,
		TCPTransport: client.TCPTransportStream,
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = cli.DialContext(ctx, "tcp", "1.1.1.1:80")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("expected dial to fail on blackhole, got nil")
	}
	if elapsed > 1*time.Second {
		t.Fatalf("dial took %v to timeout, expected ~150ms", elapsed)
	}
}

func TestStreamServer_ContextLifecycle_NoPrematureTimeout(t *testing.T) {
	psk := []byte("01234567890123456789012345678901")

	srvL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	defer srvL.Close()

	echoL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	defer echoL.Close()

	go func() {
		for {
			c, err := echoL.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	ctxRecorded := make(chan context.Context, 1)
	srv := NewStreamServer(psk, "", nil, func(ctx context.Context, network, address string) (net.Conn, error) {
		ctxRecorded <- ctx
		var d net.Dialer
		return d.DialContext(ctx, network, echoL.Addr().String())
	})
	defer srv.Close()

	go func() {
		_ = srv.Serve(srvL)
	}()

	cli, err := client.New(client.Config{
		Server:       srvL.Addr().String(),
		PSK:          psk,
		TCPTransport: client.TCPTransportStream,
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	defer cli.Close()

	conn, err := cli.DialContext(context.Background(), "tcp", "target.local:80")
	if err != nil {
		t.Fatalf("DialContext failed: %v", err)
	}

	var upstreamCtx context.Context
	select {
	case upstreamCtx = <-ctxRecorded:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for dialTarget to be called")
	}

	// Verify that upstreamCtx does NOT have a short deadline (e.g. 15s) imposed by StreamServer
	if deadline, hasDeadline := upstreamCtx.Deadline(); hasDeadline {
		t.Fatalf("upstreamCtx should NOT have a deadline, but got deadline %v", deadline)
	}

	// Verify that upstreamCtx is NOT done while connection is active
	select {
	case <-upstreamCtx.Done():
		t.Fatalf("upstreamCtx was cancelled prematurely while connection is active")
	default:
	}

	// Write and read data to prove session works
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("expected ping, got %s", string(buf))
	}

	// Close connection from client side
	_ = conn.Close()

	// Verify that upstreamCtx is cancelled once session terminates
	select {
	case <-upstreamCtx.Done():
		// Successfully cancelled when session ended!
	case <-time.After(2 * time.Second):
		t.Fatalf("upstreamCtx was not cancelled after session ended")
	}
}

func TestStreamServer_IdleLongLivedSession(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 18-second idle test in short mode")
	}
	psk := []byte("01234567890123456789012345678901")

	echoL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	defer echoL.Close()

	go func() {
		for {
			c, err := echoL.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	srvL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	defer srvL.Close()

	srv := NewStreamServer(psk, "", nil, func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, echoL.Addr().String())
	})
	defer srv.Close()

	go func() {
		_ = srv.Serve(srvL)
	}()

	cli, err := client.New(client.Config{
		Server:       srvL.Addr().String(),
		PSK:          psk,
		TCPTransport: client.TCPTransportStream,
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	defer cli.Close()

	conn, err := cli.DialContext(context.Background(), "tcp", "target.local:80")
	if err != nil {
		t.Fatalf("DialContext failed: %v", err)
	}
	defer conn.Close()

	// Initial message
	if _, err := conn.Write([]byte("hello before idle")); err != nil {
		t.Fatalf("write before idle failed: %v", err)
	}
	buf := make([]byte, len("hello before idle"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read before idle failed: %v", err)
	}

	// Sleep for 18 seconds (EXCEEDING the previous 15-second cutoff!)
	t.Logf("Sleeping for 18 seconds (idle silence test)...")
	time.Sleep(18 * time.Second)

	// Second message after 18 seconds of complete silence
	msgAfter := []byte("hello after 18s idle")
	if _, err := conn.Write(msgAfter); err != nil {
		t.Fatalf("write after 18s idle failed: %v", err)
	}
	bufAfter := make([]byte, len(msgAfter))
	if _, err := io.ReadFull(conn, bufAfter); err != nil {
		t.Fatalf("read after 18s idle failed (SESSION DIED): %v", err)
	}
	if string(bufAfter) != string(msgAfter) {
		t.Fatalf("mismatch after idle: got %q, want %q", bufAfter, msgAfter)
	}
	t.Logf("SUCCESS: Connection survived 18s of complete idle silence!")
}
