package client

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/violetaini/chitanda/internal/auth"
	"github.com/violetaini/chitanda/pkg/server"
)

func TestConfigValidation(t *testing.T) {
	// Missing PSK / invalid PSK
	_, err := New(Config{Server: "127.0.0.1:11322", ServerName: "example.com", Path: "/test"})
	if err == nil {
		t.Fatal("expected error for missing PSK")
	}

	// Valid config
	psk := []byte("01234567890123456789012345678901")
	c, err := New(Config{
		Server:     "127.0.0.1:11322",
		ServerName: "example.com",
		Path:       "/test",
		PSK:        psk,
	})
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}
	defer c.Close()

	if c.cfg.TCPTransport != TCPTransportH2 {
		t.Fatalf("default TCPTransport = %q, want %q", c.cfg.TCPTransport, TCPTransportH2)
	}
}

func TestSignRequest(t *testing.T) {
	psk := []byte("01234567890123456789012345678901")
	req, err := http.NewRequest(http.MethodPost, "https://example.com/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := signRequest(req, psk, "/test", "1.1.1.1:443", ModeTCPv2); err != nil {
		t.Fatal(err)
	}

	target := req.Header.Get(HeaderTarget)
	timestamp := req.Header.Get(HeaderTimestamp)
	nonce := req.Header.Get(HeaderNonce)
	sig := req.Header.Get(HeaderSignature)

	if target != "1.1.1.1:443" {
		t.Fatalf("target = %q, want 1.1.1.1:443", target)
	}
	if !auth.Verify(psk, ModeTCPv2, http.MethodPost, "/test", target, timestamp, nonce, sig, time.Now()) {
		t.Fatal("signature verification failed")
	}
}

func TestH3PoolSizingAndReservation(t *testing.T) {
	psk := []byte("01234567890123456789012345678901")
	tests := []struct {
		name      string
		transport string
		poolSize  int
		wantH3    int
	}{
		{name: "h2 keeps one H3 manager for UDP", transport: TCPTransportH2, poolSize: 3, wantH3: 1},
		{name: "h3 uses configured pool", transport: TCPTransportH3, poolSize: 3, wantH3: 3},
		{name: "auto prepares H3 fallback pool", transport: TCPTransportAuto, poolSize: 3, wantH3: 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := New(Config{
				Server:       "127.0.0.1:11322",
				ServerName:   "example.com",
				Path:         "/test",
				PSK:          psk,
				TCPTransport: tt.transport,
				TCPPoolSize:  tt.poolSize,
			})
			if err != nil {
				t.Fatalf("New() error: %v", err)
			}
			defer c.Close()

			if got := len(c.h3Managers); got != tt.wantH3 {
				t.Fatalf("H3 manager count = %d, want %d", got, tt.wantH3)
			}
			if tt.wantH3 < 3 {
				return
			}

			selected := make(map[*h3TransportManager]int)
			for range tt.wantH3 {
				manager := c.reserveH3Manager()
				if manager == nil {
					t.Fatal("pickBestH3Manager() returned nil")
				}
				manager.activeStreams.Add(1)
				selected[manager]++
			}
			for _, manager := range c.h3Managers {
				if selected[manager] != 1 {
					t.Fatalf("carrier selected %d times, want 1", selected[manager])
				}
				manager.activeStreams.Add(-1)
			}
		})
	}
}

func TestClientImplementsInterfaces(t *testing.T) {
	type dialer interface {
		DialContext(ctx context.Context, network, address string) (net.Conn, error)
	}
	type packetListener interface {
		ListenPacket(ctx context.Context) (net.PacketConn, error)
	}

	var _ dialer = (*Client)(nil)
	var _ packetListener = (*Client)(nil)
}

func TestPlainH1EndToEnd(t *testing.T) {
	psk := []byte(strings.Repeat("p", 32))
	replays := auth.NewReplayCache()
	defer replays.Close()

	// 1. Start a local TCP echo server (the upstream destination)
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen echo: %v", err)
	}
	defer echoLn.Close()
	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	// 2. Start a local HTTP server running MyXray server
	srvHandler := server.NewServer("/test-plain-h1", psk, replays, nil, 1024)
	srvHandler.SetDialTargetForTest(func(ctx context.Context, address string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", address)
	})
	httpServer := &http.Server{
		Handler: srvHandler,
	}
	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen http: %v", err)
	}
	defer httpLn.Close()
	go func() {
		_ = httpServer.Serve(httpLn)
	}()
	defer httpServer.Close()

	// 3. Create MyXray client in plain-h1 mode
	c, err := New(Config{
		Server:       httpLn.Addr().String(),
		Path:         "/test-plain-h1",
		PSK:          psk,
		TCPTransport: TCPTransportPlainH1,
	})
	if err != nil {
		t.Fatalf("New plain-h1 client: %v", err)
	}
	defer c.Close()

	// 4. Dial the upstream echo target through plain-h1
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := c.DialContext(ctx, "tcp", echoLn.Addr().String())
	if err != nil {
		t.Fatalf("DialContext plain-h1: %v", err)
	}
	defer conn.Close()

	// 5. Send message and verify round-trip
	msg := []byte("Hello Plain-H1 Full-Duplex AEAD Stream!")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("conn.Write: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("conn.Read: %v", err)
	}

	if string(buf) != string(msg) {
		t.Fatalf("echoed %q != sent %q", string(buf), string(msg))
	}
}

func TestPlainUDP_ListenPacket(t *testing.T) {
	psk := []byte(strings.Repeat("u", 32))

	// 1. Local UDP echo server (the upstream destination)
	echoLn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP echo: %v", err)
	}
	defer echoLn.Close()
	go func() {
		buf := make([]byte, 1024)
		for {
			n, client, err := echoLn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = echoLn.WriteToUDP(buf[:n], client)
		}
	}()

	// 2. Server UDP listener
	srvLn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP server: %v", err)
	}
	defer srvLn.Close()

	srv, err := server.NewPlainUDPServer(srvLn, psk)
	if err != nil {
		t.Fatalf("NewPlainUDPServer: %v", err)
	}
	srv.SetResolveUDPForTest(func(ctx context.Context, address string) (*net.UDPAddr, error) {
		return net.ResolveUDPAddr("udp", address)
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = srv.Serve(ctx)
	}()

	// 3. Client initializes plain-h1 client and calls ListenPacket
	c, err := New(Config{
		Server:       srvLn.LocalAddr().String(),
		Path:         "/test-udp",
		PSK:          psk,
		TCPTransport: TCPTransportPlainH1,
	})
	if err != nil {
		t.Fatalf("New plain-h1 client: %v", err)
	}
	defer c.Close()

	pconn, err := c.ListenPacket(ctx)
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pconn.Close()

	// 4. Send datagram to echoLn via PacketConn
	msg := []byte("Hello Native Plain-UDP Datagram!")
	if _, err := pconn.WriteTo(msg, echoLn.LocalAddr()); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	recvBuf := make([]byte, 2048)
	_ = pconn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, rAddr, err := pconn.ReadFrom(recvBuf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}

	if rAddr.String() != echoLn.LocalAddr().String() {
		t.Fatalf("rAddr = %q, want %q", rAddr.String(), echoLn.LocalAddr().String())
	}
	if string(recvBuf[:n]) != string(msg) {
		t.Fatalf("received %q != expected %q", string(recvBuf[:n]), string(msg))
	}
}
