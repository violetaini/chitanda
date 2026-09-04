package server

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

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

	srv := NewStreamServer(psk, func(ctx context.Context, network, address string) (net.Conn, error) {
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

	srv := NewStreamServer(psk, nil)
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

	srv := NewStreamServer(psk, nil)
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

	srv := NewStreamServer(psk, nil)
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
