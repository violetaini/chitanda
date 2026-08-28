package client

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"myxray/internal/auth"
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
	if err := signRequest(req, psk, "/test", "1.1.1.1:443", ModeTCPH2Framed); err != nil {
		t.Fatal(err)
	}

	target := req.Header.Get(HeaderTarget)
	timestamp := req.Header.Get(HeaderTimestamp)
	nonce := req.Header.Get(HeaderNonce)
	sig := req.Header.Get(HeaderSignature)

	if target != "1.1.1.1:443" {
		t.Fatalf("target = %q, want 1.1.1.1:443", target)
	}
	if !auth.Verify(psk, http.MethodPost, "/test", target, timestamp, nonce, sig, time.Now()) {
		t.Fatal("signature verification failed")
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
