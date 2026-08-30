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
	if !auth.Verify(psk, http.MethodPost, "/test", target, timestamp, nonce, sig, time.Now()) {
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
