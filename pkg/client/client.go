// Package client provides the core MyXray client SDK for embedding into
// proxy frameworks (such as Xray-core and Mihomo/Clash.Meta) or standalone binaries.
// It exposes standard Go net.Conn (TCP) and net.PacketConn (UDP) interfaces.
package client

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"myxray/internal/auth"
	"myxray/internal/quicconfig"
	"myxray/internal/sessioncache"
)

const (
	HeaderTarget         = "X-Session-Target"
	HeaderTimestamp      = "X-Session-Time"
	HeaderNonce          = "X-Session-Nonce"
	HeaderSignature      = "X-Session-Auth"
	HeaderSessionOK      = "X-Session-OK"
	HeaderFraming        = "X-Session-Framing"
	HeaderMode           = "X-Session-Mode"
	ModeTCPv2            = "tcp-v2"
	ModeUDPv2            = "udp-v2"
	ModeTCPH2Framed      = "tcp-h2-framed"
	UDPAssociationTarget = "udp-association"

	TCPTransportAuto    = "auto"
	TCPTransportH2      = "h2"
	TCPTransportH3      = "h3"
	DefaultTCPTransport = TCPTransportH2

	defaultCarrierTimeout = 15 * time.Second
	autoH2ConnectTimeout  = 4 * time.Second
)

// Config holds the client configuration.
type Config struct {
	Server                string // e.g. "170.9.59.149:11322"
	ServerName            string // e.g. "status.chitanda.org"
	PSK                   []byte // 32+ bytes PSK
	Path                  string // e.g. "/your-private-path"
	TCPTransport          string // "h2" (default), "auto", or "h3"
	SessionCacheFile      string // optional persistent session cache path
	QUICInitialPacketSize uint16 // 1200 - 1452, default 1452
}

// Client is the MyXray core client engine.
type Client struct {
	cfg          Config
	rootURL      string
	requestURL   string
	h2Client     *h2TransportClient
	h3Manager    *h3TransportManager
	sessionCache *sessioncache.Cache
	mu           sync.Mutex
	closed       bool
}

// New creates and initializes a new MyXray Client.
func New(cfg Config) (*Client, error) {
	if cfg.Server == "" || cfg.ServerName == "" || len(cfg.PSK) < 32 || cfg.Path == "" {
		return nil, errors.New("server, serverName, path, and valid PSK (>=32 bytes) are required")
	}
	if cfg.TCPTransport == "" {
		cfg.TCPTransport = DefaultTCPTransport
	}
	if cfg.TCPTransport != TCPTransportH2 && cfg.TCPTransport != TCPTransportAuto && cfg.TCPTransport != TCPTransportH3 {
		return nil, fmt.Errorf("invalid tcp transport %q: must be h2, auto or h3", cfg.TCPTransport)
	}
	if cfg.QUICInitialPacketSize == 0 {
		cfg.QUICInitialPacketSize = quicconfig.DefaultInitialPacketSize
	}

	port := portOf(cfg.Server)
	rootURL := "https://" + net.JoinHostPort(cfg.ServerName, port) + "/"
	requestURL := strings.TrimSuffix(rootURL, "/") + cfg.Path

	var cache *sessioncache.Cache
	if cfg.SessionCacheFile != "" {
		c, err := sessioncache.Open(cfg.SessionCacheFile)
		if err != nil {
			return nil, fmt.Errorf("open session cache: %w", err)
		}
		cache = c
	}

	h3Mgr := newH3TransportManager(cfg.Server, cfg.ServerName, rootURL, requestURL, cfg.Path, cfg.PSK, cache, cfg.QUICInitialPacketSize)

	var h2Cli *h2TransportClient
	if cfg.TCPTransport != TCPTransportH3 {
		var err error
		h2Cli, err = newH2TransportClient(cfg.Server, cfg.ServerName, rootURL, requestURL, cfg.Path, cfg.PSK)
		if err != nil {
			return nil, fmt.Errorf("init h2 client: %w", err)
		}
	}

	c := &Client{
		cfg:          cfg,
		rootURL:      rootURL,
		requestURL:   requestURL,
		h2Client:     h2Cli,
		h3Manager:    h3Mgr,
		sessionCache: cache,
	}
	return c, nil
}

// DialContext establishes an outbound TCP connection to target (host:port).
// Returns a standard net.Conn that can be directly used by Xray or Mihomo.
func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errors.New("client closed")
	}
	c.mu.Unlock()

	if c.h2Client != nil {
		conn, err := c.h2Client.dialH2TCP(ctx, address)
		if err == nil {
			return conn, nil
		}
		if c.cfg.TCPTransport == TCPTransportH2 {
			return nil, fmt.Errorf("h2 tcp dial failed: %w", err)
		}
		// In auto mode, fallback to H3
	}
	return c.h3Manager.dialH3TCP(ctx, address)
}

// ListenPacket creates a net.PacketConn for native UDP proxying over QUIC Datagrams.
// Returns a net.PacketConn that can be directly used by Xray or Mihomo for UDP associate / datagram dispatch.
func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errors.New("client closed")
	}
	c.mu.Unlock()

	return c.h3Manager.createPacketConn(ctx)
}

// Prewarm optionally warms the H2 TLS connection in advance.
func (c *Client) Prewarm(ctx context.Context) error {
	if c.h2Client != nil {
		return c.h2Client.prewarm(ctx)
	}
	return nil
}

// Close closes all idle connections and sessions.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if c.h2Client != nil {
		c.h2Client.close()
	}
	if c.h3Manager != nil {
		c.h3Manager.close()
	}
	return nil
}

func portOf(address string) string {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return "443"
	}
	return port
}

func signRequest(request *http.Request, psk []byte, path, target, mode string) error {
	nonceBytes := make([]byte, 18)
	if _, err := rand.Read(nonceBytes); err != nil {
		return err
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set(HeaderMode, mode)
	request.Header.Set(HeaderTarget, target)
	request.Header.Set(HeaderTimestamp, timestamp)
	request.Header.Set(HeaderNonce, nonce)
	request.Header.Set(HeaderSignature, auth.Signature(psk, request.Method, path, target, timestamp, nonce))
	return nil
}
