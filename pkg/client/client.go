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
	"sync/atomic"
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
	UDPAssociationTarget = "udp-association"

	TCPTransportAuto    = "auto"
	TCPTransportH2      = "h2"
	TCPTransportH3      = "h3"
	TCPTransportPlainH1 = "plain-h1"
	TCPTransportH1      = "h1"
	DefaultTCPTransport = TCPTransportH2
	DefaultTCPPoolSize  = 4

	defaultCarrierTimeout = 15 * time.Second
	autoH2ConnectTimeout  = 4 * time.Second
)

// Config holds the client configuration.
type Config struct {
	Server                string // e.g. "170.9.59.149:11322"
	ServerName            string // e.g. "status.chitanda.org"
	PSK                   []byte // 32+ bytes PSK
	Path                  string // e.g. "/your-private-path"
	TCPTransport          string // "h2" (default), "auto", "h3", or "plain-h1"
	TCPPoolSize           int    // Number of independent physical TCP carriers (H2 or H3, default 4)
	SessionCacheFile      string // optional persistent session cache path
	QUICInitialPacketSize uint16 // 1200 - 1452, default 1452
}

// Client is the MyXray core client engine.
type Client struct {
	cfg          Config
	rootURL      string
	requestURL   string
	h2Clients    []*h2TransportClient
	nextH2Idx    atomic.Uint64
	h3Managers   []*h3TransportManager
	sessionCache *sessioncache.Cache
	prober       *h2Prober
	mu           sync.Mutex
	closed       bool
}

// New creates and initializes a new MyXray Client.
func New(cfg Config) (*Client, error) {
	if cfg.TCPTransport == TCPTransportPlainH1 || cfg.TCPTransport == TCPTransportH1 {
		if cfg.Server == "" || len(cfg.PSK) < 32 || cfg.Path == "" {
			return nil, errors.New("server, path, and valid PSK (>=32 bytes) are required for plain-h1")
		}
		if cfg.ServerName == "" {
			cfg.ServerName = cfg.Server
		}
	} else {
		if cfg.Server == "" || cfg.ServerName == "" || len(cfg.PSK) < 32 || cfg.Path == "" {
			return nil, errors.New("server, serverName, path, and valid PSK (>=32 bytes) are required")
		}
	}
	if cfg.TCPTransport == "" {
		cfg.TCPTransport = DefaultTCPTransport
	}
	if cfg.TCPTransport != TCPTransportH2 && cfg.TCPTransport != TCPTransportAuto && cfg.TCPTransport != TCPTransportH3 && cfg.TCPTransport != TCPTransportPlainH1 && cfg.TCPTransport != TCPTransportH1 {
		return nil, fmt.Errorf("invalid tcp transport %q: must be h2, auto, h3, or plain-h1", cfg.TCPTransport)
	}
	if cfg.TCPPoolSize <= 0 {
		cfg.TCPPoolSize = DefaultTCPPoolSize
	}
	if cfg.TCPPoolSize > 16 {
		cfg.TCPPoolSize = 16
	}
	if cfg.QUICInitialPacketSize == 0 {
		cfg.QUICInitialPacketSize = quicconfig.DefaultInitialPacketSize
	}

	port := portOf(cfg.Server)
	scheme := "https://"
	if cfg.TCPTransport == TCPTransportPlainH1 || cfg.TCPTransport == TCPTransportH1 {
		scheme = "http://"
	}
	rootURL := scheme + net.JoinHostPort(cfg.ServerName, port) + "/"
	requestURL := strings.TrimSuffix(rootURL, "/") + cfg.Path

	var cache *sessioncache.Cache
	if cfg.SessionCacheFile != "" {
		c, err := sessioncache.Open(cfg.SessionCacheFile)
		if err == nil {
			cache = c
		}
	}

	var h2Clients []*h2TransportClient
	var h3Managers []*h3TransportManager

	if cfg.TCPTransport != TCPTransportPlainH1 && cfg.TCPTransport != TCPTransportH1 {
		// H2 / H3 initialization
		h2Count := cfg.TCPPoolSize
		if cfg.TCPTransport == TCPTransportH3 {
			h2Count = 0
		}
		for i := 0; i < h2Count; i++ {
			h2Cli, err := newH2TransportClient(cfg.Server, cfg.ServerName, rootURL, requestURL, cfg.Path, cfg.PSK)
			if err != nil {
				return nil, fmt.Errorf("init h2 client %d: %w", i, err)
			}
			h2Clients = append(h2Clients, h2Cli)
		}

		h3Count := 1
		if cfg.TCPTransport == TCPTransportH3 {
			h3Count = cfg.TCPPoolSize
		} else if cfg.TCPTransport == TCPTransportAuto {
			h3Count = cfg.TCPPoolSize
		}
		for i := 0; i < h3Count; i++ {
			h3Managers = append(h3Managers, newH3TransportManager(
				cfg.Server, cfg.ServerName, rootURL, requestURL, cfg.Path, cfg.PSK, cache, cfg.QUICInitialPacketSize,
			))
		}
	}

	c := &Client{
		cfg:          cfg,
		rootURL:      rootURL,
		requestURL:   requestURL,
		h2Clients:    h2Clients,
		h3Managers:   h3Managers,
		sessionCache: cache,
	}
	if cfg.TCPTransport == TCPTransportAuto {
		c.prober = newH2Prober(c)
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

	if c.cfg.TCPTransport == TCPTransportPlainH1 || c.cfg.TCPTransport == TCPTransportH1 {
		return c.dialPlainH1(ctx, address)
	}

	if c.cfg.TCPTransport == TCPTransportH2 || (c.cfg.TCPTransport == TCPTransportAuto && !c.prober.h2Degraded.Load()) {
		if h2Cli := c.pickBestH2Client(); h2Cli != nil {
			conn, err := h2Cli.dialH2TCP(ctx, address)
			if err == nil {
				return conn, nil
			}
			if c.cfg.TCPTransport == TCPTransportH2 {
				return nil, fmt.Errorf("h2 tcp dial failed: %w", err)
			}
			// In auto mode, fallback to H3
		}
	}
	h3Mgr := c.reserveH3Manager()
	if h3Mgr == nil {
		return nil, errors.New("no H3 transport available")
	}
	conn, err := h3Mgr.dialH3TCP(ctx, address)
	if err != nil {
		h3Mgr.activeStreams.Add(-1)
		return nil, err
	}
	return conn, nil
}

func (c *Client) pickBestH2Client() *h2TransportClient {
	if len(c.h2Clients) == 0 {
		return nil
	}
	if len(c.h2Clients) == 1 {
		return c.h2Clients[0]
	}

	best := c.h2Clients[0]
	minActive := best.activeStreams.Load()

	for _, cli := range c.h2Clients[1:] {
		active := cli.activeStreams.Load()
		if active < minActive {
			minActive = active
			best = cli
		}
	}
	return best
}

func (c *Client) pickBestH3Manager() *h3TransportManager {
	if len(c.h3Managers) == 0 {
		return nil
	}
	best := c.h3Managers[0]
	minActive := best.activeStreams.Load()
	for _, manager := range c.h3Managers[1:] {
		active := manager.activeStreams.Load()
		if active < minActive {
			minActive = active
			best = manager
		}
	}
	return best
}

func (c *Client) reserveH3Manager() *h3TransportManager {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	manager := c.pickBestH3Manager()
	if manager != nil {
		manager.activeStreams.Add(1)
	}
	return manager
}

// ListenPacket creates a net.PacketConn for native UDP proxying over QUIC Datagrams (or Plain-UDP Datagrams).
// Returns a net.PacketConn that can be directly used by Xray or Mihomo for UDP associate / datagram dispatch.
func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errors.New("client closed")
	}
	c.mu.Unlock()

	if c.cfg.TCPTransport == TCPTransportPlainH1 || c.cfg.TCPTransport == TCPTransportH1 {
		return newPlainUDPConn(c.cfg.Server, c.cfg.PSK)
	}

	h3Mgr := c.reserveH3Manager()
	if h3Mgr == nil {
		return nil, errors.New("no H3 transport available")
	}
	pconn, err := h3Mgr.createPacketConn(ctx)
	if err != nil {
		h3Mgr.activeStreams.Add(-1)
		return nil, err
	}
	return pconn, nil
}

// Prewarm optionally warms the H2 TLS connections in the pool concurrently.
func (c *Client) Prewarm(ctx context.Context) error {
	prewarmCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	for _, cli := range c.h2Clients {
		wg.Add(1)
		go func(h *h2TransportClient) {
			defer wg.Done()
			_ = h.prewarm(prewarmCtx)
		}(cli)
	}
	wg.Wait()
	return nil
}

// Close terminates the client and all background connections.
func (c *Client) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.mu.Unlock()

	if c.prober != nil {
		c.prober.Close()
	}

	for _, cli := range c.h2Clients {
		cli.close()
	}
	for _, manager := range c.h3Managers {
		manager.close()
	}
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
	request.Header.Set(HeaderSignature, auth.Signature(psk, mode, request.Method, path, target, timestamp, nonce))
	return nil
}
