package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

type h2TransportClient struct {
	server        string
	serverName    string
	rootURL       string
	requestURL    string
	path          string
	psk           []byte
	client        *http.Client
	transport     *http.Transport
	activeStreams atomic.Int64
}

func newH2TransportClient(server, serverName, rootURL, requestURL, path string, psk []byte) (*h2TransportClient, error) {
	transport := &http.Transport{
		Proxy:               nil,
		ForceAttemptHTTP2:   true,
		DisableCompression:  true,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     3 * time.Minute,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			ServerName: serverName,
		},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
			return dialer.DialContext(ctx, network, server)
		},
	}
	h2Transport, err := http2.ConfigureTransports(transport)
	if err != nil {
		return nil, err
	}
	h2Transport.ReadIdleTimeout = 45 * time.Second
	h2Transport.PingTimeout = 15 * time.Second
	h2Transport.MaxReadFrameSize = 1 << 20

	return &h2TransportClient{
		server:     server,
		serverName: serverName,
		rootURL:    rootURL,
		requestURL: requestURL,
		path:       path,
		psk:        psk,
		client:     &http.Client{Transport: transport},
		transport:  transport,
	}, nil
}

func (c *h2TransportClient) prewarm(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, c.rootURL, nil)
	if err != nil {
		return err
	}
	response, err := c.client.Do(request)
	if err != nil {
		return err
	}
	return response.Body.Close()
}

func (c *h2TransportClient) dialH2TCP(ctx context.Context, target string) (net.Conn, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		conn, err := c.dialH2TCPOnce(ctx, target)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if attempt == 0 {
			timer := time.NewTimer(100 * time.Millisecond)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			}
		}
	}
	return nil, lastErr
}

func (c *h2TransportClient) dialH2TCPOnce(ctx context.Context, target string) (net.Conn, error) {
	streamCtx, cancel := context.WithCancel(context.Background())
	pipeReader, pipeWriter := io.Pipe()

	request, err := http.NewRequestWithContext(streamCtx, http.MethodPost, c.requestURL, pipeReader)
	if err != nil {
		cancel()
		_ = pipeReader.Close()
		_ = pipeWriter.Close()
		return nil, fmt.Errorf("create h2 request: %w", err)
	}

	if err := signRequest(request, c.psk, c.path, target, ModeTCPv2); err != nil {
		cancel()
		_ = pipeReader.Close()
		_ = pipeWriter.Close()
		return nil, err
	}

	response, err := c.client.Do(request)
	if err != nil {
		cancel()
		_ = pipeReader.Close()
		_ = pipeWriter.Close()
		return nil, fmt.Errorf("h2 do request: %w", err)
	}

	if response.StatusCode != http.StatusOK {
		cancel()
		_ = response.Body.Close()
		_ = pipeWriter.Close()
		return nil, fmt.Errorf("unexpected status %d from %s", response.StatusCode, c.requestURL)
	}

	if response.Header.Get(HeaderSessionOK) != "1" {
		cancel()
		_ = response.Body.Close()
		_ = pipeWriter.Close()
		return nil, errors.New("missing session confirmation header")
	}

	c.activeStreams.Add(1)
	return newRawH2Conn(target, response.Body, pipeWriter, cancel, c), nil
}

func (c *h2TransportClient) close() {
	c.transport.CloseIdleConnections()
}

// rawH2Conn wraps HTTP/2 full duplex stream directly into net.Conn without custom framing.
type rawH2Conn struct {
	target     string
	body       io.ReadCloser
	pipeWriter *io.PipeWriter
	cancel     context.CancelFunc
	h2Client   *h2TransportClient
	closed     atomic.Bool
}

func newRawH2Conn(target string, body io.ReadCloser, pipeWriter *io.PipeWriter, cancel context.CancelFunc, h2Client *h2TransportClient) *rawH2Conn {
	return &rawH2Conn{
		target:     target,
		body:       body,
		pipeWriter: pipeWriter,
		cancel:     cancel,
		h2Client:   h2Client,
	}
}

func (c *rawH2Conn) Read(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, io.EOF
	}
	return c.body.Read(b)
}

func (c *rawH2Conn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if c.closed.Load() {
		return 0, errors.New("use of closed connection")
	}
	return c.pipeWriter.Write(b)
}

func (c *rawH2Conn) CloseWrite() error {
	return c.pipeWriter.Close()
}

func (c *rawH2Conn) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	if c.h2Client != nil {
		c.h2Client.activeStreams.Add(-1)
	}
	if c.cancel != nil {
		c.cancel()
	}
	_ = c.pipeWriter.CloseWithError(errors.New("use of closed network connection"))
	return c.body.Close()
}

func (c *rawH2Conn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func (c *rawH2Conn) RemoteAddr() net.Addr {
	host, portStr, err := net.SplitHostPort(c.target)
	if err == nil {
		var port int
		_, _ = fmt.Sscanf(portStr, "%d", &port)
		return &net.TCPAddr{IP: net.ParseIP(host), Port: port}
	}
	return &net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 0}
}

func (c *rawH2Conn) SetDeadline(t time.Time) error      { return nil }
func (c *rawH2Conn) SetReadDeadline(t time.Time) error  { return nil }
func (c *rawH2Conn) SetWriteDeadline(t time.Time) error { return nil }
