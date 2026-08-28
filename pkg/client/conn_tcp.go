package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"

	"myxray/internal/frame"
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

	if err := signRequest(request, c.psk, c.path, target, ModeTCPH2Framed); err != nil {
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
	return newH2FramedConn(target, response.Body, pipeWriter, cancel, c), nil
}

func (c *h2TransportClient) close() {
	c.transport.CloseIdleConnections()
}

// framedConn wraps HTTP/2 full duplex stream with private frame protocol into net.Conn.
type framedConn struct {
	target     string
	body       io.ReadCloser
	pipeWriter *io.PipeWriter
	cancel     context.CancelFunc
	h2Client   *h2TransportClient

	readMx     sync.Mutex
	readBuf    bytes.Buffer
	closed     atomic.Bool
	readClosed bool
}

func newH2FramedConn(target string, body io.ReadCloser, pipeWriter *io.PipeWriter, cancel context.CancelFunc, h2Client *h2TransportClient) *framedConn {
	return &framedConn{
		target:     target,
		body:       body,
		pipeWriter: pipeWriter,
		cancel:     cancel,
		h2Client:   h2Client,
	}
}

func (c *framedConn) Read(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, io.EOF
	}

	c.readMx.Lock()
	defer c.readMx.Unlock()

	if c.readBuf.Len() > 0 {
		return c.readBuf.Read(b)
	}
	if c.readClosed || c.closed.Load() {
		return 0, io.EOF
	}

	for {
		hdr, err := frame.ReadHeader(c.body)
		if err != nil {
			if errors.Is(err, io.EOF) || c.closed.Load() {
				c.readClosed = true
				return 0, io.EOF
			}
			return 0, err
		}
		switch hdr.Type {
		case frame.TypeData:
			if hdr.Length == 0 {
				continue
			}
			if len(b) >= int(hdr.Length) {
				// Direct in-place zero-allocation read
				if _, err := io.ReadFull(c.body, b[:hdr.Length]); err != nil {
					return 0, err
				}
				return int(hdr.Length), nil
			}
			payload, err := frame.ReadPayload(c.body, hdr.Length)
			if err != nil {
				return 0, err
			}
			n := copy(b, payload)
			if n < len(payload) {
				c.readBuf.Write(payload[n:])
			}
			return n, nil
		case frame.TypeHalfClose:
			c.readClosed = true
			return 0, io.EOF
		case frame.TypeReset:
			c.readClosed = true
			return 0, errors.New("stream reset by peer")
		default:
			// Discard unknown frame payloads
			if hdr.Length > 0 {
				if _, err := io.CopyN(io.Discard, c.body, int64(hdr.Length)); err != nil {
					return 0, err
				}
			}
		}
	}
}

func (c *framedConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if c.closed.Load() {
		return 0, errors.New("use of closed connection")
	}

	return c.pipeWriter.Write(b)
}

func (c *framedConn) CloseWrite() error {
	return c.pipeWriter.Close()
}

func (c *framedConn) Close() error {
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

func (c *framedConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func (c *framedConn) RemoteAddr() net.Addr {
	host, portStr, err := net.SplitHostPort(c.target)
	if err == nil {
		var port int
		_, _ = fmt.Sscanf(portStr, "%d", &port)
		return &net.TCPAddr{IP: net.ParseIP(host), Port: port}
	}
	return &net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 0}
}

func (c *framedConn) SetDeadline(t time.Time) error      { return nil }
func (c *framedConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *framedConn) SetWriteDeadline(t time.Time) error { return nil }
