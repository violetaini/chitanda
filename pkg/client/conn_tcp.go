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
	"time"

	"golang.org/x/net/http2"

	"myxray/internal/frame"
)

type h2TransportClient struct {
	server     string
	serverName string
	rootURL    string
	requestURL string
	path       string
	psk        []byte
	client     *http.Client
	transport  *http.Transport
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
	streamCtx, streamCancel := context.WithCancel(context.Background())
	reader, writer := io.Pipe()
	request, err := http.NewRequestWithContext(streamCtx, http.MethodPost, c.requestURL, reader)
	if err != nil {
		streamCancel()
		_ = writer.CloseWithError(err)
		return nil, err
	}
	if err := signRequest(request, c.psk, c.path, target, ModeTCPH2Framed); err != nil {
		streamCancel()
		_ = writer.CloseWithError(err)
		return nil, err
	}

	response, err := c.client.Do(request)
	if err != nil {
		streamCancel()
		_ = writer.CloseWithError(err)
		return nil, err
	}
	if response.StatusCode != http.StatusOK ||
		response.Header.Get(HeaderSessionOK) != "1" ||
		response.Header.Get(HeaderFraming) != "1" {
		_ = response.Body.Close()
		streamCancel()
		err = errors.New("HTTP/2 carrier rejected session")
		_ = writer.CloseWithError(err)
		return nil, err
	}

	return newH2FramedConn(target, response.Body, writer, streamCancel), nil
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

	readBuf    bytes.Buffer
	mu         sync.Mutex
	closed     bool
	readClosed bool
}

func newH2FramedConn(target string, body io.ReadCloser, pipeWriter *io.PipeWriter, cancel context.CancelFunc) *framedConn {
	return &framedConn{
		target:     target,
		body:       body,
		pipeWriter: pipeWriter,
		cancel:     cancel,
	}
}

func (c *framedConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.readBuf.Len() > 0 {
		return c.readBuf.Read(b)
	}
	if c.readClosed || c.closed {
		return 0, io.EOF
	}

	for {
		hdr, err := frame.ReadHeader(c.body)
		if err != nil {
			if errors.Is(err, io.EOF) {
				c.readClosed = true
			}
			return 0, err
		}
		switch hdr.Type {
		case frame.TypeData:
			if hdr.Length == 0 {
				continue
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
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, errors.New("use of closed connection")
	}
	c.mu.Unlock()

	return c.pipeWriter.Write(b)
}

func (c *framedConn) CloseWrite() error {
	return c.pipeWriter.Close()
}

func (c *framedConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if c.cancel != nil {
		c.cancel()
	}
	_ = c.pipeWriter.Close()
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
