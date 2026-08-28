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
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"myxray/internal/frame"
	"myxray/internal/quicconfig"
	"myxray/internal/sessioncache"
)

type h3Connection struct {
	quic *quic.Conn
	h3   *http3.ClientConn
}

type h3TransportManager struct {
	mu           sync.Mutex
	server       string
	serverName   string
	rootURL      string
	requestURL   string
	path         string
	psk          []byte
	tlsConfig    *tls.Config
	quicConfig   *quic.Config
	transport    *http3.Transport
	sessionCache *sessioncache.Cache

	// Separate physical connections for TCP and UDP
	currentTCP *h3Connection
	currentUDP *h3Connection
}

func newH3TransportManager(
	server, serverName, rootURL, requestURL, path string,
	psk []byte,
	sessionCache *sessioncache.Cache,
	initialPacketSize uint16,
) *h3TransportManager {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: serverName,
		NextProtos: []string{http3.NextProtoH3},
	}
	if sessionCache != nil {
		tlsConfig.ClientSessionCache = sessionCache
	}
	return &h3TransportManager{
		server:       server,
		serverName:   serverName,
		rootURL:      rootURL,
		requestURL:   requestURL,
		path:         path,
		psk:          psk,
		tlsConfig:    tlsConfig,
		quicConfig:   quicconfig.Client(initialPacketSize),
		transport:    &http3.Transport{EnableDatagrams: true, DisableCompression: true},
		sessionCache: sessionCache,
	}
}

func (m *h3TransportManager) ensureConnection(ctx context.Context, current **h3Connection) (*h3Connection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if *current != nil && (*current).quic.Context().Err() == nil {
		return *current, nil
	}
	quicConn, err := quic.DialAddrEarly(ctx, m.server, m.tlsConfig.Clone(), m.quicConfig.Clone())
	if err != nil {
		return nil, err
	}
	*current = &h3Connection{quic: quicConn, h3: m.transport.NewClientConn(quicConn)}
	return *current, nil
}

func (m *h3TransportManager) ensureTCP(ctx context.Context) (*h3Connection, error) {
	return m.ensureConnection(ctx, &m.currentTCP)
}

func (m *h3TransportManager) ensureUDP(ctx context.Context) (*h3Connection, error) {
	return m.ensureConnection(ctx, &m.currentUDP)
}

func (m *h3TransportManager) invalidate(c *h3Connection) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.currentTCP == c {
		m.currentTCP = nil
		_ = c.quic.CloseWithError(0, "reconnect")
	}
	if m.currentUDP == c {
		m.currentUDP = nil
		_ = c.quic.CloseWithError(0, "reconnect")
	}
}

func (m *h3TransportManager) dialH3TCP(ctx context.Context, target string) (net.Conn, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		conn, err := m.dialH3TCPOnce(ctx, target)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if errors.Is(err, quic.Err0RTTRejected) && m.sessionCache != nil {
			_ = m.sessionCache.Clear()
		}
		if attempt == 0 {
			time.Sleep(100 * time.Millisecond)
		}
	}
	return nil, fmt.Errorf("H3 TCP dial failed: %w", lastErr)
}

func (m *h3TransportManager) dialH3TCPOnce(ctx context.Context, target string) (net.Conn, error) {
	h3Conn, err := m.ensureTCP(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := h3Conn.h3.OpenRequestStream(ctx)
	if err != nil {
		m.invalidate(h3Conn)
		return nil, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, m.requestURL, nil)
	if err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, err
	}
	if err := signRequest(request, m.psk, m.path, target, ModeTCPv2); err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, err
	}
	if err := stream.SendRequestHeader(request); err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		m.invalidate(h3Conn)
		return nil, err
	}
	if err := frame.WriteFrame(stream, frame.TypeOpen, 0, []byte(target)); err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		m.invalidate(h3Conn)
		return nil, err
	}

	response, err := stream.ReadResponse()
	if err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		m.invalidate(h3Conn)
		return nil, err
	}
	if response.StatusCode != http.StatusOK || response.Header.Get(HeaderSessionOK) != "1" {
		_ = response.Body.Close()
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, fmt.Errorf("server rejected H3 TCP session with status %d", response.StatusCode)
	}

	// Read OPEN_ACK
	hdr, err := frame.ReadHeader(stream)
	if err != nil || hdr.Type != frame.TypeOpenAck {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		m.invalidate(h3Conn)
		return nil, errors.New("missing OPEN_ACK")
	}

	return newH3FramedConn(target, stream), nil
}

func (m *h3TransportManager) createPacketConn(ctx context.Context) (net.PacketConn, error) {
	for attempt := 0; attempt < 2; attempt++ {
		pconn, err := m.createPacketConnOnce(ctx)
		if err == nil {
			return pconn, nil
		}
		if errors.Is(err, quic.Err0RTTRejected) && m.sessionCache != nil {
			_ = m.sessionCache.Clear()
		}
		if attempt == 0 {
			time.Sleep(100 * time.Millisecond)
		}
	}
	return nil, errors.New("establish H3 UDP packet connection failed")
}

func (m *h3TransportManager) createPacketConnOnce(ctx context.Context) (net.PacketConn, error) {
	h3Conn, err := m.ensureUDP(ctx)
	if err != nil {
		return nil, err
	}

	select {
	case <-h3Conn.h3.ReceivedSettings():
	case <-h3Conn.quic.Context().Done():
		m.invalidate(h3Conn)
		return nil, context.Cause(h3Conn.quic.Context())
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	settings := h3Conn.h3.Settings()
	if !settings.EnableDatagrams || !settings.EnableExtendedConnect {
		return nil, errors.New("server does not enable HTTP datagrams")
	}

	stream, err := h3Conn.h3.OpenRequestStream(ctx)
	if err != nil {
		m.invalidate(h3Conn)
		return nil, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodConnect, m.requestURL, nil)
	if err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, err
	}
	request.Proto = "connect-udp"
	if err := signRequest(request, m.psk, m.path, UDPAssociationTarget, ModeUDPv2); err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, err
	}
	if err := stream.SendRequestHeader(request); err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		m.invalidate(h3Conn)
		return nil, err
	}

	response, err := stream.ReadResponse()
	if err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		m.invalidate(h3Conn)
		return nil, err
	}
	if response.StatusCode != http.StatusOK || response.Header.Get(HeaderSessionOK) != "1" {
		_ = response.Body.Close()
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, fmt.Errorf("server rejected UDP association: status=%d", response.StatusCode)
	}

	pconnCtx, pconnCancel := context.WithCancel(context.Background())
	return &quicPacketConn{
		stream: stream,
		ctx:    pconnCtx,
		cancel: pconnCancel,
	}, nil
}

func (m *h3TransportManager) close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.currentTCP != nil {
		_ = m.currentTCP.quic.CloseWithError(0, "shutdown")
		m.currentTCP = nil
	}
	if m.currentUDP != nil {
		_ = m.currentUDP.quic.CloseWithError(0, "shutdown")
		m.currentUDP = nil
	}
	_ = m.transport.Close()
}

// h3FramedConn wraps an HTTP/3 request stream into a net.Conn.
type h3FramedConn struct {
	target     string
	stream     *http3.RequestStream
	readBuf    bytes.Buffer
	mu         sync.Mutex
	closed     bool
	readClosed bool
}

func newH3FramedConn(target string, stream *http3.RequestStream) *h3FramedConn {
	return &h3FramedConn{
		target: target,
		stream: stream,
	}
}

func (c *h3FramedConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.readBuf.Len() > 0 {
		return c.readBuf.Read(b)
	}
	if c.readClosed || c.closed {
		return 0, io.EOF
	}

	for {
		hdr, err := frame.ReadHeader(c.stream)
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
			payload, err := frame.ReadPayload(c.stream, hdr.Length)
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
			if hdr.Length > 0 {
				if _, err := io.CopyN(io.Discard, c.stream, int64(hdr.Length)); err != nil {
					return 0, err
				}
			}
		}
	}
}

func (c *h3FramedConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, errors.New("use of closed connection")
	}
	c.mu.Unlock()

	written := 0
	for written < len(b) {
		chunkSize := min(len(b)-written, frame.DataChunkSize)
		chunk := b[written : written+chunkSize]
		if err := frame.WriteFrame(c.stream, frame.TypeData, 0, chunk); err != nil {
			return written, err
		}
		written += len(chunk)
	}
	return written, nil
}

func (c *h3FramedConn) CloseWrite() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = frame.WriteFrame(c.stream, frame.TypeHalfClose, 0, nil)
	return c.stream.Close()
}

func (c *h3FramedConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	c.stream.CancelRead(0)
	c.stream.CancelWrite(0)
	return c.stream.Close()
}

func (c *h3FramedConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func (c *h3FramedConn) RemoteAddr() net.Addr {
	host, portStr, err := net.SplitHostPort(c.target)
	if err == nil {
		port, _ := strconv.Atoi(portStr)
		return &net.TCPAddr{IP: net.ParseIP(host), Port: port}
	}
	return &net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 0}
}

func (c *h3FramedConn) SetDeadline(t time.Time) error      { return c.stream.SetDeadline(t) }
func (c *h3FramedConn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *h3FramedConn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }

// quicPacketConn wraps HTTP/3 extended CONNECT-UDP + Datagrams into standard net.PacketConn.
type quicPacketConn struct {
	stream   *http3.RequestStream
	ctx      context.Context
	cancel   context.CancelFunc
	sequence atomic.Uint64
	replay   frame.ReplayWindow
	decoder  frame.DatagramCache
	mu       sync.Mutex
	closed   bool
}

func (c *quicPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for {
		if c.ctx.Err() != nil {
			return 0, nil, c.ctx.Err()
		}
		rawPacket, err := c.stream.ReceiveDatagram(c.ctx)
		if err != nil {
			return 0, nil, err
		}
		seq, address, payload, err := c.decoder.Decode(rawPacket)
		if err != nil || !c.replay.Accept(seq) {
			continue
		}
		n = copy(p, payload)
		udpAddr, _ := net.ResolveUDPAddr("udp", address)
		if udpAddr == nil {
			udpAddr = &net.UDPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 0}
		}
		return n, udpAddr, nil
	}
}

func (c *quicPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, errors.New("use of closed network connection")
	}
	c.mu.Unlock()

	address := addr.String()
	packet, err := frame.EncodeDatagram(c.sequence.Add(1), address, p)
	if err != nil {
		return 0, err
	}
	if err := c.stream.SendDatagram(packet); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *quicPacketConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	c.cancel()
	c.stream.CancelRead(0)
	c.stream.CancelWrite(0)
	return c.stream.Close()
}

func (c *quicPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func (c *quicPacketConn) SetDeadline(t time.Time) error      { return nil }
func (c *quicPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *quicPacketConn) SetWriteDeadline(t time.Time) error { return nil }
