package server

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/violetaini/chitanda/pkg/auth"
	"github.com/violetaini/chitanda/internal/rawstream"
	"github.com/violetaini/chitanda/internal/target"
)

// StreamServer handles Chitanda RawStream (TCP) and Native PlainUDP connections.
// It is hardened for IEPL/transit environments with zero Web footprint (probes receive instant RST/close).
type StreamServer struct {
	psk          []byte
	serverID     string
	dialTarget   func(ctx context.Context, network, address string) (net.Conn, error)
	listener     net.Listener
	udpServer    *PlainUDPServer
	replays      *auth.ReplayCache
	closed       atomic.Bool
	wg           sync.WaitGroup
	maxConns     int
	activeConns  atomic.Int64
	handshakeSem chan struct{}
	ctx          context.Context
	cancel       context.CancelFunc
}

// NewStreamServer creates a new StreamServer.
func NewStreamServer(psk []byte, serverID string, replays *auth.ReplayCache, dialTarget func(ctx context.Context, network, address string) (net.Conn, error)) *StreamServer {
	if dialTarget == nil {
		dialTarget = func(ctx context.Context, network, address string) (net.Conn, error) {
			return target.DialContext(ctx, address)
		}
	}
	if replays == nil {
		replays = auth.NewReplayCache()
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &StreamServer{
		psk:          psk,
		serverID:     serverID,
		dialTarget:   dialTarget,
		replays:      replays,
		maxConns:     10000,
		handshakeSem: make(chan struct{}, 512),
		ctx:          ctx,
		cancel:       cancel,
	}
}

// SetMaxConns sets the maximum number of concurrent connections (for testing or configuration).
func (s *StreamServer) SetMaxConns(n int) {
	s.maxConns = n
}

// SetHandshakeLimit sets the maximum number of concurrent pending handshakes.
func (s *StreamServer) SetHandshakeLimit(n int) {
	s.handshakeSem = make(chan struct{}, n)
}

// SetReplayCache sets an explicit ReplayCache instance (e.g. for persistent storage or tests).
func (s *StreamServer) SetReplayCache(cache *auth.ReplayCache) {
	if cache != nil {
		s.replays = cache
	}
}

// AttachUDP binds a Native PlainUDP listener to this server and starts the UDP serve loop.
func (s *StreamServer) AttachUDP(udpConn *net.UDPConn) error {
	udpSrv, err := NewPlainUDPServer(udpConn, s.psk)
	if err != nil {
		return err
	}
	s.udpServer = udpSrv
	go func() {
		_ = udpSrv.Serve(context.Background())
	}()
	return nil
}

// UDPServer returns the underlying PlainUDPServer instance.
func (s *StreamServer) UDPServer() *PlainUDPServer {
	return s.udpServer
}

// Serve starts accepting connections on the provided TCP listener.
func (s *StreamServer) Serve(l net.Listener) error {
	s.listener = l
	for {
		conn, err := l.Accept()
		if err != nil {
			if s.closed.Load() {
				return nil
			}
			return err
		}

		if s.maxConns > 0 && s.activeConns.Load() >= int64(s.maxConns) {
			_ = conn.Close()
			continue
		}

		// Enforce bounded concurrent handshakes
		select {
		case s.handshakeSem <- struct{}{}:
		default:
			// Handshake pool full, shed load immediately
			_ = conn.Close()
			continue
		}

		s.activeConns.Add(1)
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			defer s.activeConns.Add(-1)
			s.HandleConn(c)
		}(conn)
	}
}

// HandleConn processes an incoming raw TCP connection.
// If any authentication or framing step fails (e.g. Aodun/scanner sending GET / HTTP/1.1),
// it immediately terminates the connection without returning any data.
func (s *StreamServer) HandleConn(conn net.Conn) {
	defer conn.Close()

	handshakeReleased := false
	releaseHandshake := func() {
		if !handshakeReleased {
			handshakeReleased = true
			<-s.handshakeSem
		}
	}
	defer releaseHandshake()

	// 2-second deadline for the initial handshake flight
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	// 1. Read ClientHello (48 bytes)
	var clientHelloBuf [rawstream.ClientHelloSize]byte
	if _, err := io.ReadFull(conn, clientHelloBuf[:]); err != nil {
		return
	}

	clientNonce, ts, err := rawstream.VerifyClientHello(s.psk, s.serverID, clientHelloBuf[:], time.Now())
	if err != nil {
		// Authentication failed (e.g. GET / HTTP/1.1 sent by scanner or mismatched serverID):
		// Close immediately with 0 bytes response. Never speak HTTP.
		return
	}

	// 2. Early non-mutating check in replay cache
	nonceHex := hex.EncodeToString(clientNonce[:])
	if s.replays.Check(nonceHex, time.Now()) {
		// Replayed handshake detected: drop immediately with 0 bytes
		return
	}

	// 3. Read 2-byte wire length of the 0-RTT frame
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return
	}
	wireLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if wireLen <= 16 || wireLen > rawstream.MaxChunkWireLen {
		return
	}

	// 4. Read encrypted 0-RTT frame
	encFrame := make([]byte, wireLen)
	if _, err := io.ReadFull(conn, encFrame); err != nil {
		return
	}

	// 5. Derive 0-RTT key and decrypt open frame
	k0RTT, err := rawstream.Derive0RTTKey(s.psk, s.serverID, ts, clientNonce)
	if err != nil {
		return
	}

	openFramePlaintext, err := rawstream.Decrypt0RTTChunk(k0RTT, encFrame)
	if err != nil {
		// Decryption failed: drop with 0 bytes, do NOT commit replay cache
		return
	}

	// 6. Decode target and optional initial payload (strips dynamic padding)
	targetAddr, initialPayload, err := rawstream.Decode0RTTOpenFrame(openFramePlaintext)
	if err != nil {
		// Invalid open frame / target: drop with 0 bytes, do NOT commit replay cache
		return
	}

	// 7. Both ClientHello and 0-RTT frame validated: commit Nonce to durable replay cache
	accepted, err := s.replays.Accept(nonceHex, time.Now())
	if err != nil || !accepted {
		// Concurrent replay race: drop
		return
	}

	// 8. Generate ServerHello (40 bytes)
	serverHelloRecord, serverNonce, err := rawstream.CreateServerHello(s.psk, s.serverID, ts, clientNonce)
	if err != nil {
		return
	}

	// 9. Write ServerHello to client
	if _, err := conn.Write(serverHelloRecord); err != nil {
		return
	}

	// 10. Derive bidirectional session keys
	c2sKey, s2cKey, err := rawstream.DeriveSessionKeys(s.psk, s.serverID, ts, clientNonce, serverNonce)
	if err != nil {
		return
	}

	// 11. Dial upstream target
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	upstream, err := s.dialTarget(ctx, "tcp", targetAddr)
	if err != nil {
		return
	}
	defer upstream.Close()

	// Handshake successfully completed: release handshake token early
	releaseHandshake()

	// Upgrade TCP buffer sizes only for authenticated and connected sessions
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetReadBuffer(4 << 20)
		_ = tc.SetWriteBuffer(4 << 20)
	}
	if tc, ok := upstream.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetReadBuffer(4 << 20)
		_ = tc.SetWriteBuffer(4 << 20)
	}

	// Clear deadlines for full-duplex proxying
	_ = conn.SetDeadline(time.Time{})

	// 12. Send initial payload to upstream if present
	if len(initialPayload) > 0 {
		if _, err := upstream.Write(initialPayload); err != nil {
			return
		}
	}

	// 13. Wrap client connection in AEAD StreamConn
	rStream, err := rawstream.NewAEADStream(c2sKey)
	if err != nil {
		return
	}
	wStream, err := rawstream.NewAEADStream(s2cKey)
	if err != nil {
		return
	}
	streamConn := rawstream.NewStreamConn(conn, rStream, wStream)

	// 14. Bidirectional relay
	relayBidirectional(s.ctx, streamConn, upstream)
}

type closeWriter interface {
	CloseWrite() error
}

func closeWriteConn(c net.Conn) {
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

func relayBidirectional(ctx context.Context, client, target net.Conn) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		<-ctx.Done()
		_ = client.Close()
		_ = target.Close()
	}()

	// client -> target
	go func() {
		defer wg.Done()
		bufPtr := copyBufferPool.Get().(*[]byte)
		defer copyBufferPool.Put(bufPtr)
		_, err := io.CopyBuffer(target, client, *bufPtr)
		if err != nil {
			cancel()
			return
		}
		closeWriteConn(target)
	}()

	// target -> client
	go func() {
		defer wg.Done()
		bufPtr := copyBufferPool.Get().(*[]byte)
		defer copyBufferPool.Put(bufPtr)
		_, err := io.CopyBuffer(client, target, *bufPtr)
		if err != nil {
			cancel()
			return
		}
		closeWriteConn(client)
	}()

	wg.Wait()
}

// Close gracefully closes the listener, replay cache, and active PlainUDP server.
func (s *StreamServer) Close() error {
	s.closed.Store(true)
	if s.cancel != nil {
		s.cancel()
	}
	var firstErr error
	if s.listener != nil {
		if err := s.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			firstErr = err
		}
	}
	if s.udpServer != nil {
		s.udpServer.Close()
	}
	if s.replays != nil {
		_ = s.replays.Close()
	}
	s.wg.Wait()
	return firstErr
}
