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

	"github.com/violetaini/chitanda/internal/auth"
	"github.com/violetaini/chitanda/internal/rawstream"
	"github.com/violetaini/chitanda/internal/target"
)

// StreamServer handles Chitanda RawStream (TCP) and Native PlainUDP connections.
// It is hardened for IEPL/transit environments with zero Web footprint (probes receive instant RST/close).
type StreamServer struct {
	psk        []byte
	dialTarget func(ctx context.Context, network, address string) (net.Conn, error)
	listener   net.Listener
	udpServer  *PlainUDPServer
	replays    *auth.ReplayCache
	closed     atomic.Bool
	wg         sync.WaitGroup
}

// NewStreamServer creates a new StreamServer.
func NewStreamServer(psk []byte, dialTarget func(ctx context.Context, network, address string) (net.Conn, error)) *StreamServer {
	if dialTarget == nil {
		dialTarget = func(ctx context.Context, network, address string) (net.Conn, error) {
			return target.DialContext(ctx, address)
		}
	}
	return &StreamServer{
		psk:        psk,
		dialTarget: dialTarget,
		replays:    auth.NewReplayCache(),
	}
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

		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			s.HandleConn(c)
		}(conn)
	}
}

// HandleConn processes an incoming raw TCP connection.
// If any authentication or framing step fails (e.g. Aodun/scanner sending GET / HTTP/1.1),
// it immediately terminates the connection without returning any data.
func (s *StreamServer) HandleConn(conn net.Conn) {
	defer conn.Close()

	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetReadBuffer(4 << 20)
		_ = tc.SetWriteBuffer(4 << 20)
	}

	// 5-second deadline for the initial handshake flight
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// 1. Read ClientHello (48 bytes)
	var clientHelloBuf [rawstream.ClientHelloSize]byte
	if _, err := io.ReadFull(conn, clientHelloBuf[:]); err != nil {
		// Probable scanner probe or truncated connection: close immediately
		return
	}

	clientNonce, ts, err := rawstream.VerifyClientHello(s.psk, clientHelloBuf[:], time.Now())
	if err != nil {
		// Authentication failed (e.g. GET / HTTP/1.1 sent by scanner):
		// Close immediately with 0 bytes response. Never speak HTTP.
		return
	}

	// Prevent 0-RTT replay and active probe confirmation
	nonceHex := hex.EncodeToString(clientNonce[:])
	accepted, err := s.replays.Accept(nonceHex, time.Now())
	if err != nil || !accepted {
		// Replayed handshake or replay cache failure:
		// Drop immediately with 0 bytes response to prevent active probing
		return
	}

	// 2. Read 2-byte wire length of the 0-RTT frame
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return
	}
	wireLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if wireLen <= 16 || wireLen > rawstream.MaxChunkWireLen {
		return
	}

	// 3. Read encrypted 0-RTT frame
	encFrame := make([]byte, wireLen)
	if _, err := io.ReadFull(conn, encFrame); err != nil {
		return
	}

	// 4. Derive 0-RTT key and decrypt open frame
	k0RTT, err := rawstream.Derive0RTTKey(s.psk, ts, clientNonce)
	if err != nil {
		return
	}

	openFramePlaintext, err := rawstream.Decrypt0RTTChunk(k0RTT, encFrame)
	if err != nil {
		return
	}

	// 5. Decode cipher type, target, and optional initial payload (strips dynamic padding)
	cipherType, targetAddr, initialPayload, err := rawstream.Decode0RTTOpenFrame(openFramePlaintext)
	if err != nil {
		return
	}

	// 6. Generate ServerHello (40 bytes)
	serverHelloRecord, serverNonce, err := rawstream.CreateServerHello(s.psk, ts, clientNonce)
	if err != nil {
		return
	}

	// 7. Write ServerHello to client
	if _, err := conn.Write(serverHelloRecord); err != nil {
		return
	}

	// 8. Derive bidirectional session keys
	c2sKey, s2cKey, err := rawstream.DeriveSessionKeys(s.psk, ts, clientNonce, serverNonce)
	if err != nil {
		return
	}

	// 9. Dial upstream target
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	upstream, err := s.dialTarget(ctx, "tcp", targetAddr)
	if err != nil {
		return
	}
	defer upstream.Close()

	if tc, ok := upstream.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetReadBuffer(4 << 20)
		_ = tc.SetWriteBuffer(4 << 20)
	}

	// Clear deadlines for full-duplex proxying
	_ = conn.SetDeadline(time.Time{})

	// 10. Send initial payload to upstream if present
	if len(initialPayload) > 0 {
		if _, err := upstream.Write(initialPayload); err != nil {
			return
		}
	}

	// 11. Wrap client connection in AEAD StreamConn
	rStream, err := rawstream.NewAEADStream(cipherType, c2sKey)
	if err != nil {
		return
	}
	wStream, err := rawstream.NewAEADStream(cipherType, s2cKey)
	if err != nil {
		return
	}
	streamConn := rawstream.NewStreamConn(conn, rStream, wStream)

	// 12. Bidirectional relay
	relayBidirectional(streamConn, upstream)
}

type closeWriter interface {
	CloseWrite() error
}

func closeWriteConn(c net.Conn) {
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

func relayBidirectional(client, target net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	// client -> target
	go func() {
		defer wg.Done()
		bufPtr := copyBufferPool.Get().(*[]byte)
		defer copyBufferPool.Put(bufPtr)
		_, err := io.CopyBuffer(target, client, *bufPtr)
		if err != nil {
			_ = target.Close()
			_ = client.Close()
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
			_ = client.Close()
			_ = target.Close()
			return
		}
		closeWriteConn(client)
	}()

	wg.Wait()
}

// Close gracefully closes the listener, replay cache, and active PlainUDP server.
func (s *StreamServer) Close() error {
	s.closed.Store(true)
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
