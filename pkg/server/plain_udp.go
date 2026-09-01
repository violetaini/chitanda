package server

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"myxray/internal/frame"
	"myxray/internal/plainudp"
	"myxray/internal/target"
)

type PlainUDPServer struct {
	codec      *plainudp.Codec
	conn       *net.UDPConn
	sessions   sync.Map // string(clientAddr) -> *plainUDPSession
	resolveUDP func(ctx context.Context, address string) (*net.UDPAddr, error)
	closed     atomic.Bool
}

type plainUDPSession struct {
	clientAddr *net.UDPAddr
	targets    sync.Map // string(targetAddr) -> *net.UDPConn
	lastActive atomic.Int64
	replayMu   sync.Mutex
	replay     frame.ReplayWindow
}

// NewPlainUDPServer creates a new plain-udp listener using a single pre-derived Codec instance.
func NewPlainUDPServer(conn *net.UDPConn, psk []byte) (*PlainUDPServer, error) {
	codec, err := plainudp.NewCodec(psk)
	if err != nil {
		return nil, err
	}
	return &PlainUDPServer{
		codec:      codec,
		conn:       conn,
		resolveUDP: target.ResolveUDPAddr,
	}, nil
}

// SetResolveUDPForTest overrides target resolution in unit tests.
func (s *PlainUDPServer) SetResolveUDPForTest(fn func(ctx context.Context, address string) (*net.UDPAddr, error)) {
	s.resolveUDP = fn
}

// Serve starts the UDP packet read loop.
func (s *PlainUDPServer) Serve(ctx context.Context) error {
	go s.cleaner(ctx)

	buf := make([]byte, 64<<10)
	for {
		if s.closed.Load() || ctx.Err() != nil {
			return nil
		}

		n, clientAddr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if s.closed.Load() {
				return nil
			}
			return err
		}

		now := time.Now()
		// 1. Decrypt and authenticate FIRST. Unauthenticated packets are dropped with zero state mutation.
		targetAddr, payload, _, seq, err := s.codec.DecodePacket(buf[:n], now)
		if err != nil {
			continue // Drop invalid / tampered / expired packets silently
		}

		// 2. Dispatch asynchronously so DNS / DialUDP never blocks the listener thread.
		go s.dispatch(ctx, clientAddr, targetAddr, payload, seq)
	}
}

func (s *PlainUDPServer) dispatch(ctx context.Context, clientAddr *net.UDPAddr, targetAddr string, payload []byte, seq uint64) {
	clientKey := clientAddr.String()
	val, _ := s.sessions.LoadOrStore(clientKey, &plainUDPSession{
		clientAddr: clientAddr,
	})
	session := val.(*plainUDPSession)
	session.lastActive.Store(time.Now().Unix())

	// 3. Check per-session replay window AFTER cryptographic authentication.
	session.replayMu.Lock()
	accepted := session.replay.Accept(seq)
	session.replayMu.Unlock()
	if !accepted {
		return // Drop replayed packet
	}

	targetConnVal, ok := session.targets.Load(targetAddr)
	var upstreamConn *net.UDPConn
	if !ok {
		resolved, err := s.resolveUDP(ctx, targetAddr)
		if err != nil {
			return
		}

		upConn, err := net.DialUDP("udp", nil, resolved)
		if err != nil {
			return
		}
		actual, loaded := session.targets.LoadOrStore(targetAddr, upConn)
		if loaded {
			_ = upConn.Close()
			upstreamConn = actual.(*net.UDPConn)
		} else {
			upstreamConn = upConn
			go s.listenUpstream(ctx, session, targetAddr, upstreamConn)
		}
	} else {
		upstreamConn = targetConnVal.(*net.UDPConn)
	}

	_, _ = upstreamConn.Write(payload)
}

func (s *PlainUDPServer) listenUpstream(ctx context.Context, session *plainUDPSession, targetAddr string, upstreamConn *net.UDPConn) {
	buf := make([]byte, 64<<10)
	for {
		if s.closed.Load() || ctx.Err() != nil {
			return
		}
		_ = upstreamConn.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := upstreamConn.Read(buf)
		if err != nil {
			session.targets.Delete(targetAddr)
			_ = upstreamConn.Close()
			return
		}

		session.lastActive.Store(time.Now().Unix())
		encrypted, err := s.codec.EncodePacket(nil, targetAddr, buf[:n], time.Now())
		if err != nil {
			continue
		}

		_, _ = s.conn.WriteToUDP(encrypted, session.clientAddr)
	}
}

func (s *PlainUDPServer) cleaner(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now().Unix()
			s.sessions.Range(func(key, value any) bool {
				session := value.(*plainUDPSession)
				if now-session.lastActive.Load() > 60 {
					session.targets.Range(func(tKey, tVal any) bool {
						_ = tVal.(*net.UDPConn).Close()
						session.targets.Delete(tKey)
						return true
					})
					s.sessions.Delete(key)
				}
				return true
			})
		}
	}
}

func (s *PlainUDPServer) Close() error {
	s.closed.Store(true)
	if s.conn != nil {
		_ = s.conn.Close()
	}
	s.sessions.Range(func(key, value any) bool {
		session := value.(*plainUDPSession)
		session.targets.Range(func(tKey, tVal any) bool {
			_ = tVal.(*net.UDPConn).Close()
			return true
		})
		s.sessions.Delete(key)
		return true
	})
	return nil
}
