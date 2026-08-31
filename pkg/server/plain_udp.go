package server

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"myxray/internal/plainudp"
	"myxray/internal/target"
)

type PlainUDPServer struct {
	key        [32]byte
	conn       *net.UDPConn
	sessions   sync.Map // string(clientAddr) -> *plainUDPSession
	resolveUDP func(ctx context.Context, address string) (*net.UDPAddr, error)
	closed     atomic.Bool
}

type plainUDPSession struct {
	clientAddr *net.UDPAddr
	targets    sync.Map // string(targetAddr) -> *net.UDPConn
	lastActive atomic.Int64
}

// NewPlainUDPServer creates a new plain-udp listener.
func NewPlainUDPServer(conn *net.UDPConn, psk []byte) *PlainUDPServer {
	return &PlainUDPServer{
		key:        plainudp.DeriveKey(psk),
		conn:       conn,
		resolveUDP: target.ResolveUDPAddr,
	}
}

// SetResolveUDPForTest overrides target resolution in unit tests.
func (s *PlainUDPServer) SetResolveUDPForTest(fn func(ctx context.Context, address string) (*net.UDPAddr, error)) {
	s.resolveUDP = fn
}

// Serve starts the UDP packet read loop.
func (s *PlainUDPServer) Serve(ctx context.Context) error {
	go s.cleaner(ctx)

	buf := make([]byte, plainudp.MaxPacketSize)
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
		targetAddr, payload, _, err := plainudp.DecodePacket(s.key, buf[:n], now)
		if err != nil {
			continue // Drop invalid / tampered / expired packets silently
		}

		s.dispatch(ctx, clientAddr, targetAddr, payload)
	}
}

func (s *PlainUDPServer) dispatch(ctx context.Context, clientAddr *net.UDPAddr, targetAddr string, payload []byte) {
	clientKey := clientAddr.String()
	val, _ := s.sessions.LoadOrStore(clientKey, &plainUDPSession{
		clientAddr: clientAddr,
	})
	session := val.(*plainUDPSession)
	session.lastActive.Store(time.Now().Unix())

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
	buf := make([]byte, 2048)
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
		encrypted, err := plainudp.EncodePacket(s.key, targetAddr, buf[:n], time.Now())
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
