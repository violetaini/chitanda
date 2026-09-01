package server

import (
	"context"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"myxray/internal/frame"
	"myxray/internal/plainudp"
	"myxray/internal/target"
)

var udpTaskPool = sync.Pool{
	New: func() any {
		b := make([]byte, 64<<10)
		return &b
	},
}

type udpTask struct {
	sessionID  uint64
	clientAddr *net.UDPAddr
	targetAddr string
	payload    []byte
	rawBuf     *[]byte
	seq        uint64
}

type PlainUDPServer struct {
	codec      *plainudp.Codec
	conn       *net.UDPConn
	sessions   sync.Map // uint64(sessionID) -> *plainUDPSession
	workers    []chan udpTask
	resolveUDP func(ctx context.Context, address string) (*net.UDPAddr, error)
	closed     atomic.Bool
}

type plainUDPSession struct {
	sessionID  uint64
	clientAddr atomic.Pointer[net.UDPAddr]
	targets    sync.Map // string(targetAddr) -> *net.UDPConn
	lastActive atomic.Int64
	replayMu   sync.Mutex
	replay     frame.ReplayWindow
}

// NewPlainUDPServer creates a new plain-udp listener with a bounded worker pool.
func NewPlainUDPServer(conn *net.UDPConn, psk []byte) (*PlainUDPServer, error) {
	_ = conn.SetReadBuffer(8 << 20)
	_ = conn.SetWriteBuffer(8 << 20)

	codec, err := plainudp.NewCodec(psk)
	if err != nil {
		return nil, err
	}

	numWorkers := runtime.NumCPU() * 2
	if numWorkers < 8 {
		numWorkers = 8
	}
	workers := make([]chan udpTask, numWorkers)
	for i := range workers {
		workers[i] = make(chan udpTask, 4096)
	}

	return &PlainUDPServer{
		codec:      codec,
		conn:       conn,
		workers:    workers,
		resolveUDP: target.ResolveUDPAddr,
	}, nil
}

// SetResolveUDPForTest overrides target resolution in unit tests.
func (s *PlainUDPServer) SetResolveUDPForTest(fn func(ctx context.Context, address string) (*net.UDPAddr, error)) {
	s.resolveUDP = fn
}

// Serve starts the worker pool and the UDP packet read loop.
func (s *PlainUDPServer) Serve(ctx context.Context) error {
	go s.cleaner(ctx)

	for i, ch := range s.workers {
		go s.workerLoop(ctx, i, ch)
	}

	for {
		if s.closed.Load() || ctx.Err() != nil {
			return nil
		}

		rawBufPtr := udpTaskPool.Get().(*[]byte)
		n, clientAddr, err := s.conn.ReadFromUDP(*rawBufPtr)
		if err != nil {
			udpTaskPool.Put(rawBufPtr)
			if s.closed.Load() {
				return nil
			}
			return err
		}

		now := time.Now()
		sessionID, targetAddr, payload, _, seq, err := s.codec.DecodePacket((*rawBufPtr)[:n], now)
		if err != nil {
			udpTaskPool.Put(rawBufPtr)
			continue // Drop invalid / tampered / expired packets
		}

		workerIdx := sessionID % uint64(len(s.workers))
		task := udpTask{
			sessionID:  sessionID,
			clientAddr: clientAddr,
			targetAddr: targetAddr,
			payload:    payload,
			rawBuf:     rawBufPtr,
			seq:        seq,
		}

		select {
		case s.workers[workerIdx] <- task:
		default:
			// Under extreme burst load, drop packet and recycle buffer
			udpTaskPool.Put(rawBufPtr)
		}
	}
}

func (s *PlainUDPServer) workerLoop(ctx context.Context, workerID int, tasks <-chan udpTask) {
	for {
		select {
		case <-ctx.Done():
			return
		case task, ok := <-tasks:
			if !ok {
				return
			}
			s.processTask(ctx, task)
			udpTaskPool.Put(task.rawBuf)
		}
	}
}

func (s *PlainUDPServer) processTask(ctx context.Context, task udpTask) {
	val, _ := s.sessions.LoadOrStore(task.sessionID, &plainUDPSession{
		sessionID: task.sessionID,
	})
	session := val.(*plainUDPSession)
	session.clientAddr.Store(task.clientAddr)
	session.lastActive.Store(time.Now().Unix())

	session.replayMu.Lock()
	accepted := session.replay.Accept(task.seq)
	session.replayMu.Unlock()
	if !accepted {
		return
	}

	targetConnVal, ok := session.targets.Load(task.targetAddr)
	var upstreamConn *net.UDPConn
	if !ok {
		resolved, err := s.resolveUDP(ctx, task.targetAddr)
		if err != nil {
			return
		}

		upConn, err := net.DialUDP("udp", nil, resolved)
		if err != nil {
			return
		}
		_ = upConn.SetReadBuffer(8 << 20)
		_ = upConn.SetWriteBuffer(8 << 20)

		actual, loaded := session.targets.LoadOrStore(task.targetAddr, upConn)
		if loaded {
			_ = upConn.Close()
			upstreamConn = actual.(*net.UDPConn)
		} else {
			upstreamConn = upConn
			go s.listenUpstream(ctx, session, task.targetAddr, upstreamConn)
		}
	} else {
		upstreamConn = targetConnVal.(*net.UDPConn)
	}

	_, _ = upstreamConn.Write(task.payload)
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
		encrypted, err := s.codec.EncodePacket(nil, session.sessionID, targetAddr, buf[:n], time.Now())
		if err != nil {
			continue
		}

		clientAddr := session.clientAddr.Load()
		if clientAddr != nil {
			_, _ = s.conn.WriteToUDP(encrypted, clientAddr)
		}
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
	for _, ch := range s.workers {
		close(ch)
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
