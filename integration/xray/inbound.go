package chitanda

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/violetaini/chitanda/pkg/auth"
	"github.com/violetaini/chitanda/pkg/server"

	"golang.org/x/net/http2"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// InboundHandler implements proxy.Inbound for Chitanda protocol in Xray
type InboundHandler struct {
	config       *InboundConfig
	server       *server.Server
	streamServer *server.StreamServer
	replays      *auth.ReplayCache
	dispatcher   routing.Dispatcher
	ctx          context.Context
	cancel       context.CancelFunc
	mu           sync.Mutex
}

func NewInboundHandler(ctx context.Context, config *InboundConfig) (*InboundHandler, error) {
	v := core.MustFromContext(ctx)
	dispatcher := v.GetFeature(routing.DispatcherType()).(routing.Dispatcher)

	var replays *auth.ReplayCache
	var err error
	if config.ReplayFile != "" {
		replays, err = auth.OpenReplayCache(config.ReplayFile, time.Now())
		if err != nil {
			return nil, fmt.Errorf("open replay cache: %w", err)
		}
	} else {
		replays = auth.NewReplayCache()
	}

	var fbHandler http.Handler
	if config.Fallback != "" {
		fb, err := server.NewFallback(config.Fallback, config.StrictSni)
		if err != nil {
			_ = replays.Close()
			return nil, fmt.Errorf("init fallback handler: %w", err)
		}
		fbHandler = fb
	}

	srv := server.NewServer(config.Path, []byte(config.Psk), replays, fbHandler, 1024)
	streamSrv := server.NewStreamServer([]byte(config.Psk), config.ServerId, replays, nil)

	inCtx, inCancel := context.WithCancel(context.Background())
	h := &InboundHandler{
		config:       config,
		server:       srv,
		streamServer: streamSrv,
		replays:      replays,
		dispatcher:   dispatcher,
		ctx:          inCtx,
		cancel:       inCancel,
	}

	dialTargetFn := func(ctx context.Context, address string) (net.Conn, error) {
		dest, err := xnet.ParseDestination("tcp:" + address)
		if err != nil {
			return nil, err
		}

		ctx = session.ContextWithInbound(ctx, &session.Inbound{
			Tag: "chitanda-inbound",
		})

		link, err := dispatcher.Dispatch(ctx, dest)
		if err != nil {
			return nil, err
		}

		return &pipeConn{
			reader:      &buf.BufferedReader{Reader: link.Reader},
			writer:      buf.NewBufferedWriter(link.Writer),
			readCloser:  link.Reader,
			writeCloser: link.Writer,
		}, nil
	}

	srv.SetDialTargetForTest(dialTargetFn)
	streamSrv.SetDialTargetForTest(dialTargetFn)

	return h, nil
}

func (h *InboundHandler) Network() []xnet.Network {
	return []xnet.Network{xnet.Network_TCP}
}

type bufferedConn struct {
	net.Conn
	br *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.br.Read(p)
}

type singleListener struct {
	conn   net.Conn
	once   sync.Once
	done   chan struct{}
	closed atomic.Bool
}

func (l *singleListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() {
		c = &closeNotifyConn{
			Conn: l.conn,
			onClose: func() {
				_ = l.Close()
			},
		}
	})
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *singleListener) Close() error {
	if l.closed.CompareAndSwap(false, true) {
		close(l.done)
		_ = l.conn.Close()
	}
	return nil
}

func (l *singleListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

type closeNotifyConn struct {
	net.Conn
	once    sync.Once
	onClose func()
}

func (c *closeNotifyConn) Close() error {
	c.once.Do(func() {
		if c.onClose != nil {
			c.onClose()
		}
	})
	return c.Conn.Close()
}

func (h *InboundHandler) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	if network != xnet.Network_TCP {
		return nil
	}
	defer conn.Close()

	if h.config.Transport == "stream" {
		return h.streamServer.HandleConn(conn)
	}

	br := bufio.NewReader(conn)
	prefix, err := br.Peek(4)
	if err != nil {
		return err
	}

	bconn := &bufferedConn{Conn: conn, br: br}

	if string(prefix) == "PRI " {
		// HTTP/2 Connection Preface
		h2Server := &http2.Server{}
		h2Server.ServeConn(bconn, &http2.ServeConnOpts{
			Handler: h.server,
			Context: ctx,
		})
		return nil
	}

	// HTTP/1.x
	sl := &singleListener{conn: bconn, done: make(chan struct{})}
	httpServer := &http.Server{
		Handler: h.server,
	}

	go func() {
		select {
		case <-ctx.Done():
			_ = sl.Close()
		case <-h.ctx.Done():
			_ = sl.Close()
		case <-sl.done:
		}
	}()

	return httpServer.Serve(sl)
}

func (h *InboundHandler) Close() error {
	h.cancel()
	if h.streamServer != nil {
		_ = h.streamServer.Close()
	}
	if h.replays != nil {
		_ = h.replays.Close()
	}
	return nil
}

type pipeConn struct {
	reader      *buf.BufferedReader
	writer      *buf.BufferedWriter
	readCloser  interface{}
	writeCloser interface{}
}

func (c *pipeConn) Read(b []byte) (n int, err error) {
	return c.reader.Read(b)
}

func (c *pipeConn) Write(b []byte) (n int, err error) {
	n, err = c.writer.Write(b)
	if err == nil {
		_ = c.writer.Flush()
	}
	return n, err
}

func (c *pipeConn) Close() error {
	_ = c.writer.Flush()
	var err1, err2 error
	if c.writeCloser != nil {
		err1 = common.Close(c.writeCloser)
	}
	if c.readCloser != nil {
		err2 = common.Close(c.readCloser)
	}
	if err1 != nil {
		return err1
	}
	return err2
}

func (c *pipeConn) LocalAddr() net.Addr                { return &net.TCPAddr{IP: net.IPv4zero, Port: 0} }
func (c *pipeConn) RemoteAddr() net.Addr               { return &net.TCPAddr{IP: net.IPv4zero, Port: 0} }
func (c *pipeConn) SetDeadline(t time.Time) error      { return nil }
func (c *pipeConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *pipeConn) SetWriteDeadline(t time.Time) error { return nil }

func init() {
	common.Must(common.RegisterConfig((*InboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewInboundHandler(ctx, config.(*InboundConfig))
	}))
}
