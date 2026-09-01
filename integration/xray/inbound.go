package chitanda

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"

	"chitanda/pkg/server"

	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet"
)

// InboundHandler implements proxy.Inbound for Chitanda protocol in Xray
type InboundHandler struct {
	config     *InboundConfig
	server     *server.Server
	dispatcher routing.Dispatcher
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex
}

func NewInboundHandler(ctx context.Context, config *InboundConfig) (*InboundHandler, error) {
	v := core.MustFromContext(ctx)
	dispatcher := v.GetFeature(routing.DispatcherType()).(routing.Dispatcher)

	var fbHandler http.Handler
	if config.Fallback != "" {
		fb, err := server.NewFallback(config.Fallback, config.StrictSNI)
		if err != nil {
			return nil, fmt.Errorf("init fallback handler: %w", err)
		}
		fbHandler = fb
	}

	srv := server.NewServer(config.Path, []byte(config.PSK), nil, fbHandler, 1024)
	if config.StrictSNI != "" {
		srv.SetStrictServerName(config.StrictSNI)
	}

	inCtx, inCancel := context.WithCancel(context.Background())
	h := &InboundHandler{
		config:     config,
		server:     srv,
		dispatcher: dispatcher,
		ctx:        inCtx,
		cancel:     inCancel,
	}

	// Override upstream dialer: route through Xray Dispatcher!
	srv.SetDialTargetForTest(func(ctx context.Context, address string) (net.Conn, error) {
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

		return internet.NewConnection(link), nil
	})

	return h, nil
}

func (h *InboundHandler) Network() []xnet.Network {
	return []xnet.Network{xnet.Network_TCP, xnet.Network_UDP}
}

func (h *InboundHandler) Process(ctx context.Context, network xnet.Network, conn internet.Connection, dispatcher routing.Dispatcher) error {
	// Standard Xray connection handler
	return nil
}

func (h *InboundHandler) Close() error {
	h.cancel()
	return nil
}
