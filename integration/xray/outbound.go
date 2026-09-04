package chitanda

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/violetaini/chitanda/pkg/client"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

// OutboundHandler implements proxy.Outbound for Chitanda protocol in Xray
type OutboundHandler struct {
	config *OutboundConfig
	client *client.Client
	policy policy.Manager
	initMu sync.Mutex
}

func NewOutboundHandler(ctx context.Context, config *OutboundConfig) (*OutboundHandler, error) {
	v := core.MustFromContext(ctx)
	pm := v.GetFeature(policy.ManagerType()).(policy.Manager)

	transportMode := config.Transport
	if transportMode == "" {
		transportMode = client.TCPTransportH2
	}
	poolSize := config.PoolSize
	if poolSize <= 0 {
		poolSize = 4
	}

	cli, err := client.New(client.Config{
		Server:             config.Server,
		ServerName:         config.ServerName,
		ServerID:           config.ServerId,
		PSK:                []byte(config.Psk),
		Path:               config.Path,
		TCPTransport:       transportMode,
		TCPPoolSize:        int(poolSize),
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, fmt.Errorf("init chitanda client: %w", err)
	}

	return &OutboundHandler{
		config: config,
		client: cli,
		policy: pm,
	}, nil
}

func (h *OutboundHandler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 || !outbounds[len(outbounds)-1].Target.IsValid() {
		return fmt.Errorf("chitanda: target not found in context")
	}

	destination := outbounds[len(outbounds)-1].Target
	targetAddr := destination.NetAddr()

	if destination.Network == xnet.Network_TCP {
		conn, err := h.client.DialContext(ctx, "tcp", targetAddr)
		if err != nil {
			return fmt.Errorf("chitanda dial tcp: %w", err)
		}
		defer conn.Close()

		uploadDone := make(chan error, 1)
		go func() {
			uploadDone <- buf.Copy(link.Reader, buf.NewWriter(conn))
		}()

		downloadErr := buf.Copy(buf.NewReader(conn), link.Writer)
		<-uploadDone
		return downloadErr
	} else if destination.Network == xnet.Network_UDP {
		pconn, err := h.client.ListenPacket(ctx)
		if err != nil {
			return fmt.Errorf("chitanda listen udp: %w", err)
		}
		defer pconn.Close()

		rAddr, err := net.ResolveUDPAddr("udp", targetAddr)
		if err != nil {
			return err
		}

		uploadDone := make(chan error, 1)
		go func() {
			for {
				mb, err := link.Reader.ReadMultiBuffer()
				if err != nil {
					uploadDone <- err
					return
				}
				for _, b := range mb {
					_, _ = pconn.WriteTo(b.Bytes(), rAddr)
					b.Release()
				}
			}
		}()

		recvBuf := make([]byte, 64<<10)
		for {
			n, _, err := pconn.ReadFrom(recvBuf)
			if err != nil {
				break
			}
			mb := buf.MultiBuffer{buf.FromBytes(recvBuf[:n])}
			if err := link.Writer.WriteMultiBuffer(mb); err != nil {
				break
			}
		}
		return nil
	}

	return fmt.Errorf("unsupported network: %v", destination.Network)
}

func (h *OutboundHandler) Close() error {
	if h.client != nil {
		h.client.Close()
	}
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*OutboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewOutboundHandler(ctx, config.(*OutboundConfig))
	}))
}
