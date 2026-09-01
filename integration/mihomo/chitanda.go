package outbound

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"

	"chitanda/pkg/client"

	C "github.com/metacubex/mihomo/constant"
)

type ChitandaOption struct {
	BasicOption
	Name      string `proxy:"name"`
	Server    string `proxy:"server"`
	Port      int    `proxy:"port"`
	PSK       string `proxy:"psk"`
	Path      string `proxy:"path"`
	Transport string `proxy:"transport,omitempty"` // "h2" (default), "h3", "auto", "h1"
	SNI       string `proxy:"sni,omitempty"`
	PoolSize  int    `proxy:"pool-size,omitempty"`
	UDP            bool   `proxy:"udp,omitempty"`
	SkipCertVerify bool   `proxy:"skip-cert-verify,omitempty"`
}

type Chitanda struct {
	*Base
	option *ChitandaOption
	client *client.Client
	initMu sync.Mutex
}

func NewChitanda(option ChitandaOption) (*Chitanda, error) {
	if option.Server == "" || option.Port == 0 {
		return nil, errors.New("chitanda: server and port are required")
	}
	if option.PSK == "" {
		return nil, errors.New("chitanda: psk is required")
	}
	if option.Path == "" {
		option.Path = "/api/v1/sync"
	}
	if option.Transport == "" {
		option.Transport = "h2"
	}
	if option.PoolSize <= 0 {
		option.PoolSize = 4
	}

	serverAddr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	sni := option.SNI
	if sni == "" && option.Transport != "h1" && option.Transport != "plain-h1" {
		sni = option.Server
	}

	c := &Chitanda{
		Base: NewBase(BaseOption{
			Name:        option.Name,
			Addr:        serverAddr,
			Type:        C.Chitanda,
			UDP:         option.UDP,
			TFO:         false,
			Interface:   option.Interface,
			RoutingMark: option.RoutingMark,
			Prefer:      option.IPVersion,
		}),
		option: &option,
	}

	return c, nil
}

func (c *Chitanda) getClient() (*client.Client, error) {
	c.initMu.Lock()
	defer c.initMu.Unlock()

	if c.client != nil {
		return c.client, nil
	}

	serverAddr := net.JoinHostPort(c.option.Server, strconv.Itoa(c.option.Port))
	sni := c.option.SNI
	if sni == "" && c.option.Transport != "h1" && c.option.Transport != "plain-h1" {
		sni = c.option.Server
	}

	cli, err := client.New(client.Config{
		Server:       serverAddr,
		ServerName:   sni,
		PSK:          []byte(c.option.PSK),
		Path:         c.option.Path,
		TCPTransport: c.option.Transport,
		TCPPoolSize:        c.option.PoolSize,
		InsecureSkipVerify: c.option.SkipCertVerify,
	})
	if err != nil {
		return nil, fmt.Errorf("init chitanda client sdk: %w", err)
	}

	c.client = cli
	return c.client, nil
}

func (c *Chitanda) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	cli, err := c.getClient()
	if err != nil {
		return nil, err
	}

	targetAddr := metadata.RemoteAddress()
	conn, err := cli.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return nil, fmt.Errorf("chitanda dial tcp %q: %w", targetAddr, err)
	}

	return NewConn(conn, c), nil
}

func (c *Chitanda) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if !c.option.UDP {
		return nil, errors.New("chitanda: udp is disabled for this node")
	}

	cli, err := c.getClient()
	if err != nil {
		return nil, err
	}

	pconn, err := cli.ListenPacket(ctx)
	if err != nil {
		return nil, fmt.Errorf("chitanda listen udp: %w", err)
	}

	return NewPacketConn(pconn, c), nil
}

func (c *Chitanda) SupportUDP() bool {
	return c.option.UDP
}

func (c *Chitanda) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"type":      C.Chitanda.String(),
		"server":    c.option.Server,
		"port":      c.option.Port,
		"path":      c.option.Path,
		"transport": c.option.Transport,
		"sni":       c.option.SNI,
		"udp":       c.option.UDP,
	})
}

func (c *Chitanda) Close() error {
	c.initMu.Lock()
	defer c.initMu.Unlock()

	if c.client != nil {
		c.client.Close()
		c.client = nil
	}
	return nil
}
