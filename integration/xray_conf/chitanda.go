package conf

import (
	"github.com/xtls/xray-core/proxy/chitanda"
	"google.golang.org/protobuf/proto"
)

type ChitandaInboundConfig struct {
	PSK          string `json:"psk"`
	Path         string `json:"path"`
	Transport    string `json:"transport"`
	StrictSNI    string `json:"strict_sni"`
	Fallback     string `json:"fallback"`
	ServerID     string `json:"server_id"`
	ServerId     string `json:"serverId"`
	ServerHyphen string `json:"server-id"`
	ReplayFile   string `json:"replay_file"`
}

func (c *ChitandaInboundConfig) Build() (proto.Message, error) {
	sid := c.ServerID
	if sid == "" {
		sid = c.ServerId
	}
	if sid == "" {
		sid = c.ServerHyphen
	}
	return &chitanda.InboundConfig{
		Psk:        c.PSK,
		Path:       c.Path,
		Transport:  c.Transport,
		StrictSni:  c.StrictSNI,
		Fallback:   c.Fallback,
		ServerId:   sid,
		ReplayFile: c.ReplayFile,
	}, nil
}

type ChitandaOutboundConfig struct {
	Server       string `json:"server"`
	ServerName   string `json:"server_name"`
	PSK          string `json:"psk"`
	Path         string `json:"path"`
	Transport    string `json:"transport"`
	PoolSize     int32  `json:"pool_size"`
	ServerID     string `json:"server_id"`
	ServerId     string `json:"serverId"`
	ServerHyphen string `json:"server-id"`
}

func (c *ChitandaOutboundConfig) Build() (proto.Message, error) {
	sid := c.ServerID
	if sid == "" {
		sid = c.ServerId
	}
	if sid == "" {
		sid = c.ServerHyphen
	}
	return &chitanda.OutboundConfig{
		Server:     c.Server,
		ServerName: c.ServerName,
		Psk:        c.PSK,
		Path:       c.Path,
		Transport:  c.Transport,
		PoolSize:   c.PoolSize,
		ServerId:   sid,
	}, nil
}
