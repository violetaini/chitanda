package quicconfig

import (
	"time"

	quic "github.com/quic-go/quic-go"
	h3qlog "github.com/quic-go/quic-go/http3/qlog"
)

const (
	MinInitialPacketSize     = 1200
	DefaultInitialPacketSize = 1452
	MaxInitialPacketSize     = 1452
	InitialStreamWindow      = 32 << 20
	MaxStreamWindow          = 128 << 20
	InitialConnectionWindow  = 64 << 20
	MaxConnectionWindow      = 256 << 20
)

func Client(initialPacketSize uint16) *quic.Config {
	config := base(initialPacketSize)
	config.Tracer = h3qlog.DefaultConnectionTracer
	return config
}

func Server(initialPacketSize uint16) *quic.Config {
	config := base(initialPacketSize)
	config.Allow0RTT = true
	return config
}

func base(initialPacketSize uint16) *quic.Config {
	return &quic.Config{
		InitialPacketSize:              initialPacketSize,
		HandshakeIdleTimeout:           10 * time.Second,
		MaxIdleTimeout:                 3 * time.Minute,
		InitialStreamReceiveWindow:     InitialStreamWindow,
		MaxStreamReceiveWindow:         MaxStreamWindow,
		InitialConnectionReceiveWindow: InitialConnectionWindow,
		MaxConnectionReceiveWindow:     MaxConnectionWindow,
		MaxIncomingStreams:             1024,
		MaxIncomingUniStreams:          64,
		KeepAlivePeriod:                30 * time.Second,
		EnableDatagrams:                true,
	}
}
