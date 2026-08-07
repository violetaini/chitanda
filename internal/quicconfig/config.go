package quicconfig

import (
	"time"

	quic "github.com/quic-go/quic-go"
	h3qlog "github.com/quic-go/quic-go/http3/qlog"
)

const (
	InitialStreamWindow     = 32 << 20
	MaxStreamWindow         = 128 << 20
	InitialConnectionWindow = 64 << 20
	MaxConnectionWindow     = 256 << 20
)

func Client() *quic.Config {
	config := base()
	config.Tracer = h3qlog.DefaultConnectionTracer
	return config
}

func Server() *quic.Config {
	config := base()
	config.Allow0RTT = true
	return config
}

func base() *quic.Config {
	return &quic.Config{
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
