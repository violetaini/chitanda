package server

import (
	"io"
	"net"
	"time"
)

const (
	// DefaultIdleTimeout is the maximum duration a connection can remain completely idle
	// (no traffic in either direction). Matches standard Shadowsocks/V2Ray/Sing-box behavior.
	DefaultIdleTimeout = 300 * time.Second

	// DefaultDrainTimeout is the grace period allowed for draining remaining data after target EOF.
	DefaultDrainTimeout = 250 * time.Millisecond
)

type activityReader struct {
	r          io.Reader
	onActivity func()
}

func (a *activityReader) Read(p []byte) (int, error) {
	n, err := a.r.Read(p)
	if n > 0 && a.onActivity != nil {
		a.onActivity()
	}
	return n, err
}

type closeWriter interface {
	CloseWrite() error
}

func closeWriteConn(c net.Conn) {
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}
