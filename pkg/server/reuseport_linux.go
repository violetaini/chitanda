//go:build linux

package server

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

// ListenTCPMulti creates up to N listeners on the same address using SO_REUSEPORT on Linux.
func ListenTCPMulti(address string) ([]net.Listener, error) {
	n := min(runtime.NumCPU(), 8)
	if n < 1 {
		n = 1
	}

	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			})
			if err != nil {
				return err
			}
			return opErr
		},
	}

	listeners := make([]net.Listener, 0, n)
	for i := 0; i < n; i++ {
		ln, err := lc.Listen(context.Background(), "tcp", address)
		if err != nil {
			if len(listeners) > 0 {
				// At least one listener succeeded; continue with available listeners
				break
			}
			return nil, fmt.Errorf("listen SO_REUSEPORT on %s failed: %w", address, err)
		}
		listeners = append(listeners, ln)
	}
	return listeners, nil
}
