//go:build !linux

package server

import (
	"net"
)

// ListenTCPMulti on non-Linux platforms falls back to a single net.Listener.
func ListenTCPMulti(address string) ([]net.Listener, error) {
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	return []net.Listener{ln}, nil
}
