package target

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

var ErrForbidden = errors.New("target is not a public unicast address")

func DialContext(ctx context.Context, address string) (net.Conn, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("invalid target port")
	}

	resolver := net.Resolver{}
	addresses, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, candidate := range addresses {
		if !allowed(candidate.IP) {
			continue
		}
		dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		conn, dialErr := dialer.DialContext(ctx, "tcp", net.JoinHostPort(candidate.IP.String(), portText))
		if dialErr == nil {
			return conn, nil
		}
		err = dialErr
	}
	if err != nil {
		return nil, err
	}
	return nil, ErrForbidden
}

func allowed(ip net.IP) bool {
	return ip != nil &&
		!ip.IsUnspecified() &&
		!ip.IsLoopback() &&
		!ip.IsPrivate() &&
		!ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast() &&
		!ip.IsMulticast()
}
