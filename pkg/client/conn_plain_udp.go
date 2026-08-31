package client

import (
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"myxray/internal/plainudp"
)

type plainUDPConn struct {
	conn       *net.UDPConn
	serverAddr *net.UDPAddr
	key        [32]byte
	closed     atomic.Bool
	buf        []byte
}

func newPlainUDPConn(server string, psk []byte) (*plainUDPConn, error) {
	srvAddr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return nil, fmt.Errorf("resolve server udp addr %q: %w", server, err)
	}

	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, fmt.Errorf("listen local udp: %w", err)
	}

	return &plainUDPConn{
		conn:       conn,
		serverAddr: srvAddr,
		key:        plainudp.DeriveKey(psk),
		buf:        make([]byte, 2048),
	}, nil
}

func (c *plainUDPConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if c.closed.Load() {
		return 0, nil, errors.New("conn closed")
	}

	for {
		readN, _, err := c.conn.ReadFromUDP(c.buf)
		if err != nil {
			return 0, nil, err
		}

		targetAddrStr, payload, _, err := plainudp.DecodePacket(c.key, c.buf[:readN], time.Now())
		if err != nil {
			continue // Drop corrupt or non-matching datagrams
		}

		rAddr, err := net.ResolveUDPAddr("udp", targetAddrStr)
		if err != nil {
			rAddr = &net.UDPAddr{IP: net.IPv4zero, Port: 0}
		}

		copied := copy(p, payload)
		return copied, rAddr, nil
	}
}

func (c *plainUDPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if c.closed.Load() {
		return 0, errors.New("conn closed")
	}

	packet, err := plainudp.EncodePacket(c.key, addr.String(), p, time.Now())
	if err != nil {
		return 0, err
	}

	if _, err := c.conn.WriteToUDP(packet, c.serverAddr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *plainUDPConn) Close() error {
	c.closed.Store(true)
	return c.conn.Close()
}

func (c *plainUDPConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *plainUDPConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *plainUDPConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *plainUDPConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
