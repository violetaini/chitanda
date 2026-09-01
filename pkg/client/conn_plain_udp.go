package client

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"chitanda/internal/frame"
	"chitanda/internal/plainudp"
)

type plainUDPConn struct {
	sessionID  uint64
	conn       *net.UDPConn
	serverAddr *net.UDPAddr
	codec      *plainudp.Codec
	closed     atomic.Bool
	buf        []byte
	replayMu   sync.Mutex
	replay     frame.ReplayWindow
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
	_ = conn.SetReadBuffer(8 << 20)
	_ = conn.SetWriteBuffer(8 << 20)

	codec, err := plainudp.NewCodec(psk)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	var sessionBytes [8]byte
	if _, err := io.ReadFull(rand.Reader, sessionBytes[:]); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("generate session ID: %w", err)
	}
	sessionID := binary.BigEndian.Uint64(sessionBytes[:])

	return &plainUDPConn{
		sessionID:  sessionID,
		conn:       conn,
		serverAddr: srvAddr,
		codec:      codec,
		buf:        make([]byte, 64<<10),
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

		sessionID, targetAddrStr, payload, _, seq, err := c.codec.DecodePacket(c.buf[:readN], time.Now())
		if err != nil {
			continue // Drop corrupt, unauthenticated, or expired datagrams
		}
		if sessionID != c.sessionID {
			continue // Drop mismatched session datagrams
		}

		c.replayMu.Lock()
		accepted := c.replay.Accept(seq)
		c.replayMu.Unlock()
		if !accepted {
			continue // Drop replayed responses
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

	packet, err := c.codec.EncodePacket(nil, c.sessionID, addr.String(), p, time.Now())
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
