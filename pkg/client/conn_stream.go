package client

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/violetaini/chitanda/internal/rawstream"
)

func (c *Client) dialRawStream(ctx context.Context, target string) (net.Conn, error) {
	rawConn, err := c.dialRaw(ctx, "tcp", c.cfg.Server)
	if err != nil {
		return nil, fmt.Errorf("rawstream dial server %q: %w", c.cfg.Server, err)
	}

	now := time.Now()
	clientHello, clientNonce, ts, err := rawstream.CreateClientHello(c.cfg.PSK, now)
	if err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("create client hello: %w", err)
	}

	// Derive 0-RTT key
	k0RTT, err := rawstream.Derive0RTTKey(c.cfg.PSK, ts, clientNonce)
	if err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("derive 0-rtt key: %w", err)
	}

	// Encode open frame with dynamic padding (32 to 256 bytes)
	openFramePlaintext, err := rawstream.Encode0RTTOpenFrame(target, nil, rawstream.DefaultMinPadding, rawstream.DefaultMaxPadding)
	if err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("encode 0-rtt open frame: %w", err)
	}

	encrypted0RTT, err := rawstream.Encrypt0RTTChunk(k0RTT, openFramePlaintext)
	if err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("encrypt 0-rtt chunk: %w", err)
	}

	// Assemble Flight 1 single TCP write burst:
	// [48B ClientHello] [2B 0-RTT Wire Length] [Encrypted 0-RTT Chunk]
	wireLen := len(encrypted0RTT)
	flight1 := make([]byte, 0, rawstream.ClientHelloSize+2+wireLen)
	flight1 = append(flight1, clientHello...)
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(wireLen))
	flight1 = append(flight1, lenBuf[:]...)
	flight1 = append(flight1, encrypted0RTT...)

	if _, err := rawConn.Write(flight1); err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("write flight 1: %w", err)
	}

	// Read ServerHello (40 bytes)
	var serverHello [rawstream.ServerHelloSize]byte
	if _, err := io.ReadFull(rawConn, serverHello[:]); err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("read server hello: %w", err)
	}

	serverNonce, err := rawstream.VerifyServerHello(c.cfg.PSK, ts, clientNonce, serverHello[:])
	if err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("verify server hello: %w", err)
	}

	// Derive bidirectional session keys
	c2sKey, s2cKey, err := rawstream.DeriveSessionKeys(c.cfg.PSK, ts, clientNonce, serverNonce)
	if err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("derive session keys: %w", err)
	}

	wStream, err := rawstream.NewAEADStream(c2sKey)
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	rStream, err := rawstream.NewAEADStream(s2cKey)
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	return rawstream.NewStreamConn(rawConn, rStream, wStream), nil
}
