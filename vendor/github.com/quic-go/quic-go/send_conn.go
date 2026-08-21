package quic

import (
	"net"
	"sync/atomic"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

// A sendConn allows sending using a simple Write() on a non-connected packet conn.
type sendConn interface {
	Write(b []byte, gsoSize uint16, ecn protocol.ECN) error
	WriteBatch([]packetWrite) (int, error)
	WriteTo([]byte, net.Addr, packetInfo) error
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	ChangeRemoteAddr(addr net.Addr, info packetInfo)

	capabilities() connCapabilities
}

type packetWrite struct {
	data    []byte
	gsoSize uint16
	ecn     protocol.ECN
}

type rawPacketBatchWriter interface {
	WritePackets([]packetWrite, net.Addr, []byte) (int, error)
}

type remoteAddrInfo struct {
	addr net.Addr
	oob  []byte
}

type sconn struct {
	rawConn

	localAddr net.Addr

	remoteAddrInfo atomic.Pointer[remoteAddrInfo]

	logger utils.Logger

	// If GSO enabled, and we receive a GSO error for this remote address, GSO is disabled.
	gotGSOError bool
	// Used to catch the error sometimes returned by the first sendmsg call on Linux,
	// see https://github.com/golang/go/issues/63322.
	wroteFirstPacket bool
}

var _ sendConn = &sconn{}

func newSendConn(c rawConn, remote net.Addr, info packetInfo, logger utils.Logger) *sconn {
	localAddr := c.LocalAddr()
	if info.addr.IsValid() {
		if udpAddr, ok := localAddr.(*net.UDPAddr); ok {
			addrCopy := *udpAddr
			addrCopy.IP = info.addr.AsSlice()
			localAddr = &addrCopy
		}
	}

	oob := info.OOB()
	// increase oob slice capacity, so we can add the UDP_SEGMENT and ECN control messages without allocating
	l := len(oob)
	oob = append(oob, make([]byte, 64)...)[:l]
	sc := &sconn{
		rawConn:   c,
		localAddr: localAddr,
		logger:    logger,
	}
	sc.remoteAddrInfo.Store(&remoteAddrInfo{
		addr: remote,
		oob:  oob,
	})
	return sc
}

func (c *sconn) Write(p []byte, gsoSize uint16, ecn protocol.ECN) error {
	ai := c.remoteAddrInfo.Load()
	err := c.writePacket(p, ai.addr, ai.oob, gsoSize, ecn)
	if err != nil && isGSOError(err) {
		// disable GSO for future calls
		c.gotGSOError = true
		if c.logger.Debug() {
			c.logger.Debugf("GSO failed when sending to %s", ai.addr)
		}
		// send out the packets one by one
		for len(p) > 0 {
			l := min(len(p), int(gsoSize))
			if err := c.writePacket(p[:l], ai.addr, ai.oob, 0, ecn); err != nil {
				return err
			}
			p = p[l:]
		}
		return nil
	}
	return err
}

func (c *sconn) WriteBatch(packets []packetWrite) (int, error) {
	if len(packets) == 0 {
		return 0, nil
	}
	writer, ok := c.rawConn.(rawPacketBatchWriter)
	if !ok || len(packets) == 1 {
		for i, packet := range packets {
			if err := c.Write(packet.data, packet.gsoSize, packet.ecn); err != nil {
				return i, err
			}
		}
		return len(packets), nil
	}
	ai := c.remoteAddrInfo.Load()
	written, err := writer.WritePackets(packets, ai.addr, ai.oob)
	if err != nil && written == 0 && !c.wroteFirstPacket && isPermissionError(err) {
		written, err = writer.WritePackets(packets, ai.addr, ai.oob)
	}
	c.wroteFirstPacket = true
	if err != nil && isGSOError(err) {
		c.gotGSOError = true
		for i := written; i < len(packets); i++ {
			if fallbackErr := c.writePacketWithoutGSO(packets[i], ai); fallbackErr != nil {
				return i, fallbackErr
			}
		}
		return len(packets), nil
	}
	if err != nil && !isSendMsgSizeErr(err) {
		return written, err
	}
	// Linux sendmmsg can report a partial write with either EMSGSIZE or a nil
	// error. Retry the unsent part individually so one PMTU probe doesn't
	// discard unrelated packets later in this batch.
	var firstSizeErr error
	if isSendMsgSizeErr(err) {
		firstSizeErr = err
	}
	for i := written; i < len(packets); i++ {
		if fallbackErr := c.Write(packets[i].data, packets[i].gsoSize, packets[i].ecn); fallbackErr != nil {
			if isSendMsgSizeErr(fallbackErr) {
				if firstSizeErr == nil {
					firstSizeErr = fallbackErr
				}
				continue
			}
			return i, fallbackErr
		}
	}
	return len(packets), firstSizeErr
}

func (c *sconn) writePacketWithoutGSO(packet packetWrite, ai *remoteAddrInfo) error {
	if packet.gsoSize == 0 {
		return c.writePacket(packet.data, ai.addr, ai.oob, 0, packet.ecn)
	}
	data := packet.data
	for len(data) > 0 {
		length := min(len(data), int(packet.gsoSize))
		if err := c.writePacket(data[:length], ai.addr, ai.oob, 0, packet.ecn); err != nil {
			return err
		}
		data = data[length:]
	}
	return nil
}

func (c *sconn) writePacket(p []byte, addr net.Addr, oob []byte, gsoSize uint16, ecn protocol.ECN) error {
	_, err := c.WritePacket(p, addr, oob, gsoSize, ecn)
	if err != nil && !c.wroteFirstPacket && isPermissionError(err) {
		_, err = c.WritePacket(p, addr, oob, gsoSize, ecn)
	}
	c.wroteFirstPacket = true
	return err
}

func (c *sconn) WriteTo(b []byte, addr net.Addr, info packetInfo) error {
	_, err := c.WritePacket(b, addr, info.OOB(), 0, protocol.ECNUnsupported)
	return err
}

func (c *sconn) capabilities() connCapabilities {
	capabilities := c.rawConn.capabilities()
	if capabilities.GSO {
		capabilities.GSO = !c.gotGSOError
	}
	return capabilities
}

func (c *sconn) ChangeRemoteAddr(addr net.Addr, info packetInfo) {
	c.remoteAddrInfo.Store(&remoteAddrInfo{
		addr: addr,
		oob:  info.OOB(),
	})
}

func (c *sconn) RemoteAddr() net.Addr { return c.remoteAddrInfo.Load().addr }
func (c *sconn) LocalAddr() net.Addr  { return c.localAddr }
