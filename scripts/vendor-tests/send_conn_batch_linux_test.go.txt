//go:build linux

package quic

import (
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

type partialBatchRawConn struct {
	singleWrites [][]byte
	batchResults []batchWriteResult
	batchCalls   int
}

type batchWriteResult struct {
	written int
	err     error
}

func (*partialBatchRawConn) ReadPacket() (receivedPacket, error) {
	return receivedPacket{}, errors.New("unused")
}

func (c *partialBatchRawConn) WritePacket(
	b []byte,
	_ net.Addr,
	_ []byte,
	_ uint16,
	_ protocol.ECN,
) (int, error) {
	c.singleWrites = append(c.singleWrites, append([]byte(nil), b...))
	if string(b) == "oversize" {
		return 0, syscall.EMSGSIZE
	}
	return len(b), nil
}

func (c *partialBatchRawConn) WritePackets(packets []packetWrite, _ net.Addr, _ []byte) (int, error) {
	c.batchCalls++
	if len(c.batchResults) == 0 {
		return len(packets), nil
	}
	index := min(c.batchCalls-1, len(c.batchResults)-1)
	result := c.batchResults[index]
	return result.written, result.err
}

func (*partialBatchRawConn) LocalAddr() net.Addr             { return &net.UDPAddr{} }
func (*partialBatchRawConn) SetReadDeadline(time.Time) error { return nil }
func (*partialBatchRawConn) Close() error                    { return nil }
func (*partialBatchRawConn) capabilities() connCapabilities  { return connCapabilities{GSO: true} }

func TestWriteBatchRetriesNeighborsAfterPMTUError(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		batchErr error
	}{
		{name: "errno", batchErr: syscall.EMSGSIZE},
		{name: "nil-error"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			raw := &partialBatchRawConn{batchResults: []batchWriteResult{{written: 1, err: testCase.batchErr}}}
			conn := newSendConn(raw, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}, packetInfo{}, utils.DefaultLogger)
			packets := []packetWrite{
				{data: []byte("already-sent")},
				{data: []byte("oversize")},
				{data: []byte("neighbor")},
			}
			written, err := conn.WriteBatch(packets)
			if written != len(packets) {
				t.Fatalf("written = %d, want %d", written, len(packets))
			}
			if !errors.Is(err, syscall.EMSGSIZE) {
				t.Fatalf("error = %v, want EMSGSIZE", err)
			}
			if len(raw.singleWrites) != 2 || string(raw.singleWrites[0]) != "oversize" || string(raw.singleWrites[1]) != "neighbor" {
				t.Fatalf("individual retries = %q", raw.singleWrites)
			}
		})
	}
}

func TestWriteBatchRetriesInitialSendmmsgPermissionError(t *testing.T) {
	raw := &partialBatchRawConn{batchResults: []batchWriteResult{
		{err: os.NewSyscallError("sendmmsg", syscall.EPERM)},
		{written: 2},
	}}
	conn := newSendConn(raw, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}, packetInfo{}, utils.DefaultLogger)
	packets := []packetWrite{{data: []byte("first")}, {data: []byte("second")}}
	written, err := conn.WriteBatch(packets)
	if err != nil {
		t.Fatalf("WriteBatch returned error: %v", err)
	}
	if written != len(packets) {
		t.Fatalf("written = %d, want %d", written, len(packets))
	}
	if raw.batchCalls != 2 {
		t.Fatalf("batch calls = %d, want 2", raw.batchCalls)
	}
	if len(raw.singleWrites) != 0 {
		t.Fatalf("unexpected individual retries = %q", raw.singleWrites)
	}
}
