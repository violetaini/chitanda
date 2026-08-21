package http3

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

type lazyQueueClearer struct {
	reserved int
	limit    int
}

func (*lazyQueueClearer) clearStream(quic.StreamID) {}

func (c *lazyQueueClearer) reserveDatagram(size int) bool {
	if c.limit > 0 && c.reserved+size > c.limit {
		return false
	}
	c.reserved += size
	return true
}

func (c *lazyQueueClearer) releaseDatagram(size int) { c.reserved -= size }

func TestStateTrackingStreamAllocatesDatagramQueueLazily(t *testing.T) {
	clearer := &lazyQueueClearer{}
	stream := &stateTrackingStream{
		clearer:    clearer,
		hasData:    make(chan struct{}, 1),
		recvClosed: make(chan struct{}),
	}
	if stream.queue != nil {
		t.Fatal("queue allocated before first Datagram")
	}
	stream.enqueueDatagrams([][]byte{[]byte("payload")})
	if len(stream.queue) != 1 || stream.queueLen != 1 {
		t.Fatalf("queue state = capacity %d, length %d", len(stream.queue), stream.queueLen)
	}
	if clearer.reserved != len("payload")+queuedDatagramAccountingOverhead {
		t.Fatalf("reserved bytes = %d", clearer.reserved)
	}
	stream.enqueueDatagrams([][]byte{[]byte("a"), []byte("b"), []byte("c")})
	if len(stream.queue) != 4 || stream.queueLen != 4 {
		t.Fatalf("grown queue state = capacity %d, length %d", len(stream.queue), stream.queueLen)
	}
	var batch [4][]byte
	count, err := stream.ReceiveDatagramsInto(context.Background(), batch[:])
	if err != nil || count != len(batch) {
		t.Fatalf("receive = (%d, %v)", count, err)
	}
	for i, want := range []string{"payload", "a", "b", "c"} {
		if got := string(batch[i]); got != want {
			t.Fatalf("datagram %d = %q, want %q", i, got, want)
		}
	}
	if clearer.reserved != 0 {
		t.Fatalf("reserved bytes after drain = %d", clearer.reserved)
	}
}

func TestStateTrackingStreamRejectsDatagramOverBudget(t *testing.T) {
	clearer := &lazyQueueClearer{limit: len("accepted") + queuedDatagramAccountingOverhead}
	stream := &stateTrackingStream{
		clearer:    clearer,
		hasData:    make(chan struct{}, 1),
		recvClosed: make(chan struct{}),
	}
	stream.enqueueDatagrams([][]byte{[]byte("accepted"), []byte("rejected")})
	if stream.queueLen != 1 {
		t.Fatalf("queue length = %d, want 1", stream.queueLen)
	}
	if clearer.reserved != clearer.limit {
		t.Fatalf("reserved bytes = %d, want %d", clearer.reserved, clearer.limit)
	}
	packet, err := stream.ReceiveDatagram(context.Background())
	if err != nil || string(packet) != "accepted" {
		t.Fatalf("received = (%q, %v), want accepted", packet, err)
	}
	if clearer.reserved != 0 {
		t.Fatalf("reserved bytes after receive = %d", clearer.reserved)
	}
}

func TestStateTrackingStreamCloseReleasesBudget(t *testing.T) {
	clearer := &lazyQueueClearer{}
	stream := &stateTrackingStream{
		clearer:    clearer,
		hasData:    make(chan struct{}, 1),
		recvClosed: make(chan struct{}),
	}
	stream.enqueueDatagrams([][]byte{[]byte("one"), []byte("two")})
	if clearer.reserved == 0 {
		t.Fatal("no budget reserved before close")
	}
	closeErr := errors.New("closed")
	stream.closeReceive(closeErr)
	if clearer.reserved != 0 {
		t.Fatalf("reserved bytes after close = %d", clearer.reserved)
	}
	if stream.queueLen != 0 {
		t.Fatalf("queue length after close = %d", stream.queueLen)
	}
	if count, err := stream.ReceiveDatagramsInto(context.Background(), make([][]byte, 1)); count != 0 || !errors.Is(err, closeErr) {
		t.Fatalf("receive after close = (%d, %v)", count, err)
	}
}

func TestRawConnDatagramFailureWakesTrackedStreams(t *testing.T) {
	clearer := &lazyQueueClearer{}
	stream := &stateTrackingStream{
		clearer:    clearer,
		hasData:    make(chan struct{}, 1),
		recvClosed: make(chan struct{}),
	}
	conn := &rawConn{streams: map[quic.StreamID]*stateTrackingStream{0: stream}}
	wakeErr := errors.New("connection closed")
	done := make(chan error, 1)
	go func() {
		_, err := stream.ReceiveDatagramsInto(context.Background(), make([][]byte, 1))
		done <- err
	}()
	conn.closeDatagramReceivers(wakeErr)
	select {
	case err := <-done:
		if !errors.Is(err, wakeErr) {
			t.Fatalf("receive error = %v, want %v", err, wakeErr)
		}
	case <-time.After(time.Second):
		t.Fatal("ReceiveDatagramsInto was not woken")
	}
}
