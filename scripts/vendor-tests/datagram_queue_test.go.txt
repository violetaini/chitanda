package quic

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
)

func TestDatagramQueueReceiveBatchWrapsAndClears(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)
	add := func(sequence uint64) {
		data := make([]byte, 8)
		binary.BigEndian.PutUint64(data, sequence)
		queue.HandleDatagramFrame(&wire.DatagramFrame{Data: data})
		clear(data)
	}
	for sequence := uint64(0); sequence < maxDatagramRcvQueueLen; sequence++ {
		add(sequence)
	}

	first := make([][]byte, 2000)
	count, err := queue.ReceiveBatch(context.Background(), first)
	if err != nil || count != len(first) {
		t.Fatalf("first receive = (%d, %v)", count, err)
	}
	for i, data := range first {
		if got := binary.BigEndian.Uint64(data); got != uint64(i) {
			t.Fatalf("first sequence %d = %d", i, got)
		}
	}

	for sequence := uint64(maxDatagramRcvQueueLen); sequence < 4000; sequence++ {
		add(sequence)
	}
	want := uint64(2000)
	var batch [37][]byte
	for want < 4000 {
		count, err := queue.ReceiveBatch(context.Background(), batch[:])
		if err != nil {
			t.Fatal(err)
		}
		for i := range count {
			if got := binary.BigEndian.Uint64(batch[i]); got != want {
				t.Fatalf("wrapped sequence = %d, want %d", got, want)
			}
			batch[i] = nil
			want++
		}
	}
	if queue.rcvLen != 0 || queue.rcvHead != 0 {
		t.Fatalf("drained ring state = head %d, len %d", queue.rcvHead, queue.rcvLen)
	}
	for i, data := range queue.rcvQueue {
		if data != nil {
			t.Fatalf("retained payload at slot %d", i)
		}
	}
}

func TestDatagramQueueCloseWakesAllReceivers(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)
	wantErr := errors.New("closed")
	results := make(chan error, 2)
	var started sync.WaitGroup
	started.Add(2)
	for range 2 {
		go func() {
			started.Done()
			var batch [1][]byte
			_, err := queue.ReceiveBatch(context.Background(), batch[:])
			results <- err
		}()
	}
	started.Wait()
	queue.CloseWithError(wantErr)
	for range 2 {
		select {
		case err := <-results:
			if !errors.Is(err, wantErr) {
				t.Fatalf("receive error = %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("receiver did not wake after close")
		}
	}
}

func TestDatagramQueueRejectsSendAfterClose(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)
	wantErr := errors.New("closed")
	queue.CloseWithError(wantErr)
	frame := &wire.DatagramFrame{Data: []byte("payload")}
	if err := queue.Add(frame); !errors.Is(err, wantErr) {
		t.Fatalf("Add error = %v", err)
	}
	if err := queue.AddBatch([]*wire.DatagramFrame{frame}); !errors.Is(err, wantErr) {
		t.Fatalf("AddBatch error = %v", err)
	}
	if !queue.sendQueue.Empty() {
		t.Fatal("closed queue accepted a Datagram")
	}
}

func TestDatagramQueueCloseConcurrentWithAddBatch(t *testing.T) {
	for range 1000 {
		queue := newDatagramQueue(func() {}, utils.DefaultLogger)
		wantErr := errors.New("closed")
		frame := &wire.DatagramFrame{Data: []byte("payload")}
		result := make(chan error, 1)
		go func() { result <- queue.AddBatch([]*wire.DatagramFrame{frame}) }()
		queue.CloseWithError(wantErr)
		if err := <-result; err != nil && !errors.Is(err, wantErr) {
			t.Fatalf("AddBatch error = %v", err)
		}
		if err := queue.Add(frame); !errors.Is(err, wantErr) {
			t.Fatalf("post-close Add error = %v", err)
		}
	}
}
