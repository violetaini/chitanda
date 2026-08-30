package main

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/net/ipv4"

	"myxray/internal/frame"
)

type discardDatagramStream struct{}

func (discardDatagramStream) SendDatagram([]byte) error { return nil }

func TestUDPRelayForwardBatch(t *testing.T) {
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	if err := receiver.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}

	relay := newUDPRelay(context.Background(), discardDatagramStream{})
	defer relay.Close()
	targetAddress := receiver.LocalAddr().String()
	sender, err := net.DialUDP("udp4", nil, receiver.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	targetConn := &udpTarget{address: targetAddress, conn: sender, batch: ipv4.NewPacketConn(sender)}
	for i := range targetConn.messages {
		targetConn.messages[i].Buffers = make([][]byte, 1)
	}
	relay.targets[targetAddress] = targetConn
	payloads := [][]byte{[]byte("first"), {}, []byte("second"), []byte("third")}
	packets := make([][]byte, len(payloads))
	for i, payload := range payloads {
		packet, err := frame.EncodeDatagram(uint64(i+1), targetAddress, payload)
		if err != nil {
			t.Fatal(err)
		}
		packets[i] = packet
	}

	if err := relay.ForwardBatch(packets); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	for i, expected := range payloads {
		n, _, err := receiver.ReadFromUDP(buffer)
		if err != nil {
			t.Fatalf("read datagram %d: %v", i, err)
		}
		if got := string(buffer[:n]); got != string(expected) {
			t.Fatalf("datagram %d = %q, want %q", i, got, expected)
		}
	}
}
