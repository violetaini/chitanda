package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/ipv4"

	"myxray/internal/frame"
)

type discardDatagramStream struct{}

func (discardDatagramStream) SendDatagram([]byte) error { return nil }

func TestCopyFramesToTCPRejectsOpenMetadataBeforePayload(t *testing.T) {
	targetAddress := "1.1.1.1:443"
	for _, test := range []struct {
		name   string
		flags  uint16
		length uint32
		want   string
	}{
		{name: "flags", flags: 1, length: uint32(len(targetAddress)), want: "not OPEN"},
		{name: "length", length: uint32(len(targetAddress) + 1), want: "length mismatch"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var header [frame.HeaderSize]byte
			header[0] = frame.Version
			header[1] = byte(frame.TypeOpen)
			binary.BigEndian.PutUint16(header[2:4], test.flags)
			binary.BigEndian.PutUint32(header[4:8], test.length)
			err := readOpenFrame(bytes.NewReader(header[:]), targetAddress)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

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
