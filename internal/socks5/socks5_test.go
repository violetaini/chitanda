package socks5

import (
	"bytes"
	"testing"
)

func TestUDPPacketRoundTrip(t *testing.T) {
	packet, err := BuildUDPPacket("example.com:53", []byte("dns"))
	if err != nil {
		t.Fatal(err)
	}
	address, payload, err := ParseUDPPacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	if address != "example.com:53" || !bytes.Equal(payload, []byte("dns")) {
		t.Fatalf("decoded address=%q payload=%q", address, payload)
	}
}

func TestRejectsFragmentedUDPPacket(t *testing.T) {
	packet, err := BuildUDPPacket("1.1.1.1:53", []byte("dns"))
	if err != nil {
		t.Fatal(err)
	}
	packet[2] = 1
	if _, _, err := ParseUDPPacket(packet); err == nil {
		t.Fatal("fragmented packet accepted")
	}
}
