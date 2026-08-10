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

func TestUDPCacheAndBuildInto(t *testing.T) {
	for _, address := range []string{"1.1.1.1:53", "example.com:443", "[2001:db8::1]:5353"} {
		buffer := make([]byte, 64<<10)
		packet, err := BuildUDPPacketInto(buffer, address, []byte("payload"))
		if err != nil {
			t.Fatalf("BuildUDPPacketInto(%q): %v", address, err)
		}
		if len(packet) == 0 || &packet[0] != &buffer[0] {
			t.Fatalf("BuildUDPPacketInto(%q) did not reuse caller buffer", address)
		}

		var cache UDPCache
		for i := 0; i < 2; i++ {
			gotAddress, payload, err := cache.Parse(packet)
			if err != nil {
				t.Fatalf("Parse(%q): %v", address, err)
			}
			if gotAddress != address || !bytes.Equal(payload, []byte("payload")) {
				t.Fatalf("decoded address=%q payload=%q", gotAddress, payload)
			}
		}
	}
}

func TestBuildUDPPacketIntoRejectsSmallBuffer(t *testing.T) {
	if _, err := BuildUDPPacketInto(make([]byte, 2), "1.1.1.1:53", []byte("dns")); err == nil {
		t.Fatal("small output buffer accepted")
	}
}
