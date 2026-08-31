package plainudp

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestPlainUDPRoundTrip(t *testing.T) {
	psk := []byte(strings.Repeat("u", 32))
	key := DeriveKey(psk)
	now := time.Now()

	testCases := []struct {
		target  string
		payload string
	}{
		{"1.1.1.1:53", "DNS query data payload"},
		{"8.8.8.8:853", "DoT query"},
		{"[2606:4700:4700::1111]:53", "IPv6 DNS packet"},
		{"dns.google:53", "Domain target DNS"},
	}

	for _, tc := range testCases {
		packet, err := EncodePacket(key, tc.target, []byte(tc.payload), now)
		if err != nil {
			t.Fatalf("EncodePacket(%q): %v", tc.target, err)
		}

		decodedTarget, decodedPayload, ts, err := DecodePacket(key, packet, now)
		if err != nil {
			t.Fatalf("DecodePacket(%q): %v", tc.target, err)
		}

		if decodedTarget != tc.target {
			t.Fatalf("target %q != expected %q", decodedTarget, tc.target)
		}
		if !bytes.Equal(decodedPayload, []byte(tc.payload)) {
			t.Fatalf("payload %q != expected %q", string(decodedPayload), tc.payload)
		}
		if ts != uint64(now.Unix()) {
			t.Fatalf("timestamp %d != expected %d", ts, uint64(now.Unix()))
		}
	}
}

func TestPlainUDPTamperAndExpire(t *testing.T) {
	psk := []byte(strings.Repeat("u", 32))
	key := DeriveKey(psk)
	now := time.Now()

	packet, err := EncodePacket(key, "1.1.1.1:53", []byte("hello"), now)
	if err != nil {
		t.Fatalf("EncodePacket: %v", err)
	}

	// Tampered payload
	tampered := make([]byte, len(packet))
	copy(tampered, packet)
	tampered[len(tampered)-1] ^= 0xff
	if _, _, _, err := DecodePacket(key, tampered, now); err == nil {
		t.Fatal("expected decryption error on tampered packet")
	}

	// Expired packet (>30s)
	future := now.Add(45 * time.Second)
	if _, _, _, err := DecodePacket(key, packet, future); err == nil {
		t.Fatal("expected expired error on out-of-window packet")
	}
}
