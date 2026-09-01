package plainudp

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestPlainUDPRoundTripAndReplay(t *testing.T) {
	psk := []byte(strings.Repeat("u", 32))
	codec, err := NewCodec(psk)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
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
		packet, err := codec.EncodePacket(nil, tc.target, []byte(tc.payload), now)
		if err != nil {
			t.Fatalf("EncodePacket(%q): %v", tc.target, err)
		}

		decodedTarget, decodedPayload, ts, seq, err := codec.DecodePacket(packet, now)
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
		if seq == 0 {
			t.Fatalf("expected non-zero sequence")
		}

		// Replay attempt must be rejected!
		if _, _, _, _, err := codec.DecodePacket(packet, now); err != ErrReplayDetected {
			t.Fatalf("expected ErrReplayDetected on replayed packet, got %v", err)
		}
	}
}

func TestPlainUDPTamperAndExpire(t *testing.T) {
	psk := []byte(strings.Repeat("u", 32))
	codec, err := NewCodec(psk)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	now := time.Now()

	packet, err := codec.EncodePacket(nil, "1.1.1.1:53", []byte("hello"), now)
	if err != nil {
		t.Fatalf("EncodePacket: %v", err)
	}

	// Tampered payload
	tampered := make([]byte, len(packet))
	copy(tampered, packet)
	tampered[len(tampered)-1] ^= 0xff
	if _, _, _, _, err := codec.DecodePacket(tampered, now); err == nil {
		t.Fatal("expected decryption error on tampered packet")
	}

	// Expired packet (>30s)
	future := now.Add(45 * time.Second)
	if _, _, _, _, err := codec.DecodePacket(packet, future); err != ErrTimestampExpired {
		t.Fatalf("expected ErrTimestampExpired on out-of-window packet, got %v", err)
	}
}
