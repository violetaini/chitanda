package plainudp

import (
	"bytes"
	"encoding/binary"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/violetaini/chitanda/internal/frame"
)

func TestPlainUDPRoundTripAndReplay(t *testing.T) {
	psk := []byte(strings.Repeat("u", 32))
	codec, err := NewCodec(psk)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	now := time.Now()
	var replay frame.ReplayWindow
	sessionID := uint64(0x1122334455667788)

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
		packet, err := codec.EncodePacket(nil, sessionID, tc.target, []byte(tc.payload), now)
		if err != nil {
			t.Fatalf("EncodePacket(%q): %v", tc.target, err)
		}

		decodedSessionID, decodedTarget, decodedPayload, ts, seq, err := codec.DecodePacket(packet, now)
		if err != nil {
			t.Fatalf("DecodePacket(%q): %v", tc.target, err)
		}

		if decodedSessionID != sessionID {
			t.Fatalf("sessionID %x != expected %x", decodedSessionID, sessionID)
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

		// First arrival: replay window accepts
		if !replay.Accept(seq) {
			t.Fatalf("expected replay window to accept first-time sequence %d", seq)
		}

		// Replay arrival: replay window rejects!
		if replay.Accept(seq) {
			t.Fatalf("expected replay window to reject duplicate sequence %d", seq)
		}
	}
}

func TestUnauthenticatedPacketCannotPoisonReplayWindow(t *testing.T) {
	psk := []byte(strings.Repeat("u", 32))
	codec, err := NewCodec(psk)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	now := time.Now()
	var replay frame.ReplayWindow

	// Attacker crafts unauthenticated packet with high sequence number
	fakePacket := make([]byte, 100)
	nowSec := uint64(now.Unix())
	binary.BigEndian.PutUint64(fakePacket[0:8], nowSec)
	binary.BigEndian.PutUint64(fakePacket[8:16], math.MaxUint64)

	// Decode must fail immediately due to AEAD decryption failure
	_, _, _, _, _, err = codec.DecodePacket(fakePacket, now)
	if err != ErrDecryptionFailed {
		t.Fatalf("expected ErrDecryptionFailed, got %v", err)
	}

	// Replay window state must remain completely unaffected
	// Legitimate client with seq=1 must still be accepted!
	if !replay.Accept(1) {
		t.Fatal("replay window was poisoned by unauthenticated packet!")
	}
}

func TestPlainUDPTamperAndExpire(t *testing.T) {
	psk := []byte(strings.Repeat("u", 32))
	codec, err := NewCodec(psk)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	now := time.Now()

	packet, err := codec.EncodePacket(nil, 0x1234, "1.1.1.1:53", []byte("hello"), now)
	if err != nil {
		t.Fatalf("EncodePacket: %v", err)
	}

	// Tampered payload
	tampered := make([]byte, len(packet))
	copy(tampered, packet)
	tampered[len(tampered)-1] ^= 0xff
	if _, _, _, _, _, err := codec.DecodePacket(tampered, now); err == nil {
		t.Fatal("expected decryption error on tampered packet")
	}

	// Expired packet (>30s)
	future := now.Add(45 * time.Second)
	if _, _, _, _, _, err := codec.DecodePacket(packet, future); err != ErrTimestampExpired {
		t.Fatalf("expected ErrTimestampExpired on out-of-window packet, got %v", err)
	}
}
