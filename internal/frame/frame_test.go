package frame

import (
	"bytes"
	"io"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	var buffer bytes.Buffer
	if err := WriteFrame(&buffer, TypeOpen, 7, []byte("example.com:443")); err != nil {
		t.Fatal(err)
	}
	header, err := ReadHeader(&buffer)
	if err != nil {
		t.Fatal(err)
	}
	if header.Type != TypeOpen || header.Flags != 7 {
		t.Fatalf("header = %+v", header)
	}
	payload, err := ReadPayload(&buffer, header.Length)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "example.com:443" {
		t.Fatalf("payload = %q", payload)
	}
}

func TestCopyAsDataFrames(t *testing.T) {
	source := bytes.Repeat([]byte("data"), DataChunkSize)
	var encoded bytes.Buffer
	written, err := CopyAsDataFrames(&encoded, bytes.NewReader(source))
	if err != nil {
		t.Fatal(err)
	}
	if written != int64(len(source)) {
		t.Fatalf("written = %d", written)
	}
	var decoded bytes.Buffer
	for encoded.Len() > 0 {
		header, err := ReadHeader(&encoded)
		if err != nil {
			t.Fatal(err)
		}
		if header.Type != TypeData {
			t.Fatalf("frame type = %d", header.Type)
		}
		if _, err := io.CopyN(&decoded, &encoded, int64(header.Length)); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(decoded.Bytes(), source) {
		t.Fatal("decoded payload differs")
	}
}

func TestDatagramRoundTripAndReplayWindow(t *testing.T) {
	packet, err := EncodeDatagram(42, "1.1.1.1:53", []byte("query"))
	if err != nil {
		t.Fatal(err)
	}
	sequence, address, payload, err := DecodeDatagram(packet)
	if err != nil {
		t.Fatal(err)
	}
	if sequence != 42 || address != "1.1.1.1:53" || string(payload) != "query" {
		t.Fatalf("decoded = %d %q %q", sequence, address, payload)
	}
	var window ReplayWindow
	for _, sequence := range []uint64{42, 44, 43, 80} {
		if !window.Accept(sequence) {
			t.Fatalf("sequence %d rejected", sequence)
		}
	}
	if window.Accept(44) {
		t.Fatal("duplicate sequence accepted")
	}
	if !window.Accept(3000) {
		t.Fatal("new highest sequence rejected")
	}
	if window.Accept(1) {
		t.Fatal("stale sequence accepted")
	}
}

func TestEncodeDatagramIntoMatchesEncodeDatagram(t *testing.T) {
	want, err := EncodeDatagram(99, "[2001:db8::1]:443", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, MaxDatagramSize)
	got, err := EncodeDatagramInto(buffer, 99, "[2001:db8::1]:443", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("encoded datagram differs: got %x want %x", got, want)
	}
	if len(got) == 0 || &got[0] != &buffer[0] {
		t.Fatal("caller buffer was not reused")
	}
}

func TestEncodeDatagramIntoRejectsSmallBuffer(t *testing.T) {
	if _, err := EncodeDatagramInto(make([]byte, 1), 1, "1.1.1.1:53", []byte("query")); err == nil {
		t.Fatal("small output buffer accepted")
	}
}

func TestDatagramCacheTracksAddressChanges(t *testing.T) {
	var cache DatagramCache
	for _, address := range []string{"1.1.1.1:53", "1.1.1.1:53", "8.8.8.8:53"} {
		packet, err := EncodeDatagram(1, address, []byte("query"))
		if err != nil {
			t.Fatal(err)
		}
		_, got, payload, err := cache.Decode(packet)
		if err != nil {
			t.Fatal(err)
		}
		if got != address || string(payload) != "query" {
			t.Fatalf("decoded address=%q payload=%q", got, payload)
		}
	}
}

func TestReplayWindowAcceptsDeepReordering(t *testing.T) {
	var window ReplayWindow
	if !window.Accept(4096) || !window.Accept(4096-1500) {
		t.Fatal("valid reordered sequence rejected")
	}
	if window.Accept(4096 - 1500) {
		t.Fatal("reordered duplicate accepted")
	}
	if window.Accept(4096 - ReplayWindowSize) {
		t.Fatal("sequence outside replay window accepted")
	}
	if !window.Accept(4097) || window.Accept(4096) {
		t.Fatal("window shift lost duplicate state")
	}
}
