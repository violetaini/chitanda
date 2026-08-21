package frame

import (
	"bytes"
	"errors"
	"io"
	"math"
	"math/rand"
	"testing"
)

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

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

func TestCopyAsDataFramesAndCloseMarksCleanEOF(t *testing.T) {
	var encoded bytes.Buffer
	if err := CopyAsDataFramesAndClose(&encoded, bytes.NewReader(nil)); err != nil {
		t.Fatal(err)
	}
	header, err := ReadHeader(&encoded)
	if err != nil {
		t.Fatal(err)
	}
	if header.Type != TypeHalfClose || header.Length != 0 {
		t.Fatalf("terminal frame = %+v", header)
	}
}

func TestCopyAsDataFramesAndCloseMarksSourceFailure(t *testing.T) {
	wantErr := errors.New("source failed")
	var encoded bytes.Buffer
	err := CopyAsDataFramesAndClose(&encoded, failingReader{err: wantErr})
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v", err)
	}
	header, readErr := ReadHeader(&encoded)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if header.Type != TypeReset || header.Length != 0 {
		t.Fatalf("terminal frame = %+v", header)
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

type replayWindowModel struct {
	initialized bool
	highest     uint64
	seen        map[uint64]struct{}
}

func (m *replayWindowModel) Accept(sequence uint64) bool {
	if !m.initialized {
		m.initialized = true
		m.highest = sequence
		m.seen = make(map[uint64]struct{})
	} else {
		if sequence > m.highest {
			m.highest = sequence
		}
		if m.highest-sequence >= ReplayWindowSize {
			return false
		}
	}
	if _, duplicate := m.seen[sequence]; duplicate {
		return false
	}
	m.seen[sequence] = struct{}{}
	return true
}

func TestReplayWindowMatchesReferenceModel(t *testing.T) {
	for seed := int64(0); seed < 8; seed++ {
		rng := rand.New(rand.NewSource(seed))
		var window ReplayWindow
		var model replayWindowModel
		sequence := uint64(1 << 40)
		for operation := 0; operation < 20000; operation++ {
			switch choice := rng.Intn(100); {
			case !model.initialized:
				sequence += uint64(rng.Intn(ReplayWindowSize * 2))
			case choice < 45:
				sequence = model.highest + 1 + uint64(rng.Intn(8))
			case choice < 60:
				sequence = model.highest + 1 + uint64(rng.Intn(ReplayWindowSize-1))
			case choice < 65:
				sequence = model.highest + ReplayWindowSize + uint64(rng.Intn(ReplayWindowSize*2))
			default:
				delta := uint64(rng.Intn(ReplayWindowSize + 512))
				if delta > model.highest {
					sequence = 0
				} else {
					sequence = model.highest - delta
				}
			}
			got := window.Accept(sequence)
			want := model.Accept(sequence)
			if got != want {
				t.Fatalf("seed=%d operation=%d sequence=%d highest=%d: got %v want %v", seed, operation, sequence, model.highest, got, want)
			}
		}
	}
}

func TestReplayWindowUint64Boundary(t *testing.T) {
	sequences := []uint64{
		math.MaxUint64 - ReplayWindowSize - 10,
		math.MaxUint64 - ReplayWindowSize,
		math.MaxUint64 - 2,
		math.MaxUint64,
		math.MaxUint64 - 1,
		math.MaxUint64 - 1,
		math.MaxUint64 - ReplayWindowSize + 1,
		math.MaxUint64 - ReplayWindowSize,
		0,
		1,
		math.MaxUint64,
	}
	var window ReplayWindow
	var model replayWindowModel
	for index, sequence := range sequences {
		got := window.Accept(sequence)
		want := model.Accept(sequence)
		if got != want {
			t.Fatalf("index=%d sequence=%d: got %v want %v", index, sequence, got, want)
		}
	}
}

func BenchmarkReplayWindowAcceptInOrder(b *testing.B) {
	var window ReplayWindow
	for sequence := uint64(0); sequence < uint64(b.N); sequence++ {
		if !window.Accept(sequence) {
			b.Fatalf("sequence %d rejected", sequence)
		}
	}
}
