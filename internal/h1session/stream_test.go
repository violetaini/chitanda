package h1session

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestFramedReaderWriter(t *testing.T) {
	clientKey := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	encStream, err := NewAEADStream(clientKey, DirClientToServer)
	if err != nil {
		t.Fatalf("NewAEADStream: %v", err)
	}
	decStream, err := NewAEADStream(clientKey, DirClientToServer)
	if err != nil {
		t.Fatalf("NewAEADStream: %v", err)
	}

	pr, pw := io.Pipe()
	fw := NewFramedWriter(pw, encStream)
	fr := NewFramedReader(pr, decStream)

	// Send small chunk
	msg1 := []byte("Hello World over AEAD")
	go func() {
		if _, err := fw.Write(msg1); err != nil {
			t.Errorf("fw.Write: %v", err)
		}
	}()

	recvBuf := make([]byte, 100)
	n, err := fr.Read(recvBuf)
	if err != nil {
		t.Fatalf("fr.Read: %v", err)
	}
	if string(recvBuf[:n]) != string(msg1) {
		t.Fatalf("received %q != %q", string(recvBuf[:n]), string(msg1))
	}

	// Send large payload exceeding MaxChunkPayloadLen (multi-chunk streaming)
	largeMsg := []byte(strings.Repeat("ABCDEFGHIJ1234567890", 2000)) // 40,000 bytes
	go func() {
		_, _ = fw.Write(largeMsg)
		_ = pw.Close()
	}()

	recvLarge := make([]byte, len(largeMsg))
	if _, err := io.ReadFull(fr, recvLarge); err != nil {
		t.Fatalf("ReadFull large message: %v", err)
	}
	if !bytes.Equal(recvLarge, largeMsg) {
		t.Fatalf("large message content mismatch")
	}
}
