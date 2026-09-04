package rawstream

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"testing"
	"time"
)

func TestClientServerHandshake(t *testing.T) {
	psk := []byte("01234567890123456789012345678901") // 32 bytes
	serverID := "node-alpha"
	now := time.Now()

	// 0. PSK < 32 bytes must be rejected
	if _, _, _, err := CreateClientHello([]byte("short-psk"), serverID, now); err == nil {
		t.Fatalf("expected error for PSK < 32 bytes, got nil")
	}

	// 1. Client creates ClientHello
	cHello, clientNonce, ts, err := CreateClientHello(psk, serverID, now)
	if err != nil {
		t.Fatalf("CreateClientHello failed: %v", err)
	}
	if len(cHello) != ClientHelloSize {
		t.Fatalf("expected client hello size %d, got %d", ClientHelloSize, len(cHello))
	}

	// 2. Server verifies ClientHello with matching serverID
	verifiedNonce, verifiedTs, err := VerifyClientHello(psk, serverID, cHello, now)
	if err != nil {
		t.Fatalf("VerifyClientHello failed: %v", err)
	}
	if verifiedNonce != clientNonce || verifiedTs != ts {
		t.Fatalf("nonce or timestamp mismatch")
	}

	// 2b. Server with mismatched serverID must reject ClientHello (cross-node replay defense)
	if _, _, err := VerifyClientHello(psk, "node-beta", cHello, now); err == nil {
		t.Fatalf("expected VerifyClientHello to reject mismatched serverID, but it passed!")
	}

	// 3. Keys derivation
	k0RTTClient, err := Derive0RTTKey(psk, serverID, ts, clientNonce)
	if err != nil {
		t.Fatalf("Derive0RTTKey client failed: %v", err)
	}
	k0RTTServer, err := Derive0RTTKey(psk, serverID, verifiedTs, verifiedNonce)
	if err != nil {
		t.Fatalf("Derive0RTTKey server failed: %v", err)
	}
	if k0RTTClient != k0RTTServer {
		t.Fatalf("0-RTT key mismatch")
	}

	// 4. Server creates ServerHello
	sHello, serverNonce, err := CreateServerHello(psk, serverID, verifiedTs, verifiedNonce)
	if err != nil {
		t.Fatalf("CreateServerHello failed: %v", err)
	}
	if len(sHello) != ServerHelloSize {
		t.Fatalf("expected server hello size %d, got %d", ServerHelloSize, len(sHello))
	}

	// 5. Client verifies ServerHello
	verifiedServerNonce, err := VerifyServerHello(psk, serverID, ts, clientNonce, sHello)
	if err != nil {
		t.Fatalf("VerifyServerHello failed: %v", err)
	}
	if verifiedServerNonce != serverNonce {
		t.Fatalf("server nonce mismatch")
	}

	// 6. Session keys match
	c2sClient, s2cClient, err := DeriveSessionKeys(psk, serverID, ts, clientNonce, serverNonce)
	if err != nil {
		t.Fatalf("DeriveSessionKeys client: %v", err)
	}
	c2sServer, s2cServer, err := DeriveSessionKeys(psk, serverID, verifiedTs, verifiedNonce, verifiedServerNonce)
	if err != nil {
		t.Fatalf("DeriveSessionKeys server: %v", err)
	}

	if c2sClient != c2sServer || s2cClient != s2cServer {
		t.Fatalf("session keys mismatch between client and server")
	}
}

func TestDynamicPaddingVariance(t *testing.T) {
	target := "1.1.1.1:53"
	payload := []byte("ping payload data")

	lengths := make(map[int]bool)
	for i := 0; i < 20; i++ {
		frame, err := Encode0RTTOpenFrame(target, payload, 32, 256)
		if err != nil {
			t.Fatalf("Encode0RTTOpenFrame failed: %v", err)
		}
		lengths[len(frame)] = true

		decodedTarget, decodedPayload, err := Decode0RTTOpenFrame(frame)
		if err != nil {
			t.Fatalf("Decode0RTTOpenFrame failed: %v", err)
		}
		if decodedTarget != target {
			t.Fatalf("expected target %s, got %s", target, decodedTarget)
		}
		if !bytes.Equal(decodedPayload, payload) {
			t.Fatalf("payload mismatch")
		}
	}

	// Dynamic padding must yield multiple different wire lengths
	if len(lengths) < 5 {
		t.Fatalf("expected at least 5 different wire lengths across 20 samples, got %d", len(lengths))
	}
}

func TestAntiProbeResistance(t *testing.T) {
	psk := []byte("01234567890123456789012345678901")
	now := time.Now()

	// 1. Scanner sends HTTP GET request
	httpScan := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
	_, _, err := VerifyClientHello(psk, "", httpScan, now)
	if err == nil {
		t.Fatalf("expected VerifyClientHello to reject HTTP scan request, but it passed!")
	}

	// 2. Scanner sends random bytes of exact 48 length
	junk48 := make([]byte, ClientHelloSize)
	for i := range junk48 {
		junk48[i] = 0xAA
	}
	_, _, err = VerifyClientHello(psk, "", junk48, now)
	if err == nil {
		t.Fatalf("expected VerifyClientHello to reject random junk, but it passed!")
	}
}

func TestStreamConnBidirectional(t *testing.T) {
	keyC2S := [16]byte{1, 2, 3}
	keyS2C := [16]byte{4, 5, 6}

	cStreamOut, _ := NewAEADStream(keyC2S)
	cStreamIn, _ := NewAEADStream(keyS2C)
	sStreamIn, _ := NewAEADStream(keyC2S)
	sStreamOut, _ := NewAEADStream(keyS2C)

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	clientConn := NewStreamConn(c1, cStreamIn, cStreamOut)
	serverConn := NewStreamConn(c2, sStreamIn, sStreamOut)

	testData := bytes.Repeat([]byte("abcdef123456"), 5000) // 60KB

	errCh := make(chan error, 2)

	// Server echoes back
	go func() {
		buf := make([]byte, len(testData))
		if _, err := io.ReadFull(serverConn, buf); err != nil {
			errCh <- err
			return
		}
		if _, err := serverConn.Write(buf); err != nil {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	// Client sends and receives
	go func() {
		if _, err := clientConn.Write(testData); err != nil {
			errCh <- err
			return
		}
		buf := make([]byte, len(testData))
		if _, err := io.ReadFull(clientConn, buf); err != nil {
			errCh <- err
			return
		}
		if !bytes.Equal(buf, testData) {
			t.Errorf("echoed data mismatch")
		}
		errCh <- nil
	}()

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("concurrent stream error: %v", err)
		}
	}
}

func BenchmarkStreamConn_Throughput(b *testing.B) {
	keyC2S := [16]byte{1, 2, 3}
	keyS2C := [16]byte{4, 5, 6}

	cStreamOut, _ := NewAEADStream(keyC2S)
	cStreamIn, _ := NewAEADStream(keyS2C)
	sStreamIn, _ := NewAEADStream(keyC2S)
	sStreamOut, _ := NewAEADStream(keyS2C)

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	clientConn := NewStreamConn(c1, cStreamIn, cStreamOut)
	serverConn := NewStreamConn(c2, sStreamIn, sStreamOut)

	chunk := make([]byte, 32*1024) // 32KB payload
	b.SetBytes(int64(len(chunk)))
	b.ResetTimer()

	go func() {
		buf := make([]byte, len(chunk))
		for {
			_, err := io.ReadFull(serverConn, buf)
			if err != nil {
				return
			}
		}
	}()

	for i := 0; i < b.N; i++ {
		if _, err := clientConn.Write(chunk); err != nil {
			b.Fatalf("write failed: %v", err)
		}
	}
}

func BenchmarkAEADStream_Direct(b *testing.B) {
	key := [16]byte{1, 2, 3, 4}
	streamEnc, _ := NewAEADStream(key)
	streamDec, _ := NewAEADStream(key)

	plaintext := make([]byte, 16384) // 16KB
	b.SetBytes(int64(len(plaintext)))
	encBuf := make([]byte, 0, MaxChunkWireLen+2)
	decBuf := make([]byte, 0, MaxChunkPayloadLen)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enc, _ := streamEnc.EncryptChunk(encBuf[:0], plaintext)
		wireLen := binary.BigEndian.Uint16(enc[:2])
		_, _ = streamDec.DecryptChunk(decBuf[:0], enc[2:], wireLen)
	}
}

func BenchmarkAES128GCM_Direct(b *testing.B) {
	key := make([]byte, 16)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	plaintext := make([]byte, 16384)
	b.SetBytes(int64(len(plaintext)))
	nonce := make([]byte, 12)
	encBuf := make([]byte, 0, 16384+16)
	decBuf := make([]byte, 0, 16384)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enc := gcm.Seal(encBuf[:0], nonce, plaintext, nil)
		_, _ = gcm.Open(decBuf[:0], nonce, enc, nil)
	}
}

func TestAEADStream_SequenceExhaustion(t *testing.T) {
	key := [16]byte{1, 2, 3, 4}
	streamEnc, err := NewAEADStream(key)
	if err != nil {
		t.Fatalf("NewAEADStream: %v", err)
	}
	streamEnc.sequence = math.MaxUint64

	_, err = streamEnc.EncryptChunk(nil, []byte("data"))
	if !errors.Is(err, ErrSequenceExhausted) {
		t.Fatalf("expected ErrSequenceExhausted on EncryptChunk, got %v", err)
	}

	streamDec, err := NewAEADStream(key)
	if err != nil {
		t.Fatalf("NewAEADStream: %v", err)
	}
	streamDec.sequence = math.MaxUint64

	_, err = streamDec.DecryptChunk(nil, make([]byte, 32), 32)
	if !errors.Is(err, ErrSequenceExhausted) {
		t.Fatalf("expected ErrSequenceExhausted on DecryptChunk, got %v", err)
	}
}

func TestFramedWriter_LargeWrite_Batching(t *testing.T) {
	key := [16]byte{1, 2, 3, 4}
	encStream, _ := NewAEADStream(key)
	decStream, _ := NewAEADStream(key)

	r, w := io.Pipe()
	fw := NewFramedWriter(w, encStream)
	fr := NewFramedReader(r, decStream)

	largeData := bytes.Repeat([]byte("1234567890abcdef"), 64*1024) // 1 MiB

	errCh := make(chan error, 1)
	go func() {
		defer w.Close()
		_, err := fw.Write(largeData)
		errCh <- err
	}()

	readBuf := make([]byte, len(largeData))
	if _, err := io.ReadFull(fr, readBuf); err != nil {
		t.Fatalf("ReadFull failed: %v", err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("fw.Write failed: %v", err)
	}

	if !bytes.Equal(readBuf, largeData) {
		t.Fatalf("large write data corrupted")
	}
}
