package h1session

import (
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"sync"
)

// FramedWriter encrypts outgoing byte streams into length-prefixed AEAD chunks.
type FramedWriter struct {
	w       io.Writer
	stream  *AEADStream
	mu      sync.Mutex
	flusher http.Flusher
	buf     []byte
}

// NewFramedWriter wraps an io.Writer with an AEAD encryption stream.
func NewFramedWriter(w io.Writer, stream *AEADStream) *FramedWriter {
	flusher, _ := w.(http.Flusher)
	return &FramedWriter{
		w:       w,
		stream:  stream,
		flusher: flusher,
		buf:     make([]byte, 0, MaxChunkWireLen+2),
	}
}

func (fw *FramedWriter) Write(p []byte) (n int, err error) {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	total := len(p)
	for len(p) > 0 {
		chunkSize := len(p)
		if chunkSize > MaxChunkPayloadLen {
			chunkSize = MaxChunkPayloadLen
		}
		chunk := p[:chunkSize]
		p = p[chunkSize:]

		fw.buf = fw.buf[:0]
		fw.buf, err = fw.stream.EncryptChunk(fw.buf, chunk)
		if err != nil {
			return n, err
		}

		if _, err := fw.w.Write(fw.buf); err != nil {
			return n, err
		}
		if fw.flusher != nil {
			fw.flusher.Flush()
		}
		n += chunkSize
	}
	return total, nil
}

// FramedReader decrypts incoming length-prefixed AEAD chunks into a plaintext byte stream.
type FramedReader struct {
	r      io.Reader
	stream *AEADStream
	mu     sync.Mutex
	hdrBuf [2]byte
	rawBuf []byte
	decBuf []byte
}

// NewFramedReader wraps an io.Reader with an AEAD decryption stream.
func NewFramedReader(r io.Reader, stream *AEADStream) *FramedReader {
	return &FramedReader{
		r:      r,
		stream: stream,
		rawBuf: make([]byte, MaxChunkWireLen),
	}
}

func (fr *FramedReader) Read(p []byte) (int, error) {
	fr.mu.Lock()
	defer fr.mu.Unlock()

	if len(fr.decBuf) > 0 {
		n := copy(p, fr.decBuf)
		fr.decBuf = fr.decBuf[n:]
		return n, nil
	}

	// Read 2-byte chunk wire length
	if _, err := io.ReadFull(fr.r, fr.hdrBuf[:]); err != nil {
		return 0, err
	}
	wireLen := int(binary.BigEndian.Uint16(fr.hdrBuf[:]))
	if wireLen == 0 {
		return 0, io.EOF
	}
	if wireLen > MaxChunkWireLen {
		return 0, ErrChunkTooLarge
	}

	raw := fr.rawBuf[:wireLen]
	if _, err := io.ReadFull(fr.r, raw); err != nil {
		return 0, err
	}

	decrypted, err := fr.stream.DecryptChunk(nil, raw)
	if err != nil {
		return 0, err
	}

	n := copy(p, decrypted)
	if n < len(decrypted) {
		fr.decBuf = append(fr.decBuf[:0], decrypted[n:]...)
	}
	return n, nil
}

// Conn wraps a net.Conn with bidirectional AEAD framed reading and writing.
type Conn struct {
	net.Conn
	reader *FramedReader
	writer *FramedWriter
}

// NewConn wraps a net.Conn with AEAD stream framing.
func NewConn(raw net.Conn, clientKey, serverKey [32]byte, isClient bool) (*Conn, error) {
	var encStream, decStream *AEADStream
	var err error

	if isClient {
		encStream, err = NewAEADStream(clientKey, DirClientToServer)
		if err != nil {
			return nil, err
		}
		decStream, err = NewAEADStream(serverKey, DirServerToClient)
		if err != nil {
			return nil, err
		}
	} else {
		encStream, err = NewAEADStream(serverKey, DirServerToClient)
		if err != nil {
			return nil, err
		}
		decStream, err = NewAEADStream(clientKey, DirClientToServer)
		if err != nil {
			return nil, err
		}
	}

	return &Conn{
		Conn:   raw,
		reader: NewFramedReader(raw, decStream),
		writer: NewFramedWriter(raw, encStream),
	}, nil
}

func (c *Conn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *Conn) Write(p []byte) (int, error) {
	return c.writer.Write(p)
}
