package rawstream

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
)

// FramedWriter encrypts outgoing byte streams into length-prefixed AEAD chunks.
type FramedWriter struct {
	w      io.Writer
	stream *AEADStream
	mu     sync.Mutex
	buf    []byte
}

// NewFramedWriter wraps an io.Writer with an AEAD encryption stream.
func NewFramedWriter(w io.Writer, stream *AEADStream) *FramedWriter {
	return &FramedWriter{
		w:      w,
		stream: stream,
		buf:    make([]byte, 0, MaxChunkWireLen+2),
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

	if cap(fr.rawBuf) < wireLen {
		fr.rawBuf = make([]byte, wireLen)
	} else {
		fr.rawBuf = fr.rawBuf[:wireLen]
	}

	if _, err := io.ReadFull(fr.r, fr.rawBuf); err != nil {
		return 0, err
	}

	var err error
	fr.decBuf, err = fr.stream.DecryptChunk(fr.decBuf[:0], fr.rawBuf, uint16(wireLen))
	if err != nil {
		return 0, ErrDecryptionFailed
	}

	n := copy(p, fr.decBuf)
	fr.decBuf = fr.decBuf[n:]
	return n, nil
}

// StreamConn wraps a raw net.Conn with bidirectional AEAD framed streaming.
type StreamConn struct {
	net.Conn
	Reader *FramedReader
	Writer *FramedWriter
}

func NewStreamConn(conn net.Conn, rStream, wStream *AEADStream) *StreamConn {
	return &StreamConn{
		Conn:   conn,
		Reader: NewFramedReader(conn, rStream),
		Writer: NewFramedWriter(conn, wStream),
	}
}

func (c *StreamConn) Read(b []byte) (int, error) {
	return c.Reader.Read(b)
}

func (c *StreamConn) Write(b []byte) (int, error) {
	return c.Writer.Write(b)
}
