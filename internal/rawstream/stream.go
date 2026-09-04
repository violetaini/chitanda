package rawstream

import (
	"bufio"
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

const MaxBatchFlushLen = 128 * 1024 // 128 KiB batch flush ceiling

// NewFramedWriter wraps an io.Writer with an AEAD encryption stream.
func NewFramedWriter(w io.Writer, stream *AEADStream) *FramedWriter {
	return &FramedWriter{
		w:      w,
		stream: stream,
		buf:    make([]byte, 0, MaxBatchFlushLen+MaxChunkWireLen+2),
	}
}

func (fw *FramedWriter) Write(p []byte) (n int, err error) {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	fw.buf = fw.buf[:0]
	unflushedPlaintext := 0

	for len(p) > 0 {
		chunkSize := len(p)
		if chunkSize > MaxChunkPayloadLen {
			chunkSize = MaxChunkPayloadLen
		}
		chunk := p[:chunkSize]
		p = p[chunkSize:]

		fw.buf, err = fw.stream.EncryptChunk(fw.buf, chunk)
		if err != nil {
			return n, err
		}
		unflushedPlaintext += chunkSize

		// Flush batch if accumulated buffer exceeds MaxBatchFlushLen
		if len(fw.buf) >= MaxBatchFlushLen {
			if _, err := fw.w.Write(fw.buf); err != nil {
				return n, err
			}
			n += unflushedPlaintext
			unflushedPlaintext = 0
			fw.buf = fw.buf[:0]
		}
	}

	if len(fw.buf) > 0 {
		if _, err := fw.w.Write(fw.buf); err != nil {
			return n, err
		}
		n += unflushedPlaintext
		unflushedPlaintext = 0
		fw.buf = fw.buf[:0]
	}
	return n, nil
}

// FramedReader decrypts incoming length-prefixed AEAD chunks into a plaintext byte stream.
type FramedReader struct {
	r          io.Reader
	br         *bufio.Reader
	stream     *AEADStream
	mu         sync.Mutex
	hdrBuf     [2]byte
	rawBuf     []byte
	decBuf     []byte
	decOff     int
	eofReached bool
}

// NewFramedReader wraps an io.Reader with an AEAD decryption stream.
func NewFramedReader(r io.Reader, stream *AEADStream) *FramedReader {
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReaderSize(r, 64*1024)
	}
	return &FramedReader{
		r:      br,
		br:     br,
		stream: stream,
		rawBuf: make([]byte, MaxChunkWireLen),
		decBuf: make([]byte, 0, MaxChunkPayloadLen),
	}
}

func (fr *FramedReader) Read(p []byte) (int, error) {
	fr.mu.Lock()
	defer fr.mu.Unlock()

	if fr.eofReached && fr.decOff >= len(fr.decBuf) {
		return 0, io.EOF
	}

	var totalRead int

	for len(p) > 0 {
		// 1. Consume any remaining decrypted data from previous chunk
		if fr.decOff < len(fr.decBuf) {
			n := copy(p, fr.decBuf[fr.decOff:])
			fr.decOff += n
			totalRead += n
			p = p[n:]
			if len(p) == 0 {
				return totalRead, nil
			}
		}

		if fr.eofReached {
			if totalRead > 0 {
				return totalRead, nil
			}
			return 0, io.EOF
		}

		// 2. If we already read some bytes and no further header is buffered in memory,
		// return immediately so we don't block the caller.
		if totalRead > 0 && fr.br.Buffered() < 2 {
			return totalRead, nil
		}

		// Read 2-byte chunk wire length
		if _, err := io.ReadFull(fr.r, fr.hdrBuf[:]); err != nil {
			fr.eofReached = true
			if totalRead > 0 {
				return totalRead, nil
			}
			return 0, err
		}
		wireLen := int(binary.BigEndian.Uint16(fr.hdrBuf[:]))
		if wireLen == 0 {
			fr.eofReached = true
			if totalRead > 0 {
				return totalRead, nil
			}
			return 0, io.EOF
		}
		if wireLen > MaxChunkWireLen {
			return totalRead, ErrChunkTooLarge
		}

		if cap(fr.rawBuf) < wireLen {
			fr.rawBuf = make([]byte, wireLen)
		} else {
			fr.rawBuf = fr.rawBuf[:wireLen]
		}

		if _, err := io.ReadFull(fr.r, fr.rawBuf); err != nil {
			fr.eofReached = true
			if totalRead > 0 {
				return totalRead, nil
			}
			return 0, err
		}

		var err error
		fr.decBuf, err = fr.stream.DecryptChunk(fr.decBuf[:0], fr.rawBuf, uint16(wireLen))
		if err != nil {
			return totalRead, ErrDecryptionFailed
		}

		fr.decOff = 0
		n := copy(p, fr.decBuf)
		fr.decOff = n
		totalRead += n
		p = p[n:]
	}

	return totalRead, nil
}

type closeWriter interface {
	CloseWrite() error
}

type closeReader interface {
	CloseRead() error
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

func (c *StreamConn) CloseWrite() error {
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (c *StreamConn) CloseRead() error {
	if cr, ok := c.Conn.(closeReader); ok {
		return cr.CloseRead()
	}
	return nil
}
