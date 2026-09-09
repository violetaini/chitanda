package rawstream

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const (
	MinRecordPayloadLen = 1380              // MTU-aligned single-packet record for ultra-low TTFB
	MidRecordPayloadLen = 8192              // Intermediate ramp-up chunk (8 KiB)
	MaxBatchFlushLen    = 128 * 1024        // 128 KiB batch flush ceiling for maximum bulk throughput
	Phase1Threshold     = 128 * 1024        // First 128 KiB uses MinRecordPayloadLen with immediate write
	Phase2Threshold     = 1024 * 1024       // Next 128 KiB to 1 MiB uses MidRecordPayloadLen
	IdleResetThreshold  = 1 * time.Second   // Idle silence after which record size drops back to Phase 1
)

// FramedWriter encrypts outgoing byte streams into length-prefixed AEAD chunks.
type FramedWriter struct {
	w          io.Writer
	stream     *AEADStream
	mu         sync.Mutex
	buf        []byte
	burstBytes int64
	lastWrite  time.Time
}

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

	now := time.Now()
	if !fw.lastWrite.IsZero() && now.Sub(fw.lastWrite) > IdleResetThreshold {
		fw.burstBytes = 0
	}
	fw.lastWrite = now

	fw.buf = fw.buf[:0]
	unflushedPlaintext := 0

	for len(p) > 0 {
		var maxChunk int
		var flushThreshold int

		if fw.burstBytes < Phase1Threshold {
			maxChunk = MinRecordPayloadLen
			flushThreshold = 0 // Immediate flush for sub-millisecond TTFB
		} else if fw.burstBytes < Phase2Threshold {
			maxChunk = MidRecordPayloadLen
			flushThreshold = MidRecordPayloadLen
		} else {
			maxChunk = MaxChunkPayloadLen
			flushThreshold = MaxBatchFlushLen
		}

		chunkSize := len(p)
		if chunkSize > maxChunk {
			chunkSize = maxChunk
		}
		chunk := p[:chunkSize]
		p = p[chunkSize:]

		fw.buf, err = fw.stream.EncryptChunk(fw.buf, chunk)
		if err != nil {
			return n, err
		}
		unflushedPlaintext += chunkSize
		fw.burstBytes += int64(chunkSize)

		// Flush batch if accumulated buffer reaches flushThreshold (or immediate in Phase 1)
		if flushThreshold == 0 || len(fw.buf) >= flushThreshold {
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
	fatalErr   error
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
	if len(p) == 0 {
		return 0, nil
	}

	fr.mu.Lock()
	defer fr.mu.Unlock()

	// 1. Consume any remaining decrypted data from previous chunk
	if fr.decOff < len(fr.decBuf) {
		n := copy(p, fr.decBuf[fr.decOff:])
		fr.decOff += n
		return n, nil
	}

	// 2. Check for sticky EOF or fatal error
	if fr.fatalErr != nil {
		err := fr.fatalErr
		fr.fatalErr = nil
		return 0, err
	}

	if fr.eofReached {
		return 0, io.EOF
	}

	// 3. Read 2-byte chunk wire length
	if _, err := io.ReadFull(fr.r, fr.hdrBuf[:]); err != nil {
		if errors.Is(err, io.EOF) {
			fr.eofReached = true
			return 0, io.EOF
		} else if errors.Is(err, io.ErrUnexpectedEOF) {
			fr.fatalErr = io.ErrUnexpectedEOF
			return 0, io.ErrUnexpectedEOF
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return 0, err
		}
		fr.fatalErr = err
		return 0, err
	}

	wireLen := int(binary.BigEndian.Uint16(fr.hdrBuf[:]))
	if wireLen == 0 {
		fr.eofReached = true
		return 0, io.EOF
	}
	if wireLen > MaxChunkWireLen {
		fr.fatalErr = ErrChunkTooLarge
		return 0, ErrChunkTooLarge
	}

	if cap(fr.rawBuf) < wireLen {
		fr.rawBuf = make([]byte, wireLen)
	} else {
		fr.rawBuf = fr.rawBuf[:wireLen]
	}

	// 4. Read chunk body
	if _, err := io.ReadFull(fr.r, fr.rawBuf); err != nil {
		if errors.Is(err, io.EOF) {
			fr.fatalErr = io.ErrUnexpectedEOF
			return 0, io.ErrUnexpectedEOF
		}
		fr.fatalErr = err
		return 0, err
	}

	// 5. Decrypt chunk
	var err error
	fr.decBuf, err = fr.stream.DecryptChunk(fr.decBuf[:0], fr.rawBuf, uint16(wireLen))
	if err != nil {
		fr.fatalErr = ErrDecryptionFailed
		return 0, ErrDecryptionFailed
	}

	// 6. Copy decrypted data to destination buffer
	fr.decOff = 0
	n := copy(p, fr.decBuf)
	fr.decOff = n
	return n, nil
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
