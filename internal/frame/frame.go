package frame

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	Version       = 1
	HeaderSize    = 8
	DataChunkSize = 256 << 10
	MaxPayload    = 16 << 20
)

type Type byte

const (
	TypeOpen Type = iota + 1
	TypeOpenAck
	TypeData
	TypeHalfClose
	TypeReset
	TypeWindowUpdate
)

type Header struct {
	Type   Type
	Flags  uint16
	Length uint32
}

func ReadHeader(r io.Reader) (Header, error) {
	var raw [HeaderSize]byte
	if _, err := io.ReadFull(r, raw[:]); err != nil {
		return Header{}, err
	}
	if raw[0] != Version {
		return Header{}, fmt.Errorf("unsupported frame version %d", raw[0])
	}
	header := Header{
		Type:   Type(raw[1]),
		Flags:  binary.BigEndian.Uint16(raw[2:4]),
		Length: binary.BigEndian.Uint32(raw[4:8]),
	}
	if header.Length > MaxPayload {
		return Header{}, fmt.Errorf("frame payload too large: %d", header.Length)
	}
	return header, nil
}

func ReadPayload(r io.Reader, length uint32) ([]byte, error) {
	if length > MaxPayload {
		return nil, fmt.Errorf("frame payload too large: %d", length)
	}
	payload := make([]byte, int(length))
	_, err := io.ReadFull(r, payload)
	return payload, err
}

func WriteFrame(w io.Writer, frameType Type, flags uint16, payload []byte) error {
	if len(payload) > MaxPayload {
		return fmt.Errorf("frame payload too large: %d", len(payload))
	}
	buffer := make([]byte, HeaderSize+len(payload))
	encodeHeader(buffer[:HeaderSize], frameType, flags, uint32(len(payload)))
	copy(buffer[HeaderSize:], payload)
	return writeFull(w, buffer)
}

func CopyAsDataFrames(w io.Writer, r io.Reader) (int64, error) {
	buffer := make([]byte, HeaderSize+DataChunkSize)
	var total int64
	for {
		n, readErr := r.Read(buffer[HeaderSize:])
		if n > 0 {
			encodeHeader(buffer[:HeaderSize], TypeData, 0, uint32(n))
			if err := writeFull(w, buffer[:HeaderSize+n]); err != nil {
				return total, err
			}
			total += int64(n)
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return total, nil
			}
			return total, readErr
		}
	}
}

func encodeHeader(dst []byte, frameType Type, flags uint16, length uint32) {
	dst[0] = Version
	dst[1] = byte(frameType)
	binary.BigEndian.PutUint16(dst[2:4], flags)
	binary.BigEndian.PutUint32(dst[4:8], length)
}

func writeFull(w io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := w.Write(payload)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}

const (
	datagramVersion    = 1
	datagramHeaderSize = 11
	maxDatagramAddress = 512
	// 1350 leaves headroom for the private frame, HTTP Datagram, QUIC, UDP and
	// IPv4 headers on a 1500-byte path while reducing per-packet CPU overhead.
	MaxDatagramPayload = 1350
	MaxDatagramSize    = datagramHeaderSize + maxDatagramAddress + MaxDatagramPayload
	ReplayWindowSize   = 2048
)

func EncodeDatagram(sequence uint64, address string, payload []byte) ([]byte, error) {
	return EncodeDatagramInto(make([]byte, datagramHeaderSize+len(address)+len(payload)), sequence, address, payload)
}

// EncodeDatagramInto writes a datagram into dst. The caller may reuse dst after
// SendDatagram returns because quic-go copies the payload before returning.
func EncodeDatagramInto(dst []byte, sequence uint64, address string, payload []byte) ([]byte, error) {
	if len(address) == 0 || len(address) > maxDatagramAddress {
		return nil, errors.New("invalid datagram address")
	}
	if len(payload) > MaxDatagramPayload {
		return nil, fmt.Errorf("datagram payload too large: %d", len(payload))
	}
	length := datagramHeaderSize + len(address) + len(payload)
	if cap(dst) < length {
		return nil, fmt.Errorf("datagram buffer too small: %d", cap(dst))
	}
	result := dst[:length]
	result[0] = datagramVersion
	binary.BigEndian.PutUint64(result[1:9], sequence)
	binary.BigEndian.PutUint16(result[9:11], uint16(len(address)))
	copy(result[datagramHeaderSize:], address)
	copy(result[datagramHeaderSize+len(address):], payload)
	return result, nil
}

func DecodeDatagram(packet []byte) (uint64, string, []byte, error) {
	var cache DatagramCache
	return cache.Decode(packet)
}

// DatagramCache avoids allocating a new address string for every packet in a
// flow whose destination is unchanged.
type DatagramCache struct {
	key     []byte
	address string
}

func (c *DatagramCache) Decode(packet []byte) (uint64, string, []byte, error) {
	if len(packet) < datagramHeaderSize || packet[0] != datagramVersion {
		return 0, "", nil, errors.New("invalid datagram header")
	}
	addressLength := int(binary.BigEndian.Uint16(packet[9:11]))
	if addressLength == 0 || addressLength > maxDatagramAddress || datagramHeaderSize+addressLength > len(packet) {
		return 0, "", nil, errors.New("invalid datagram address length")
	}
	payload := packet[datagramHeaderSize+addressLength:]
	if len(payload) > MaxDatagramPayload {
		return 0, "", nil, errors.New("datagram payload too large")
	}
	addressBytes := packet[datagramHeaderSize : datagramHeaderSize+addressLength]
	if c.address == "" || !bytes.Equal(c.key, addressBytes) {
		c.key = append(c.key[:0], addressBytes...)
		c.address = string(addressBytes)
	}
	return binary.BigEndian.Uint64(packet[1:9]), c.address, payload, nil
}

type ReplayWindow struct {
	initialized bool
	highest     uint64
	bits        [ReplayWindowSize / 64]uint64
}

func (w *ReplayWindow) Accept(sequence uint64) bool {
	if !w.initialized {
		w.initialized = true
		w.highest = sequence
		w.bits[0] = 1
		return true
	}
	if sequence > w.highest {
		shift := sequence - w.highest
		if shift >= ReplayWindowSize {
			clear(w.bits[:])
		} else {
			wordShift := int(shift / 64)
			bitShift := uint(shift % 64)
			for index := len(w.bits) - 1; index >= 0; index-- {
				source := index - wordShift
				var value uint64
				if source >= 0 {
					value = w.bits[source] << bitShift
					if bitShift != 0 && source > 0 {
						value |= w.bits[source-1] >> (64 - bitShift)
					}
				}
				w.bits[index] = value
			}
		}
		w.bits[0] |= 1
		w.highest = sequence
		return true
	}
	delta := w.highest - sequence
	if delta >= ReplayWindowSize {
		return false
	}
	word := delta / 64
	mask := uint64(1) << (delta % 64)
	if w.bits[word]&mask != 0 {
		return false
	}
	w.bits[word] |= mask
	return true
}
