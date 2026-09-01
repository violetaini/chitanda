package plainudp

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// Header: Timestamp (8B) + Sequence (8B) + Nonce (12B) = 28B
	HeaderSize       = 28
	MaxPacketSize    = 64 << 10 // 64KB max datagram buffer
	MaxTimestampSkew = 30 * time.Second

	SaltUDP = "MYXRAY-PLAIN-UDP-SALT-V1"
	InfoUDP = "MYXRAY-PLAIN-UDP-KEY-V1"
)

var (
	ErrPacketTooShort     = errors.New("plainudp: packet too short")
	ErrTimestampExpired   = errors.New("plainudp: timestamp out of acceptable window")
	ErrReplayDetected     = errors.New("plainudp: duplicate or replayed datagram")
	ErrDecryptionFailed   = errors.New("plainudp: AEAD packet decryption failed")
	ErrInvalidAddressType = errors.New("plainudp: unsupported SOCKS5 address type")
	ErrInvalidAddress     = errors.New("plainudp: malformed address in packet")
)

// DeriveKey derives a 32-byte key for plain UDP datagrams.
func DeriveKey(psk []byte) [32]byte {
	extractor := hmac.New(sha256.New, []byte(SaltUDP))
	extractor.Write(psk)
	prk := extractor.Sum(nil)

	expander := hmac.New(sha256.New, prk)
	expander.Write([]byte(InfoUDP))
	expander.Write([]byte{0x01})
	out := expander.Sum(nil)

	var key [32]byte
	copy(key[:], out[0:32])
	return key
}

// Codec provides stateless ChaCha20-Poly1305 AEAD encryption and decryption.
// Anti-replay protection is decoupled and maintained per authenticated SessionID.
type Codec struct {
	key      [32]byte
	aead     cipher.AEAD
	sequence atomic.Uint64
}

// NewCodec creates a persistent Codec instance holding the initialized AEAD cipher.
func NewCodec(psk []byte) (*Codec, error) {
	key := DeriveKey(psk)
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	return &Codec{
		key:  key,
		aead: aead,
	}, nil
}

// EncodePacket encrypts sessionID, target address and payload into a plain-udp datagram.
func (c *Codec) EncodePacket(dst []byte, sessionID uint64, targetAddr string, payload []byte, now time.Time) ([]byte, error) {
	addrBuf, err := encodeTargetAddress(targetAddr)
	if err != nil {
		return nil, err
	}

	// Plaintext: [SessionID (8B)] [Target SOCKS5 Addr] [Payload]
	plaintext := make([]byte, 8+len(addrBuf)+len(payload))
	binary.BigEndian.PutUint64(plaintext[0:8], sessionID)
	copy(plaintext[8:], addrBuf)
	copy(plaintext[8+len(addrBuf):], payload)

	seq := c.sequence.Add(1)

	var nonce [12]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:4]); err != nil {
		return nil, fmt.Errorf("plainudp: random nonce failed: %w", err)
	}
	binary.BigEndian.PutUint64(nonce[4:12], seq)

	ts := uint64(now.Unix())
	var ad [16]byte
	binary.BigEndian.PutUint64(ad[0:8], ts)
	binary.BigEndian.PutUint64(ad[8:16], seq)

	// Wire: [Timestamp (8B)] [Sequence (8B)] [Nonce (12B)] [Ciphertext + Tag (16B)]
	if dst == nil {
		dst = make([]byte, 0, HeaderSize+len(plaintext)+c.aead.Overhead())
	}
	dst = append(dst, ad[:]...)
	dst = append(dst, nonce[:]...)
	dst = c.aead.Seal(dst, nonce[:], plaintext, ad[:])

	return dst, nil
}

// DecodePacket decrypts a plain-udp datagram, authenticates via AEAD, and extracts sessionID, target address and payload.
// It is strictly stateless and verifies the cryptographic tag FIRST before returning seq to prevent replay window poisoning.
func (c *Codec) DecodePacket(packet []byte, now time.Time) (sessionID uint64, targetAddr string, payload []byte, timestamp uint64, seq uint64, err error) {
	if len(packet) < HeaderSize+8+1+4+2+16 { // min size with SessionID + IPv4
		return 0, "", nil, 0, 0, ErrPacketTooShort
	}

	timestamp = binary.BigEndian.Uint64(packet[0:8])
	nowSec := uint64(now.Unix())
	diff := int64(nowSec) - int64(timestamp)
	if diff < -int64(MaxTimestampSkew/time.Second) || diff > int64(MaxTimestampSkew/time.Second) {
		return 0, "", nil, timestamp, 0, ErrTimestampExpired
	}

	seq = binary.BigEndian.Uint64(packet[8:16])
	ad := packet[0:16]
	nonce := packet[16:28]
	ciphertextWithTag := packet[28:]

	// 1. Authenticate and decrypt FIRST. Unauthenticated packets fail immediately without modifying any state.
	plaintext, err := c.aead.Open(nil, nonce, ciphertextWithTag, ad)
	if err != nil {
		return 0, "", nil, timestamp, seq, ErrDecryptionFailed
	}

	if len(plaintext) < 8 {
		return 0, "", nil, timestamp, seq, ErrPacketTooShort
	}

	sessionID = binary.BigEndian.Uint64(plaintext[0:8])

	// 2. Parse target address and payload.
	targetAddr, payload, err = decodeTargetAddress(plaintext[8:])
	if err != nil {
		return sessionID, "", nil, timestamp, seq, err
	}

	return sessionID, targetAddr, payload, timestamp, seq, nil
}

func encodeTargetAddress(address string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %w", address, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid port %q", portText)
	}

	buf := make([]byte, 0, 1+1+16+2)
	if ip := net.ParseIP(host); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			buf = append(buf, 0x01)
			buf = append(buf, ipv4...)
		} else {
			buf = append(buf, 0x04)
			buf = append(buf, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, fmt.Errorf("invalid domain host length: %d", len(host))
		}
		buf = append(buf, 0x03, byte(len(host)))
		buf = append(buf, host...)
	}
	buf = binary.BigEndian.AppendUint16(buf, uint16(port))
	return buf, nil
}

func decodeTargetAddress(data []byte) (targetAddress string, payload []byte, err error) {
	if len(data) < 7 {
		return "", nil, ErrInvalidAddress
	}

	offset := 0
	var host string
	addrType := data[offset]
	offset++

	switch addrType {
	case 0x01: // IPv4
		if len(data) < offset+4+2 {
			return "", nil, ErrInvalidAddress
		}
		host = net.IP(data[offset : offset+4]).String()
		offset += 4
	case 0x03: // Domain
		if len(data) < offset+1 {
			return "", nil, ErrInvalidAddress
		}
		domainLen := int(data[offset])
		offset++
		if len(data) < offset+domainLen+2 {
			return "", nil, ErrInvalidAddress
		}
		host = string(data[offset : offset+domainLen])
		offset += domainLen
	case 0x04: // IPv6
		if len(data) < offset+16+2 {
			return "", nil, ErrInvalidAddress
		}
		host = net.IP(data[offset : offset+16]).String()
		offset += 16
	default:
		return "", nil, ErrInvalidAddressType
	}

	port := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	targetAddress = net.JoinHostPort(host, strconv.Itoa(int(port)))
	if len(data) > offset {
		payload = data[offset:]
	}
	return targetAddress, payload, nil
}
