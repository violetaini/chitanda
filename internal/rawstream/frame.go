package rawstream

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	ClientHelloSize    = 48 // 8B Timestamp + 24B ClientNonce + 16B AuthTag
	ServerHelloSize    = 40 // 24B ServerNonce + 16B ServerAuthTag
	MaxChunkPayloadLen = 16384
	MaxChunkWireLen    = MaxChunkPayloadLen + 16 // 16B Poly1305 tag
	MaxTimestampSkew   = 90 * time.Second

	DefaultMinPadding = 32
	DefaultMaxPadding = 256

	DomainClientHello = "CHITANDA-RAWSTREAM-CLIENT-V1"
	DomainServerHello = "CHITANDA-RAWSTREAM-SERVER-V1"
	Domain0RTTKey     = "CHITANDA-RAWSTREAM-0RTT-V1"
	DomainSessionKey  = "CHITANDA-RAWSTREAM-SESSION-V1"
)

var (
	ErrInvalidRecordLen  = errors.New("rawstream: invalid handshake record length")
	ErrTimestampExpired  = errors.New("rawstream: timestamp out of acceptable window")
	ErrInvalidClientAuth = errors.New("rawstream: invalid client authentication tag")
	ErrInvalidServerAuth = errors.New("rawstream: invalid server authentication tag")
	ErrDecryptionFailed  = errors.New("rawstream: AEAD chunk decryption failed")
	ErrChunkTooLarge     = errors.New("rawstream: AEAD chunk length exceeds maximum allowed size")
	ErrInvalidOpenFrame  = errors.New("rawstream: invalid OPEN frame structure")
	ErrInvalidAddress    = errors.New("rawstream: unsupported address type in OPEN frame")
)

// CreateClientHello generates a 48-byte ClientHello record.
func CreateClientHello(psk []byte, now time.Time) (record []byte, clientNonce [24]byte, timestamp uint64, err error) {
	if len(psk) < 16 {
		return nil, clientNonce, 0, errors.New("rawstream: PSK must be at least 16 bytes")
	}
	timestamp = uint64(now.Unix())
	if _, err := io.ReadFull(rand.Reader, clientNonce[:]); err != nil {
		return nil, clientNonce, 0, fmt.Errorf("rawstream: random generator failed: %w", err)
	}

	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte(DomainClientHello))
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], timestamp)
	mac.Write(tsBuf[:])
	mac.Write(clientNonce[:])
	fullTag := mac.Sum(nil)

	record = make([]byte, ClientHelloSize)
	copy(record[0:8], tsBuf[:])
	copy(record[8:32], clientNonce[:])
	copy(record[32:48], fullTag[:16])

	return record, clientNonce, timestamp, nil
}

// VerifyClientHello verifies an incoming 48-byte ClientHello record.
func VerifyClientHello(psk []byte, record []byte, now time.Time) (clientNonce [24]byte, timestamp uint64, err error) {
	if len(psk) < 16 {
		return clientNonce, 0, errors.New("rawstream: PSK must be at least 16 bytes")
	}
	if len(record) != ClientHelloSize {
		return clientNonce, 0, ErrInvalidRecordLen
	}

	timestamp = binary.BigEndian.Uint64(record[0:8])
	copy(clientNonce[:], record[8:32])
	clientTag := record[32:48]

	nowSec := uint64(now.Unix())
	diff := int64(nowSec) - int64(timestamp)
	if diff < -int64(MaxTimestampSkew/time.Second) || diff > int64(MaxTimestampSkew/time.Second) {
		return clientNonce, 0, ErrTimestampExpired
	}

	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte(DomainClientHello))
	mac.Write(record[0:8])
	mac.Write(clientNonce[:])
	expectedFullTag := mac.Sum(nil)

	if !hmac.Equal(clientTag, expectedFullTag[:16]) {
		return clientNonce, 0, ErrInvalidClientAuth
	}

	return clientNonce, timestamp, nil
}

// Derive0RTTKey derives a 32-byte key for 0-RTT frame encryption.
func Derive0RTTKey(psk []byte, timestamp uint64, clientNonce [24]byte) ([32]byte, error) {
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte(Domain0RTTKey))
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], timestamp)
	mac.Write(tsBuf[:])
	mac.Write(clientNonce[:])
	sum := mac.Sum(nil)

	var key [32]byte
	copy(key[:], sum[:32])
	return key, nil
}

// DeriveSessionKeys derives bidirectional 32-byte keys for established sessions.
func DeriveSessionKeys(psk []byte, timestamp uint64, clientNonce, serverNonce [24]byte) (clientKey, serverKey [32]byte, err error) {
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte(DomainSessionKey))
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], timestamp)
	mac.Write(tsBuf[:])
	mac.Write(clientNonce[:])
	mac.Write(serverNonce[:])
	prk := mac.Sum(nil)

	// Client to Server key
	h1 := hmac.New(sha256.New, prk)
	h1.Write([]byte("C2S"))
	copy(clientKey[:], h1.Sum(nil)[:32])

	// Server to Client key
	h2 := hmac.New(sha256.New, prk)
	h2.Write([]byte("S2C"))
	copy(serverKey[:], h2.Sum(nil)[:32])

	return clientKey, serverKey, nil
}

// CreateServerHello generates a 40-byte ServerHello response record.
func CreateServerHello(psk []byte, timestamp uint64, clientNonce [24]byte) (record []byte, serverNonce [24]byte, err error) {
	if _, err := io.ReadFull(rand.Reader, serverNonce[:]); err != nil {
		return nil, serverNonce, fmt.Errorf("rawstream: server random failed: %w", err)
	}

	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte(DomainServerHello))
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], timestamp)
	mac.Write(tsBuf[:])
	mac.Write(clientNonce[:])
	mac.Write(serverNonce[:])
	fullTag := mac.Sum(nil)

	record = make([]byte, ServerHelloSize)
	copy(record[0:24], serverNonce[:])
	copy(record[24:40], fullTag[:16])

	return record, serverNonce, nil
}

// VerifyServerHello verifies the incoming 40-byte ServerHello record.
func VerifyServerHello(psk []byte, timestamp uint64, clientNonce [24]byte, record []byte) (serverNonce [24]byte, err error) {
	if len(record) != ServerHelloSize {
		return serverNonce, ErrInvalidRecordLen
	}
	copy(serverNonce[:], record[0:24])
	serverTag := record[24:40]

	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte(DomainServerHello))
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], timestamp)
	mac.Write(tsBuf[:])
	mac.Write(clientNonce[:])
	mac.Write(serverNonce[:])
	expectedFullTag := mac.Sum(nil)

	if !hmac.Equal(serverTag, expectedFullTag[:16]) {
		return serverNonce, ErrInvalidServerAuth
	}

	return serverNonce, nil
}

// Encode0RTTOpenFrame encodes target address and initial payload with dynamic random padding.
// Plaintext structure:
// [2B PaddingLen] [PaddingBytes] [TargetAddr (SOCKS5)] [InitialPayload]
func Encode0RTTOpenFrame(target string, initialPayload []byte, minPad, maxPad int) ([]byte, error) {
	if minPad < 0 {
		minPad = DefaultMinPadding
	}
	if maxPad < minPad {
		maxPad = DefaultMaxPadding
	}

	padSpan := maxPad - minPad + 1
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(padSpan)))
	if err != nil {
		return nil, fmt.Errorf("rawstream: rand padding: %w", err)
	}
	paddingLen := minPad + int(nBig.Int64())

	padding := make([]byte, paddingLen)
	if _, err := io.ReadFull(rand.Reader, padding); err != nil {
		return nil, fmt.Errorf("rawstream: fill padding: %w", err)
	}

	targetBytes, err := encodeTargetAddress(target)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 2+paddingLen+len(targetBytes)+len(initialPayload))
	binary.BigEndian.PutUint16(buf[0:2], uint16(paddingLen))
	copy(buf[2:2+paddingLen], padding)
	offset := 2 + paddingLen
	copy(buf[offset:offset+len(targetBytes)], targetBytes)
	offset += len(targetBytes)
	copy(buf[offset:], initialPayload)

	return buf, nil
}

// Decode0RTTOpenFrame decodes target address and initial payload, stripping dynamic padding.
func Decode0RTTOpenFrame(plaintext []byte) (target string, initialPayload []byte, err error) {
	if len(plaintext) < 2 {
		return "", nil, ErrInvalidOpenFrame
	}
	paddingLen := int(binary.BigEndian.Uint16(plaintext[0:2]))
	if len(plaintext) < 2+paddingLen {
		return "", nil, ErrInvalidOpenFrame
	}

	rest := plaintext[2+paddingLen:]
	target, consumed, err := decodeTargetAddress(rest)
	if err != nil {
		return "", nil, err
	}

	initialPayload = rest[consumed:]
	return target, initialPayload, nil
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

	var buf []byte
	if ip := net.ParseIP(host); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			buf = append(buf, 0x01) // IPv4
			buf = append(buf, ipv4...)
		} else {
			buf = append(buf, 0x04) // IPv6
			buf = append(buf, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, fmt.Errorf("invalid domain length %d", len(host))
		}
		buf = append(buf, 0x03) // Domain
		buf = append(buf, byte(len(host)))
		buf = append(buf, host...)
	}

	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], uint16(port))
	buf = append(buf, portBuf[:]...)
	return buf, nil
}

func decodeTargetAddress(b []byte) (string, int, error) {
	if len(b) < 1+4+2 {
		return "", 0, ErrInvalidOpenFrame
	}
	atyp := b[0]
	switch atyp {
	case 0x01: // IPv4
		if len(b) < 1+net.IPv4len+2 {
			return "", 0, ErrInvalidOpenFrame
		}
		ip := net.IP(b[1 : 1+net.IPv4len])
		port := binary.BigEndian.Uint16(b[1+net.IPv4len : 1+net.IPv4len+2])
		return net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), 1 + net.IPv4len + 2, nil

	case 0x04: // IPv6
		if len(b) < 1+net.IPv6len+2 {
			return "", 0, ErrInvalidOpenFrame
		}
		ip := net.IP(b[1 : 1+net.IPv6len])
		port := binary.BigEndian.Uint16(b[1+net.IPv6len : 1+net.IPv6len+2])
		return net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), 1 + net.IPv6len + 2, nil

	case 0x03: // Domain
		domainLen := int(b[1])
		if len(b) < 2+domainLen+2 {
			return "", 0, ErrInvalidOpenFrame
		}
		domain := string(b[2 : 2+domainLen])
		port := binary.BigEndian.Uint16(b[2+domainLen : 2+domainLen+2])
		return net.JoinHostPort(domain, strconv.Itoa(int(port))), 2 + domainLen + 2, nil

	default:
		return "", 0, ErrInvalidAddress
	}
}

// Encrypt0RTTChunk encrypts plaintext using the 0-RTT key.
func Encrypt0RTTChunk(k0RTT [32]byte, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(k0RTT[:])
	if err != nil {
		return nil, err
	}
	var nonce [12]byte // 0-RTT uses single fixed zero nonce
	return aead.Seal(nil, nonce[:], plaintext, nil), nil
}

// Decrypt0RTTChunk decrypts ciphertext using the 0-RTT key.
func Decrypt0RTTChunk(k0RTT [32]byte, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(k0RTT[:])
	if err != nil {
		return nil, err
	}
	var nonce [12]byte
	return aead.Open(nil, nonce[:], ciphertext, nil)
}

// AEADStream manages sequential chunk encryption/decryption with monotonic nonces.
type AEADStream struct {
	aead     cipher.AEAD
	sequence uint64
}

// NewAEADStream creates an AEADStream with ChaCha20-Poly1305.
func NewAEADStream(key [32]byte) (*AEADStream, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	return &AEADStream{aead: aead}, nil
}

// EncryptChunk seals plaintext into dst (allocating if nil) prefixed with a 2-byte length.
func (s *AEADStream) EncryptChunk(dst, plaintext []byte) ([]byte, error) {
	if len(plaintext) > MaxChunkPayloadLen {
		return nil, ErrChunkTooLarge
	}
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:12], s.sequence)
	s.sequence++

	wirePayloadLen := len(plaintext) + s.aead.Overhead()
	if dst == nil {
		dst = make([]byte, 0, 2+wirePayloadLen)
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(wirePayloadLen))
	dst = append(dst, lenBuf[:]...)
	dst = s.aead.Seal(dst, nonce[:], plaintext, lenBuf[:])
	return dst, nil
}

// DecryptChunk opens ciphertext with associated 2-byte wire length data.
func (s *AEADStream) DecryptChunk(dst, ciphertext []byte, wireLen uint16) ([]byte, error) {
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:12], s.sequence)
	s.sequence++

	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], wireLen)
	return s.aead.Open(dst, nonce[:], ciphertext, lenBuf[:])
}
