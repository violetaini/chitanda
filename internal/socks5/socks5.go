package socks5

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

const (
	CommandConnect      = 0x01
	CommandUDPAssociate = 0x03
)

type Request struct {
	Command byte
	Target  string
	Reader  *bufio.Reader
}

func Negotiate(conn net.Conn) (Request, error) {
	reader := bufio.NewReader(conn)
	var greeting [2]byte
	if _, err := io.ReadFull(reader, greeting[:]); err != nil || greeting[0] != 0x05 {
		return Request{}, errors.New("invalid SOCKS greeting")
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(reader, methods); err != nil {
		return Request{}, err
	}
	noAuth := false
	for _, method := range methods {
		if method == 0x00 {
			noAuth = true
			break
		}
	}
	if !noAuth {
		_, _ = conn.Write([]byte{0x05, 0xff})
		return Request{}, errors.New("no supported authentication method")
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return Request{}, err
	}
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil || header[0] != 0x05 {
		return Request{}, errors.New("invalid SOCKS request")
	}
	if header[1] != CommandConnect && header[1] != CommandUDPAssociate {
		return Request{}, errors.New("unsupported SOCKS command")
	}
	target, err := readAddress(reader, header[3])
	if err != nil {
		return Request{}, err
	}
	return Request{Command: header[1], Target: target, Reader: reader}, nil
}

func WriteReply(conn net.Conn, status byte, bound net.Addr) error {
	address := "0.0.0.0:0"
	if bound != nil {
		address = bound.String()
	}
	encoded, err := encodeAddress(address)
	if err != nil {
		return err
	}
	reply := append([]byte{0x05, status, 0x00}, encoded...)
	_, err = conn.Write(reply)
	return err
}

func ParseUDPPacket(packet []byte) (string, []byte, error) {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return "", nil, errors.New("invalid or fragmented SOCKS UDP packet")
	}
	reader := &sliceReader{value: packet[4:]}
	address, err := readAddress(reader, packet[3])
	if err != nil {
		return "", nil, err
	}
	return address, reader.value, nil
}

func BuildUDPPacket(address string, payload []byte) ([]byte, error) {
	encoded, err := encodeAddress(address)
	if err != nil {
		return nil, err
	}
	packet := make([]byte, 3, 3+len(encoded)+len(payload))
	packet = append(packet, encoded...)
	packet = append(packet, payload...)
	return packet, nil
}

func readAddress(reader io.Reader, addressType byte) (string, error) {
	var host string
	switch addressType {
	case 0x01:
		value := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(reader, value); err != nil {
			return "", err
		}
		host = net.IP(value).String()
	case 0x03:
		var length [1]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil {
			return "", err
		}
		value := make([]byte, int(length[0]))
		if _, err := io.ReadFull(reader, value); err != nil {
			return "", err
		}
		host = string(value)
	case 0x04:
		value := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(reader, value); err != nil {
			return "", err
		}
		host = net.IP(value).String()
	default:
		return "", errors.New("unsupported SOCKS address type")
	}
	var port [2]byte
	if _, err := io.ReadFull(reader, port[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))), nil
}

func encodeAddress(address string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 || port > 65535 {
		return nil, errors.New("invalid port")
	}
	var encoded []byte
	if ip := net.ParseIP(host); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			encoded = append([]byte{0x01}, ipv4...)
		} else {
			encoded = append([]byte{0x04}, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, fmt.Errorf("invalid host length: %d", len(host))
		}
		encoded = append([]byte{0x03, byte(len(host))}, []byte(host)...)
	}
	return binary.BigEndian.AppendUint16(encoded, uint16(port)), nil
}

type sliceReader struct {
	value []byte
}

func (r *sliceReader) Read(p []byte) (int, error) {
	if len(r.value) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.value)
	r.value = r.value[n:]
	return n, nil
}
