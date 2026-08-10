package main

import (
	"fmt"
	"os"
	"strings"
)

type replacement struct {
	path string
	old  string
	new  string
}

func main() {
	replacements := []replacement{
		{
			path: "vendor/github.com/quic-go/quic-go/connection.go",
			old: `func (c *Conn) SendDatagram(p []byte) error {
	if !c.supportsDatagrams() {
		return errors.New("datagram support disabled")
	}

	f := &wire.DatagramFrame{DataLenPresent: true}
	// The payload size estimate is conservative.
	// Under many circumstances we could send a few more bytes.
	maxDataLen := min(
		f.MaxDataLen(c.peerParams.MaxDatagramFrameSize, c.version),
		protocol.ByteCount(c.maxPayloadSizeEstimate.Load()),
	)
	if protocol.ByteCount(len(p)) > maxDataLen {
		return &DatagramTooLargeError{MaxDatagramPayloadSize: int64(maxDataLen)}
	}
	f.Data = make([]byte, len(p))
	copy(f.Data, p)
	return c.datagramQueue.Add(f)
}`,
			new: `func (c *Conn) SendDatagram(p []byte) error {
	return c.sendDatagram(p, true)
}

// SendDatagramNoCopy transfers ownership of p to the connection. The caller
// must not access p after this method returns.
func (c *Conn) SendDatagramNoCopy(p []byte) error {
	return c.sendDatagram(p, false)
}

func (c *Conn) sendDatagram(p []byte, copyPayload bool) error {
	if !c.supportsDatagrams() {
		return errors.New("datagram support disabled")
	}

	f := &wire.DatagramFrame{DataLenPresent: true}
	// The payload size estimate is conservative.
	// Under many circumstances we could send a few more bytes.
	maxDataLen := min(
		f.MaxDataLen(c.peerParams.MaxDatagramFrameSize, c.version),
		protocol.ByteCount(c.maxPayloadSizeEstimate.Load()),
	)
	if protocol.ByteCount(len(p)) > maxDataLen {
		return &DatagramTooLargeError{MaxDatagramPayloadSize: int64(maxDataLen)}
	}
	if copyPayload {
		p = bytes.Clone(p)
	}
	f.Data = p
	return c.datagramQueue.Add(f)
}`,
		},
		{
			path: "vendor/github.com/quic-go/quic-go/http3/conn.go",
			old:  "return c.conn.SendDatagram(data)",
			new:  "return c.conn.SendDatagramNoCopy(data)",
		},
		{
			path: "vendor/github.com/quic-go/quic-go/internal/wire/datagram_frame.go",
			old:  "f.Data = make([]byte, length)\n\tcopy(f.Data, b)",
			new:  "// The connection copies the payload into its receive queue before the\n\t// packet buffer is released, so retaining this view here is safe.\n\tf.Data = b[:length]",
		},
	}

	for _, replacement := range replacements {
		if err := replaceExactlyOnce(replacement); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}

func replaceExactlyOnce(replacement replacement) error {
	contents, err := os.ReadFile(replacement.path)
	if err != nil {
		return err
	}
	if strings.Count(string(contents), replacement.old) != 1 {
		return fmt.Errorf("vendor patch context changed in %s", replacement.path)
	}
	updated := strings.Replace(string(contents), replacement.old, replacement.new, 1)
	return os.WriteFile(replacement.path, []byte(updated), 0o644)
}
