package main

import (
	"bytes"
	"io"
	"net"
	"testing"
)

func TestNegotiateSOCKSPreservesBufferedPayload(t *testing.T) {
	server, peer := net.Pipe()
	defer server.Close()
	defer peer.Close()

	peerDone := make(chan error, 1)
	go func() {
		if _, err := peer.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			peerDone <- err
			return
		}
		method := make([]byte, 2)
		if _, err := io.ReadFull(peer, method); err != nil {
			peerDone <- err
			return
		}
		requestAndPayload := append(
			[]byte{0x05, 0x01, 0x00, 0x03, 0x0b},
			[]byte("example.com")...,
		)
		requestAndPayload = append(requestAndPayload, 0x01, 0xbb)
		requestAndPayload = append(requestAndPayload, []byte("hello")...)
		_, err := peer.Write(requestAndPayload)
		peerDone <- err
	}()

	target, buffered, err := negotiateSOCKS(server)
	if err != nil {
		t.Fatal(err)
	}
	if target != "example.com:443" {
		t.Fatalf("target = %q", target)
	}
	payload := make([]byte, 5)
	if _, err := io.ReadFull(buffered, payload); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, []byte("hello")) {
		t.Fatalf("payload = %q", payload)
	}
	if err := <-peerDone; err != nil {
		t.Fatal(err)
	}
}
