#!/bin/sh
set -eu

go mod tidy
go mod vendor
sed -i 's/transportDefaultStreamFlow = 4 << 20/transportDefaultStreamFlow = 16 << 20/' \
  vendor/golang.org/x/net/http2/transport.go
grep -q 'transportDefaultStreamFlow = 16 << 20' vendor/golang.org/x/net/http2/transport.go
sed -i 's/maxDatagramRcvQueueLen  = 128/maxDatagramRcvQueueLen  = 2048/' \
  vendor/github.com/quic-go/quic-go/datagram_queue.go
grep -q 'maxDatagramRcvQueueLen  = 2048' vendor/github.com/quic-go/quic-go/datagram_queue.go
go run ./scripts/patch-vendor.go
gofmt -w cmd internal scripts/patch-vendor.go
