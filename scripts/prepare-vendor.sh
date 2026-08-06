#!/bin/sh
set -eu

go mod tidy
go mod vendor
sed -i 's/transportDefaultStreamFlow = 4 << 20/transportDefaultStreamFlow = 16 << 20/' \
  vendor/golang.org/x/net/http2/transport.go
grep -q 'transportDefaultStreamFlow = 16 << 20' vendor/golang.org/x/net/http2/transport.go
gofmt -w cmd internal
