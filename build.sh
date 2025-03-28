#!/bin/sh

version=$1

set -- arm64 amd64

for arch in "$@"; do
	CGO_ENABLED=0 GOOS='linux' GOARCH=$arch go build -ldflags="-s -w" -o "build/gp" main.go
  tar czf "build/gp_${version}_linux_${arch}.tar.gz" build/gp
done
