#!/usr/bin/env bash
set -euo pipefail

BINARY="proc-trace-exec"
IMAGE="golang:1.22-alpine"
VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo dev)"

platforms=(
  "linux/amd64"
  "linux/arm64"
)

mkdir -p dist

echo "┌──────────────────────────────────────────┐"
echo "│  proc-trace-exec — Docker build          │"
echo "└──────────────────────────────────────────┘"
echo ""
echo "  binary  : ${BINARY}"
echo "  version : ${VERSION}"
echo "  image   : ${IMAGE}"
echo ""

for platform in "${platforms[@]}"; do
  os="${platform%%/*}"
  arch="${platform##*/}"
  out="${BINARY}-${os}-${arch}"
  printf "  building %-36s" "dist/${out} ..."
  docker run --rm \
    -v "$(pwd):/src:ro" \
    -v "$(pwd)/dist:/out" \
    -w /src \
    -e CGO_ENABLED=0 \
    -e GOOS="${os}" \
    -e GOARCH="${arch}" \
    "${IMAGE}" \
    go build \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o "/out/${out}" .
  size=$(du -sh "dist/${out}" 2>/dev/null | cut -f1)
  echo " [${size}]"
done

echo ""
echo "Done. Binaries in ./dist/:"
ls -lh dist/ | grep "${BINARY}"
