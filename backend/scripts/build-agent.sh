#!/usr/bin/env bash
# 交叉编译终端 Agent：Windows / macOS / Linux（含 ARM64 与龙芯 LoongArch64）
# 用法：scripts/build-agent.sh [版本号]
set -euo pipefail
cd "$(dirname "$0")/.."
version="${1:-$(git describe --tags --always 2>/dev/null || echo dev)}"
out=bin/agent
mkdir -p "$out"
targets=(windows/amd64 windows/arm64 darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 linux/loong64)
for t in "${targets[@]}"; do
  os="${t%/*}"; arch="${t#*/}"
  name="opendlp-agent-$os-$arch"
  [ "$os" = windows ] && name="$name.exe"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath \
    -ldflags "-s -w -X opendlp/internal/agent.Version=$version" -o "$out/$name" ./cmd/opendlp-agent
  echo "built $out/$name"
done
(cd "$out" && shasum -a 256 opendlp-agent-* > SHA256SUMS)
