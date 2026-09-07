#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
version=2.14.5
case "$(uname -m)" in
  x86_64) arch=amd64; checksum=5e3b603d47c447bda1f77f9ac16dbf91c90aac4ff3681f8fbbc7201e4ed99355 ;;
  aarch64|arm64) arch=arm64; checksum=673a98d3faa79dde3f9ebf16d6dfac36a5f694e7ad2015e4954dd7939c85cd4c ;;
  *) echo 'Supported development architectures: amd64 and arm64' >&2; exit 1 ;;
esac
umask 077
mkdir -p .dev/nats-image
archive=".dev/nats-image/nats.tar.gz"
curl --fail --location --proto '=https' --tlsv1.2 "https://github.com/nats-io/nats-server/releases/download/v${version}/nats-server-v${version}-linux-${arch}.tar.gz" -o "$archive"
printf '%s  %s\n' "$checksum" "$archive" | sha256sum --check -
tar -xzf "$archive" -C .dev/nats-image --strip-components=1 "nats-server-v${version}-linux-${arch}/nats-server" "nats-server-v${version}-linux-${arch}/LICENSE"
cp config/nats.Dockerfile .dev/nats-image/Dockerfile
