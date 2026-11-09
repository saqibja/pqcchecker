#!/usr/bin/env bash
# Builds the study's server OpenSSL (3.5.7, upstream source) into <prefix> on a macOS runner.
# The Linux server is Debian's 3.5.7 package; same upstream release, built natively here so
# the macOS clients can reach it on localhost. Usage: native/build-openssl.sh <prefix>
set -euo pipefail
VERSION=3.5.7
SHA256=a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8
PREFIX=$1

if [[ -x "$PREFIX/bin/openssl" ]] && "$PREFIX/bin/openssl" version | grep -q "OpenSSL $VERSION "; then
  echo "cached: $("$PREFIX/bin/openssl" version)"
  exit 0
fi
work=$(mktemp -d)
curl -fsSL -o "$work/openssl.tar.gz" \
  "https://github.com/openssl/openssl/releases/download/openssl-$VERSION/openssl-$VERSION.tar.gz"
echo "$SHA256  $work/openssl.tar.gz" | shasum -a 256 -c -
tar -xzf "$work/openssl.tar.gz" -C "$work"
cd "$work/openssl-$VERSION"
./Configure --prefix="$PREFIX" --openssldir="$PREFIX/ssl" --libdir=lib no-docs no-tests
make -j"$(sysctl -n hw.ncpu)" >/dev/null
make install_sw >/dev/null
"$PREFIX/bin/openssl" version
