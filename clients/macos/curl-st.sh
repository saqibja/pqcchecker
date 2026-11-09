#!/usr/bin/env bash
# macOS /usr/bin/curl with its SecureTransport backend (Apple's multi-SSL build defaults to
# LibreSSL). SecureTransport is Apple's legacy TLS API and stops at TLS 1.2.
# Usage: version | <variant> <mode> <host> <port>. Certificates from $PQCC_CERTS.
set -uo pipefail
export CURL_SSL_BACKEND=secure-transport
CURL=/usr/bin/curl

# In `curl -V` the active backend is the one not in parentheses.
active=$("$CURL" -V | head -1)
if ! grep -q ' SecureTransport (' <<<"$active"; then
  echo "stage failed: select SecureTransport backend" >&2
  echo "$active" >&2
  exit 1
fi
if [[ "${1:-}" == "version" ]]; then
  echo "$active [active backend: SecureTransport]"
  exit 0
fi

variant=$1 mode=$2 host=$3 port=$4
d=$PQCC_CERTS/$variant
args=(-sS -v --max-time 20 --cacert "$d/root.crt" -o /dev/null -w 'HTTP status: %{http_code}\n')
if [[ "$mode" == "mtls" ]]; then
  args+=(--cert "$d/client.p12:pqcc" --cert-type P12)
fi

out=$("$CURL" "${args[@]}" "https://$host:$port/" 2>&1)
rc=$?
# -v with SecureTransport also dumps the server certificates as PEM; drop those blocks.
printf '%s\n' "$out" | sed '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/d'
# "* TLS 1.2 connection using TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
proto=$(grep -oE 'TLS 1\.[0-3] connection using' <<<"$out" | grep -oE '1\.[0-3]')
[[ -n "$proto" ]] && echo "Protocol version: TLSv$proto"

if [[ $rc -eq 0 ]] && grep -q '^HTTP status: 200' <<<"$out"; then
  exit 0
fi
echo "stage failed: handshake" >&2
echo "curl exit code $rc" >&2
[[ $rc -eq 0 ]] && rc=1
exit $rc
