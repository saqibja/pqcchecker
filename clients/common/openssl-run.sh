#!/usr/bin/env bash
# Client contract (shared by every client in /clients):
#   run.sh version                          -> print the client's runtime version string
#   run.sh <variant> <mode> <host> <port>   -> connect, validate, send "GET /", exit 0 only on
#                                              a validated handshake + HTTP 200 from the server
# Certs for a variant live in $PQCC_CERTS/<variant>/ (default /certs/out, the container mount).
# Also run natively on the macOS/Windows runners as a cross-check of the native server.
set -uo pipefail

if [[ "${1:-}" == "version" ]]; then
  "${PQCC_OPENSSL:-openssl}" version
  exit 0
fi

variant=$1 mode=$2 host=$3 port=$4
d=${PQCC_CERTS:-/certs/out}/$variant

args=(-connect "$host:$port" -servername "$host"
      -CAfile "$d/root.crt" -verify_return_error -verify_hostname "$host"
      -brief -ign_eof)
if [[ "$mode" == "mtls" ]]; then
  args+=(-cert "$d/client.crt" -key "$d/client.key" -cert_chain "$d/int.crt")
fi

OPENSSL=${PQCC_OPENSSL:-openssl}
# GNU timeout is not on macOS/Windows hosts; there the runner's per-cell timeout applies.
# (No empty-array expansion: macOS bash 3.2 treats it as unbound under set -u.)
limit=""; command -v timeout >/dev/null && limit="timeout 20"
out=$(printf 'GET / HTTP/1.0\r\n\r\n' | $limit "$OPENSSL" s_client "${args[@]}" 2>&1)
rc=$?
printf '%s\n' "$out"

if [[ $rc -eq 0 ]] && grep -q '^HTTP/1.0 200' <<<"$out"; then
  exit 0
fi
[[ $rc -eq 0 ]] && rc=1
exit $rc
