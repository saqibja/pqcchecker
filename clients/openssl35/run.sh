#!/usr/bin/env bash
# Client contract (shared by every client in /clients):
#   run.sh version                          -> print the client's runtime version string
#   run.sh <variant> <mode> <host> <port>   -> connect, validate, send "GET /", exit 0 only on
#                                              a validated handshake + HTTP 200 from the server
# Certs for a variant live in /certs/out/<variant>/.
set -uo pipefail

if [[ "${1:-}" == "version" ]]; then
  openssl version
  exit 0
fi

variant=$1 mode=$2 host=$3 port=$4
d=/certs/out/$variant

args=(-connect "$host:$port" -servername "$host"
      -CAfile "$d/root.crt" -verify_return_error -verify_hostname "$host"
      -brief -ign_eof)
if [[ "$mode" == "mtls" ]]; then
  args+=(-cert "$d/client.crt" -key "$d/client.key" -cert_chain "$d/int.crt")
fi

out=$(printf 'GET / HTTP/1.0\r\n\r\n' | timeout 20 openssl s_client "${args[@]}" 2>&1)
rc=$?
printf '%s\n' "$out"

if [[ $rc -eq 0 ]] && grep -q '^HTTP/1.0 200' <<<"$out"; then
  exit 0
fi
[[ $rc -eq 0 ]] && rc=1
exit $rc
