#!/usr/bin/env bash
# Starts one OpenSSL s_server per (variant, mode) row in ports.tsv.
# -www answers "GET /" with HTTP 200, which clients use as their pass signal.
set -euo pipefail

echo "Server stack: $(openssl version)"
while read -r variant mode port; do
  [[ -z "$variant" || "$variant" == \#* ]] && continue
  d=/certs/out/$variant
  [[ -f "$d/server.crt" ]] || { echo "missing certs for $variant (run 'make certs')" >&2; exit 1; }

  # -trace logs every handshake message: the runner reads the client's offered signature
  # algorithms and the negotiated group/version from it (server-side evidence per cell).
  args=(-accept "$port" -www -trace
        -cert "$d/server.crt" -key "$d/server.key" -cert_chain "$d/int.crt")
  if [[ "$mode" == "mtls" ]]; then
    args+=(-Verify 1 -CAfile "$d/root.crt" -verify_return_error)
  fi

  echo "listening: $variant/$mode on :$port"
  # Line-buffered so the runner can attribute each server-side error to the cell that caused it.
  stdbuf -oL -eL openssl s_server "${args[@]}" < /dev/null 2>&1 | sed -u "s/^/[$variant\/$mode] /" &
done < /server/ports.tsv

# If any listener exits, take the container down so the failure is visible.
wait -n
echo "a listener exited; stopping" >&2
exit 1
