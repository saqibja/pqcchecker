#!/usr/bin/env bash
# Quick check: run one client against every port in ports.tsv (or only one mode).
# Usage: runner/smoke.sh <client_id> [mode]
set -uo pipefail
cd "$(dirname "$0")/.."

client=$1 only_mode=${2:-}
echo "client version: $(docker compose run --rm -T "$client" version </dev/null)"

fail=0
while read -r variant mode port; do
  [[ -z "$variant" || "$variant" == \#* ]] && continue
  [[ -n "$only_mode" && "$mode" != "$only_mode" ]] && continue
  out=$(docker compose run --rm -T "$client" "$variant" "$mode" server.pqcc.test "$port" 2>&1 </dev/null)
  rc=$?
  if [[ $rc -eq 0 ]]; then status=PASS; else status="FAIL (rc=$rc)"; fail=1; fi
  printf '%-10s %-7s %-5s %s\n' "$variant" "$mode" "$port" "$status"
  printf '%s\n' "$out" | grep -E 'Protocol version|Negotiated TLS1.3 group|Signature type|Verification:|verify error|error' | sed 's/^/    /'
done < server/ports.tsv
exit $fail
