#!/usr/bin/env bash
# Generates root -> intermediate -> {server, client} leaf chains for each variant.
# Runs inside the openssl35 image; output goes to /certs/out/<variant>/.
set -euo pipefail

OUT=${OUT:-/certs/out}
# <variant>-untrusted is an independent chain (own root) with the same algorithm and
# hostnames; clients never trust it. It backs the untrusted-root negative control.
VARIANTS=${VARIANTS:-classical mldsa classical-untrusted mldsa-untrusted}
DAYS=${DAYS:-365}
CNF=/certs/ext.cnf

keygen() { # <variant> <outfile>
  case "${1%-untrusted}" in
    classical) openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$2"; return ;;
    mldsa)     openssl genpkey -algorithm ML-DSA-65 -out "$2" ;;
    mldsa44)   openssl genpkey -algorithm ML-DSA-44 -out "$2" ;;
    mldsa87)   openssl genpkey -algorithm ML-DSA-87 -out "$2" ;;
    *) echo "unknown variant: $1" >&2; exit 1 ;;
  esac
  # Store ML-DSA keys seed-only (the IETF-recommended encoding). OpenSSL's default
  # seed+expanded form is rejected by some clients (e.g. Go) before TLS even starts.
  openssl pkey -in "$2" -provparam ml-dsa.output_formats=seed-only -out "$2.tmp" && mv "$2.tmp" "$2"
}

# ECDSA needs an explicit digest; ML-DSA signs the message directly and takes none.
digest() { [[ "${1%-untrusted}" == classical ]] && echo -sha256 || true; }

serial() { echo "0x$(openssl rand -hex 16)"; }

sign() { # <variant> <dir> <name> <issuer> <subject> <extsection>
  local v=$1 d=$2 name=$3 issuer=$4 subj=$5 ext=$6
  keygen "$v" "$d/$name.key"
  openssl req -new -config "$CNF" -key "$d/$name.key" -subj "$subj" -out "$d/$name.csr"
  openssl x509 -req -in "$d/$name.csr" -CA "$d/$issuer.crt" -CAkey "$d/$issuer.key" \
    -set_serial "$(serial)" -days "$DAYS" -extfile "$CNF" -extensions "$ext" \
    $(digest "$v") -out "$d/$name.crt"
  rm "$d/$name.csr"
}

echo "Generating with: $(openssl version)"
for v in $VARIANTS; do
  d=$OUT/$v
  rm -rf "$d"; mkdir -p "$d"
  echo "== $v"

  keygen "$v" "$d/root.key"
  openssl req -x509 -new -config "$CNF" -key "$d/root.key" -subj "/O=PQCC Study/CN=PQCC $v Root CA" \
    -set_serial "$(serial)" -days "$DAYS" -extensions v3_root $(digest "$v") -out "$d/root.crt"

  sign "$v" "$d" int    root "/O=PQCC Study/CN=PQCC $v Intermediate CA" v3_int
  sign "$v" "$d" server int  "/O=PQCC Study/CN=server.pqcc.test"          v3_server
  sign "$v" "$d" client int  "/O=PQCC Study/CN=client.pqcc.test"          v3_client

  cat "$d/server.crt" "$d/int.crt" > "$d/server-chain.crt"
  cat "$d/client.crt" "$d/int.crt" > "$d/client-chain.crt"
  # Client identity for clients that import PKCS#12 (Chrome via NSS pk12util).
  openssl pkcs12 -export -inkey "$d/client.key" -in "$d/client.crt" -certfile "$d/int.crt" \
    -name pqcc-client -passout pass:pqcc -out "$d/client.p12"

  openssl verify -CAfile "$d/root.crt" -untrusted "$d/int.crt" -purpose sslserver "$d/server.crt"
  openssl verify -CAfile "$d/root.crt" -untrusted "$d/int.crt" -purpose sslclient "$d/client.crt"

  for c in root int server client; do
    openssl x509 -in "$d/$c.crt" -noout -text > "$d/$c.txt"
  done
  openssl version > "$d/GENERATED_WITH"
  grep -m1 'Signature Algorithm' "$d/server.txt"
done
