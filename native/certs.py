#!/usr/bin/env python3
"""Ships the study's chains to the hosted runners without publishing private keys.

  native/certs.py pack   --openssl <path>   certs/out -> native/certs.tar.gz.enc + native/certs.sha256
  native/certs.py unpack --openssl <path>   native/certs.tar.gz.enc -> certs/out, then verify

The passphrase comes from $PQCC_CERTS_PASSPHRASE (a repository secret on GitHub). The bundle
holds what the server and clients use: leaf certificates and keys, client.p12, root.crt and
int.crt. The root and intermediate CA private keys are left out, so the bundle cannot be used
to issue new certificates. certs.sha256 lists every bundled file, so a runner can show it
used the same chains as the Linux run.
"""
import argparse
import hashlib
import io
import os
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "certs/out"
BUNDLE = ROOT / "native/certs.tar.gz.enc"
SUMS = ROOT / "native/certs.sha256"
EXCLUDE = {"root.key", "int.key"}
ENC = ["enc", "-aes-256-cbc", "-pbkdf2", "-iter", "600000", "-pass", "env:PQCC_CERTS_PASSPHRASE"]


def bundled_files():
    return sorted(p for p in OUT.rglob("*") if p.is_file() and p.name not in EXCLUDE
                  and p.suffix != ".txt" and not p.name.startswith("."))


def sums(paths):
    return "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(OUT).as_posix()}\n"
                   for p in paths)


def openssl(binary, *args, data):
    if not os.environ.get("PQCC_CERTS_PASSPHRASE"):
        sys.exit("PQCC_CERTS_PASSPHRASE is not set")
    r = subprocess.run([binary, *ENC, *args], input=data, capture_output=True)
    if r.returncode != 0:
        sys.exit(f"openssl enc failed: {r.stderr.decode(errors='replace').strip()}")
    return r.stdout


def pack(binary):
    files = bundled_files()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for p in files:
            info = tar.gettarinfo(p, arcname=p.relative_to(OUT).as_posix())
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = 0
            with open(p, "rb") as f:
                tar.addfile(info, f)
    BUNDLE.write_bytes(openssl(binary, "-salt", data=buf.getvalue()))
    SUMS.write_text(sums(files))
    print(f"packed {len(files)} files -> {BUNDLE.relative_to(ROOT)} ({BUNDLE.stat().st_size} bytes)")


def unpack(binary):
    data = openssl(binary, "-d", data=BUNDLE.read_bytes())
    OUT.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        tar.extractall(OUT, filter="data")
    expected = SUMS.read_text()
    listed = [OUT / line.split("  ", 1)[1].strip() for line in expected.splitlines()]
    if sums(listed) != expected or sorted(listed) != bundled_files():
        sys.exit("unpacked chains do not match native/certs.sha256")
    print(f"unpacked and verified {len(listed)} files into {OUT.relative_to(ROOT)}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["pack", "unpack"])
    ap.add_argument("--openssl", default="openssl")
    a = ap.parse_args()
    (pack if a.action == "pack" else unpack)(a.openssl)


if __name__ == "__main__":
    main()
