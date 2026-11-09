#!/usr/bin/env python3
"""Native counterpart of server/start.sh, for the macOS and Windows runners.

Usage: server/native.py --openssl <path> --certs <dir> --log <file>

Starts one `openssl s_server -www -trace` per row of server/ports.tsv with the same arguments
as start.sh, and appends every output line to --log prefixed with "[variant/mode] ", which is
what runner/run.py reads in native mode. "listening:" is logged only once s_server reports it
has bound its port (ACCEPT). Runs until stopped (SIGTERM/SIGINT stops every listener too), or
exits non-zero if any listener exits.

Each s_server writes to a pseudo-terminal rather than a pipe so its output is line-buffered
(start.sh uses stdbuf -oL for the same reason): the runner attributes server lines to cells
by position in the log, so they must arrive as they are produced.
"""
import argparse
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent


def listeners():
    for line in (HERE / "ports.tsv").read_text().splitlines():
        if line.strip() and not line.startswith("#"):
            yield line.split()


def server_args(openssl, certs, variant, mode, port):
    d = Path(certs) / variant
    args = [openssl, "s_server", "-accept", port, "-www", "-trace",
            "-cert", str(d / "server.crt"), "-key", str(d / "server.key"),
            "-cert_chain", str(d / "int.crt")]
    if mode == "mtls":
        args += ["-Verify", "1", "-CAfile", str(d / "root.crt"), "-verify_return_error"]
    return args


class Log:
    def __init__(self, path):
        self.f = open(path, "a", encoding="utf-8", buffering=1)
        self.lock = threading.Lock()

    def write(self, line):
        with self.lock:
            self.f.write(line.rstrip("\r\n") + "\n")
            self.f.flush()


def spawn(args, prefix, log, bound):
    """Start one listener; a thread copies its output lines into the log with the prefix and
    sets `bound` when s_server prints ACCEPT."""
    if os.name == "posix":
        import pty
        master, slave = pty.openpty()
        proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=slave, stderr=slave)
        os.close(slave)
        stream = os.fdopen(master, "rb", buffering=0)
    else:
        raise SystemExit("native server: Windows support is added with the Windows runner")

    def pump():
        buf = b""
        while True:
            try:
                chunk = stream.read(4096)
            except OSError:  # pty closed when the process exits
                chunk = b""
            if not chunk:
                break
            buf += chunk
            *lines, buf = buf.split(b"\n")
            for l in lines:
                text = l.decode("utf-8", "replace")
                log.write(prefix + text)
                if text.strip() == "ACCEPT":
                    bound.set()
        if buf:
            log.write(prefix + buf.decode("utf-8", "replace"))

    threading.Thread(target=pump, daemon=True).start()
    return proc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--openssl", required=True)
    ap.add_argument("--certs", required=True)
    ap.add_argument("--log", required=True)
    a = ap.parse_args()

    log = Log(a.log)
    version = subprocess.run([a.openssl, "version"], capture_output=True, text=True).stdout.strip()
    log.write(f"Server stack: {version}")
    procs = []

    def stop(code):
        for _, _, p in procs:
            if p.poll() is None:
                p.terminate()
        for _, _, p in procs:
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()
        sys.exit(code)

    signal.signal(signal.SIGTERM, lambda *_: stop(0))
    signal.signal(signal.SIGINT, lambda *_: stop(0))

    for variant, mode, port in listeners():
        if not (Path(a.certs) / variant / "server.crt").is_file():
            log.write(f"missing certs for {variant} in {a.certs}")
            stop(1)
        bound = threading.Event()
        p = spawn(server_args(a.openssl, a.certs, variant, mode, port), f"[{variant}/{mode}] ", log, bound)
        procs.append((variant, mode, p))
        deadline = time.monotonic() + 15
        while not bound.wait(0.2):
            if p.poll() is not None or time.monotonic() > deadline:
                log.write(f"listener {variant}/{mode} failed to start on :{port}; stopping")
                stop(1)
        log.write(f"listening: {variant}/{mode} on :{port}")

    # If any listener exits, stop everything so the failure is visible.
    while all(p.poll() is None for _, _, p in procs):
        time.sleep(1)
    for variant, mode, p in procs:
        if p.poll() is not None:
            log.write(f"listener {variant}/{mode} exited with {p.returncode}; stopping")
    stop(1)


if __name__ == "__main__":
    main()
