#!/usr/bin/env python3
"""Runs every client x variant x mode cell, plus negative controls, and records the results.

Usage: runner/run.py [client ...]          (default: every client, in CLIENTS order)

Writes results/runs/<run_id>/{results.csv, negative_controls.csv, meta.json, logs/}
and copies the CSVs and meta.json to results/ as the latest run.

Each cell log holds the client's full output plus the server's -trace lines for that
listener during the cell, so every classification can be audited.

Exits with status 2 if any negative control unexpectedly passes: the PASS cells it
guards cannot be trusted until that is explained.
"""
import csv
import json
import platform
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOST = "server.pqcc.test"
CLIENTS = ["openssl35", "openssl30", "java", "java-bc", "java-bc-pq", "go", "chrome", "chrome-nss"]
CELL_TIMEOUT = 120  # seconds; clients enforce their own ~15-30s network timeouts inside this
UNTRUSTED = "-untrusted"
# The spec's schema, plus the CertificateVerify signature schemes seen by the server.
COLUMNS = ["run_id", "timestamp_utc", "client_id", "client_version", "variant", "mode", "outcome",
           "error_class", "tls_version", "kex_group", "raw_error_excerpt", "log_path",
           "server_sig_scheme", "client_sig_scheme"]
NEG_COLUMNS = ["run_id", "timestamp_utc", "client_id", "client_version", "variant", "control",
               "expected", "observed", "verdict", "guards", "guarded_outcomes", "error_class",
               "tls_version", "kex_group", "server_sig_scheme", "raw_error_excerpt", "log_path"]


def sh(*cmd, timeout=None):
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                          stdin=subprocess.DEVNULL, timeout=timeout)


def compose(*args, timeout=None):
    return sh("docker", "compose", *args, timeout=timeout)


def read_listeners():
    listeners = []
    for line in (ROOT / "server/ports.tsv").read_text().splitlines():
        if line.strip() and not line.startswith("#"):
            variant, mode, port = line.split()
            listeners.append((variant, mode, port))
    return listeners


def matrix_cells(listeners):
    cells = [l for l in listeners if not l[0].endswith(UNTRUSTED)]
    # Controls first, so a broken harness is visible before any ML-DSA result.
    return sorted(cells, key=lambda c: c[0] != "classical")


def negative_controls(listeners, cells):
    """Each control: the client trusts `variant`'s root but must still fail."""
    port = {(v, m): p for v, m, p in listeners}
    controls = []
    for variant in dict.fromkeys(v for v, _, _ in cells):
        if (variant + UNTRUSTED, "server") in port:
            # Same algorithm and hostname, different root: only the trust anchor is wrong.
            controls.append(dict(control="untrusted_root", variant=variant, client_mode="server",
                                 listener=(variant + UNTRUSTED, "server"),
                                 port=port[(variant + UNTRUSTED, "server")],
                                 guards=[(variant, "server"), (variant, "mtls")]))
        if (variant, "mtls") in port:
            # Client connects in server mode (no certificate) to the mTLS listener.
            controls.append(dict(control="missing_client_cert", variant=variant, client_mode="server",
                                 listener=(variant, "mtls"), port=port[(variant, "mtls")],
                                 guards=[(variant, "mtls")]))
    return controls


def server_lines():
    return compose("logs", "--no-log-prefix", "server").stdout.splitlines()


# ---------------------------------------------------------------- parsing

def norm_version(s):
    m = re.search(r"1\.([0-3])", s or "")
    return f"TLSv1.{m.group(1)}" if m else ""


def norm_group(s):
    s = (s or "").lower()
    for key, name in (("x25519mlkem768", "X25519MLKEM768"), ("secp256r1mlkem768", "SecP256r1MLKEM768"),
                      ("mlkem", s.upper()), ("x25519", "X25519"), ("x448", "X448"),
                      ("secp256r1", "P-256"), ("p-256", "P-256"), ("secp384r1", "P-384"),
                      ("secp521r1", "P-521"), ("ffdhe", s)):
        if key in s:
            return name
    return s


def parse_client(out):
    v = re.search(r"Protocol version: (.+)", out)
    g = re.search(r"Negotiated (?:TLS1\.3 )?group: (\S+)|Server Temp Key: ([^,\s]+)", out)
    return (norm_version(v.group(1)) if v else "",
            norm_group(next(x for x in g.groups() if x)) if g else "")


def parse_server(trace):
    """From the server's -trace output: negotiated version/group (last ServerHello), the
    client's offered signature algorithms, and the CertificateVerify scheme in each direction
    (Sent = server's signature, Received = client's signature in mTLS)."""
    p = dict(version="", group="", sigalgs=[], server_sig="", client_sig="")
    section = direction = cv = None
    for line in trace:
        if line.startswith("Sent TLS Record"):
            direction = "sent"
        elif line.startswith("Received TLS Record"):
            direction = "recv"
        if "ClientHello, Length" in line:
            section, p["sigalgs"] = "ch", []
        elif "ServerHello, Length" in line:
            section = "sh"
        elif "CertificateVerify, Length" in line:
            cv = direction
        elif re.search(r"^\s*(Inner )?Content Type =", line):
            section = None  # a new record; ClientHello/ServerHello fields don't continue across it
        if cv and (m := re.search(r"Signature Algorithm: (\S+) \(0x[0-9a-f]{4}\)", line)):
            key = "server_sig" if cv == "sent" else "client_sig"
            p[key] = p[key] or m.group(1)
            cv = None
        if "extension_type=" in line:
            if section and section.startswith("ch"):
                section = "ch_sigalgs" if "signature_algorithms(13)" in line else "ch"
            elif section and section.startswith("sh"):
                section = ("sh_ks" if "key_share" in line else
                           "sh_sv" if "supported_versions" in line else "sh")
            continue
        if section == "ch_sigalgs" and (m := re.match(r"\s+([a-z0-9_]+) \(0x[0-9a-f]{4}\)", line)):
            p["sigalgs"].append(m.group(1))
        elif section == "sh_ks" and "NamedGroup:" in line:
            p["group"] = norm_group(line.split("NamedGroup:", 1)[1])
        elif section == "sh_sv" and re.search(r"TLS 1\.[0-3]", line):
            p["version"] = norm_version(line)
        elif section == "sh" and "server_version=" in line and not p["version"]:
            p["version"] = norm_version(line)
    return p


# ---------------------------------------------------------- classification

# (error_class, where, pattern). Evaluated in order; first match wins.
# where: "c" = client output, "s" = server log for this cell.
# TRUST_STORE_IMPORT_ERROR and KEY_LOAD_ERROR happen while provisioning the client, before
# any TLS traffic; the others happen during the handshake.
RULES = [
    ("TIMEOUT", "c", r"timed out|SocketTimeoutException|i/o timeout|ERR_(CONNECTION_)?TIMED_OUT"),
    ("TRUST_STORE_IMPORT_ERROR", "c", r"stage failed: (read root certificate|parse root certificate|"
                                      r"import root into NSS|import client certificate/key into NSS)"),
    ("TRUST_STORE_IMPORT_ERROR", "c", r"Error loading (CA )?file|Could not (read|load) CA|"
                                      r"unable to load CA"),
    ("KEY_LOAD_ERROR", "c", r"stage failed: load client certificate/key"),
    ("KEY_LOAD_ERROR", "c", r"Could not (read|find|load) (client certificate|private key)|"
                            r"unable to load (client certificate|private key)|failed to parse private key"),
    ("UNSUPPORTED_SIG_ALG", "s", r"no suitable signature algorithm"),
    ("UNSUPPORTED_SIG_ALG", "c", r"no suitable signature algorithm|[Uu]nsupported signature algorithm|"
                                 r"No supported signature algorithm"),
    ("CERT_PARSE_ERROR", "c", r"failed to parse certificate|CertificateParsingException|"
                              r"Could not parse certificate|decode.error|"
                              r"(unsupported|unknown) public key algorithm|ASN1 routines"),
    ("CHAIN_VALIDATION_ERROR", "c", r"verify error|certificate verify failed|PKIX|CertPathValidator|"
                                    r"valid certification path|x509: |ERR_CERT_|bad.certificate|"
                                    r"certificate.unknown|unknown.ca"),
    ("CHAIN_VALIDATION_ERROR", "s", r"verify error|certificate verify failed"),
    # The server's own reason is the authoritative one for an mTLS rejection. Clients describe
    # it inconsistently (Chrome retries after aborted attempts and ends with a socket error).
    ("HANDSHAKE_FAILURE", "s", r"peer did not return a certificate"),
    ("HANDSHAKE_FAILURE", "c", r"alert|handshake.failure|SSLHandshakeException|TlsFatalAlert|"
                               r"remote error: tls|ERR_SSL_|ERR_BAD_SSL_CLIENT_AUTH_CERT|"
                               r"SSL_CLIENT_AUTH"),
    ("HANDSHAKE_FAILURE", "s", r"SSL routines|alert"),
]

NOISE = re.compile(r"^\s*(at |\$ |WARNING|Container |Picked up|.*DisabledAlgorithmConstraints)")


def excerpt(text, limit=300):
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= limit else text[:limit - 3] + "..."


def classify(out, srv, rc, variant, offered):
    if rc is None or rc == 124:
        return "TIMEOUT", "cell timed out"
    client_lines = [l.strip() for l in out.splitlines() if l.strip() and not NOISE.match(l)]
    sources = {"c": client_lines, "s": srv}

    def with_detail(lines, i):
        # "stage failed: X" names where it failed; the next line carries the actual error.
        if lines[i].startswith("stage failed") and i + 1 < len(lines):
            return f"{lines[i]} | {lines[i + 1]}"
        return lines[i]

    for cls, where, pat in RULES:
        for i, line in enumerate(sources[where]):
            if re.search(pat, line):
                ex = ("server: " if where == "s" else "") + with_detail(sources[where], i)
                if cls == "UNSUPPORTED_SIG_ALG" and variant != "classical" and offered is not None:
                    pq = [a for a in offered if a.startswith("mldsa")]
                    ex += f" [client offered ML-DSA sigalgs: {', '.join(pq) or 'none'}]"
                return cls, ex
    stage = next((i for i, l in enumerate(client_lines) if l.startswith("stage failed")), None)
    if stage is not None:
        return "OTHER", with_detail(client_lines, stage)
    return "OTHER", client_lines[-1] if client_lines else f"exit code {rc}"


# -------------------------------------------------------------------- run

def run_cell(client, variant, client_mode, port, listener, log_path, version, label):
    """Runs one client invocation. `variant` picks the certs the client trusts/presents;
    `listener` is the server (variant, mode) it connects to."""
    start = len(server_lines())
    name = f"pqcc-cell-{client}"
    sh("docker", "rm", "-f", name)
    t0 = time.monotonic()
    try:
        r = compose("run", "--rm", "-T", "--name", name, client, variant, client_mode, HOST, port,
                    timeout=CELL_TIMEOUT)
        rc, out = r.returncode, r.stdout + r.stderr
    except subprocess.TimeoutExpired as e:
        sh("docker", "rm", "-f", name)
        rc, out = None, (e.stdout or b"").decode() + (e.stderr or b"").decode()
    duration = time.monotonic() - t0
    time.sleep(0.5)  # let the server flush its last trace lines
    prefix = f"[{listener[0]}/{listener[1]}] "
    srv = [l[len(prefix):] for l in server_lines()[start:] if l.startswith(prefix)]

    c_ver, c_grp = parse_client(out)
    s = parse_server(srv)
    row = {
        "outcome": "PASS" if rc == 0 else "FAIL",
        "tls_version": c_ver or s["version"],
        "kex_group": c_grp or s["group"],
        "server_sig_scheme": s["server_sig"],
        "client_sig_scheme": s["client_sig"],
        "error_class": "", "raw_error_excerpt": "",
    }
    if rc != 0:
        cls, ex = classify(out, srv, rc, variant, s["sigalgs"] if srv else None)
        row["error_class"], row["raw_error_excerpt"] = cls, excerpt(ex)

    log_path.write_text("\n".join([
        f"client={client} version={version}",
        f"cell={label} client_args=({variant} {client_mode}) "
        f"listener={listener[0]}/{listener[1]} port={port} host={HOST}",
        f"exit_code={rc} duration_s={duration:.1f}",
        f"outcome={row['outcome']} error_class={row['error_class']}",
        f"client_reported: tls={c_ver or '-'} group={c_grp or '-'}",
        f"server_observed: tls={s['version'] or '-'} group={s['group'] or '-'} "
        f"server_sig={s['server_sig'] or '-'} client_sig={s['client_sig'] or '-'} "
        f"client_offered_sigalgs={','.join(s['sigalgs']) or '-'}",
        "", "=== client output", out.rstrip(),
        "", f"=== server log for {listener[0]}/{listener[1]} during this cell", *srv, "",
    ]))
    return row


def client_version(client):
    r = compose("run", "--rm", "-T", client, "version", timeout=CELL_TIMEOUT)
    lines = [l for l in r.stdout.splitlines() if l.strip()]
    return lines[-1].strip() if r.returncode == 0 and lines else "unknown"


def now_utc():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def write_csv(path, columns, rows):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=columns)
        w.writeheader()
        w.writerows({k: r.get(k, "") for k in columns} for r in rows)


def main():
    clients = sys.argv[1:] or CLIENTS
    unknown = set(clients) - set(CLIENTS)
    if unknown:
        sys.exit(f"unknown client(s): {', '.join(sorted(unknown))}")
    if "running" not in compose("ps", "--format", "{{.State}}", "server").stdout:
        sys.exit("server is not running (make up)")

    now = datetime.now(timezone.utc)
    run_id = now.strftime("%Y%m%dT%H%M%SZ")
    run_dir = ROOT / "results/runs" / run_id
    (run_dir / "logs").mkdir(parents=True)
    listeners = read_listeners()
    cells = matrix_cells(listeners)
    controls = negative_controls(listeners, cells)

    git = sh("git", "rev-parse", "--short", "HEAD").stdout.strip()
    dirty = bool(sh("git", "status", "--porcelain").stdout.strip())
    meta = {
        "run_id": run_id,
        "started_utc": now.isoformat(timespec="seconds"),
        "git_commit": git + ("-dirty" if dirty else ""),
        "host": f"{platform.system()} {platform.release()} {platform.machine()}",
        "docker_server": sh("docker", "version", "--format", "{{.Server.Version}}").stdout.strip(),
        "server_stack": compose("exec", "-T", "server", "openssl", "version").stdout.strip(),
        "server_ports": [{"variant": v, "mode": m, "port": p} for v, m, p in listeners],
        "clients": {},
    }

    rows, neg_rows = [], []
    for client in clients:
        version = client_version(client)
        meta["clients"][client] = version
        print(f"== {client}: {version}", flush=True)
        client_rows = {}
        for variant, mode, port in cells:
            log_rel = Path("results/runs") / run_id / "logs" / f"{client}_{variant}_{mode}.log"
            row = run_cell(client, variant, mode, port, (variant, mode), ROOT / log_rel, version,
                           f"{variant}/{mode}")
            row.update(run_id=run_id, client_id=client, client_version=version, variant=variant,
                       mode=mode, log_path=str(log_rel), timestamp_utc=now_utc())
            client_rows[(variant, mode)] = row
            print(f"   {variant:<10} {mode:<7} {row['outcome']:<5} {row['error_class']:<24} "
                  f"{row['tls_version']:<8} {row['kex_group']:<15} {row['server_sig_scheme']}"
                  f"{' / ' + row['client_sig_scheme'] if row['client_sig_scheme'] else ''}", flush=True)

        # Classical control: if it fails for a mode, that mode's cells for this client are
        # not trustworthy and are recorded as SETUP_ERROR.
        for (variant, mode), row in client_rows.items():
            control = client_rows.get(("classical", mode))
            if control and control["outcome"] != "PASS":
                note = f"classical {mode} control failed"
                if variant == "classical":
                    note += f" ({row['error_class']}: {row['raw_error_excerpt']})"
                row.update(outcome="SETUP_ERROR", error_class="",
                           raw_error_excerpt=excerpt(note))
                print(f"   !! {variant}/{mode} -> SETUP_ERROR ({note.split(' (')[0]})", flush=True)
        rows.extend(client_rows.values())

        for c in controls:
            log_rel = (Path("results/runs") / run_id / "logs" /
                       f"{client}_{c['variant']}_neg-{c['control']}.log")
            row = run_cell(client, c["variant"], c["client_mode"], c["port"], c["listener"],
                           ROOT / log_rel, version, f"negative:{c['control']} {c['variant']}")
            guarded = [client_rows[g]["outcome"] for g in c["guards"] if g in client_rows]
            row.update(run_id=run_id, client_id=client, client_version=version,
                       variant=c["variant"], control=c["control"], expected="FAIL",
                       observed=row["outcome"],
                       verdict="OK" if row["outcome"] == "FAIL" else "UNEXPECTED_PASS",
                       guards=" ".join(f"{v}/{m}" for v, m in c["guards"]),
                       guarded_outcomes=" ".join(guarded),
                       log_path=str(log_rel), timestamp_utc=now_utc())
            neg_rows.append(row)
            print(f"   neg {c['variant']:<10} {c['control']:<20} {row['observed']:<5} "
                  f"{row['verdict']:<16} {row['error_class']}", flush=True)

    bad = [r for r in neg_rows if r["verdict"] != "OK"]
    meta["finished_utc"] = now_utc()
    meta["negative_controls"] = {"total": len(neg_rows), "unexpected_passes": len(bad)}
    write_csv(run_dir / "results.csv", COLUMNS, rows)
    write_csv(run_dir / "negative_controls.csv", NEG_COLUMNS, neg_rows)
    (run_dir / "meta.json").write_text(json.dumps(meta, indent=2) + "\n")
    for f in ("results.csv", "negative_controls.csv", "meta.json"):
        shutil.copy(run_dir / f, ROOT / "results" / f)

    counts = {o: sum(r["outcome"] == o for r in rows) for o in ("PASS", "FAIL", "SETUP_ERROR")}
    print(f"\nrun {run_id}: {len(rows)} cells, " + ", ".join(f"{k} {v}" for k, v in counts.items()))
    print(f"negative controls: {len(neg_rows)} run, {len(neg_rows) - len(bad)} failed as expected, "
          f"{len(bad)} unexpected passes")
    print(f"results: results/results.csv, results/negative_controls.csv  "
          f"logs: {run_dir.relative_to(ROOT)}/logs/")
    if bad:
        print("\n!! NEGATIVE CONTROL PASSED - the guarded PASS cells are not trustworthy:")
        for r in bad:
            print(f"   {r['client_id']} {r['variant']} {r['control']} (guards {r['guards']}: "
                  f"{r['guarded_outcomes']}) -> {r['log_path']}")
        sys.exit(2)


if __name__ == "__main__":
    main()
