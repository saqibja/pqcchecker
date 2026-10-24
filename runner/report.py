#!/usr/bin/env python3
"""Builds a single self-contained report.html from a run's results.csv, meta.json and logs.

Usage: runner/report.py [run_dir]     (default: latest run, from results/meta.json)
Writes <run_dir>/report.html and copies it to results/report.html.
"""
import csv
import html
import json
import shutil
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

CLIENT_NOTES = {
    "openssl35": "OpenSSL s_client (Debian 13 package). Trust: -CAfile with the variant root.",
    "openssl30": "OpenSSL s_client, Ubuntu 22.04 system package. Trust: -CAfile with the variant root.",
    "java": "Default JSSE (SunJSSE). Root loaded into an in-memory trust store; PKIX validation "
            "with HTTPS endpoint identification.",
    "java-bc": "Bouncy Castle JCE and JSSE providers registered first, default settings.",
    "java-bc-pq": "As java-bc, with mldsa44/65/87 added to jdk.tls.client.SignatureSchemes. "
                  "Not a default configuration.",
    "go": "crypto/tls with the variant root as the only RootCAs entry.",
    "chrome": "Headless Chrome. Root trusted via the CACertificates enterprise policy (Chrome's own "
              "verifier). mTLS client identity imported into NSS, the only source on Linux.",
    "chrome-nss": "Headless Chrome. Root imported into the user NSS database with certutil; "
                  "mTLS client identity imported with pk12util.",
}

# (class, phase, definition). Provisioning failures happen while setting the client up,
# before any TLS traffic; handshake failures happen on the wire.
ERROR_CLASSES = [
    ("TRUST_STORE_IMPORT_ERROR", "Provisioning",
     "The client's tooling could not import the root, intermediate or client certificate/key "
     "into its store (for example NSS certutil or pk12util)."),
    ("KEY_LOAD_ERROR", "Provisioning",
     "The client could not load its own private key (or the certificate paired with it) for mTLS."),
    ("UNSUPPORTED_SIG_ALG", "Handshake",
     "The client does not offer or support the signature algorithm, so the server has no usable "
     "certificate or signature for it."),
    ("CERT_PARSE_ERROR", "Handshake",
     "The client could not parse a certificate received from the peer."),
    ("CHAIN_VALIDATION_ERROR", "Handshake",
     "The certificate parsed, but chain or path validation failed."),
    ("HANDSHAKE_FAILURE", "Handshake",
     "TLS alert or handshake abort not explained by the classes above."),
    ("TIMEOUT", "Either", "No result within the time limit."),
    ("OTHER", "Either", "Unclassified; see the raw output."),
]


CONTROL_LABELS = {"untrusted_root": "untrusted root", "missing_client_cert": "no client cert"}
SIG_NAMES = {"mldsa44": "ML-DSA-44", "mldsa65": "ML-DSA-65", "mldsa87": "ML-DSA-87",
             "ecdsa_secp256r1_sha256": "ECDSA P-256", "ecdsa_secp384r1_sha384": "ECDSA P-384",
             "ed25519": "Ed25519", "rsa_pss_rsae_sha256": "RSA-PSS"}


def attach_log(r):
    log = (ROOT / r["log_path"]).read_text() if (ROOT / r["log_path"]).exists() else ""
    head, _, rest = log.partition("\n=== client output\n")
    r["log_summary"] = "\n".join(l for l in head.splitlines()
                                 if l.startswith(("cell=", "client_reported", "server_observed",
                                                  "exit_code")))
    r["client_output"] = rest.split("\n=== server log", 1)[0].strip()


def load_run(run_dir):
    rows = list(csv.DictReader(open(run_dir / "results.csv")))
    neg_path = run_dir / "negative_controls.csv"
    negs = list(csv.DictReader(open(neg_path))) if neg_path.exists() else []
    meta = json.loads((run_dir / "meta.json").read_text())
    for r in rows + negs:
        attach_log(r)
    return rows, negs, meta


def ordered(values):
    return list(dict.fromkeys(values))


def sig_label(r):
    """Short 'sig ...' line for a passing cell: server signature, plus client's in mTLS."""
    s = [SIG_NAMES.get(x, x) for x in (r.get("server_sig_scheme"), r.get("client_sig_scheme")) if x]
    if not s:
        return ""
    return "sig " + s[0] + (f" · client {s[1]}" if len(s) > 1 else "")


def build(rows, negs, meta):
    e = html.escape
    clients = ordered(r["client_id"] for r in rows)
    columns = ordered((r["variant"], r["mode"]) for r in rows)
    variants = ordered(v for v, _ in columns)
    cell = {(r["client_id"], r["variant"], r["mode"]): r for r in rows}
    started = datetime.fromisoformat(meta["started_utc"])
    date = started.strftime("%Y-%m-%d")
    counts = {o: sum(r["outcome"] == o for r in rows) for o in ("PASS", "FAIL", "SETUP_ERROR")}

    def button(idx, cls, label, subs, aria, title, panel):
        lines = "".join(f'<span class="sub">{e(s).replace("_", "_<wbr>")}</span>' for s in subs if s)
        return (f'<button class="{cls}" data-i="{idx}" data-panel="{panel}" title="{e(title)}" '
                f'aria-label="{e(aria)}"><span class="o">{e(label)}</span>{lines}</button>')

    head_variant = "".join(
        f'<th scope="colgroup" colspan="{sum(1 for v, _ in columns if v == var)}">{e(var)}</th>'
        for var in variants)
    head_mode = "".join(f'<th scope="col">{e(m)}</th>' for _, m in columns)

    body = []
    for c in clients:
        tds = []
        for v, m in columns:
            r = cell.get((c, v, m))
            if not r:
                tds.append('<td class="cell none">—</td>')
                continue
            if r["error_class"]:
                subs = [r["error_class"]]
            else:
                subs = [" · ".join(x for x in (r["tls_version"], r["kex_group"]) if x), sig_label(r)]
            tds.append('<td class="cell">' + button(
                rows.index(r), f'o-{r["outcome"].lower()}', r["outcome"].replace("_", " "), subs,
                f'{c} {v} {m}: {r["outcome"]} {r["error_class"]}',
                r["raw_error_excerpt"] or r["outcome"], "detail") + "</td>")
        body.append(f'<tr><th scope="row"><span class="cid">{e(c)}</span></th>{"".join(tds)}</tr>')

    # Negative controls: same clients as rows, one column per (variant, control).
    neg_cols = ordered((n["variant"], n["control"]) for n in negs)
    neg_cell = {(n["client_id"], n["variant"], n["control"]): n for n in negs}
    neg_head_variant = "".join(
        f'<th scope="colgroup" colspan="{sum(1 for v, _ in neg_cols if v == var)}">{e(var)}</th>'
        for var in ordered(v for v, _ in neg_cols))
    neg_head_ctrl = "".join(f'<th scope="col">{e(CONTROL_LABELS.get(k, k))}</th>' for _, k in neg_cols)
    neg_body = []
    for c in clients:
        tds = []
        for v, k in neg_cols:
            n = neg_cell.get((c, v, k))
            if not n:
                tds.append('<td class="cell none">—</td>')
                continue
            ok = n["verdict"] == "OK"
            guards_pass = "PASS" in n["guarded_outcomes"].split()
            label = "FAIL · expected" if ok else "PASSED · unexpected"
            cls = ("o-pass" if guards_pass else "o-pass muted") if ok else "o-fail"
            subs = [n["error_class"], "" if guards_pass else "guards no PASS cell"]
            tds.append('<td class="cell">' + button(
                len(rows) + negs.index(n), cls, label, subs,
                f'{c} {v} {k}: observed {n["observed"]}, {n["verdict"]}',
                n["raw_error_excerpt"] or n["observed"], "neg-detail") + "</td>")
        neg_body.append(f'<tr><th scope="row"><span class="cid">{e(c)}</span></th>{"".join(tds)}</tr>')
    n_neg_ok = sum(n["verdict"] == "OK" for n in negs)

    versions = "".join(
        f'<tr><th scope="row">{e(c)}</th><td><code>{e(meta["clients"].get(c, ""))}</code>'
        f'<div class="note">{e(CLIENT_NOTES.get(c, ""))}</div></td></tr>' for c in clients)
    legend = "".join(f'<dt>{e(k)}</dt><dd><span class="phase">{e(p)}</span> {e(d)}</dd>'
                     for k, p, d in ERROR_CLASSES)

    keys = ("client_id", "client_version", "variant", "mode", "outcome", "error_class", "tls_version",
            "kex_group", "server_sig_scheme", "client_sig_scheme", "raw_error_excerpt", "log_path",
            "log_summary", "client_output", "control", "expected", "observed", "verdict", "guards",
            "guarded_outcomes")
    data = json.dumps([{k: r.get(k, "") for k in keys} for r in rows + negs])
    data = data.replace("</", "<\\/")

    return TEMPLATE.format(
        date=e(date), run_id=e(meta["run_id"]), started=e(meta["started_utc"]),
        finished=e(meta.get("finished_utc", "")), commit=e(meta.get("git_commit", "")),
        host=e(meta.get("host", "")), docker=e(meta.get("docker_server", "")),
        server=e(meta.get("server_stack", "")), n=len(rows), n_clients=len(clients),
        n_pass=counts["PASS"], n_fail=counts["FAIL"], n_setup=counts["SETUP_ERROR"],
        n_neg=len(negs), n_neg_ok=n_neg_ok,
        neg_pill="pass" if n_neg_ok == len(negs) else "fail",
        head_variant=head_variant, head_mode=head_mode, body="\n".join(body),
        neg_head_variant=neg_head_variant, neg_head_ctrl=neg_head_ctrl, neg_body="\n".join(neg_body),
        versions=versions, legend=legend, data=data)


TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PQ Certificate Compatibility</title>
<meta name="description" content="How common TLS clients handle ML-DSA certificate chains compared with classical ECDSA chains, in server-auth and mutual-TLS modes. Run {run_id}.">
<style>
:root {{
  --bg: #fbfbfa; --surface: #ffffff; --text: #1d1d1b; --muted: #64645f; --border: #e3e3df;
  --pass-bg: #e3f4e8; --pass-fg: #135c2b; --pass-bd: #9fd3ae;
  --fail-bg: #fbe5e3; --fail-fg: #8f1d14; --fail-bd: #eba7a0;
  --setup-bg: #fdf1d6; --setup-fg: #7a5100; --setup-bd: #e8c77a;
  --focus: #2b5fd9;
}}
@media (prefers-color-scheme: dark) {{
  :root:not([data-theme="light"]) {{
    --bg: #161615; --surface: #1f1f1d; --text: #ecece8; --muted: #a3a39c; --border: #343431;
    --pass-bg: #15301e; --pass-fg: #8fdca6; --pass-bd: #2f6a42;
    --fail-bg: #3a1714; --fail-fg: #f3a59c; --fail-bd: #7c3229;
    --setup-bg: #352a10; --setup-fg: #f0cd7d; --setup-bd: #7a5f1f;
    --focus: #8fb0ff;
  }}
}}
:root[data-theme="dark"] {{
  --bg: #161615; --surface: #1f1f1d; --text: #ecece8; --muted: #a3a39c; --border: #343431;
  --pass-bg: #15301e; --pass-fg: #8fdca6; --pass-bd: #2f6a42;
  --fail-bg: #3a1714; --fail-fg: #f3a59c; --fail-bd: #7c3229;
  --setup-bg: #352a10; --setup-fg: #f0cd7d; --setup-bd: #7a5f1f;
  --focus: #8fb0ff;
}}
* {{ box-sizing: border-box; }}
body {{ margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }}
main {{ max-width: 1040px; margin: 0 auto; padding: 32px 16px 64px; }}
h1 {{ font-size: 1.6rem; line-height: 1.25; margin: 0 0 4px; }}
h2 {{ font-size: 1.1rem; margin: 40px 0 12px; }}
p {{ margin: 0 0 12px; }}
code, pre {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.82rem; }}
.lede {{ color: var(--muted); max-width: 70ch; }}
.meta {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 8px 24px;
  margin: 20px 0 0; padding: 16px; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; }}
.meta div {{ min-width: 0; }}
.meta dt {{ font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.04em; color: var(--muted); }}
.meta dd {{ margin: 0; overflow-wrap: anywhere; }}
.totals {{ display: flex; flex-wrap: wrap; gap: 8px; margin: 16px 0 0; }}
.pill {{ padding: 2px 10px; border-radius: 999px; border: 1px solid; font-size: 0.85rem; font-weight: 600; }}
.wrap {{ overflow-x: auto; border: 1px solid var(--border); border-radius: 8px; background: var(--surface); }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ padding: 8px 10px; text-align: left; vertical-align: top; border-bottom: 1px solid var(--border); }}
tr:last-child > * {{ border-bottom: 0; }}
thead th {{ font-size: 0.8rem; color: var(--muted); font-weight: 600; text-align: center; white-space: nowrap; }}
thead tr:first-child th {{ text-transform: uppercase; letter-spacing: 0.05em; color: var(--text); }}
.matrix tbody th {{ white-space: nowrap; }}
.cid {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.88rem; }}
td.cell {{ padding: 6px; min-width: 150px; }}
td.cell button {{ width: 100%; min-height: 54px; display: flex; flex-direction: column; justify-content: center;
  align-items: center; gap: 2px; padding: 6px 8px; border: 1px solid; border-radius: 6px; cursor: pointer;
  font: inherit; text-align: center; }}
td.cell button:focus-visible {{ outline: 2px solid var(--focus); outline-offset: 2px; }}
td.cell button[aria-pressed="true"] {{ box-shadow: 0 0 0 2px var(--focus); }}
.o {{ font-weight: 700; font-size: 0.85rem; letter-spacing: 0.03em; }}
.sub {{ font-size: 0.72rem; opacity: 0.9; overflow-wrap: anywhere; }}
.o-pass, .pill.pass {{ background: var(--pass-bg); color: var(--pass-fg); border-color: var(--pass-bd); }}
.o-fail, .pill.fail {{ background: var(--fail-bg); color: var(--fail-fg); border-color: var(--fail-bd); }}
.o-setup_error, .pill.setup {{ background: var(--setup-bg); color: var(--setup-fg); border-color: var(--setup-bd); }}
.hint {{ color: var(--muted); font-size: 0.85rem; margin: 8px 0 0; }}
.detail {{ margin-top: 16px; padding: 16px; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; }}
.detail[hidden] {{ display: none; }}
.detail h3 {{ margin: 0 0 8px; font-size: 1rem; }}
.detail dl {{ display: grid; grid-template-columns: max-content 1fr; gap: 4px 16px; margin: 0 0 12px; }}
.detail dt {{ color: var(--muted); }}
.detail dd {{ margin: 0; overflow-wrap: anywhere; }}
td.cell button.muted {{ opacity: 0.6; }}
a.pill {{ text-decoration: none; }}
a {{ color: var(--focus); }}
.side-note {{ margin: 16px 0 0; padding: 12px 16px; border-left: 3px solid var(--setup-bd);
  background: var(--surface); border-radius: 0 8px 8px 0; }}
.side-note h3 {{ margin: 0 0 6px; font-size: 0.95rem; }}
.side-note p {{ margin: 0; font-size: 0.9rem; }}
pre {{ margin: 8px 0 0; padding: 12px; background: var(--bg); border: 1px solid var(--border); border-radius: 6px;
  white-space: pre-wrap; overflow-wrap: anywhere; max-height: 420px; overflow-y: auto; }}
details summary {{ cursor: pointer; color: var(--muted); }}
.versions th {{ white-space: nowrap; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.88rem; }}
.versions code {{ overflow-wrap: anywhere; }}
.note {{ color: var(--muted); font-size: 0.85rem; margin-top: 2px; }}
.legend {{ display: grid; grid-template-columns: max-content 1fr; gap: 6px 16px; margin: 0; }}
.legend dt {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.82rem; }}
.legend dd {{ margin: 0; }}
.phase {{ display: inline-block; min-width: 92px; margin-right: 6px; padding: 0 6px; border: 1px solid var(--border);
  border-radius: 4px; font-size: 0.75rem; color: var(--muted); text-align: center; }}
ul {{ padding-left: 20px; margin: 0; }}
li {{ margin-bottom: 6px; }}
.matrix tbody th, .matrix thead td {{ position: sticky; left: 0; z-index: 1; background: var(--surface); }}
.scroll-hint {{ display: none; }}
@media (max-width: 560px) {{
  .legend, .detail dl {{ grid-template-columns: 1fr; }}
  .legend dd, .detail dd {{ margin-bottom: 8px; }}
  td.cell {{ min-width: 112px; }}
  .matrix tbody th {{ padding: 8px 6px; box-shadow: 1px 0 0 var(--border); }}
  .cid {{ font-size: 0.8rem; }}
  .scroll-hint {{ display: block; }}
}}
</style>
</head>
<body>
<main>
<h1>PQ Certificate Compatibility Study — {date}</h1>
<p class="lede">How common TLS clients handle ML-DSA-65 certificate chains compared with a classical
ECDSA P-256 control chain, in server-authentication and mutual-TLS modes. Every client validates
the chain against the study's own root; no verification is bypassed.</p>

<dl class="meta">
  <div><dt>Run</dt><dd><code>{run_id}</code></dd></div>
  <div><dt>Started (UTC)</dt><dd>{started}</dd></div>
  <div><dt>Server stack</dt><dd>{server}</dd></div>
  <div><dt>Harness commit</dt><dd><code>{commit}</code></dd></div>
  <div><dt>Host</dt><dd>{host}; Docker {docker}</dd></div>
</dl>
<div class="totals">
  <span class="pill pass">{n_pass} PASS</span>
  <span class="pill fail">{n_fail} FAIL</span>
  <span class="pill setup">{n_setup} SETUP ERROR</span>
  <span class="pill" style="border-color:var(--border);color:var(--muted)">{n} cells · {n_clients} clients</span>
  <a class="pill {neg_pill}" href="#negative-controls">{n_neg_ok} / {n_neg} negative controls failed as expected</a>
</div>

<h2>Results</h2>
<p class="hint scroll-hint">Scroll the table sideways for the ML-DSA columns.</p>
<div class="wrap">
<table class="matrix">
<thead>
<tr><td rowspan="2"></td>{head_variant}</tr>
<tr>{head_mode}</tr>
</thead>
<tbody>
{body}
</tbody>
</table>
</div>
<p class="hint">Select a cell for the raw error, the negotiated parameters and the client's full output.
Passing cells show the TLS version, key-exchange group and the signature scheme the server saw in each
CertificateVerify (the client's too, in mTLS).</p>
<section id="detail" class="detail" hidden aria-live="polite"></section>

<h2 id="negative-controls">Negative controls</h2>
<p class="lede">Each control must fail. <b>Untrusted root</b>: the server presents a chain with the same
algorithm and hostname, issued by a root the client does not trust. <b>No client cert</b>: the client
connects to the mTLS listener without a certificate. A control that passed would invalidate the PASS
cells it guards. Controls marked “guards no PASS cell” failed for an unrelated reason (the client cannot
handle the variant at all), so they test nothing, but there is no PASS for them to protect.</p>
<p class="hint scroll-hint">Scroll the table sideways for the ML-DSA columns.</p>
<div class="wrap">
<table class="matrix">
<thead>
<tr><td rowspan="2"></td>{neg_head_variant}</tr>
<tr>{neg_head_ctrl}</tr>
</thead>
<tbody>
{neg_body}
</tbody>
</table>
</div>
<section id="neg-detail" class="detail" hidden aria-live="polite"></section>

<h2>Clients and versions</h2>
<div class="wrap">
<table class="versions"><tbody>
{versions}
</tbody></table>
</div>

<h2>Error classes</h2>
<dl class="legend">{legend}</dl>

<h2>Method</h2>
<ul>
  <li>Each variant is a three-level chain (root → intermediate → leaf) with separate server and client
    leaves, generated with the server's OpenSSL. <code>classical</code> is ECDSA P-256 with SHA-256;
    <code>mldsa</code> is ML-DSA-65 throughout. ML-DSA private keys are stored in the seed-only encoding.</li>
  <li>The server is OpenSSL <code>s_server</code> with one listener per variant and mode. mTLS listeners
    require a client certificate and verify it against the same variant's root.</li>
  <li>A cell passes only if the client completes a validated handshake (including hostname checks)
    and receives an HTTP 200 response to <code>GET /</code>. For every handshake the server records the
    signature scheme in each CertificateVerify, so an ML-DSA pass shows that ML-DSA was actually used.</li>
  <li>The classical cell is a control. If it fails for a client and mode, that client's cells for the
    mode are recorded as SETUP ERROR rather than as results.</li>
  <li>Every client also runs two <a href="#negative-controls">negative controls</a> per variant: a chain
    from an untrusted root, and connecting to the mTLS listener without a client certificate. Both must
    fail; one that passed would invalidate the PASS cells it guards.</li>
  <li>TLS version and key-exchange group come from the client where it reports them, otherwise from the
    server's handshake trace. Error classes are a best-effort mapping of client and server messages,
    split into provisioning failures (before any TLS traffic) and handshake failures; the raw excerpt is
    kept for every failure.</li>
  <li>Google Chrome for Linux is published for x86-64 only. On this run's Apple Silicon host, the Chrome
    containers ran as x86-64 under Rosetta emulation inside Colima; every other container ran natively
    on arm64.</li>
  <li>There are two Chrome rows because Chrome on Linux trusts locally added roots through the user's NSS
    database, and the NSS in the Selenium image (3.98, Ubuntu 24.04) cannot store an ML-DSA certificate.
    Measuring only that path would report an NSS limitation as a Chrome result. The <code>chrome</code>
    row therefore trusts the root through Chrome's <code>CACertificates</code> enterprise policy, which
    hands it straight to Chrome's own certificate verifier; the <code>chrome-nss</code> row imports it
    into NSS. In mTLS both rows take the client certificate from NSS, the only client-certificate source
    for Chrome on Linux.</li>
  <li>ML-DSA private keys are stored in the seed-only encoding rather than OpenSSL's default, so that
    cells measure TLS and certificate handling rather than key-file parsing (see the side note).</li>
</ul>
<aside class="side-note">
  <h3>Side note: OpenSSL's default ML-DSA key encoding</h3>
  <p>OpenSSL 3.5 writes ML-DSA private keys as seed plus expanded key by default. Go 1.27.2 refuses to
  load that encoding (<code>x509: ML-DSA private keys with both seed and expanded key are not
  supported</code>), so with OpenSSL's default keys Go's ML-DSA mTLS cell fails before any TLS traffic;
  with seed-only keys it passes. OpenSSL 3.5.7, JDK 25 and Bouncy Castle 1.86 loaded the default
  encoding. This was observed with the same versions on 2026-10-16 while building the harness; it is
  not a cell in this run.</p>
</aside>
</main>

<script type="application/json" id="cells">{data}</script>
<script>
(function () {{
  var cells = JSON.parse(document.getElementById("cells").textContent);
  var current = null;
  function esc(s) {{
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {{
      return {{"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}}[c];
    }});
  }}
  function row(k, v) {{ return v ? "<dt>" + k + "</dt><dd>" + v + "</dd>" : ""; }}
  function show(btn) {{
    document.querySelectorAll(".detail").forEach(function (p) {{ p.hidden = true; }});
    if (current) current.setAttribute("aria-pressed", "false");
    if (current === btn) {{ current = null; return; }}
    current = btn; btn.setAttribute("aria-pressed", "true");
    var panel = document.getElementById(btn.dataset.panel);
    var c = cells[+btn.dataset.i];
    var neg = !!c.control;
    panel.innerHTML =
      "<h3>" + esc(c.client_id) + " · " + esc(c.variant) + " / " +
        esc(neg ? "negative control: " + c.control : c.mode) + "</h3>" +
      "<dl>" +
      (neg ? row("Expected", esc(c.expected)) + row("Observed", esc(c.observed)) +
             row("Verdict", esc(c.verdict === "OK" ? "OK (failed as expected)" : "UNEXPECTED PASS")) +
             row("Guards", esc(c.guards) + (c.guarded_outcomes ? " (" + esc(c.guarded_outcomes) + ")" : "")) +
             row("Error class", esc(c.error_class))
           : row("Outcome", esc(c.outcome) + (c.error_class ? " — " + esc(c.error_class) : ""))) +
      row("TLS version", esc(c.tls_version)) +
      row("Key exchange", esc(c.kex_group)) +
      row("Server signature", esc(c.server_sig_scheme)) +
      row("Client signature", esc(c.client_sig_scheme)) +
      row("Client", "<code>" + esc(c.client_version) + "</code>") +
      row("Raw error", c.raw_error_excerpt ? "<code>" + esc(c.raw_error_excerpt) + "</code>" : "") +
      row("Log", "<code>" + esc(c.log_path) + "</code>") +
      "</dl>" +
      (c.log_summary ? "<pre>" + esc(c.log_summary) + "</pre>" : "") +
      "<details><summary>Client output</summary><pre>" + esc(c.client_output) + "</pre></details>";
    panel.hidden = false;
    panel.scrollIntoView({{block: "nearest", behavior: "smooth"}});
  }}
  document.querySelectorAll("td.cell button").forEach(function (b) {{
    b.setAttribute("aria-pressed", "false");
    b.addEventListener("click", function () {{ show(b); }});
  }});
}})();
</script>
</body>
</html>
"""


def main():
    if len(sys.argv) > 1:
        run_dir = Path(sys.argv[1]).resolve()
    else:
        run_id = json.loads((ROOT / "results/meta.json").read_text())["run_id"]
        run_dir = ROOT / "results/runs" / run_id
    rows, negs, meta = load_run(run_dir)
    out = run_dir / "report.html"
    out.write_text(build(rows, negs, meta))
    shutil.copy(out, ROOT / "results/report.html")
    print(f"report: results/report.html ({out.stat().st_size // 1024} KB, run {meta['run_id']})")


if __name__ == "__main__":
    main()
