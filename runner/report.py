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

ERROR_CLASSES = [
    ("UNSUPPORTED_SIG_ALG", "Client does not recognize or support the signature algorithm."),
    ("CERT_PARSE_ERROR", "Certificate or key could not be parsed or loaded."),
    ("CHAIN_VALIDATION_ERROR", "Parsed, but chain or path validation failed."),
    ("HANDSHAKE_FAILURE", "TLS alert or handshake abort not explained by the above."),
    ("TIMEOUT", "No result within the time limit."),
    ("OTHER", "Unclassified; see the raw output."),
]


def load_run(run_dir):
    rows = list(csv.DictReader(open(run_dir / "results.csv")))
    meta = json.loads((run_dir / "meta.json").read_text())
    for r in rows:
        log = (ROOT / r["log_path"]).read_text() if (ROOT / r["log_path"]).exists() else ""
        head, _, rest = log.partition("\n=== client output\n")
        client_out = rest.split("\n=== server log", 1)[0]
        r["log_summary"] = "\n".join(l for l in head.splitlines()
                                     if l.startswith(("client_reported", "server_observed", "exit_code")))
        r["client_output"] = client_out.strip()
    return rows, meta


def ordered(values):
    return list(dict.fromkeys(values))


def build(rows, meta):
    e = html.escape
    clients = ordered(r["client_id"] for r in rows)
    columns = ordered((r["variant"], r["mode"]) for r in rows)
    variants = ordered(v for v, _ in columns)
    cell = {(r["client_id"], r["variant"], r["mode"]): r for r in rows}
    started = datetime.fromisoformat(meta["started_utc"])
    date = started.strftime("%Y-%m-%d")
    counts = {o: sum(r["outcome"] == o for r in rows) for o in ("PASS", "FAIL", "SETUP_ERROR")}

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
            idx = rows.index(r)
            sub = r["error_class"] or " · ".join(x for x in (r["tls_version"], r["kex_group"]) if x)
            tds.append(
                f'<td class="cell"><button class="o-{r["outcome"].lower()}" data-i="{idx}" '
                f'title="{e(r["raw_error_excerpt"] or r["outcome"])}" aria-label="{e(c)} {e(v)} {e(m)}: '
                f'{e(r["outcome"])} {e(r["error_class"])}">'
                f'<span class="o">{e(r["outcome"].replace("_", " "))}</span>'
                f'<span class="sub">{e(sub).replace("_", "_<wbr>")}</span></button></td>')
        body.append(f'<tr><th scope="row"><span class="cid">{e(c)}</span></th>{"".join(tds)}</tr>')

    versions = "".join(
        f'<tr><th scope="row">{e(c)}</th><td><code>{e(meta["clients"].get(c, ""))}</code>'
        f'<div class="note">{e(CLIENT_NOTES.get(c, ""))}</div></td></tr>' for c in clients)
    legend = "".join(f"<dt>{e(k)}</dt><dd>{e(d)}</dd>" for k, d in ERROR_CLASSES)

    data = json.dumps([{k: r[k] for k in ("client_id", "client_version", "variant", "mode", "outcome",
                                          "error_class", "tls_version", "kex_group",
                                          "raw_error_excerpt", "log_path", "log_summary",
                                          "client_output")} for r in rows])
    data = data.replace("</", "<\\/")

    return TEMPLATE.format(
        date=e(date), run_id=e(meta["run_id"]), started=e(meta["started_utc"]),
        finished=e(meta.get("finished_utc", "")), commit=e(meta.get("git_commit", "")),
        host=e(meta.get("host", "")), docker=e(meta.get("docker_server", "")),
        server=e(meta.get("server_stack", "")), n=len(rows), n_clients=len(clients),
        n_pass=counts["PASS"], n_fail=counts["FAIL"], n_setup=counts["SETUP_ERROR"],
        head_variant=head_variant, head_mode=head_mode, body="\n".join(body),
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
#detail {{ margin-top: 16px; padding: 16px; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; }}
#detail[hidden] {{ display: none; }}
#detail h3 {{ margin: 0 0 8px; font-size: 1rem; }}
#detail dl {{ display: grid; grid-template-columns: max-content 1fr; gap: 4px 16px; margin: 0 0 12px; }}
#detail dt {{ color: var(--muted); }}
#detail dd {{ margin: 0; overflow-wrap: anywhere; }}
pre {{ margin: 8px 0 0; padding: 12px; background: var(--bg); border: 1px solid var(--border); border-radius: 6px;
  white-space: pre-wrap; overflow-wrap: anywhere; max-height: 420px; overflow-y: auto; }}
details summary {{ cursor: pointer; color: var(--muted); }}
.versions th {{ white-space: nowrap; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.88rem; }}
.versions code {{ overflow-wrap: anywhere; }}
.note {{ color: var(--muted); font-size: 0.85rem; margin-top: 2px; }}
.legend {{ display: grid; grid-template-columns: max-content 1fr; gap: 6px 16px; margin: 0; }}
.legend dt {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.82rem; }}
.legend dd {{ margin: 0; }}
ul {{ padding-left: 20px; margin: 0; }}
li {{ margin-bottom: 6px; }}
.matrix tbody th, .matrix thead td {{ position: sticky; left: 0; z-index: 1; background: var(--surface); }}
.scroll-hint {{ display: none; }}
@media (max-width: 560px) {{
  .legend, #detail dl {{ grid-template-columns: 1fr; }}
  .legend dd, #detail dd {{ margin-bottom: 8px; }}
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
Passing cells show the TLS version and key-exchange group.</p>
<section id="detail" hidden aria-live="polite"></section>

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
    and receives an HTTP 200 response to <code>GET /</code>.</li>
  <li>The classical cell is a control. If it fails for a client and mode, that client's cells for the
    mode are recorded as SETUP ERROR rather than as results.</li>
  <li>TLS version and key-exchange group come from the client where it reports them, otherwise from the
    server's handshake trace. Error classes are a best-effort mapping of client and server messages;
    the raw excerpt is kept for every failure.</li>
</ul>
</main>

<script type="application/json" id="cells">{data}</script>
<script>
(function () {{
  var cells = JSON.parse(document.getElementById("cells").textContent);
  var panel = document.getElementById("detail");
  var current = null;
  function esc(s) {{
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {{
      return {{"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}}[c];
    }});
  }}
  function row(k, v) {{ return v ? "<dt>" + k + "</dt><dd>" + v + "</dd>" : ""; }}
  function show(btn) {{
    if (current) current.setAttribute("aria-pressed", "false");
    if (current === btn) {{ current = null; panel.hidden = true; return; }}
    current = btn; btn.setAttribute("aria-pressed", "true");
    var c = cells[+btn.dataset.i];
    panel.innerHTML =
      "<h3>" + esc(c.client_id) + " · " + esc(c.variant) + " / " + esc(c.mode) + "</h3>" +
      "<dl>" +
      row("Outcome", esc(c.outcome) + (c.error_class ? " — " + esc(c.error_class) : "")) +
      row("TLS version", esc(c.tls_version)) +
      row("Key exchange", esc(c.kex_group)) +
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
    rows, meta = load_run(run_dir)
    out = run_dir / "report.html"
    out.write_text(build(rows, meta))
    shutil.copy(out, ROOT / "results/report.html")
    print(f"report: results/report.html ({out.stat().st_size // 1024} KB, run {meta['run_id']})")


if __name__ == "__main__":
    main()
