# PQ Certificate Compatibility Study — Phase 1 Build Spec

Kickoff brief for Claude Code. Put this file in the root of a new repo and start Claude Code with:
"Read pq-cert-compat-study-spec.md and build Phase 1. Work milestone by milestone and check with me after each one."

## Goal

Measure how common TLS clients handle post-quantum (ML-DSA) certificate chains compared with classical chains, in both server-auth and mutual-TLS modes, and produce a reproducible pass/fail matrix with classified errors. Results will be published as a dated study.

## Phase 1 scope

### Clients (pin and record exact versions)
| ID | Client | How to run |
|---|---|---|
| openssl35 | OpenSSL 3.5.x `s_client` | Container with OpenSSL 3.5 (distro package or built from source) |
| openssl30 | OpenSSL 3.0.x `s_client` | `ubuntu:22.04` (or RHEL 9 UBI) system OpenSSL |
| java | Java (current LTS, Eclipse Temurin) default JSSE | Small Java client |
| java-bc | Java + Bouncy Castle JSSE provider | Same client, BC provider first |
| go | Go `crypto/tls` (current release) | ~30-line Go client |
| chrome | Google Chrome (Selenium standalone image) | Headless page load via script |

### Certificate variants
| ID | Chain |
|---|---|
| classical | ECDSA P-256 root → intermediate → leaf (control) |
| mldsa | ML-DSA-65 root → intermediate → leaf (generated with OpenSSL 3.5) |

Optional if time allows: ML-DSA-44 and ML-DSA-87 variants.

### Modes
- `server` — client validates the server's chain
- `mtls` — server also requires and validates a client certificate from the same variant

Matrix size: 6 clients × 2 variants × 2 modes = 24 cells (Chrome may be server-auth only in Phase 1).

## Rules that keep results honest

- **Never bypass validation.** No `-k`, no `--ignore-certificate-errors`, no trust-all managers. Each client must trust the test root properly (CA file, Java truststore, Chrome's NSS database inside the container).
- **The classical control must pass for every client.** If a classical cell fails, mark that client's run as `SETUP_ERROR` and fix the harness before recording ML-DSA results.
- Pin image tags and package versions; record the actual version string each client reports at runtime.
- Also record the negotiated TLS version and key-exchange group when available (to separate certificate issues from key-exchange issues).

## Architecture

```
/certs/         generation scripts + generated chains per variant (gitignored output)
/server/        TLS server container (OpenSSL 3.5 s_server or nginx built on 3.5),
                one port per variant x mode
/clients/<id>/  Dockerfile + minimal client program/script per client
/runner/        orchestration: loops clients x variants x modes, captures output
/results/       results.csv, raw logs per cell, report.html
docker-compose.yml
Makefile        make certs | make up | make run | make report | make clean
```

One command after setup: `make all` regenerates certs, starts the server, runs every cell, and builds the report.

## Result schema (results.csv)

`run_id, timestamp_utc, client_id, client_version, variant, mode, outcome, error_class, tls_version, kex_group, raw_error_excerpt, log_path`

- `outcome`: PASS | FAIL | SETUP_ERROR
- `error_class` (for FAIL):
  - `UNSUPPORTED_SIG_ALG` — client does not recognize/support the signature algorithm
  - `CERT_PARSE_ERROR` — certificate or key could not be parsed
  - `CHAIN_VALIDATION_ERROR` — parsed but chain/path validation failed
  - `HANDSHAKE_FAILURE` — TLS alert or handshake abort not explained by the above
  - `TIMEOUT`
  - `OTHER` — keep the raw error; review manually

Classification is a best-effort mapping of each client's error strings; keep the raw excerpt so every cell can be audited.

## Report

- `report.html`: color-coded matrix (clients as rows; variant x mode as columns), each cell showing outcome + error class, hover/click for raw error.
- Header lists run date, every client version, and the server stack version.
- Single self-contained HTML file so it can be published as-is.

## Milestones

1. Cert generation for both variants + server serving them; verified with `openssl35` in server mode.
2. All Linux library clients (openssl35, openssl30, java, java-bc, go) in both modes, controls passing.
3. Chrome container with the test root installed in its trust store.
4. Runner, CSV output, error classification.
5. HTML report.

## Out of scope for Phase 1

Composite/hybrid certificates, wolfSSL, Mbed TLS, Rustls, Firefox, Windows SChannel, Apple URLSession (GitHub Actions runners), load balancers, HSMs, smartcards. These belong to Phase 2.
