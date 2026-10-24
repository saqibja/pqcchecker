# PQ Certificate Compatibility Study

Measures how common TLS clients handle **post-quantum (ML-DSA-65) certificate chains** compared
with a classical ECDSA P-256 control chain, in two modes:

- `server`: the client validates the server's chain.
- `mtls`: the server also requires and validates a client certificate from the same chain.

Every cell is a real, validated handshake against the study's own root. Nothing bypasses
verification (no `-k`, no trust-all managers, no `--ignore-certificate-errors`). The output is a
reproducible pass/fail matrix with classified errors, a set of negative controls, and a
self-contained `report.html` for publishing.

The original brief is [pq-cert-compat-study-spec.md](pq-cert-compat-study-spec.md).

## Clients (Phase 1)

| ID | What it runs |
|---|---|
| `openssl35` | OpenSSL 3.5 `s_client` (Debian 13 package) |
| `openssl30` | OpenSSL 3.0 `s_client` (Ubuntu 22.04 system package) |
| `java` | Java 25 LTS (Eclipse Temurin), default JSSE |
| `java-bc` | Same client with Bouncy Castle JCE + JSSE registered first, default settings |
| `java-bc-pq` | `java-bc` with ML-DSA added to `jdk.tls.client.SignatureSchemes` (not a default) |
| `go` | Go `crypto/tls` |
| `chrome` | Headless Google Chrome; root trusted via the `CACertificates` enterprise policy |
| `chrome-nss` | Headless Google Chrome; root imported into the user NSS database |

Exact versions are pinned in the Dockerfiles and recorded at runtime in `results/meta.json`.
The report explains why Bouncy Castle and Chrome each have two rows.

## Prerequisites

- Docker Engine with Compose v2 and BuildKit (`docker buildx`).
- Python 3.10+ on the host (the runner and report use only the standard library).
- About 6 GB of RAM for the Docker VM.

**Apple Silicon:** Google Chrome for Linux is published for x86-64 only, so the Chrome
containers need x86-64 emulation. With [Colima](https://github.com/abiosoft/colima):

```sh
brew install colima docker docker-compose docker-buildx
# Let Docker find the Compose and buildx plugins:
#   ~/.docker/config.json -> { "cliPluginsExtraDirs": ["/opt/homebrew/lib/docker/cli-plugins"] }
colima start --vm-type vz --vz-rosetta --cpu 4 --memory 6
```

Everything else runs natively on arm64. On an x86-64 Linux host, plain Docker is enough.

## Running

```sh
make all        # certs -> up -> run -> report (the whole study, one command)
```

Individual targets:

| Target | What it does |
|---|---|
| `make build` | Build every image (server, cert generator, all clients). |
| `make certs` | Generate all chains into `certs/out/` (gitignored). |
| `make up` | (Re)start the TLS server with one listener per row of `server/ports.tsv`. |
| `make run` | Run every cell and negative control; `make run CLIENTS="go chrome"` runs a subset. |
| `make report` | Build `results/report.html` from the latest run. |
| `make down` | Stop the server. |
| `make clean` | Stop the server and delete generated certs and results. |

`make run` exits with status 2 if any negative control unexpectedly passes, so `make all` stops
before building a report from untrustworthy results.

## Repo layout

```
certs/gen.sh, ext.cnf    Chain generation (root -> intermediate -> server/client leaf) per variant,
                         plus an independent "<variant>-untrusted" chain for the negative control
server/start.sh          One OpenSSL 3.5 s_server -www -trace per listener
server/ports.tsv         Listeners: variant, mode, port
clients/<id>/            Dockerfile + client program per client (java-bc, java-bc-pq and
                         chrome-nss reuse another client's image with different settings)
clients/common/          Shared OpenSSL s_client wrapper
runner/run.py            Runs all cells and controls, classifies errors, writes results
runner/report.py         Builds the self-contained HTML report
docker-compose.yml       Server, cert generator and one service per client
results/                 Output (gitignored): latest results + runs/<run_id>/ archive
```

## Reproducibility

- Base images are pinned by digest; downloaded jars are checksum-verified.
- The OpenSSL packages are installed from fixed snapshots of the distribution archives
  (`snapshot.debian.org` and `snapshot.ubuntu.com`, timestamp `20261016T000000Z`), so the builds
  keep working after those versions leave the live mirrors. To move to newer packages, change
  the `SNAPSHOT` and version build arguments in `clients/openssl35/Dockerfile` and
  `clients/openssl30/Dockerfile` together.
- Each run records the harness git commit (`-dirty` if there were uncommitted changes), the host,
  the Docker version, the server stack and every client's runtime version string.

## Adding a client

1. Create `clients/<id>/Dockerfile` (build context is `clients/`). The image must provide an
   executable `pqcc-client` that implements this contract:

   ```
   pqcc-client version                          print the client's version string, exit 0
   pqcc-client <variant> <mode> <host> <port>   connect, validate, send "GET /"
   ```

   - Certificates are mounted read-only at `/certs/out/<variant>/`: `root.crt` (the only trust
     anchor), `int.crt`, `client.crt`, `client.key` (PKCS#8 PEM; ML-DSA keys are seed-only),
     `client-chain.crt` and `client.p12` (password `pqcc`).
   - In `mtls` mode, present `client.crt` + `int.crt` with `client.key`. In `server` mode, present
     no client certificate (the missing-client-cert control relies on this).
   - Verify the hostname. Exit 0 **only** after a validated handshake and an `HTTP/1.0 200`
     response line.
   - On failure, print `stage failed: <stage>` then the underlying error on the next line. Use
     `read root certificate`, `parse root certificate`, `load client certificate/key` or
     `handshake` where they fit; the classifier keys off them.
   - Optionally print `Protocol version: ...` and `Negotiated group: ...`; otherwise both are
     taken from the server's trace.
2. Add a service to `docker-compose.yml` using the `*client` anchor.
3. Add the id to `CLIENTS` in `runner/run.py`, and a one-line note to `CLIENT_NOTES` in
   `runner/report.py`.
4. Run `make run CLIENTS=<id>` and check that its classical controls pass and its negative
   controls fail.

## Reading the results

`results/results.csv`: one row per client x variant x mode cell.

| Column | Meaning |
|---|---|
| `run_id`, `timestamp_utc` | Run identifier and when the cell finished |
| `client_id`, `client_version` | Client and the version string it reported at runtime |
| `variant`, `mode` | `classical` or `mldsa`; `server` or `mtls` |
| `outcome` | `PASS`, `FAIL`, or `SETUP_ERROR` (that client's classical control failed in this mode) |
| `error_class` | Classification of a FAIL (below) |
| `tls_version`, `kex_group` | Negotiated protocol and key-exchange group (client-reported, else server trace) |
| `raw_error_excerpt` | The line(s) the classification is based on; `server:` marks server-side evidence |
| `log_path` | Full log: client output plus the server's trace for that listener during the cell |
| `server_sig_scheme`, `client_sig_scheme` | Signature scheme in the server's / client's CertificateVerify, from the server trace |

`results/negative_controls.csv`: per client and variant, `untrusted_root` (chain from a root
the client does not trust) and `missing_client_cert` (no client certificate to the mTLS
listener). Each should have `observed=FAIL` and `verdict=OK`. `guards` lists the main cells a
control protects and `guarded_outcomes` their results; a control that guards no PASS cell
may fail for an unrelated reason.

### Error classes

| Class | Phase | Meaning |
|---|---|---|
| `TRUST_STORE_IMPORT_ERROR` | Provisioning | The client's tooling could not import the root, intermediate or client certificate/key (e.g. NSS `certutil`/`pk12util`). |
| `KEY_LOAD_ERROR` | Provisioning | The client could not load its own private key (or its paired certificate) for mTLS. |
| `UNSUPPORTED_SIG_ALG` | Handshake | The client does not offer or support the signature algorithm. |
| `CERT_PARSE_ERROR` | Handshake | The client could not parse a certificate received from the peer. |
| `CHAIN_VALIDATION_ERROR` | Handshake | The certificate parsed, but chain or path validation failed. |
| `HANDSHAKE_FAILURE` | Handshake | TLS alert or abort not explained by the above. |
| `TIMEOUT` | Either | No result within the time limit. |
| `OTHER` | Either | Unclassified; see the raw output. |

Provisioning failures happen before any TLS traffic. Classification is best-effort pattern
matching on client and server messages; the excerpt and full log are kept so every cell can be
audited.
