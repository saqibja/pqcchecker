# OpenSSL 3.0 client: Ubuntu 22.04 system OpenSSL. Build context: ./clients

# snapshot.ubuntu.com is HTTPS-only and the Ubuntu base image has no CA bundle, so apt
# borrows one from the (already pinned) Go image for the first update.
FROM golang:1.27.3-trixie@sha256:af1bfc2614ebb1dbd31af514b78740fd678850e76498762b425ecee4c5c6ea80 AS cacerts

FROM ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11

# Packages come from a fixed snapshot of the Ubuntu archive (all architectures, including
# arm64, are served under /ubuntu), so the build keeps working after these versions leave
# the live mirrors.
ARG SNAPSHOT=20261108T000000Z
ARG OPENSSL_VERSION=3.0.2-0ubuntu1.30
COPY --from=cacerts /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN printf 'deb [check-valid-until=no] https://snapshot.ubuntu.com/ubuntu/%s %s main\n' \
      "$SNAPSHOT" jammy "$SNAPSHOT" jammy-updates "$SNAPSHOT" jammy-security > /etc/apt/sources.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      "openssl=${OPENSSL_VERSION}" "libssl3=${OPENSSL_VERSION}" ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --chmod=755 common/openssl-run.sh /usr/local/bin/pqcc-client
