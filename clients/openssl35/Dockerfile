# OpenSSL 3.5 client (Debian 13 package). The server and cert generator use their own image
# (server/Dockerfile), frozen at Round 1's build. Build context: ./clients
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

# Packages come from a fixed snapshot of the Debian archive, so the build keeps working after
# these versions leave the live mirrors. snapshot.debian.org serves old Release files whose
# Valid-Until has passed, hence check-valid-until=no.
ARG SNAPSHOT=20261108T000000Z
ARG OPENSSL_VERSION=3.5.7-1~deb13u3
RUN rm -f /etc/apt/sources.list.d/debian.sources \
 && printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/%s/%s %s main\n' \
      debian "$SNAPSHOT" trixie \
      debian-security "$SNAPSHOT" trixie-security > /etc/apt/sources.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      "openssl=${OPENSSL_VERSION}" "libssl3t64=${OPENSSL_VERSION}" ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --chmod=755 common/openssl-run.sh /usr/local/bin/pqcc-client
