# Server and cert-generator image: OpenSSL 3.5.7, frozen at Round 1's exact build so every round
# is measured against the same server. Client images are updated separately. Build context: ./server
FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f

# Packages come from a fixed snapshot of the Debian archive, so the build keeps working after
# these versions leave the live mirrors. snapshot.debian.org serves old Release files whose
# Valid-Until has passed, hence check-valid-until=no.
ARG SNAPSHOT=20261016T000000Z
ARG OPENSSL_VERSION=3.5.7-1~deb13u3
RUN rm -f /etc/apt/sources.list.d/debian.sources \
 && printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/%s/%s %s main\n' \
      debian "$SNAPSHOT" trixie \
      debian-security "$SNAPSHOT" trixie-security > /etc/apt/sources.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      "openssl=${OPENSSL_VERSION}" "libssl3t64=${OPENSSL_VERSION}" ca-certificates \
 && rm -rf /var/lib/apt/lists/*
