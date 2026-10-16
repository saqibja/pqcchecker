# OpenSSL 3.0 client: Ubuntu 22.04 system OpenSSL. Build context: ./clients
FROM ubuntu:22.04@sha256:5ec03bb3441e8b0bf3b4f9cd4629a1ae763010dc3035bb8da3ae6cf026486401

ARG OPENSSL_VERSION=3.0.2-0ubuntu1.30
RUN apt-get update \
 && apt-get install -y --no-install-recommends "openssl=${OPENSSL_VERSION}" "libssl3=${OPENSSL_VERSION}" ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --chmod=755 common/openssl-run.sh /usr/local/bin/pqcc-client
