# OpenSSL 3.5 image. Used for cert generation, the TLS server, and the openssl35 client,
# so all three share one exact OpenSSL build.
FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f

ARG OPENSSL_VERSION=3.5.7-1~deb13u3
RUN apt-get update \
 && apt-get install -y --no-install-recommends "openssl=${OPENSSL_VERSION}" ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY run.sh /clients/openssl35/run.sh
RUN chmod +x /clients/openssl35/run.sh
