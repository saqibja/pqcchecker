# Mozilla Firefox client: Mozilla's own APT build (native on amd64 and arm64) driven by
# geckodriver. Ubuntu 26.04 base so the NSS tools (certutil/pk12util) match the Chrome image.
# Build context: ./clients
FROM ubuntu:26.04@sha256:6a06111c3b0a8600feadb270aec771dc239bf407b25625f93f44ab00e11f4d3c

ARG FIREFOX_VERSION=159.0.1~build1
ARG GECKODRIVER_VERSION=0.37.1
# Mozilla's published APT signing key fingerprint (packages.mozilla.org).
ARG MOZILLA_KEY_FPR=35BAA0B33E9EB396F59CA838C0BA5CE6DC6315A3
ARG TARGETARCH

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl gpg libnss3-tools \
      python3 python3-venv \
 && install -d -m 0755 /etc/apt/keyrings \
 && curl -fsSL https://packages.mozilla.org/apt/repo-signing-key.gpg -o /etc/apt/keyrings/mozilla.asc \
 && gpg --show-keys --with-colons /etc/apt/keyrings/mozilla.asc | grep -q "^fpr:::::::::${MOZILLA_KEY_FPR}:" \
 && echo "deb [signed-by=/etc/apt/keyrings/mozilla.asc] https://packages.mozilla.org/apt mozilla main" \
      > /etc/apt/sources.list.d/mozilla.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends "firefox=${FIREFOX_VERSION}" \
 && rm -rf /var/lib/apt/lists/*

RUN case "$TARGETARCH" in \
      arm64) asset=linux-aarch64 sum=8fd90b951422fbad5b56539fb344dff66eb3f986d615d8d6fde9f1f62dad610c ;; \
      amd64) asset=linux64       sum=e815130ea95983e162ae91843b48d3a3ce991735635fce83a647afde21e09f7e ;; \
      *) echo "unsupported arch $TARGETARCH" >&2; exit 1 ;; \
    esac \
 && curl -fsSL -o /tmp/gd.tgz \
      "https://github.com/mozilla/geckodriver/releases/download/v${GECKODRIVER_VERSION}/geckodriver-v${GECKODRIVER_VERSION}-${asset}.tar.gz" \
 && echo "$sum  /tmp/gd.tgz" | sha256sum -c - \
 && tar -xzf /tmp/gd.tgz -C /usr/local/bin geckodriver && rm /tmp/gd.tgz

RUN python3 -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir selenium==4.52.0
COPY --chmod=755 firefox/client.py /usr/local/bin/pqcc-client
