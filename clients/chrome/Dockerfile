# Google Chrome client (Selenium standalone image; amd64 only, runs under Rosetta on Apple
# Silicon). Build context: ./clients
FROM selenium/standalone-chrome:155.0.8059.79-chromedriver-155.0.8059.79-grid-4.51.0-20261010@sha256:afadf25669d3f1f54b20fcb92b813dd64a40c3bfb03fc286c0ce3d373c735890

RUN pip3 install --no-cache-dir selenium==4.51.0

# mTLS: pick the imported client certificate automatically instead of showing a chooser.
# The managed-policy dir is writable by seluser so the client can add a CACertificates
# policy at runtime (PQCC_CHROME_TRUST=policy).
USER root
RUN mkdir -p /etc/opt/chrome/policies/managed \
 && echo '{"AutoSelectCertificateForUrls": ["{\"pattern\":\"[*.]pqcc.test\",\"filter\":{}}"]}' \
    > /etc/opt/chrome/policies/managed/pqcc.json \
 && chown seluser /etc/opt/chrome/policies/managed
COPY --chmod=755 chrome/client.py /usr/local/bin/pqcc-client
USER seluser
