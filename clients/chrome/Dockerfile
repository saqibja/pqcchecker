# Google Chrome client (Selenium standalone image; amd64 only, runs under Rosetta on Apple
# Silicon). Build context: ./clients
FROM selenium/standalone-chrome:157.0.8103.38-chromedriver-157.0.8103.38-grid-4.52.0-20261101@sha256:e84d0ebd89836a4310060ae550d8103ba847c81f5a3f985319067d671248c628

RUN pip3 install --no-cache-dir selenium==4.52.0

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
