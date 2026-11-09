#!/usr/bin/env bash
# One-time setup on a disposable macOS runner (never run on a workstation: it enables Safari
# automation and adds the study roots to the System keychain as trusted for SSL).
set -euo pipefail
# Fail instead of hanging if any command waits for an authorization prompt (no GUI here).
limit() { perl -e 'alarm shift; exec @ARGV or die "exec $ARGV[0]: $!"' 60 "$@"; }

# Safari WebDriver (also turns on "Allow Remote Automation").
limit sudo safaridriver --enable

# Safari has no per-session trust, so the two study roots are trusted for the whole job.
# Removing admin trust settings again waits for an authorization prompt, so they stay until
# the runner is discarded. Each cell still validates against only its own root (the classical
# and ML-DSA chains share no certificates), and the *-untrusted roots are never added.
for v in classical mldsa; do
  if limit sudo security add-trusted-cert -d -r trustRoot -p ssl \
       -k /Library/Keychains/System.keychain "certs/out/$v/root.crt"; then
    echo "trusted for SSL: $v root"
  else
    echo "could not trust the $v root; Safari's $v cells will fail" >&2
  fi
done

# Dedicated keychain for client identities (Safari mTLS), unlocked with no auto-lock.
limit security create-keychain -p pqcc pqcc.keychain
limit security set-keychain-settings pqcc.keychain
limit security unlock-keychain -p pqcc pqcc.keychain
limit security list-keychains -d user -s pqcc.keychain $(security list-keychains -d user | tr -d '"')
# SecureTransport (curl) imports client.p12 into the default keychain; the runner's login
# keychain is locked, which curl reports as "Incorrect password". Use the unlocked one.
limit security default-keychain -d user -s pqcc.keychain
echo "127.0.0.1 server.pqcc.test" | limit sudo tee -a /etc/hosts
