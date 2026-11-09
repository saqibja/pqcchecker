#!/usr/bin/env bash
# One-time setup on a disposable macOS runner (never run on a workstation: it changes system
# authorization rules and enables Safari automation).
set -euo pipefail
# Safari WebDriver (also turns on "Allow Remote Automation").
sudo safaridriver --enable
# Allow admin trust settings without an interactive prompt (security add-trusted-cert -d).
# macOS 26 may refuse this (-60005); add-trusted-cert can still work as root, so carry on and
# check below. If it does not, only the Safari row is affected (its classical control fails).
sudo security authorizationdb write com.apple.trust-settings.admin allow \
  || echo "note: authorizationdb write refused; checking add-trusted-cert directly"
root=certs/out/classical/root.crt
if sudo security add-trusted-cert -d -r trustRoot -p ssl -k /Library/Keychains/System.keychain "$root"; then
  echo "preflight: System keychain trust settings can be added (Safari trust will work)"
  sudo security remove-trusted-cert -d "$root"
  sudo security delete-certificate -c "PQCC classical Root CA" /Library/Keychains/System.keychain
else
  echo "preflight: cannot add System keychain trust settings; Safari cells will fail setup"
fi
# Dedicated keychain for client identities (Safari mTLS), unlocked with no auto-lock.
security create-keychain -p pqcc pqcc.keychain
security set-keychain-settings pqcc.keychain
security unlock-keychain -p pqcc pqcc.keychain
security list-keychains -d user -s pqcc.keychain $(security list-keychains -d user | tr -d '"')
echo "127.0.0.1 server.pqcc.test" | sudo tee -a /etc/hosts
