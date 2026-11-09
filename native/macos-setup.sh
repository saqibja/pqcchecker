#!/usr/bin/env bash
# One-time setup on a disposable macOS runner (never run on a workstation: it changes system
# authorization rules and enables Safari automation).
set -euo pipefail
# Safari WebDriver (also turns on "Allow Remote Automation").
sudo safaridriver --enable
# Allow admin trust settings without an interactive prompt (security add-trusted-cert -d).
sudo security authorizationdb write com.apple.trust-settings.admin allow
# Dedicated keychain for client identities (Safari mTLS), unlocked with no auto-lock.
security create-keychain -p pqcc pqcc.keychain
security set-keychain-settings pqcc.keychain
security unlock-keychain -p pqcc pqcc.keychain
security list-keychains -d user -s pqcc.keychain $(security list-keychains -d user | tr -d '"')
echo "127.0.0.1 server.pqcc.test" | sudo tee -a /etc/hosts
