#!/usr/bin/env python3
"""PQCC Safari client (macOS runner only). Usage: version | <variant> <mode> <host> <port>

Safari has no per-session trust setting, so for each cell the variant's root is added to the
System keychain with admin trust settings for SSL, and removed again afterwards (also before
starting, in case an earlier cell was interrupted). Only that root is trusted during the cell.
mTLS: client.p12 is imported into the dedicated pqcc keychain (created by native/macos-setup.sh)
with an identity preference for the server URL, so Safari picks it without a prompt.

Safari exposes neither the HTTP status nor TLS details to WebDriver, so a pass is: the
top-level document is the https URL and contains the s_server -www page marker.
Requires: native/macos-setup.sh (safaridriver enabled, trust-settings authorization, keychain).
"""
import hashlib
import os
import re
import subprocess
import sys

SYSTEM_KEYCHAIN = "/Library/Keychains/System.keychain"
KEYCHAIN = os.path.expanduser("~/Library/Keychains/pqcc.keychain-db")
P12_PASS = "pqcc"
CLIENT_CN = "client.pqcc.test"
MARKER = "Ciphers supported in s_server binary"


def run(*cmd, check_stage=None):
    r = subprocess.run(cmd, capture_output=True, text=True)
    out = (r.stdout + r.stderr).strip()
    print(f"$ {' '.join(cmd)}" + (f"\n{out}" if out else ""))
    if check_stage and r.returncode != 0:
        fail(check_stage, out or f"exit code {r.returncode}")
    return r.returncode, out


def fail(stage, detail=""):
    print(f"stage failed: {stage}", file=sys.stderr)
    if detail:
        print(detail, file=sys.stderr)
    sys.exit(1)


def version():
    plist = "/Applications/Safari.app/Contents/Info.plist"
    v = subprocess.run(["defaults", "read", plist, "CFBundleShortVersionString"], capture_output=True, text=True).stdout.strip()
    b = subprocess.run(["defaults", "read", plist, "CFBundleVersion"], capture_output=True, text=True).stdout.strip()
    os_v = subprocess.run(["sw_vers", "-productVersion"], capture_output=True, text=True).stdout.strip()
    os_b = subprocess.run(["sw_vers", "-buildVersion"], capture_output=True, text=True).stdout.strip()
    print(f"Safari {v} ({b}) on macOS {os_v} ({os_b})")


def pem_der(path):
    pem = open(path).read()
    b64 = "".join(l for l in pem.splitlines() if l and not l.startswith("-----"))
    import base64
    return base64.b64decode(b64)


def cleanup(roots):
    """Remove the study roots' trust settings and certificates, and the client identity."""
    for root in roots:
        if not os.path.exists(root):
            continue
        sha1 = hashlib.sha1(pem_der(root)).hexdigest().upper()
        run("sudo", "security", "remove-trusted-cert", "-d", root)
        run("sudo", "security", "delete-certificate", "-Z", sha1, SYSTEM_KEYCHAIN)
    run("security", "delete-identity", "-c", CLIENT_CN, KEYCHAIN)


def main():
    if sys.argv[1:] == ["version"]:
        return version()
    variant, mode, host, port = sys.argv[1:5]
    certs = os.environ.get("PQCC_CERTS", "/certs/out")
    d = f"{certs}/{variant}"
    all_roots = [f"{certs}/{v}/root.crt" for v in os.listdir(certs) if not v.startswith(".")]
    url = f"https://{host}:{port}/"

    cleanup(all_roots)
    try:
        run("sudo", "security", "add-trusted-cert", "-d", "-r", "trustRoot", "-p", "ssl",
            "-k", SYSTEM_KEYCHAIN, f"{d}/root.crt", check_stage="import root into keychain")
        if mode == "mtls":
            run("security", "import", f"{d}/client.p12", "-k", KEYCHAIN, "-f", "pkcs12", "-P", P12_PASS,
                "-T", "/Applications/Safari.app", check_stage="import client identity into keychain")
            # Let Apple-signed apps (Safari) use the key without a keychain prompt.
            run("security", "set-key-partition-list", "-S", "apple-tool:,apple:", "-s", "-k", P12_PASS,
                KEYCHAIN, check_stage="import client identity into keychain")
            run("security", "set-identity-preference", "-c", CLIENT_CN, "-s", url, KEYCHAIN,
                check_stage="import client identity into keychain")

        from selenium import webdriver
        from selenium.common.exceptions import WebDriverException

        opts = webdriver.SafariOptions()
        opts.accept_insecure_certs = False
        driver = webdriver.Safari(options=opts)
        try:
            insecure = driver.capabilities.get("acceptInsecureCerts")
            print("Session acceptInsecureCerts:", insecure)
            if insecure:
                fail("webdriver setup", f"acceptInsecureCerts={insecure}; refusing to run without validation")
            driver.set_page_load_timeout(30)
            nav_error = None
            try:
                driver.get(url)
            except WebDriverException as e:
                nav_error = e.msg
            info = driver.execute_script(
                "return {uri: document.documentURI, title: document.title,"
                " text: document.body ? document.body.innerText : ''}")
        finally:
            driver.quit()
    finally:
        cleanup(all_roots)

    text = info.get("text") or ""
    print("Document:", info.get("uri"))
    print("Title:", info.get("title"))
    if nav_error:
        print("Navigation error:", nav_error)
    m = re.search(r"New, (TLSv1\.[0-3]), Cipher is (\S+)", text)
    if m:
        print("Protocol version:", m.group(1))
        print("Cipher:", m.group(2))
    if MARKER in text and str(info.get("uri", "")).startswith("https://"):
        print("Response: s_server page loaded")
        return
    print("Page text:", " ".join(text.split())[:600])
    fail("page load", nav_error or info.get("title") or "s_server page not loaded")


if __name__ == "__main__":
    main()
