#!/home/seluser/venv/bin/python3
"""PQCC Chrome client. Usage: version | <variant> <mode> <host> <port>

Trust: only the variant's root CA is imported into the user's NSS database, which is where
Chrome on Linux reads locally trusted roots. No certificate-error bypass flags are used.
The result comes from Chrome's DevTools network events for the top-level document.
"""
import base64
import json
import os
import subprocess
import sys
import tempfile

NSSDB = "sql:" + os.path.expanduser("~/.pki/nssdb")
POLICY = "/etc/opt/chrome/policies/managed/pqcc-trust.json"
P12_PASS = "pqcc"


def run(*cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    out = (r.stdout + r.stderr).strip()
    print(f"$ {' '.join(cmd)}" + (f"\n{out}" if out else ""))
    return r.returncode


def fail(stage, detail=""):
    print(f"stage failed: {stage}", file=sys.stderr)
    if detail:
        print(detail, file=sys.stderr)
    sys.exit(1)


def version():
    chrome = subprocess.run(["google-chrome", "--version"], capture_output=True, text=True).stdout.strip()
    driver = subprocess.run(["chromedriver", "--version"], capture_output=True, text=True).stdout.split()[1]
    nss = subprocess.run(["dpkg-query", "-W", "-f", "${Version}", "libnss3"], capture_output=True, text=True).stdout
    trust = os.environ.get("PQCC_CHROME_TRUST", "nss")
    print(f"{chrome} (chromedriver {driver}; NSS {nss}; trust={trust})")


def main():
    if sys.argv[1:] == ["version"]:
        return version()
    variant, mode, host, port = sys.argv[1:5]
    d = f"/certs/out/{variant}"

    trust = os.environ.get("PQCC_CHROME_TRUST", "nss")
    print("Trust mechanism:", trust)
    if trust == "policy":
        # Chrome enterprise policy: hands the root straight to Chrome's verifier, no NSS.
        der = subprocess.run(["openssl", "x509", "-in", f"{d}/root.crt", "-outform", "DER"],
                             capture_output=True, check=True).stdout
        with open(POLICY, "w") as f:
            json.dump({"CACertificates": [base64.b64encode(der).decode()]}, f)
    elif run("certutil", "-d", NSSDB, "-A", "-t", "C,,", "-n", "pqcc-root", "-i", f"{d}/root.crt") != 0:
        fail("import root into NSS")
    if mode == "mtls":
        if run("pk12util", "-d", NSSDB, "-i", f"{d}/client.p12", "-W", P12_PASS) != 0:
            fail("import client certificate/key into NSS")
    run("certutil", "-d", NSSDB, "-L")

    from selenium import webdriver
    from selenium.common.exceptions import WebDriverException

    opts = webdriver.ChromeOptions()
    for a in ("--headless=new", "--no-sandbox", "--disable-dev-shm-usage",
              f"--user-data-dir={tempfile.mkdtemp()}"):
        opts.add_argument(a)
    opts.set_capability("goog:loggingPrefs", {"performance": "ALL"})

    url = f"https://{host}:{port}/"
    driver = webdriver.Chrome(options=opts)
    try:
        driver.set_page_load_timeout(30)
        nav_error = None
        try:
            driver.get(url)
        except WebDriverException as e:
            nav_error = e.msg
        events = [json.loads(e["message"])["message"] for e in driver.get_log("performance")]
        title = driver.title
    finally:
        driver.quit()

    req_id = response = failed = None
    for ev in events:
        p = ev.get("params", {})
        if ev["method"] == "Network.requestWillBeSent" and req_id is None and p["request"]["url"] == url:
            req_id = p["requestId"]
        elif p.get("requestId") != req_id or req_id is None:
            continue
        elif ev["method"] == "Network.responseReceived":
            response = p["response"]
        elif ev["method"] == "Network.loadingFailed":
            failed = p

    if response:
        sec = response.get("securityDetails") or {}
        print("Protocol version:", sec.get("protocol"))
        print("Negotiated group:", sec.get("keyExchangeGroup"))
        print("Cipher:", sec.get("cipher"))
        sig = sec.get("serverSignatureAlgorithm")
        print("Server signature algorithm:", f"0x{sig:04x}" if isinstance(sig, int) else sig)
        print("Response: HTTP", response.get("status"))
    if failed:
        print("Network error:", failed.get("errorText"))
    if nav_error:
        print("Navigation error:", nav_error)
    print("Page title:", title)

    if response and response.get("status") == 200 and not failed:
        return
    fail("page load", (failed or {}).get("errorText") or nav_error or "no response for top-level document")


if __name__ == "__main__":
    main()
