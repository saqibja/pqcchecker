#!/usr/bin/env python3
"""PQCC Safari client (macOS runner only). Usage: version | <variant> <mode> <host> <port>

Trust: Safari has no per-session trust setting, so native/macos-setup.sh trusts the two study
roots (classical, mldsa) for SSL in the System keychain for the whole job; removing admin trust
settings needs an interactive prompt. Each cell still validates against only its own root (the
chains share no certificates) and the *-untrusted roots are never trusted.
mTLS is not tested: when a server requests a client certificate, Safari shows a certificate
chooser that WebDriver cannot see or answer, even with identity preferences set, and the
stalled connection blocks s_server's listener for every later client. mtls cells therefore
fail at setup without connecting (recorded as SETUP_ERROR). The missing-client-cert control
still runs (no identity is installed); Safari is the last macOS client so a stall there
cannot affect other rows.

Safari exposes neither the HTTP status nor TLS details to WebDriver, so a pass is: the
top-level document is the https URL and contains the s_server -www page marker.
Requires: native/macos-setup.sh (safaridriver enabled, trust-settings authorization, keychain).
"""
import os
import re
import subprocess
import sys

MARKER = "Ciphers supported in s_server binary"


def run(*cmd, check_stage=None):
    try:
        # A keychain authorization prompt would wait forever on a headless runner.
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        print(f"$ {' '.join(cmd)}\ntimed out after 30s (waiting for an authorization prompt?)")
        if check_stage:
            fail(check_stage, f"{cmd[0]} {cmd[1]} timed out")
        return 124, "timed out"
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


def reset_safari():
    # A cell that timed out can leave Safari paired with its WebDriver session, which makes
    # the next session fail to start.
    run("pkill", "-x", "safaridriver")
    run("pkill", "-x", "Safari")


def main():
    if sys.argv[1:] == ["version"]:
        return version()
    variant, mode, host, port = sys.argv[1:5]
    certs = os.environ.get("PQCC_CERTS", "/certs/out")
    d = f"{certs}/{variant}"
    url = f"https://{host}:{port}/"
    if mode == "mtls":
        fail("client certificate selection",
             "not automatable: Safari's certificate chooser is not reachable from WebDriver")

    reset_safari()
    try:
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
            if MARKER not in (info.get("text") or ""):
                # What Safari showed (e.g. a certificate chooser); uploaded with the results.
                shot = os.path.join("results", "screenshots", f"safari_{variant}_{mode}_{port}.png")
                os.makedirs(os.path.dirname(shot), exist_ok=True)
                print("Screenshot:", shot, driver.save_screenshot(shot))
        finally:
            driver.quit()
    finally:
        reset_safari()

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
