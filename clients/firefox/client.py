#!/opt/venv/bin/python3
"""PQCC Firefox client. Usage: version | <variant> <mode> <host> <port>

Trust (PQCC_FIREFOX_TRUST):
  policy  the root is installed by the Certificates.Install enterprise policy
  nss     the root is imported into the profile's NSS database with certutil
Either way only the variant's root is trusted and no certificate-error override is used.
In mTLS the client identity is imported into the profile with pk12util, and Firefox is set
to pick it automatically. Pass = the top-level navigation returned HTTP 200.
"""
import json
import os
import subprocess
import sys
import tempfile

POLICIES = "/usr/lib/firefox/distribution/policies.json"
P12_PASS = "pqcc"


def run(*cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    out = (r.stdout + r.stderr).strip()
    print(f"$ {' '.join(cmd)}" + (f"\n{out}" if out else ""))
    return r.returncode, out


def fail(stage, detail=""):
    print(f"stage failed: {stage}", file=sys.stderr)
    if detail:
        print(detail, file=sys.stderr)
    sys.exit(1)


def bundled_nss():
    # Firefox ships its own NSS (certutil/pk12util come from the distribution); ask it.
    import ctypes
    lib = "/usr/lib/firefox"
    for dep in ("libnspr4.so", "libplc4.so", "libplds4.so", "libnssutil3.so"):
        ctypes.CDLL(f"{lib}/{dep}", mode=ctypes.RTLD_GLOBAL)
    get = ctypes.CDLL(f"{lib}/libnss3.so").NSS_GetVersion
    get.restype = ctypes.c_char_p
    return get().decode()


def version():
    ff = subprocess.run(["firefox", "--version"], capture_output=True, text=True).stdout.strip()
    gd = subprocess.run(["geckodriver", "--version"], capture_output=True, text=True).stdout.split()[1]
    tools = subprocess.run(["dpkg-query", "-W", "-f", "${Version}", "libnss3-tools"],
                           capture_output=True, text=True).stdout
    trust = os.environ.get("PQCC_FIREFOX_TRUST", "nss")
    print(f"{ff} (geckodriver {gd}; NSS {bundled_nss()}; nss-tools {tools}; trust={trust})")


ERROR_JS = """
const out = {uri: document.documentURI, text: (document.body && document.body.innerText) || ""};
for (const fn of ["getNetErrorInfo", "getFailedCertSecurityInfo"]) {
  try { const i = document[fn](); out[fn] = i && (i.errorCodeString || JSON.stringify(i)); } catch (e) {}
}
const nav = performance.getEntriesByType("navigation")[0];
out.status = nav ? nav.responseStatus : null;
return out;
"""


def main():
    if sys.argv[1:] == ["version"]:
        return version()
    variant, mode, host, port = sys.argv[1:5]
    d = f"/certs/out/{variant}"
    profile = tempfile.mkdtemp(prefix="pqcc-ff-")
    db = f"sql:{profile}"

    trust = os.environ.get("PQCC_FIREFOX_TRUST", "nss")
    print("Trust mechanism:", trust)
    policies = {}
    run("certutil", "-N", "--empty-password", "-d", db)
    if trust == "policy":
        policies["Certificates"] = {"Install": [f"{d}/root.crt"]}
    else:
        rc, out = run("certutil", "-A", "-t", "C,,", "-n", "pqcc-root", "-i", f"{d}/root.crt", "-d", db)
        if rc != 0:
            fail("import root into NSS", out)
    os.makedirs(os.path.dirname(POLICIES), exist_ok=True)
    with open(POLICIES, "w") as f:
        json.dump({"policies": policies}, f)
    if mode == "mtls":
        rc, out = run("pk12util", "-i", f"{d}/client.p12", "-W", P12_PASS, "-d", db)
        if rc != 0:
            fail("import client certificate/key into NSS", out)
    run("certutil", "-L", "-d", db)
    with open(f"{profile}/user.js", "w") as f:
        for k, v in (("security.default_personal_cert", "Select Automatically"),
                     ("network.trr.mode", 5),  # resolve server.pqcc.test via the container's DNS
                     ("browser.shell.checkDefaultBrowser", False)):
            f.write(f"user_pref({json.dumps(k)}, {json.dumps(v)});\n")

    from selenium import webdriver
    from selenium.common.exceptions import WebDriverException

    opts = webdriver.FirefoxOptions()
    for a in ("-headless", "-profile", profile):
        opts.add_argument(a)
    # Selenium's Firefox defaults include acceptInsecureCerts=True, which makes Firefox ignore
    # certificate errors. Switch it off and refuse to run unless the session confirms it.
    opts.accept_insecure_certs = False
    url = f"https://{host}:{port}/"
    driver = webdriver.Firefox(options=opts)
    try:
        insecure = driver.capabilities.get("acceptInsecureCerts")
        print("Session acceptInsecureCerts:", insecure)
        if insecure is not False:
            fail("webdriver setup", f"acceptInsecureCerts={insecure}; refusing to run without validation")
        driver.set_page_load_timeout(30)
        nav_error = None
        try:
            driver.get(url)
        except WebDriverException as e:
            nav_error = e.msg
        info = driver.execute_script(ERROR_JS)
    finally:
        driver.quit()

    code = info.get("getFailedCertSecurityInfo") or info.get("getNetErrorInfo")
    print("Document:", info["uri"])
    print("Response: HTTP", info["status"])
    if code:
        print("Firefox error code:", code)
    if nav_error:
        print("Navigation error:", nav_error)
    if info["uri"].startswith("about:"):
        print("Error page text:", " ".join(info["text"].split())[:600])

    if info["status"] == 200 and info["uri"].startswith("https://") and not nav_error:
        return
    fail("page load", code or nav_error or "no response for top-level document")


if __name__ == "__main__":
    main()
