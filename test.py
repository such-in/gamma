#!/usr/bin/env python3
# Verifies:
# - Browsers (Chrome/Brave/Firefox): load example.org + capture requests
# - nmap: ping scan works
# - testssl: protocols-only; confirm TLS versions listing
# - Geolocation: RIPE IPmap, ipwho.is, ipinfo (only if ipinfo.token exists)
# - Traceroute: system traceroute/tracert + Scapy probe
# No files written.

import os
import time
import shutil
import subprocess
import json
import platform

# Selenium/Selenium-Wire are required for browser tests
try:
    from seleniumwire import webdriver
except Exception as e:
    print(f"[FAIL] selenium/selenium-wire import: {e}")
    webdriver = None

# Scapy (optional)
try:
    from scapy.all import IP, ICMP, sr1
    HAVE_SCAPY = True
except Exception as e:
    print(f"[FAIL] scapy import: {e}")
    HAVE_SCAPY = False

EXAMPLE_URL = "https://example.org"
EXPECTED_TITLE_SNIPPET = "Example Domain"
TEST_IP = "1.1.1.1"

def _has_cmd(cmd): return shutil.which(cmd) is not None
def _print(ok, name, details=""):
    prefix = "[OK]" if ok else "[FAIL]"
    print(f"{prefix} {name}{': ' + details if details else ''}")

# -------- Browsers (Selenium Manager) --------

def _test_chrome():
    if webdriver is None:
        _print(False, "Chrome", "selenium-wire not available"); return
    chrome_bins = ["/usr/bin/google-chrome","/usr/bin/google-chrome-stable", os.getenv("GOOGLE_CHROME_BIN")]
    chrome_bin = next((p for p in chrome_bins if p and os.path.exists(p)), None)
    if not chrome_bin:
        _print(False, "Chrome", "chrome binary not found"); return
    try:
        opts = webdriver.ChromeOptions()
        opts.binary_location = chrome_bin
        opts.add_argument("--headless=new"); opts.add_argument("--no-sandbox"); opts.add_argument("--disable-dev-shm-usage")
        driver = webdriver.Chrome(options=opts, seleniumwire_options={"enable_har": True})
        try:
            driver.scopes = [".*"]; driver.get(EXAMPLE_URL)
            ok_title=False
            for _ in range(40):
                if EXPECTED_TITLE_SNIPPET.lower() in (driver.title or "").lower(): ok_title=True; break
                time.sleep(0.25)
            reqs_ok = len(driver.requests) > 0
            _print(ok_title and reqs_ok, "Chrome", f"title_ok={ok_title}, requests_captured={reqs_ok}")
        finally:
            try: driver.quit()
            except: pass
    except Exception as e:
        _print(False, "Chrome", str(e))

def _test_brave():
    if webdriver is None:
        _print(False, "Brave", "selenium-wire not available"); return
    brave_bins = ["/usr/bin/brave-browser","/usr/bin/brave-browser-stable", os.getenv("BRAVE_PATH"),
                  "/opt/brave.com/brave/brave-browser","/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"]
    brave_bin = next((p for p in brave_bins if p and os.path.exists(p)), None)
    if not brave_bin:
        _print(False, "Brave", "brave binary not found"); return
    try:
        opts = webdriver.ChromeOptions()
        opts.binary_location = brave_bin
        opts.add_argument("--headless=new"); opts.add_argument("--no-sandbox"); opts.add_argument("--disable-dev-shm-usage")
        driver = webdriver.Chrome(options=opts, seleniumwire_options={"enable_har": True})
        try:
            driver.scopes = [".*"]; driver.get(EXAMPLE_URL)
            ok_title=False
            for _ in range(40):
                if EXPECTED_TITLE_SNIPPET.lower() in (driver.title or "").lower(): ok_title=True; break
                time.sleep(0.25)
            reqs_ok = len(driver.requests) > 0
            _print(ok_title and reqs_ok, "Brave", f"title_ok={ok_title}, requests_captured={reqs_ok}")
        finally:
            try: driver.quit()
            except: pass
    except Exception as e:
        _print(False, "Brave", str(e))

def _test_firefox():
    if webdriver is None:
        _print(False, "Firefox", "selenium-wire not available"); return
    try:
        fopts = webdriver.FirefoxOptions()
        fopts.add_argument("-headless")
        driver = webdriver.Firefox(options=fopts, seleniumwire_options={"enable_har": True})
        try:
            driver.scopes = [".*"]; driver.get(EXAMPLE_URL)
            ok_title=False
            for _ in range(40):
                if EXPECTED_TITLE_SNIPPET.lower() in (driver.title or "").lower(): ok_title=True; break
                time.sleep(0.25)
            reqs_ok = len(driver.requests) > 0
            _print(ok_title and reqs_ok, "Firefox", f"title_ok={ok_title}, requests_captured={reqs_ok}")
        finally:
            try: driver.quit()
            except: pass
    except Exception as e:
        _print(False, "Firefox", str(e))

# -------- Tools --------

def _test_nmap():
    if not _has_cmd("nmap"):
        _print(False, "nmap", "nmap not found"); return
    try:
        p = subprocess.run(["nmap","-sn","-n", TEST_IP], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
        ok = (p.returncode == 0) and p.stdout.strip() != ""
        _print(ok, "nmap", f"exit={p.returncode}")
    except Exception as e:
        _print(False, "nmap", str(e))

def _test_testssl_protocols():
    binary = shutil.which("testssl") or shutil.which("testssl.sh")
    if not binary:
        _print(False, "testssl(protocols)", "testssl(.sh) not found"); return
    try:
        p = subprocess.run([binary,"--protocols","--quiet","--warnings","off","example.org"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=180)
        text = p.stdout or p.stderr
        ok = (p.returncode == 0) and any(v in text for v in ("TLS", "SSL"))
        _print(ok, "testssl(protocols)", f"exit={p.returncode}")
    except Exception as e:
        _print(False, "testssl(protocols)", str(e))

# -------- Geolocation --------

def _test_geo_ripeipmap():
    try:
        p = subprocess.run(["curl","-sS","--max-time","20", f"https://ipmap-api.ripe.net/v1/locate/{TEST_IP}"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=25)
        ok = (p.returncode == 0) and (p.stdout.strip() != "")
        _print(ok, "geo:ripeipmap", f"exit={p.returncode}")
    except Exception as e:
        _print(False, "geo:ripeipmap", str(e))

def _test_geo_ipwhois():
    try:
        p = subprocess.run(["curl","-sS","--max-time","20", f"http://ipwho.is/{TEST_IP}"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=25)
        ok = False
        if p.returncode == 0 and p.stdout:
            try:
                data = json.loads(p.stdout)
                ok = bool(data.get("success", True))
            except Exception:
                ok = p.stdout.strip() != ""
        _print(ok, "geo:ipwho.is", f"exit={p.returncode}")
    except Exception as e:
        _print(False, "geo:ipwho.is", str(e))

def _test_geo_ipinfo():
    token_file = os.getenv("IPINFO_TOKEN_FILE", "ipinfo.token")
    if not os.path.isfile(token_file):
        print("[SKIP] geo:ipinfo token not found; skipping ipinfo")
        return
    try:
        with open(token_file, "r", encoding="utf-8") as f:
            token = f.read().strip()
        p = subprocess.run(["curl","-sS","--max-time","20","-H",f"Authorization: Bearer {token}",
                            f"https://ipinfo.io/{TEST_IP}/json"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=25)
        ok = (p.returncode == 0) and (p.stdout.strip() != "")
        _print(ok, "geo:ipinfo", f"exit={p.returncode}")
    except Exception as e:
        _print(False, "geo:ipinfo", str(e))

# -------- Traceroute / Tracert --------

def _test_traceroute_system():
    is_windows = platform.system().lower().startswith('win')
    binary = "tracert" if is_windows else "traceroute"
    if not _has_cmd(binary):
        _print(False, f"{binary}", f"{binary} not found"); return
    try:
        cmd = [binary, "-d", TEST_IP] if is_windows else [binary, "-n", TEST_IP]
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=90)
        ok = (p.returncode in (0,1,2)) and (p.stdout.strip() != "" or p.stderr.strip() != "")
        _print(ok, f"{binary}", f"exit={p.returncode}")
    except Exception as e:
        _print(False, f"{binary}", str(e))

def _test_traceroute_scapy():
    if not HAVE_SCAPY:
        _print(False, "traceroute(scapy)", "scapy unavailable"); return
    try:
        _ = sr1(IP(dst=TEST_IP, ttl=1) / ICMP(), verbose=0, timeout=2)  # one probe
        _print(True, "traceroute(scapy)", "probe sent")
    except Exception as e:
        _print(False, "traceroute(scapy)", str(e))

def main():
    _test_chrome(); _test_brave(); _test_firefox()
    _test_nmap(); _test_testssl_protocols()
    _test_geo_ripeipmap(); _test_geo_ipwhois(); _test_geo_ipinfo()
    _test_traceroute_system(); _test_traceroute_scapy()

if __name__ == "__main__":
    main()
