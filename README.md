# Gamma: Web Measurement Toolkit

Gamma is a toolkit for measuring web. It can load pages in browsers, record HAR and network requests, save full HTML and resources, geolocate participating IPs using APIs, and run network diagnostics (traceroute, ping, nmap, testssl).

---

## What’s inside

- `setup.sh` – Install Dependencies (browsers, drivers via Selenium Manager, CLI tools, Python deps, Scapy).
- `test.py` – smoke tests to verify browsers and tools work. It does not write files.
- `main.py` – the main tool (page loads + captures → URL/IP extraction → geolocation → diagnostics). Saves artifacts.

---

## Quick start

```bash
# 1) Install Dependencies
bash setup.sh

# 2) Optional: provide an ipinfo token (see below)
echo "<YOUR_TOKEN>" > ipinfo.token

# 3) Sanity check the environment (no files written)
python3 test.py

# 4) Run the main tool
python3 main.py
```

---

## 1) `setup.sh` — Install Dependencies 

This script:

- Installs system packages: Chrome/Firefox/Brave, `nmap`, `traceroute`, `iputils-ping`, `openssl`, and `testssl.sh`.
- Installs Python packages (system-wide): `selenium`, `selenium-wire`, `requests`, `pandas`, `scapy`.

> If Scapy probes fail, either run `main.py` with sudo or ensure the capability grant succeeded.

---

## 2) `test.py` — smoke tests

`test.py` verifies that the stack is usable.

### What it tests

- **Browsers** (headless): Chrome, Brave, Firefox open `https://example.org`, confirm page title and  selenium-wire captured network requests.
- **CLI tools**:
  - `nmap` — ping scan
  - `testssl` — protocols only (TLS versions listing)
- **Geolocation**:
  - **RIPE IPmap** (HTTP response OK)
  - **ipwho.is** (`curl http://ipwho.is/1.1.1.1`)
  - **ipinfo** (only if token file exists)
- **Traceroute**:
  - System traceroute (`traceroute -n` on Linux/macOS or `tracert -d` on Windows)
  - Scapy single ICMP probe (skips if permissions aren’t available)

### Example output

```
[OK] Chrome: title_ok=True, requests_captured=True
[OK] Brave: title_ok=True, requests_captured=True
[OK] Firefox: title_ok=True, requests_captured=True
[OK] nmap: exit=0
[OK] testssl(protocols): exit=0
[OK] geo:ripeipmap: exit=0
[OK] geo:ipwho.is: exit=0
[SKIP] geo:ipinfo token not found; skipping ipinfo
[OK] traceroute(system): exit=0
[OK] traceroute(scapy): probe sent
```

> If you see `[SKIP] geo:ipinfo…`, create a token file first.

### `ipinfo.token`

If you want **ipinfo** lookups in `main.py`:

```bash
echo "<YOUR_IPINFO_TOKEN>" > ipinfo.token
# or set a custom path:
export IPINFO_TOKEN_FILE=/path/to/ipinfo.token
```

If the token is missing, Gamma prints `"[ipinfo] token not found; skipping ipinfo"` and continues with RIPE IPmap + ipwho.is.

---

## 3) `main.py` — the main tool

### What it does (per site)

1. **Launch a browser** (Chrome/Brave/Firefox, headless) via Selenium + selenium-wire.
2. **Load the page**, wait a few seconds.
3. **Save artifacts**:
   - Full HTML
   - HAR (exported by selenium-wire)
   - JSON log of all requests
   - Downloaded CSS/JS/images referenced in the observed traffic
4. **Extract base URLs** from HAR and **derive IPs** for each:
   - **Configurable** (see `IP_SOURCE` below):
     - From HAR entries’ `"serverIPAddress"`
     - From DNS (resolver)
     - Union of both
5. **Geolocate** each IP via three providers (each in its own directory):
   - RIPE IPmap
   - ipwho.is (curl)
   - ipinfo (only if token present)
6. **Diagnose each IP** (in parallel threads, capped):
   - System traceroute (or Windows `tracert`) → JSON (parsed hops)
   - Scapy traceroute → JSON
   - `ping` (4 probes)
   - `nmap` (`-Pn -n -p 80,443 --reason`)
   - `testssl.sh --protocols --ip=<IP> <domain>` → raw TXT output
   - Server certificate (PEM), via TLS handshake or `openssl s_client`

**Nmap** and **Testssl.sh** can be customized for different probes/tasks.

Throughout, Gamma prints live progress:
- “sites: N done / remaining”
- “IPs: M done / remaining”
- Per-IP probe status lines as they complete

### Key configuration knobs

Open `main.py` and tweak:

```python
# Parallel page crawls
NUM_INSTANCES = 2          # total site processes running in parallel

# Browser selection
BROWSER = 'chrome'         # 'chrome' | 'brave' | 'firefox'

# Wait time after initial page load (sec)
WAIT_SECONDS = 12

# Input websites
WEBSITES = [
    'https://example.org',
    'https://www.python.org',
]

# Where to store output
OUT_DIR = 'capture/'

# Per-IP probe concurrency (threads inside each process)
PROBE_THREADS = 8          # auto-reduced when fewer tasks are pending

# How to derive IPs for each base URL
#   'har'  -> from HAR 'serverIPAddress' (no DNS lookups)
#   'dns'  -> DNS resolution only
#   'both' -> union of HAR + DNS
IP_SOURCE = 'har'
```

### Output layout

```
capture/
  <domain>/
    html/page.html
    har/network.har
    network/requests.json
    resources/{css,js,img}/...
    diagnostics/<ip>/
      traceroute_system.json
      traceroute_scapy.json
      ping.txt
      nmap.txt
      testssl_protocols.txt
      certificate.pem
url_ip_geo/
  <domain>/
    url_ip_map.json
  <domain>/geo/
    ripeipmap/<ip>.json
    ipwhois/<ip>.json
    ipinfo/<ip>.json  (only if token is present)
```
