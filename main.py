#!/usr/bin/env python3
import os
import re
import json
import time
import ssl
import socket
import hashlib
import pathlib
import subprocess
import multiprocessing as mp
import platform
from datetime import datetime, date
from urllib.parse import urlsplit, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

from seleniumwire import webdriver
from scapy.all import IP, ICMP, sr1  # Scapy may need root

# ======================== small utils ========================

def ensure_dir(path: str) -> str:
    pathlib.Path(path).mkdir(parents=True, exist_ok=True)
    return path

def safe_name(s: str) -> str:
    s = unquote(s or "")
    s = re.sub(r'[^A-Za-z0-9._-]+', '_', s).strip('._')
    return s or 'file'

def content_category(content_type: str) -> str:
    ct = (content_type or '').lower()
    if 'text/css' in ct: return 'css'
    if 'javascript' in ct or 'ecmascript' in ct or ct.endswith('/js'): return 'js'
    if ct.startswith('image/'): return 'img'
    return ''

def unique_path(base_dir: str, filename: str, ext_hint: str = '') -> str:
    root, ext = os.path.splitext(filename)
    if not ext and ext_hint:
        ext = ext_hint
    digest = hashlib.sha1(filename.encode('utf-8')).hexdigest()[:8]
    return os.path.join(base_dir, f"{root}-{digest}{ext}")

def base_url_from(url: str) -> str:
    try:
        u = urlsplit(url)
        if not u.scheme or not u.netloc:
            return ''
        return f"{u.scheme}://{u.netloc}/"
    except Exception:
        return ''

def resolve_ips(host: str) -> list:
    out = set()
    try:
        for fam in (socket.AF_INET, socket.AF_INET6):
            try:
                res = socket.getaddrinfo(host, None, fam, socket.SOCK_STREAM)
                for r in res:
                    out.add(r[4][0])
            except Exception:
                pass
    except Exception:
        pass
    return sorted(out)

def save_text(path: str, content: str):
    ensure_dir(os.path.dirname(path))
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)

def _json_default(o):
    if isinstance(o, (datetime, date)):
        return o.isoformat()
    if isinstance(o, (bytes, bytearray)):
        return o.decode('utf-8', 'ignore')
    return str(o)

def save_json(path: str, obj):
    ensure_dir(os.path.dirname(path))
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(obj, f, indent=2, default=_json_default)

def run_cmd(cmd: list, timeout: int = 120) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout ({timeout}s)"
    except Exception as e:
        return 1, "", str(e)

# ======================== HAR tolerant save/load ========================

def save_har(har_obj, har_path: str):
    ensure_dir(os.path.dirname(har_path))
    if isinstance(har_obj, str):
        with open(har_path, 'w', encoding='utf-8') as f:
            f.write(har_obj)
    else:
        with open(har_path, 'w', encoding='utf-8') as f:
            json.dump(har_obj, f, indent=2, default=_json_default)

def load_har_any(path: str):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            text = f.read()
    except Exception:
        return None
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return None
    if isinstance(obj, str):
        try:
            obj = json.loads(obj)
        except json.JSONDecodeError:
            pass
    return obj

# ======================== driver factory ========================

def get_driver(browser: str = 'chrome', headless: bool = True):
    browser = (browser or '').strip().lower()
    sw_opts = {'enable_har': True, 'verify_ssl': False}

    if browser in ('chrome', 'brave'):
        opts = webdriver.ChromeOptions()
        if headless: opts.add_argument('--headless=new')
        opts.add_argument('--no-sandbox'); opts.add_argument('--disable-dev-shm-usage')
        if browser == 'brave':
            for cand in (os.getenv('BRAVE_PATH'), '/usr/bin/brave-browser', '/usr/bin/brave-browser-stable',
                         '/Applications/Brave Browser.app/Contents/MacOS/Brave Browser'):
                if cand and os.path.exists(cand):
                    opts.binary_location = cand; break
        return webdriver.Chrome(options=opts, seleniumwire_options=sw_opts)

    if browser == 'firefox':
        fopts = webdriver.FirefoxOptions()
        if headless: fopts.add_argument('-headless')
        return webdriver.Firefox(options=fopts, seleniumwire_options=sw_opts)

    raise ValueError("Unsupported browser. Use: 'chrome' | 'brave' | 'firefox'.")

# ======================== crawl + save ========================

def crawl_page(url: str, browser: str, out_dir: str, wait_seconds: int, status_cb=lambda msg: None):
    domain = safe_name(urlsplit(url).netloc or 'site')
    base = ensure_dir(os.path.join(out_dir, domain))
    html_dir = ensure_dir(os.path.join(base, 'html'))
    har_dir  = ensure_dir(os.path.join(base, 'har'))
    net_dir  = ensure_dir(os.path.join(base, 'network'))
    res_css_dir = ensure_dir(os.path.join(base, 'resources', 'css'))
    res_js_dir  = ensure_dir(os.path.join(base, 'resources', 'js'))
    res_img_dir = ensure_dir(os.path.join(base, 'resources', 'img'))

    artifacts = {'page_html':'','har_file':'','requests_json':'','downloaded_resources':[]}

    driver = None
    try:
        status_cb(f"[{domain}] launching {browser}")
        driver = get_driver(browser=browser, headless=True)
        driver.scopes = ['.*']
        driver.get(url); time.sleep(wait_seconds)

        html_path = os.path.join(html_dir, 'page.html')
        with open(html_path, 'w', encoding='utf-8') as f: f.write(driver.page_source)
        artifacts['page_html'] = html_path
        status_cb(f"[{domain}] saved HTML")

        har_path = os.path.join(har_dir, 'network.har')
        saved_har = False
        export = getattr(driver, 'export_har', None)
        if callable(export):
            export(har_path); saved_har = True
        else:
            har_obj = getattr(driver, 'har', None)
            if har_obj is not None:
                save_har(har_obj, har_path); saved_har = True
        if saved_har:
            artifacts['har_file'] = har_path
            status_cb(f"[{domain}] saved HAR")

        req_log = []
        for req in driver.requests:
            ts = getattr(req, 'date', None)
            if isinstance(ts, (datetime, date)): ts = ts.isoformat()
            entry = {
                'url': req.url,
                'method': req.method,
                'headers': {str(k): str(v) for k, v in dict(req.headers or {}).items()},
                'timestamp': ts,
                'response': None
            }
            if req.response:
                entry['response'] = {
                    'status_code': req.response.status_code,
                    'headers': {str(k): str(v) for k, v in dict(req.response.headers or {}).items()},
                }
            req_log.append(entry)
        req_json_path = os.path.join(net_dir, 'requests.json')
        save_json(req_json_path, req_log)
        artifacts['requests_json'] = req_json_path
        status_cb(f"[{domain}] saved request log ({len(req_log)} entries)")

        import requests
        saved = 0
        for req in driver.requests:
            if not req.response: continue
            ctype = req.response.headers.get('Content-Type', '')
            cat = content_category(ctype)
            if not cat: continue
            path = urlsplit(req.url).path
            fname = safe_name(os.path.basename(path)) or cat
            ext_hint = ''
            if cat == 'css' and not fname.endswith('.css'): ext_hint = '.css'
            elif cat == 'js' and not re.search(r'\.(js|mjs)$', fname, re.I): ext_hint = '.js'
            elif cat == 'img' and not re.search(r'\.(png|jpg|jpeg|gif|webp|svg)$', fname, re.I): ext_hint = ''
            target_dir = res_css_dir if cat=='css' else res_js_dir if cat=='js' else res_img_dir
            target_path = unique_path(target_dir, fname, ext_hint=ext_hint)
            try:
                r = requests.get(req.url, timeout=30, stream=True); r.raise_for_status()
                with open(target_path, 'wb') as outf:
                    for chunk in r.iter_content(8192):
                        if chunk: outf.write(chunk)
                artifacts['downloaded_resources'].append(target_path); saved += 1
            except Exception:
                pass
        status_cb(f"[{domain}] saved {saved} resources")

        return artifacts
    finally:
        if driver is not None:
            try: driver.quit()
            except Exception: pass

# ======================== HAR → URLs ========================

def read_har_urls(har_path: str) -> set:
    urls = set()
    har = load_har_any(har_path)
    if not isinstance(har, dict): return urls
    entries = []
    if 'log' in har and isinstance(har['log'], dict) and 'entries' in har['log']:
        entries = har['log']['entries']
    elif 'entries' in har:
        entries = har['entries']
    for e in entries or []:
        try:
            req = e.get('request', {})
            u = req.get('url', '')
            b = base_url_from(u)
            if b: urls.add(b)
        except Exception:
            pass
    return urls

# ======================== Geolocation (3 providers, 3 dirs) ========================

def geodir(base_out_dir: str, domain: str, provider: str) -> str:
    return ensure_dir(os.path.join(base_out_dir, domain, "geo", provider))

def geo_ip_ripeipmap(ip: str, token: str = None) -> dict:
    import requests
    headers = {}
    if token: headers["Authorization"] = f"Key {token}"
    try:
        r = requests.get(f"https://ipmap-api.ripe.net/v1/locate/{ip}", headers=headers, timeout=20)
        return {"status": r.status_code, "body": (r.json() if "application/json" in r.headers.get("Content-Type","") else r.text)}
    except Exception as e:
        return {"error": str(e)}

def geo_ip_ipwhois_via_curl(ip: str) -> dict:
    code, out, err = run_cmd(["curl", "-sS", "--max-time", "20", f"http://ipwho.is/{ip}"], timeout=25)
    if code == 0:
        try: return json.loads(out)
        except Exception: return {"raw": out}
    return {"error": err or f"curl exit {code}"}

def geo_ip_ipinfo(ip: str, token: str) -> dict:
    import requests
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", headers=headers, timeout=15)
        if r.status_code == 200: return r.json()
        return {"status": r.status_code, "body": r.text}
    except Exception as e:
        return {"error": str(e)}

def save_geo_records(out_dir: str, domain: str, ip: str, ripe_obj: dict, whois_obj: dict, ipinfo_obj: dict or None, status_cb=lambda m: None):
    ripe_dir  = geodir(out_dir, domain, "ripeipmap")
    whois_dir = geodir(out_dir, domain, "ipwhois")
    ipinfo_dir= geodir(out_dir, domain, "ipinfo")
    save_json(os.path.join(ripe_dir,  f"{ip}.json"), ripe_obj)
    save_json(os.path.join(whois_dir, f"{ip}.json"), whois_obj)
    if ipinfo_obj is not None:
        save_json(os.path.join(ipinfo_dir, f"{ip}.json"), ipinfo_obj)
    status_cb(f"[{domain}][{ip}] saved geolocation (ripeipmap/ipwhois{'/ipinfo' if ipinfo_obj else ''})")

# ======================== Traceroute parsing & diagnostics ========================

def parse_traceroute_system(output: str) -> list:
    """Parse `traceroute -n` (Unix)."""
    hops = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.lower().startswith('traceroute'): continue
        parts = line.split()
        if not parts: continue
        try: hop_no = int(parts[0])
        except ValueError: continue
        ip = '*'; rtts = []
        for tok in parts[1:]:
            if tok == '*': ip = '*'; break
            if re.match(r'^[0-9a-f:.]+$', tok, re.I):
                ip = tok; break
        for tok in parts:
            if tok.endswith('ms'):
                try: rtts.append(float(tok.replace('ms','')))
                except: pass
        hops.append({"hop": hop_no, "ip": ip, "rtt_ms": rtts})
    return hops

def parse_tracert_windows(output: str) -> list:
    """Parse `tracert -d` (Windows)."""
    hops = []
    for line in output.splitlines():
        line = line.strip()
        # lines look like: "  1     2 ms     1 ms     1 ms  192.168.1.1"
        m = re.match(r'^(\d+)\s+(.*)$', line)
        if not m: continue
        hop = int(m.group(1))
        # pick first IPv4/IPv6 or '*' if all timeouts
        ip = '*'
        for tok in line.split():
            if tok == '*': ip = '*'
            if re.match(r'^[0-9a-f:.]+$', tok, re.I): ip = tok; break
        # collect RTTs
        rtts = []
        for tok in line.split():
            if tok.endswith('ms'):
                try: rtts.append(float(tok.replace('ms','')))
                except: pass
        hops.append({"hop": hop, "ip": ip, "rtt_ms": rtts})
    return hops

def save_certificate(host: str, ip: str, out_path: str):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((ip, 443), timeout=20) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(True)
                pem = ssl.DER_cert_to_PEM_cert(der)
                save_text(out_path, pem)
                return True
    except Exception:
        code, out, err = run_cmd(["openssl", "s_client", "-showcerts", "-servername", host, "-connect", f"{ip}:443"], timeout=40)
        if code == 0 and "BEGIN CERTIFICATE" in out:
            save_text(out_path, out); return True
    return False

# ======================== Diagnose (parallel probe threads) ========================

PROBE_THREADS = 8  # cap for per-IP probe concurrency

def diagnose_ip(domain: str, url: str, ip: str, out_base: str, status_cb=lambda m: None):
    """
    Runs probes in parallel threads:
      - traceroute (system or Windows 'tracert') -> JSON
      - traceroute (scapy) -> JSON
      - ping -> text
      - nmap -> text
      - testssl --protocols (TLS versions only) -> tls_versions.json
      - server certificate -> certificate.pem
    """
    ddir = ensure_dir(os.path.join(out_base, domain, "diagnostics", ip))
    host = urlsplit(url).hostname or domain
    is_windows = platform.system().lower().startswith('win')

    def task_traceroute_system():
        if is_windows:
            status_cb(f"[{domain}][{ip}] tracert (Windows)")
            code, out, err = run_cmd(["tracert", "-d", ip], timeout=180)
            obj = {"command":["tracert","-d",ip], "exit_code": code, "raw": out or err,
                   "hops": parse_tracert_windows(out or "")}
        else:
            status_cb(f"[{domain}][{ip}] traceroute (system)")
            code, out, err = run_cmd(["traceroute", "-n", ip], timeout=120)
            obj = {"command":["traceroute","-n",ip], "exit_code": code, "raw": out or err,
                   "hops": parse_traceroute_system(out or "")}
        save_json(os.path.join(ddir, "traceroute_system.json"), obj)
        return "traceroute_system"

    def task_traceroute_scapy():
        status_cb(f"[{domain}][{ip}] traceroute (scapy)")
        scapy_hops = []
        try:
            for ttl in range(1, 31):
                pkt = IP(dst=ip, ttl=ttl) / ICMP()
                start = time.time()
                reply = sr1(pkt, verbose=0, timeout=2)
                rtt = (time.time() - start) * 1000.0
                if reply is None:
                    scapy_hops.append({"hop": ttl, "ip": "*", "rtt_ms": rtt, "status": "timeout"})
                else:
                    scapy_hops.append({"hop": ttl, "ip": reply.src, "rtt_ms": rtt,
                                       "status": "dest" if getattr(reply, "type", None) == 0 else "intermediate"})
                    if getattr(reply, "type", None) == 0: break
        except Exception as e:
            scapy_hops.append({"error": f"{e}"})
        save_json(os.path.join(ddir, "traceroute_scapy.json"), {"hops": scapy_hops})
        return "traceroute_scapy"

    def task_ping():
        status_cb(f"[{domain}][{ip}] ping")
        code, out, err = run_cmd(["ping", "-c", "4", "-n", ip] if not is_windows else ["ping", "-n", "4", ip], timeout=30)
        save_text(os.path.join(ddir, "ping.txt"), out or err)
        return "ping"

    def task_nmap():
        status_cb(f"[{domain}][{ip}] nmap")
        code, out, err = run_cmd(["nmap", "-Pn", "-n", "-p", "80,443", "--reason", ip], timeout=150)
        save_text(os.path.join(ddir, "nmap.txt"), out or err)
        return "nmap"

    
    def task_testssl_tls():
        # Protocols-only; save raw output to TXT (no parsing)
        status_cb(f"[{domain}][{ip}] testssl --protocols")
        binary = shutil.which("testssl") or shutil.which("testssl.sh")
        out_path = os.path.join(ddir, "testssl_protocols.txt")
        if binary:
            # NOTE: required form: testssl.sh --protocols --ip=<IP> <domain>
            code, out, err = run_cmd([binary, "--protocols", f"--ip={ip}", host], timeout=240)
            # Save stdout (or stderr if empty) verbatim
            save_text(out_path, (out or err) or f"(no output; exit={code})")
        else:
            save_text(out_path, "testssl(.sh) not found")
        return "testssl_protocols"


    def task_certificate():
        status_cb(f"[{domain}][{ip}] saving certificate")
        ok = save_certificate(host, ip, os.path.join(ddir, "certificate.pem"))
        if not ok:
            save_text(os.path.join(ddir, "certificate.pem"), "failed to fetch certificate")
        return "certificate"

    # Collect tasks
    import shutil  # used in testssl task
    tasks = [task_traceroute_system, task_traceroute_scapy, task_ping, task_nmap, task_testssl_tls, task_certificate]
    max_workers = min(PROBE_THREADS, len(tasks))
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = [ex.submit(t) for t in tasks]
        for _ in as_completed(futs):
            pass  # status already printed by tasks

# ======================== Orchestration (site/IP counters) ========================

def write_url_ip_map(out_dir: str, domain: str, mapping: dict, status_cb=lambda m: None):
    path = ensure_dir(os.path.join(out_dir, domain))
    outf = os.path.join(path, "url_ip_map.json")
    save_json(outf, mapping)
    status_cb(f"[{domain}] wrote URL→IP map to {outf}")
    return outf

def status_printer(total_sites, done_sites, total_ips, done_ips, lock, msg):
    with lock:
        print(f"{msg} | sites: {done_sites.value}/{total_sites} done, {total_sites - done_sites.value} remaining"
              f" | IPs: {done_ips.value}/{total_ips.value} done, {max(0, total_ips.value - done_ips.value)} remaining")

def process_url(url: str, browser: str, out_dir: str, wait_seconds: int,
                total_sites, done_sites, total_ips, done_ips, lock):
    """
    Crawl a single URL, extract base URLs from HAR, build URL→IPs according to IP_SOURCE,
    save a convenience map, run geolocation and diagnostics per IP, and print site/IP progress.

    Depends on globals/helpers:
      - IP_SOURCE ('har' | 'dns' | 'both')
      - crawl_page, read_har_urls, read_har_url_ip_map, resolve_ips,
        write_url_ip_map, geo_ip_ripeipmap, geo_ip_ipwhois_via_curl,
        geo_ip_ipinfo, save_geo_records, diagnose_ip, status_printer
    """
    domain = safe_name(urlsplit(url).netloc or 'site')

    def cb(m):
        status_printer(total_sites, done_sites, total_ips, done_ips, lock, m)

    try:
        cb(f"[{domain}] starting")
        artifacts = crawl_page(
            url,
            browser=browser,
            out_dir=out_dir,
            wait_seconds=wait_seconds,
            status_cb=cb
        )

        # ---- Extract base URLs from HAR ----
        har_path = artifacts.get('har_file')
        urls = set()
        if har_path and os.path.isfile(har_path):
            urls = read_har_urls(har_path)
            cb(f"[{domain}] HAR URLs: {len(urls)}")

        # ---- Build URL → IPs per IP_SOURCE ('har' | 'dns' | 'both') ----
        url_ip_map = {}
        newly_found_ips = 0

        # choice = (IP_SOURCE or 'dns').lower()
        choice = 'har'

        if choice == 'har' and har_path and os.path.isfile(har_path):
            # Take IPs directly from HAR 'serverIPAddress'
            url_ip_map = read_har_url_ip_map(har_path)

        elif choice == 'both' and har_path and os.path.isfile(har_path):
            # Union of HAR server IPs + DNS
            har_map = read_har_url_ip_map(har_path)
            # start with HAR entries
            combined = {k: set(v) for k, v in har_map.items()}
            # also include any base URLs seen from HAR parsing (even if no serverIPAddress)
            all_urls = set(urls) | set(har_map.keys())
            for burl in sorted(all_urls):
                host = urlsplit(burl).hostname or ''
                dns_ips = set(resolve_ips(host)) if host else set()
                combined.setdefault(burl, set()).update(dns_ips)
            url_ip_map = {k: sorted(v) for k, v in combined.items()}

        else:
            # Default DNS-only path
            for burl in sorted(urls):
                host = urlsplit(burl).hostname or ''
                ips = resolve_ips(host) if host else []
                url_ip_map[burl] = ips

        newly_found_ips = sum(len(ips) for ips in url_ip_map.values())

        if urls:
            write_url_ip_map(os.path.join(out_dir, "url_ip_geo"), domain, url_ip_map, status_cb=cb)

        with lock:
            total_ips.value += newly_found_ips
        cb(f"[{domain}] discovered {newly_found_ips} IPs (global total now {total_ips.value})")

        # ---- Optional ipinfo token from file ----
        ipinfo_token = None
        token_file = os.getenv("IPINFO_TOKEN_FILE", "ipinfo.token")
        if os.path.isfile(token_file):
            try:
                with open(token_file, "r", encoding="utf-8") as tf:
                    ipinfo_token = tf.read().strip()
            except Exception:
                ipinfo_token = None
        else:
            print("[ipinfo] token not found; skipping ipinfo")

        # ---- Geolocation + diagnostics per IP ----
        for burl, ips in url_ip_map.items():
            for ip in ips:
                ripe_obj  = geo_ip_ripeipmap(ip)
                whois_obj = geo_ip_ipwhois_via_curl(ip)
                ipinfo_obj = geo_ip_ipinfo(ip, token=ipinfo_token) if ipinfo_token else None

                save_geo_records(
                    os.path.join(out_dir, "url_ip_geo"),
                    domain,
                    ip,
                    ripe_obj,
                    whois_obj,
                    ipinfo_obj,
                    status_cb=cb
                )

                diagnose_ip(domain, burl, ip, out_dir, status_cb=cb)

                with lock:
                    done_ips.value += 1
                status_printer(
                    total_sites, done_sites, total_ips, done_ips, lock,
                    f"[{domain}][{ip}] IP processed"
                )

        cb(f"[{domain}] complete")

    except Exception as e:
        cb(f"[{domain}] ERROR: {e}")

    finally:
        with lock:
            done_sites.value += 1
        status_printer(
            total_sites, done_sites, total_ips, done_ips, lock,
            f"[status] site processed"
        )
def read_har_url_ip_map(har_path: str) -> dict:
    """
    Build { base_url: [unique IPs] } from HAR using entry['serverIPAddress'].
    Tolerant to variants like '_serverIPAddress'. Returns lists (JSON-friendly).
    """
    mapping = {}
    har = load_har_any(har_path)
    if not isinstance(har, dict):
        return mapping

    # Get entries from standard HAR shape
    entries = []
    if 'log' in har and isinstance(har['log'], dict) and 'entries' in har['log']:
        entries = har['log']['entries']
    elif 'entries' in har:
        entries = har['entries']

    for e in entries or []:
        try:
            req = e.get('request', {})
            url = req.get('url', '')
            base = base_url_from(url)
            if not base:
                continue
            ip = e.get('serverIPAddress')
            if not ip:
                continue
            mapping.setdefault(base, set()).add(str(ip))
        except Exception:
            # skip malformed entries
            pass

    # Convert sets → sorted lists
    return {k: sorted(v) for k, v in mapping.items()}


def _chunk_list(seq, n):
    n = max(1, int(n))
    k, m = divmod(len(seq), n)
    chunks = []
    start = 0
    for i in range(n):
        end = start + k + (1 if i < m else 0)
        if start < end: chunks.append(seq[start:end])
        start = end
    return chunks

def _process_chunk(urls, browser, out_dir, wait_seconds, total_sites, done_sites, total_ips, done_ips, lock):
    for u in urls:
        process_url(u, browser, out_dir, wait_seconds, total_sites, done_sites, total_ips, done_ips, lock)

# ======================== main ========================

if __name__ == '__main__':
    NUM_INSTANCES = 2
    BROWSER = 'chrome'                # 'chrome' | 'brave' | 'firefox'
    OUT_DIR = 'capture/'
    WAIT_SECONDS = 10
    WEBSITES = ['https://example.org','https://www.python.org']

    total_sites = len(WEBSITES)
    manager = mp.Manager()
    done_sites = manager.Value('i', 0)
    total_ips  = manager.Value('i', 0)
    done_ips   = manager.Value('i', 0)
    lock = manager.Lock()

    print(f"[init] sites: {total_sites}, instances: {NUM_INSTANCES}")

    chunks = _chunk_list(WEBSITES, NUM_INSTANCES)
    procs = []
    for chunk in chunks:
        p = mp.Process(target=_process_chunk,
                       args=(chunk, BROWSER, OUT_DIR, WAIT_SECONDS, total_sites, done_sites, total_ips, done_ips, lock))
        p.start(); procs.append(p)

    try:
        while any(p.is_alive() for p in procs):
            status_printer(total_sites, done_sites, total_ips, done_ips, lock, "[progress]")
            time.sleep(10)
    finally:
        for p in procs: p.join()

    status_printer(total_sites, done_sites, total_ips, done_ips, lock, "[done]")

