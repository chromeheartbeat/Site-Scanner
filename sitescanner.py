#!/usr/bin/env python3
# Site-Scanner - Website Vulnerability Assessment Tool.
# Version: 1.1.0 - patched
# Date: Oct 10, 2025 (patched)
# Copyrights © Solution

import requests
import time
import socket
import concurrent.futures
import json
import re
import signal
import sys
import ssl
import logging
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import datetime
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# -------------------------
# Logging
# -------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("site-scanner")

# -------------------------
# HTTP session helper
# -------------------------
def make_session(retries=3, backoff_factor=0.3, timeout=10):
    """
    Create a requests.Session with retries and sensible headers.
    The returned session has a default timeout applied in `session.request`.
    """
    session = requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS'])
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update({
        "User-Agent": "Site-Scanner/1.1.0 (+https://example.com)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    })

    # attach a default timeout property and wrap request to apply it
    session._default_timeout = timeout

    # wrap session.request to always include timeout unless explicitly provided
    orig_request = session.request

    def request_with_timeout(method, url, **kwargs):
        if "timeout" not in kwargs:
            kwargs["timeout"] = session._default_timeout
        return orig_request(method, url, **kwargs)

    session.request = request_with_timeout
    # convenience shorthand
    session.get = lambda url, **kwargs: session.request("GET", url, **kwargs)
    session.post = lambda url, **kwargs: session.request("POST", url, **kwargs)
    return session

# global session used across functions
session = make_session()

# -------------------------
# Utilities & Robust Parsing
# -------------------------
def signal_handler(sig, frame):
    logger.info("Shutting down...")
    time.sleep(1)
    sys.exit(1)

def print_logo():
    try:
        with open("src/logo.txt", "r") as logo_file:
            logo = logo_file.read()
            print(logo)
    except Exception:
        # If no logo file, continue silently
        pass

def get_url():
    while True:
        try:
            url = input('\nEnter URL: ').strip()
            if not url:
                print('\033[31mError:\033[0m URL cannot be empty.')
                continue
            if not url.startswith(('http://', 'https://')):
                print('\033[31mError:\033[0m URL must start with http:// or https://')
                continue
            if url.endswith('/'):
                url = url[:-1]
            return url
        except KeyboardInterrupt:
            print("\n\nShutting down...")
            time.sleep(1)
            sys.exit(0)
        except Exception as e:
            logger.error("An error occurred while reading URL: %s", e)

def load_cms_metadata(json_file):
    with open(json_file, "r") as file:
        data = json.load(file)
    # precompile regex patterns to speed up detection
    for cms, meta in data.items():
        ind = meta.get("identification", {}).get("indicators", [])
        meta.setdefault("identification", {})["_compiled_indicators"] = [re.compile(p, re.I) for p in ind]
        ver = meta.get("version_detection", {}).get("indicators", [])
        meta.setdefault("version_detection", {})["_compiled_indicators"] = [re.compile(p) for p in ver]
    return data

def detect_cms_and_version(url, cms_metadata):
    """
    Return detected_cms (string) and detected_version (string or None).
    Uses session to fetch, handles errors gracefully.
    """
    try:
        r = session.get(url)
        if r.status_code != 200:
            logger.warning("Unable to fetch URL for CMS detection: %s (status %s)", url, r.status_code)
            return "Unknown CMS", None
        html_content = r.text
        detected_cms = "Unknown CMS"
        detected_version = None

        for cms, metadata in cms_metadata.items():
            # identification
            compiled_indicators = metadata.get("identification", {}).get("_compiled_indicators", [])
            found = False
            for patt in compiled_indicators:
                if patt.search(html_content):
                    detected_cms = cms
                    found = True
                    break
            # version detection
            compiled_versions = metadata.get("version_detection", {}).get("_compiled_indicators", [])
            for vpatt in compiled_versions:
                vm = vpatt.search(html_content)
                if vm:
                    # group 1 expected to hold version
                    try:
                        detected_version = vm.group(1)
                    except Exception:
                        detected_version = vm.group(0)
                    break
            if found:
                # don't break immediately; prefer version detection before finalizing if available
                if detected_version:
                    break
                # if no version, still break to report detected cms
                break

        return detected_cms, detected_version
    except requests.RequestException as e:
        logger.error("Request error in detect_cms_and_version: %s", e)
        return "Unknown CMS", None

# -------------------------
# WordPress backup leak parsing (robust)
# -------------------------
def find_wp_config_backup(base_url):
    try:
        wp_config_backup_url = urljoin(base_url, "/wp-config.php-bak")
        response = session.get(wp_config_backup_url)
        if response.status_code == 200 and response.text:
            logger.critical("\n[+] Major Leak Found! wp-config backup exposed: %s\n", wp_config_backup_url)
            wp_config_content = response.text
            creds = parse_wp_config(wp_config_content)
            for k, v in creds.items():
                print(f"{k}: {v}")
            print(f"\nFor more info: {wp_config_backup_url}")
            return creds
        else:
            logger.debug("wp-config backup not found at %s (status %s)", wp_config_backup_url, response.status_code)
    except requests.RequestException as e:
        logger.error("Error fetching URL %s: %s", wp_config_backup_url, e)
    return None

def parse_wp_config(text):
    """
    Use regex to safely extract WP constants. Returns a dict with DB_NAME, DB_USER, DB_PASSWORD, DB_HOST (or None).
    """
    def find_key(key):
        patt = re.compile(r"define\(\s*['\"]" + re.escape(key) + r"['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)", re.I)
        m = patt.search(text)
        return m.group(1) if m else None
    return {
        "DB_NAME": find_key("DB_NAME"),
        "DB_USER": find_key("DB_USER"),
        "DB_PASSWORD": find_key("DB_PASSWORD"),
        "DB_HOST": find_key("DB_HOST")
    }

# -------------------------
# CVE Search (improved: use passed cms param)
# -------------------------
def search_vulnerabilities(cms, version, base_url):
    """
    Search for CVEs on cve.mitre.org by building a query string.
    Note: this is still HTML scraping and brittle; consider using an API for production.
    """
    if not cms or cms == "Unknown CMS":
        return "CMS unknown; skipping CVE lookup."

    if version:
        major_minor_version = ".".join(version.split(".")[:2])
        search_query = f"{cms}+{major_minor_version}"
    else:
        major_minor_version = ""
        search_query = f"{cms}"

    search_url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={search_query}"
    headers = session.headers.copy()

    # special case for Wordpress: check backup leaks
    if cms.lower() == "wordpress":
        find_wp_config_backup(base_url)

    try:
        r = session.get(search_url, headers=headers)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, 'html.parser')
        cve_info = soup.find("div", class_="smaller", style=lambda s: s and "background-color" in s)
        if cve_info:
            b = cve_info.find("b")
            cve_count = b.text.strip() if b else "Unknown"
            return f"\n\033[31m{cve_count}\033[0m CVE Records found for {cms} {major_minor_version}\nSee more at {search_url}"
        else:
            return f"\nNo CVE Records found for {cms} {major_minor_version}."
    except requests.RequestException as e:
        return f"Error fetching CVE page: {str(e)}"

# -------------------------
# Login page detection
# -------------------------
def search_login_variations(cms_name, base_url, cms_metadata):
    cms_info = cms_metadata.get(cms_name, {}) if cms_name else {}
    login_pages = cms_info.get("login_pages", [])
    valid_login_page = None
    for page in login_pages:
        try:
            r = session.get(f"{base_url}{page}")
            if r.status_code == 200:
                valid_login_page = f"{base_url}{page}"
                break
        except requests.RequestException:
            continue
    if valid_login_page:
        print("\n[-] Login page found: " + valid_login_page)
    else:
        print("\n[-] Login page not found")

# -------------------------
# IP & Server info
# -------------------------
def get_ip(url):
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except Exception as e:
        logger.error("Error resolving IP for %s: %s", url, e)
        return "N/A"

def get_server_info(res, url, start_time):
    try:
        response = res
        end_time = time.time()
        ip_address = get_ip(url)
        if response.status_code == 200:
            load_time = end_time - start_time
            server_headers = response.headers
            server = server_headers.get('Server', 'N/A')
            os_hdr = server_headers.get('X-Powered-By', 'N/A')

            print(f"\n\033[31mLoad Time:\033[0m {load_time:.1f} seconds")
            print(f"\033[31mIP Address:\033[0m {ip_address}")
            print(f"\033[31mServer Software:\033[0m {server}")
            print(f"\033[31mServer OS:\033[0m {os_hdr}")
        else:
            print('Failed to fetch URL:', response.status_code)
            time.sleep(1)
            sys.exit(1)
    except requests.exceptions.RequestException as e:
        logger.error("Error in get_server_info: %s", e)

# -------------------------
# Port scanning (kept similar but safer)
# -------------------------
def scan_port(ip, port, timeout=1):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((ip, port))
    except Exception:
        result = 1
    finally:
        sock.close()
    if result == 0:
        return port
    return None

def get_open_ports(ip_address):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=40) as executor:
        future_to_port = {executor.submit(scan_port, ip_address, port): port for port in range(1, 1024)}
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                res = future.result()
                if res:
                    open_ports.append(res)
            except Exception as e:
                logger.debug("Port scan error on %s: %s", port, e)
    return sorted(open_ports)

# -------------------------
# Form extraction & form-driven tests (XSS and SQLi)
# -------------------------
def extract_forms(html, base_url):
    """
    Parse HTML and return a list of forms:
    [{'action': full_action_url, 'method': 'get'|'post', 'inputs': [{'name':..., 'value':...}, ...]}, ...]
    """
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action") or ""
        method = form.get("method", "get").lower()
        inputs = []
        for elem in form.find_all(["input", "textarea", "select"]):
            name = elem.get("name")
            if not name:
                continue
            value = elem.get("value") or ""
            inputs.append({"name": name, "value": value})
        full_action = urljoin(base_url, action)
        forms.append({"action": full_action, "method": method, "inputs": inputs})
    return forms

def submit_form(form, payloads, check_for_payload=True):
    """
    Submits payload(s) to a form. If check_for_payload=True, looks for payload presence in response text.
    Returns list of findings (tuples): (payload, action_url, method, found_boolean)
    """
    findings = []
    for payload in payloads:
        data = {}
        for inp in form["inputs"]:
            # Use existing value for hidden fields; inject payload into common text inputs
            in_name = inp["name"]
            default = inp.get("value", "")
            # choose which inputs to inject into: text-like fields (heuristic)
            data[in_name] = payload if any(k in in_name.lower() for k in ("search","q","query","name","email","comment","msg","message","body","text")) else default
        try:
            if form["method"] == "post":
                r = session.post(form["action"], data=data)
            else:
                r = session.get(form["action"], params=data)
            found = False
            if check_for_payload and payload in (r.text or ""):
                found = True
            findings.append((payload, form["action"], form["method"], found))
        except requests.RequestException as e:
            logger.debug("Form submit error to %s: %s", form["action"], e)
            findings.append((payload, form["action"], form["method"], False))
    return findings

def check_xss_vulnerability(target_url):
    headers = session.headers.copy()
    try:
        r = session.get(target_url, headers=headers)
    except requests.RequestException as e:
        logger.error("Failed to fetch the URL for XSS test. %s", e)
        return
    if r.status_code != 200:
        logger.warning("Failed to fetch the URL. Status Code: %s", r.status_code)
        return

    html = r.text
    forms = extract_forms(html, target_url)
    payloads = [
        "<script>alert('XSS')</script>",
        "\"'><img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>"
    ]
    found_any = False

    # test forms
    for form in forms:
        findings = submit_form(form, payloads)
        for payload, action, method, found in findings:
            if found:
                found_any = True
                print("Potential XSS vulnerability found in form:", action)
                print("Payload:", payload)

    # fallback: test URL parameter injection
    for payload in payloads:
        test_url = target_url + "?q=" + payload
        try:
            r2 = session.get(test_url)
            if payload in (r2.text or ""):
                found_any = True
                print("Potential XSS vulnerability found in URL parameter:", test_url)
                print("Payload:", payload)
        except requests.RequestException:
            continue

    if not found_any:
        print("No XSS Vulnerabilities found.")

# -------------------------
# SQL Injection detection (form-driven + pattern checks)
# -------------------------
def generate_test_urls(domain, patterns_file):
    test_urls = []
    try:
        with open(patterns_file, 'r') as file:
            patterns = json.load(file)
    except Exception as e:
        logger.error("Error loading patterns file %s: %s", patterns_file, e)
        return test_urls

    for pattern in patterns:
        full_url = urljoin(domain, pattern)
        test_urls.append(full_url)
    return test_urls

def sql_injection_vulnerability(target_url):
    # First, load page forms and test forms for SQLi payloads
    try:
        r = session.get(target_url)
    except requests.RequestException as e:
        logger.error("Failed to fetch URL for SQLi tests: %s", e)
        return

    payloads_error_based = [
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR 'x'='x",
        "'; --",
    ]
    payloads_time_based = [
        "' OR SLEEP(5)--",
        "\" OR SLEEP(5)--",
        "'; IF(1=1, SLEEP(5), 0)--"
    ]
    html = r.text or ""
    forms = extract_forms(html, target_url)
    # test forms
    for form in forms:
        findings = submit_form(form, payloads_error_based + payloads_time_based, check_for_payload=False)
        # Check results for error patterns or time delay
        for payload, action, method, _ in findings:
            try:
                # send single payload and evaluate response and timing
                before = time.time()
                if method == "post":
                    resp = session.post(action, data={inp['name']: payload for inp in form['inputs']})
                else:
                    resp = session.get(action, params={inp['name']: payload for inp in form['inputs']})
                after = time.time()
                elapsed = after - before
                # look for common SQL error messages
                error_signatures = ["sql syntax", "mysql", "syntax error", "odbc", "sqlstate", "database error", "query failed"]
                resp_text = (resp.text or "").lower()
                if any(sig in resp_text for sig in error_signatures):
                    print("SQL injection error-based vulnerability suspected at:", action)
                    print("Payload:", payload)
                    return
                # time-based heuristics
                if elapsed > 4:
                    print("SQL injection time-based vulnerability suspected at:", action)
                    print("Payload (time-based):", payload)
                    print(f"Response took {elapsed:.1f}s which indicates a possible time-based injection.")
                    return
            except requests.RequestException:
                continue

    # If no forms detected or nothing found, fall back to parameter-based testing using patterns.json
    test_urls = generate_test_urls(target_url, "src/patterns.json")
    for test_url in test_urls:
        for payload in payloads_error_based + payloads_time_based:
            full_url = f"{test_url}{payload}" if '?' in test_url else f"{test_url}?param={payload}"
            try:
                before = time.time()
                resp = session.get(full_url)
                after = time.time()
                elapsed = after - before
                text = (resp.text or "").lower()
                if resp.status_code == 200 and ("error" in text or "syntax error" in text):
                    print("SQL injection vulnerability found in:", test_url)
                    print("Payload:", payload)
                    return
                if elapsed > 4:
                    print("Possible time-based SQL injection at:", full_url)
                    print("Payload:", payload)
                    return
            except requests.RequestException:
                continue

    print("No SQL injection vulnerabilities found (heuristic-based checks).")

# -------------------------
# robots.txt, directory & subdomain search
# -------------------------
def robots_txt(url):
    try:
        parsed_url = urlparse(url)
        robots_url = f"{parsed_url.scheme}://{parsed_url.netloc}/robots.txt"
        response = session.get(robots_url)
        if response.status_code == 200:
            print("\n[+] Fetching robots.txt...\n")
            for line in response.text.split('\n'):
                if line.strip().startswith('Disallow:'):
                    print(line.strip())
        else:
            print("\nFailed to fetch robots.txt. Status Code:", response.status_code)
    except Exception as e:
        logger.error("Error fetching robots.txt: %s", e)

def refactor_url(url):
    parsed_url = urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    if url == base_url:
        return url
    print(f"Specefied URL: {url}\n")
    print(f"1. Stripped URL: {base_url}")
    print("2. Enter new URL")
    print(f"3. Continue with: {url}")
    user = input("\nEnter your selection: ")
    if user == '1':
        url = base_url
    if user == '2':
        url = get_url()
    return url

def check_directory(url, directory):
    full_url = url.rstrip('/') + '/' + directory
    try:
        response = session.get(full_url, timeout=5)
        if response.status_code in [200, 204, 301, 302, 307, 401]:
            return (full_url, response.status_code)
    except requests.RequestException:
        pass

def search_directories(url, wordlist_path):
    try:
        with open(wordlist_path, 'r') as f:
            directories = f.read().splitlines()
    except Exception as e:
        logger.error("Error reading directory wordlist %s: %s", wordlist_path, e)
        return

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_directory = {executor.submit(check_directory, url, directory): directory for directory in directories}
        for future in concurrent.futures.as_completed(future_to_directory):
            result = future.result()
            if result:
                print(f"[+] {result[0]} (Status: {result[1]})")
    return

# -------------------------
# Security headers check
# -------------------------
def check_security_headers(url):
    headers_to_check = [
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "X-XSS-Protection",
        "Referrer-Policy",
        "Feature-Policy",
        "Expect-CT",
        "Content-Encoding",
        "Permissions-Policy",
        "Cache-Control"
    ]
    try:
        response = session.get(url)
    except requests.RequestException as e:
        logger.error("Error fetching URL for headers: %s", e)
        return
    missing_headers = []
    for header in headers_to_check:
        if header not in response.headers:
            missing_headers.append(f"[+] {header}")

    if missing_headers:
        missing_headers_str = '\n'.join(missing_headers)
        print(f"Missing security headers for {url}:\n{missing_headers_str}")
    else:
        print(f"All security headers are present for {url}")

# -------------------------
# Subdomain search
# -------------------------
def check_subdomain(scheme, base_url, subdomain):
    full_url = f"{scheme}://{subdomain}.{base_url}"
    try:
        response = session.get(full_url, timeout=5)
        if response.status_code == 200:
            return full_url, response.status_code
    except requests.RequestException:
        return None

def search_subdomains(url, wordlist_path):
    parsed_url = urlparse(url)
    scheme = parsed_url.scheme
    base_url = parsed_url.netloc

    try:
        with open(wordlist_path, 'r') as f:
            subdomains = f.read().splitlines()
    except Exception as e:
        logger.error("Error reading subdomain wordlist %s: %s", wordlist_path, e)
        return

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_subdomain = {executor.submit(check_subdomain, scheme, base_url, subdomain): subdomain for subdomain in subdomains}
        for future in concurrent.futures.as_completed(future_to_subdomain):
            result = future.result()
            if result:
                print(f"[+] {result[0]} (Status: {result[1]})")

# -------------------------
# SSL certificate checking (safer)
# -------------------------
def check_ssl_certificate(url):
    if not url.startswith("https://"):
        print("URL must start with https://")
        return
    host = url.replace("https://", "").split("/")[0]
    try:
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(), server_hostname=host) as sock:
            sock.settimeout(5)
            sock.connect((host, 443))
            ssl_info = sock.getpeercert()

            issuer = ssl_info.get('issuer', [])
            issuer_dict = {}
            for part in issuer:
                for k, v in part:
                    issuer_dict[k] = v

            not_after = ssl_info.get('notAfter')
            if not_after:
                try:
                    expiration_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                except Exception:
                    # try alternative format
                    expiration_date = not_after
                current_date = datetime.datetime.now()
                try:
                    days_until_expire = (expiration_date - current_date).days
                except Exception:
                    days_until_expire = "N/A"
            else:
                expiration_date = "N/A"
                days_until_expire = "N/A"

            print(f"[+] Issuer Info: {issuer_dict}")
            print(f"[+] Expiration Date: {expiration_date}")
            print(f"[+] Days until Expiry: {days_until_expire}")
    except ssl.SSLError as e:
        logger.error("SSL error for %s: %s", host, e)
    except Exception as e:
        logger.error("Error checking SSL/TLS certificate for %s: %s", host, e)

# -------------------------
# Menu & main loop
# -------------------------
def print_menu():
    print("\n\033[31m1.CMS Detection & Vulnerability Report\033[0m")
    print("\033[31m2.Admin Panel Auth Detection\033[0m")
    print("\033[31m3.Robots.txt Disallowed\033[0m")
    print("\033[31m4.Check Security Headers\033[0m")
    print("\033[31m5.Validate SSL Certificate\033[0m")
    print("\033[31m6.Open Ports Scan\033[0m - Heavy Op")
    print("\033[31m7.Scanning Directories\033[0m")
    print("\033[31m8.Scanning Subdomains\033[0m")
    print("\033[31m9.SQL Injection Detection\033[0m")
    print("\033[31m10.XSS Detection\033[0m")
    print("\033[31m0.Exit\033[0m")

if __name__ == '__main__':
    print_logo()
    url = get_url()

    print("\nFetching URL...")
    start_time = time.time()
    try:
        response = session.get(url)
    except requests.RequestException as e:
        logger.error("Failed to fetch initial URL: %s", e)
        sys.exit(1)

    get_server_info(response, url, start_time)

    # Load cms metadata
    try:
        cms_metadata = load_cms_metadata("src/cms_metadata.json")
    except Exception as e:
        logger.error("Could not load cms_metadata.json: %s", e)
        cms_metadata = {}

    cms_name = "Unknown CMS"
    cms_version = None

    while True:
        signal.signal(signal.SIGINT, signal_handler)
        print_menu()
        user = input("\033[32mSelect Task:\033[0m")
        # Switch case tasks
        if user == "1":
            print(f"\n[+] Detecting CMS...")
            cms_name, cms_version = detect_cms_and_version(url, cms_metadata)
            print("\nDetected CMS:", cms_name)
            if cms_version:
                print("Detected Version:", cms_version)
            if cms_name != "Unknown CMS":
                print("\n[+] Searching Vulnerabilities")
                print(search_vulnerabilities(cms_name, cms_version, url))

        if user == "2":
            print("\n[+] Detecting Admin Panel Auth...")
            search_login_variations(cms_name, url, cms_metadata)

        if user == "3":
            robots_txt(url)

        if user == "4":
            print("\n[+] Checking Security Headers...\n")
            check_security_headers(url)

        if user == "5":
            print(url)
            print("\n[+] Checking SSL Certificate...\n")
            check_ssl_certificate(url)

        if user == "6":
            print("\n[+] Scanning Ports...\n")
            ip_addr = get_ip(url)
            if ip_addr != "N/A":
                print(get_open_ports(ip_addr))
            else:
                print("Could not resolve IP for port scan.")

        if user == "7":
            print("\n[+] Scanning Directories...\n")
            wordlist_path = "src/dir.txt"
            url = refactor_url(url)
            search_directories(url, wordlist_path)

        if user == "8":
            print("\n[+] Scanning Subdomains...\n")
            wordlist_path = "src/sub.txt"
            url = refactor_url(url)
            search_subdomains(url, wordlist_path)

        if user == "9":
            print("\n[+] Looking for SQL Injection Vulnerabilities...")
            sql_injection_vulnerability(url)

        if user == "10":
            print("\n[+] Looking for XSS Vulnerabilities...")
            check_xss_vulnerability(url)

        if user == "0":
            print("\nShutting down...")
            time.sleep(1)
            sys.exit(1)
