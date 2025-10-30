# 🚨 Site-Scanner — Website Vulnerability Assessment Tool

![Site-Scanner](https://img.shields.io/badge/Site--Scanner-v1.1.0-brightgreen?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

---

> **Site-Scanner** is a fast, pragmatic, and extensible website vulnerability assessment toolkit focused on common web weaknesses (CMS detection, header checks, XSS/SQLi heuristics, directory & subdomain discovery, SSL checks and safer port scanning).  
> Built for pen-testers, devops, and security-minded engineers who want a reliable CLI scanner with sensible defaults.

---

## 🎯 Highlights (Why use this)
- ✅ Clean, modular Python 3 code with retries and sensible timeouts  
- ✅ CMS & version detection (pluggable JSON metadata)  
- ✅ XSS & SQLi form-driven heuristics (includes time-based checks)  
- ✅ Directory and subdomain enumeration (threaded)  
- ✅ Security headers & SSL certificate inspection  
- ✅ Lightweight port scanner for initial surface discovery  
- ✅ Designed to be production-hardened (safer defaults & error handling)

---

## 🧾 Table of Contents
- [Demo screenshot](#-demo)
- [Quick Start](#-quick-start)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Usage](#-usage)
- [Configuration & Data Files](#-configuration--data-files)
- [How it works (internals)](#-how-it-works-internals)
- [Best Practices & Safety](#-best-practices--safety)
- [Contributing](#-contributing)
- [License](#-license)
- [Changelog](#-changelog)

---

## 🖼 Demo

```
$ python3 main.py
Fetching URL...
Load Time: 0.6 seconds
IP Address: 93.184.216.34
Server Software: nginx/1.18.0
Server OS: N/A

1.CMS Detection & Vulnerability Report
2.Admin Panel Auth Detection
3.Robots.txt Disallowed
...
Select Task:
```

> Use the menu to run targeted checks. Each check prints concise findings and suggestions.

---

## ⚡ Quick Start

```bash
# Clone
git clone https://github.com/chromeheartbeat/site-scanner.git
cd site-scanner

# Create venv & install
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run
python3 main.py
```

---

## 🧰 Requirements
- Python 3.9+
- pip packages (see `requirements.txt`):
  - requests
  - beautifulsoup4
  - urllib3
  - (optional) apscheduler for scheduled tasks
- Network access to the target(s) you own or are authorized to test

---

## 🔧 Installation (detailed)
1. Create and activate a virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Populate `src/` data files (samples included):
   - `src/cms_metadata.json` — CMS signatures & version regex (precompiled on load)
   - `src/dir.txt` — directory wordlist for enumeration
   - `src/sub.txt` — subdomain wordlist
   - `src/patterns.json` — URL patterns for SQLi heuristics

**Tip:** Keep your wordlists tuned to the target scope (large lists are slower but broader).

---

## ▶️ Usage & Menu Overview

When you start `main.py`, you'll be prompted for a URL (must start with `http://` or `https://`). Example:

```
Enter URL: https://example.com
```

Menu options (brief):
- **1. CMS Detection & Vulnerability Report** — Detects CMS & queries CVE listings (MITRE scraping fallback).
- **2. Admin Panel Auth Detection** — Checks common admin login paths from `cms_metadata.json`.
- **3. Robots.txt Disallowed** — Prints `Disallow` entries found.
- **4. Check Security Headers** — Checks for missing HTTP security headers.
- **5. Validate SSL Certificate** — Fetches certificate issuer and expiration details.
- **6. Open Ports Scan** — Scans ports 1–1023 (threaded) — *heavy operation*.
- **7. Scanning Directories** — Uses `src/dir.txt` to find existing directories.
- **8. Scanning Subdomains** — Uses `src/sub.txt` to find subdomains (threaded).
- **9. SQL Injection Detection** — Form-driven + pattern-based heuristics (error & time-based).
- **10. XSS Detection** — Form-driven & URL parameter reflection tests.
- **0. Exit** — Quit the program.

---

## 🗂 Configuration & Data Files
- `src/cms_metadata.json` — JSON file containing identification indicators and version detection regex. Keep this updated with new signatures.
- `src/dir.txt` — Directory wordlist (one per line).
- `src/sub.txt` — Subdomain partials (one per line).
- `src/patterns.json` — URL path patterns used for SQLi fallback testing.

---

## 🔍 How it works (internals)
- Uses a persistent `requests.Session` with an HTTPAdapter + Retry policy and a default timeout to avoid hanging.
- `cms_metadata.json` is loaded and regex patterns are **precompiled** to speed up detection.
- Form extraction uses BeautifulSoup to normalize `input`, `textarea`, and `select` elements; forms are submitted with safe heuristics.
- SQLi checks use:
  - Error-based payloads (detect SQL errors in responses),
  - Time-based payloads (detect delayed responses > 4s).
- XSS detection:
  - Injects several payloads into forms and URL parameters, checking for reflection.
- Port scans and directory/subdomain scans are threaded to speed up enumeration.

---

## ⚠️ Safety, Ethics & Legal
**IMPORTANT** — Use Site-Scanner only on assets you own or for which you have explicit, written authorization. Unauthorized scanning, enumeration, or exploitation may be illegal and unethical.

By using this tool you confirm you have permission to test the target(s).

---

## 🛡 Security Best Practices
- Run from a controlled network (VPN/isolated host) when appropriate.
- Do **NOT** run destructive payloads or full exploitation routines from this repository.
- Log findings responsibly and disclose issues privately to the target's owner/operator or follow a coordinated disclosure process.

---

## 🧪 Testing & Validation
- Basic unit/functional tests: add tests for `extract_forms`, `parse_wp_config`, and `generate_test_urls`.
- CI suggestion: run `pytest` on PRs and run flake8/black for linting and formatting.

---

## 🤝 Contributing
Contributions are welcome. Please:
1. Fork the repo
2. Create a feature branch (`git checkout -b feat/awesome`)
3. Open a Pull Request with clear motivation and tests

When contributing signature or detection rules:
- Add tests or sample HTML snippets demonstrating detection
- Keep regexes focused to reduce false positives

---

## 📬 Contact & Author
**Author:** Solution  
**Repo:** `https://github.com/chromeheartbeat`  
(Replace contact info in `README` with your preferred email/handle if you want employers to contact you)

---

## 📝 Sample `requirements.txt`
```
requests>=2.28
beautifulsoup4>=4.12
urllib3>=1.26
```

---

## 🧾 License
This project is released under the **MIT License**. See `LICENSE` for details.

---

## 🧭 Changelog (selected)
- **v1.1.0 (2025-10-10)** — Patched: safer defaults, improved retry/backoff, precompiled CMS regex, better SSL parsing.
- **v1.0.0** — Initial public release.

---

## 🙌 Acknowledgements
- Thanks to the open-source security community and contributors who keep detection signatures up to date.

---

## 🔎 Final Notes (for hiring / portfolio)
Add the following to your GitHub repo to impress recruiters:
- A short demo GIF showing the scanner in action (menu selection + a couple of detections).
- `EXAMPLES.md` with real-world sample outputs (redacted) and how to interpret them.
- `SECURITY.md` with responsible disclosure instructions.
