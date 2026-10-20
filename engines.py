#!/usr/bin/env python3
"""
subBlitz - Enumeration engines.
Each engine queries a public data source and yields subdomains.

Working keyless: HackerTarget, RapidDNS, CertSpotter, URLScan, Anubis, Domainee, crt.sh
Keyed: VirusTotal (VIRUSTOTAL_API_KEY), Chaos (PDCP_API_KEY)
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.parse as urlparse
from abc import ABC, abstractmethod
from typing import Iterable, Optional

import requests


# ── Base engine ──────────────────────────────────────────────
class Engine(ABC):
    """Base class for every enumeration source."""

    name: str = "base"
    timeout: int = 25
    debug: bool = False

    HEADERS = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/122.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
    }

    def __init__(self, domain: str, on_found=None, debug: bool = False):
        parsed = urlparse.urlparse(domain if "://" in domain else f"http://{domain}")
        self.domain: str = (parsed.netloc or parsed.path).lower().strip(".")
        if not self.domain or "." not in self.domain:
            raise ValueError(f"invalid domain: {self.domain!r}")
        self.subdomains: list[str] = []
        self._seen: set[str] = set()
        self.session = requests.Session()
        self.session.headers.update(self.HEADERS)
        self.on_found = on_found
        self.debug = debug or Engine.debug

    # ── logging ─────────────────────────────────────────────
    def _log(self, msg: str) -> None:
        if self.debug:
            try:
                from ui import console
                console.print(f"  [muted]   ↳ {self.name}: {msg}[/muted]")
            except Exception:
                print(f"   ↳ {self.name}: {msg}")

    # ── subdomain bookkeeping ──────────────────────────────
    def _add(self, subdomain: str) -> bool:
        if not isinstance(subdomain, str):
            return False
        subdomain = subdomain.strip().lower().lstrip("*.").rstrip(".")
        if not subdomain or subdomain in self._seen:
            return False
        if subdomain == self.domain:
            return False
        if not subdomain.endswith("." + self.domain):
            return False
        self._seen.add(subdomain)
        self.subdomains.append(subdomain)
        if self.on_found:
            try:
                self.on_found(self.name, subdomain)
            except Exception as e:
                self._log(f"on_found callback failed: {type(e).__name__}: {e}")
        return True

    # ── HTTP helpers ───────────────────────────────────────
    def _get(self, url: str, **kw) -> Optional[str]:
        try:
            r = self.session.get(url, timeout=self.timeout, **kw)
            if r.status_code == 429:
                self._log("HTTP 429 (rate-limited)")
                return None
            if r.status_code >= 400:
                self._log(f"HTTP {r.status_code}")
                return None
            return r.text
        except requests.exceptions.Timeout:
            self._log("timeout")
        except requests.exceptions.ConnectionError:
            self._log("connection refused")
        except Exception as e:
            self._log(f"{type(e).__name__}: {e}")
        return None

    def _get_json(self, url: str, **kw):
        text = self._get(url, **kw)
        if not text:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            self._log("response was not JSON")
            return None

    @abstractmethod
    def enumerate(self) -> list[str]:
        ...


# ── WORKING KEYLESS ENGINES ─────────────────────────────────

class HackerTargetEngine(Engine):
    name = "HackerTarget"
    BASE = "https://api.hackertarget.com/hostsearch/?q={domain}"

    def enumerate(self) -> list[str]:
        text = self._get(self.BASE.format(domain=self.domain))
        if not text:
            return self.subdomains
        low = text.lower()
        if "api count exceeded" in low or low.startswith("error"):
            self._log("rate-limited or invalid host")
            return self.subdomains
        for line in text.splitlines():
            if "," in line:
                self._add(line.split(",", 1)[0])
        return self.subdomains


class RapidDNSEngine(Engine):
    name = "RapidDNS"
    BASE = "https://rapiddns.io/subdomain/{domain}?full=1"

    def enumerate(self) -> list[str]:
        html = self._get(self.BASE.format(domain=self.domain))
        if not html:
            return self.subdomains
        pattern = re.compile(
            r'<td>([a-zA-Z0-9_\-\.]+\.' + re.escape(self.domain) + r')</td>',
            re.IGNORECASE,
        )
        for m in pattern.finditer(html):
            self._add(m.group(1))
        return self.subdomains


class CertSpotterEngine(Engine):
    name = "CertSpotter"
    BASE = (
        "https://api.certspotter.com/v1/issuances"
        "?domain={domain}&include_subdomains=true&expand=dns_names"
    )

    def enumerate(self) -> list[str]:
        data = self._get_json(self.BASE.format(domain=self.domain))
        if not isinstance(data, list):
            return self.subdomains
        for entry in data:
            for name in entry.get("dns_names", []) or []:
                self._add(name)
        return self.subdomains


class URLScanEngine(Engine):
    name = "URLScan"
    BASE = "https://urlscan.io/api/v1/search/?q=domain%3A{domain}&size=10000"

    def enumerate(self) -> list[str]:
        data = self._get_json(self.BASE.format(domain=self.domain))
        if not data:
            return self.subdomains
        for r in data.get("results", []):
            task = r.get("task", {}) or {}
            host = (task.get("domain") or "").lower()
            if host:
                self._add(host)
            page = r.get("page", {}) or {}
            for key in ("domain", "apexDomain"):
                host = (page.get(key) or "").lower()
                if host:
                    self._add(host)
        return self.subdomains


class AnubisEngine(Engine):
    name = "Anubis"
    BASE = "https://anubisdb.com/subdomains/{domain}"
    MAX_RESULTS = 10000

    def enumerate(self) -> list[str]:
        text = self._get(self.BASE.format(domain=self.domain))
        if not text:
            return self.subdomains
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return self.subdomains
        if not isinstance(data, list):
            return self.subdomains
        for sub in data[: self.MAX_RESULTS]:
            if isinstance(sub, str):
                self._add(sub)
        return self.subdomains


class DomaineeEngine(Engine):
    name = "Domainee"
    BASE = "https://api.domainee.dev/v1/tools/subdomain-finder?domain={domain}"

    def enumerate(self) -> list[str]:
        data = self._get_json(self.BASE.format(domain=self.domain))
        if not data or not data.get("ok"):
            return self.subdomains
        for entry in (data.get("data") or {}).get("subdomains", []):
            host = entry.get("host", "")
            if host:
                self._add(host)
        return self.subdomains


class CrtShEngine(Engine):
    name = "crt.sh"
    BASE = "https://crt.sh/?q=%25.{domain}&output=json"

    def enumerate(self) -> list[str]:
        for attempt in range(2):
            text = self._get(self.BASE.format(domain=self.domain))
            if text and text.strip().startswith("["):
                try:
                    data = json.loads(text)
                except json.JSONDecodeError:
                    self._log(f"attempt {attempt + 1}: invalid JSON")
                    time.sleep(3)
                    continue
                for entry in data:
                    for name in entry.get("name_value", "").splitlines():
                        name = name.strip().lower().lstrip("*.")
                        if "@" in name:
                            name = name.split("@", 1)[1]
                        self._add(name)
                return self.subdomains
            self._log(f"attempt {attempt + 1}: no valid response")
            time.sleep(3)
        return self.subdomains


# ── KEYED ENGINES ───────────────────────────────────────────

class VirusTotalEngine(Engine):
    """VirusTotal - free API key: 4 req/min, 500/day."""
    name = "VirusTotal"
    BASE = "https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"

    def enumerate(self) -> list[str]:
        key = os.environ.get("VIRUSTOTAL_API_KEY")
        if not key:
            self._log("no API key (set VIRUSTOTAL_API_KEY)")
            return self.subdomains

        url = self.BASE.format(domain=self.domain)
        headers = {"x-apikey": key}
        pages = 0

        while url and pages < 25:
            try:
                r = self.session.get(url, headers=headers, timeout=self.timeout)
            except Exception as e:
                self._log(f"{e}")
                break
            if r.status_code == 401:
                self._log("invalid API key")
                break
            if r.status_code == 429:
                self._log("rate-limited, sleeping 20s")
                time.sleep(20)
                continue
            if r.status_code != 200:
                self._log(f"HTTP {r.status_code}")
                break
            data = r.json()
            for item in data.get("data", []):
                if item.get("type") == "domain":
                    self._add(item.get("id", ""))
            url = data.get("links", {}).get("next", "")
            pages += 1
            time.sleep(0.3)
        return self.subdomains


class ChaosEngine(Engine):
    """
    Chaos (ProjectDiscovery) - public bug bounty subdomain dataset.
    Free API key: cloud.projectdiscovery.io
    Env var: PDCP_API_KEY (or CHAOS_KEY)
    """
    name = "Chaos"
    BASE = "https://chaos.projectdiscovery.io/api/v1/domains/{domain}/subdomains"

    def enumerate(self) -> list[str]:
        key = os.environ.get("PDCP_API_KEY") or os.environ.get("CHAOS_KEY")
        if not key:
            self._log("no API key (set PDCP_API_KEY or CHAOS_KEY)")
            return self.subdomains

        headers = {"Authorization": key}
        url = self.BASE.format(domain=self.domain)

        try:
            r = self.session.get(url, headers=headers, timeout=self.timeout)
        except Exception as e:
            self._log(f"{e}")
            return self.subdomains

        if r.status_code == 401:
            self._log("invalid API key")
            return self.subdomains
        if r.status_code == 404:
            self._log("domain not in Chaos dataset")
            return self.subdomains
        if r.status_code != 200:
            self._log(f"HTTP {r.status_code}")
            return self.subdomains

        try:
            data = r.json()
        except json.JSONDecodeError:
            self._log("response was not JSON")
            return self.subdomains

        subs = data.get("subdomains", []) if isinstance(data, dict) else data
        if not isinstance(subs, list):
            return self.subdomains

        for sub in subs:
            if isinstance(sub, str):
                if "." not in sub:
                    sub = f"{sub}.{self.domain}"
                self._add(sub)

        return self.subdomains


# ── Registry ─────────────────────────────────────────────────
ALL_ENGINES: dict[str, type[Engine]] = {
    # ── Working keyless (default) ──
    "hackertarget": HackerTargetEngine,
    "rapiddns":     RapidDNSEngine,
    "certspotter":  CertSpotterEngine,
    "urlscan":      URLScanEngine,
    "anubis":       AnubisEngine,
    "domainee":     DomaineeEngine,
    "crt":          CrtShEngine,

    # ── Keyed (optional) ──
    "virustotal":   VirusTotalEngine,
    "chaos":        ChaosEngine,
}

# Default set — all keyless engines
WORKING_KEYLESS = [
    "hackertarget",
    "rapiddns",
    "certspotter",
    "urlscan",
    "anubis",
    "domainee",
    "crt",
]


def get_engines(selected: Optional[Iterable[str]] = None) -> list[type[Engine]]:
    """
    Return a list of engine classes.

    - selected=None or empty  -> all keyless engines
    - selected=["all"]        -> every registered engine (incl. keyed)
    - selected=["working"]    -> same as default
    - selected=[...]          -> specific engines by name.
    """
    if not selected:
        return [ALL_ENGINES[k] for k in WORKING_KEYLESS]

    out: list[type[Engine]] = []
    for key in selected:
        key = (key or "").strip().lower()
        if key == "all":
            return list(ALL_ENGINES.values())
        if key == "working":
            return [ALL_ENGINES[k] for k in WORKING_KEYLESS]
        if key in ALL_ENGINES:
            out.append(ALL_ENGINES[key])

    return out or [ALL_ENGINES[k] for k in WORKING_KEYLESS]
