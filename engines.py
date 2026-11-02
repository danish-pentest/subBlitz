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


class CrtnameEngine(Engine):
    name = "crt.name"
    BASE = "https://crt.name/v1/search?apex={domain}"
    MAX_RESULTS = 10000

    def enumerate(self) -> list[str]:
        text = self._get(self.BASE.format(domain=self.domain))
        if not text:
            return self.subdomains
        for line in text.splitlines()[: self.MAX_RESULTS]:
            self._add(line.strip())
        return self.subdomains


class ScanMalwareEngine(Engine):
    name = "ScanMalware"
    BASE = "https://scanmalware.com/api/v1/ct/dns/{domain}?subdomain_limit=5000"

    def enumerate(self) -> list[str]:
        data = self._get_json(self.BASE.format(domain=self.domain))
        if not data:
            return self.subdomains

        # The API returns a JSON object containing a subdomains array
        subs = data.get("subdomains", [])
        if not isinstance(subs, list):
            self._log("unexpected JSON shape (missing 'subdomains' list)")
            return self.subdomains

        for sub in subs:
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

class SubdomainCenterEngine(Engine):
    name = "SubdomainCenter"
    BASE = "https://api.subdomain.center/?domain={domain}"

    def enumerate(self) -> list[str]:
        data = self._get_json(self.BASE.format(domain=self.domain))
        if not data:
            return self.subdomains

        # API returns a plain JSON array of subdomain strings
        if not isinstance(data, list):
            self._log("unexpected response shape (expected a list)")
            return self.subdomains

        for sub in data:
            if isinstance(sub, str):
                self._add(sub)

        return self.subdomains


class THCEngine(Engine):
    name = "THC"
    BASE = "https://ip.thc.org/sb/{domain}"

    def enumerate(self) -> list[str]:
        text = self._get(self.BASE.format(domain=self.domain))
        if not text:
            return self.subdomains

        # Strip ANSI color codes
        ansi = re.compile(r'\x1b\[[0-9;]*m')
        clean = ansi.sub('', text)

        for line in clean.splitlines():
            line = line.strip()
            # Skip comments, empty lines, and metadata lines
            if not line or line.startswith(";;"):
                continue
            # Skip the bare domain itself (handled by _add)
            self._add(line)

        return self.subdomains

        # The API returns one JSON object per line (JSONL)
        import json as _json
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = _json.loads(line)
            except _json.JSONDecodeError:
                continue

            url = record.get("url")
            if not url:
                continue

            # Extract the hostname and add it
            import urllib.parse as _urlparse
            host = _urlparse.urlparse(url).hostname
            if host:
                self._add(host)

        return self.subdomains






class BlitzCrawlerEngine(Engine):
    name = "BlitzCrawler"

    MAX_PAGES = 150
    MAX_BYTES = 30_000_000
    MAX_DEPTH = 6

    def enumerate(self) -> list[str]:
        from collections import deque
        from html.parser import HTMLParser

        class LinkParser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.links = []

            def handle_starttag(self, tag, attrs):
                for attr, value in attrs:
                    if not value:
                        continue

                    if attr.lower() in (
                        "href", "src", "action", "data", "poster"
                    ):
                        self.links.append(value.strip())

                    elif attr.lower() == "srcset":
                        for item in value.split(","):
                            parts = item.strip().split()
                            if parts:
                                self.links.append(parts[0])

        headers = {
            "User-Agent": "curl/8.5.0",
            "Accept": (
                "text/html,application/xhtml+xml,"
                "application/xml;q=0.9,*/*;q=0.8"
            ),
            "Accept-Language": "en-US,en;q=0.9",
        }

        # Absolute URLs, protocol-relative URLs, and hostname references.
        url_pattern = re.compile(
            r"""(?ix)
            (?:
                https?://
                |
                //
            )
            ([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)
            |
            \b
            (
                (?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+
                [a-z]{2,63}
            )
            \b
            """
        )

        def extract_hosts(text, base_url):
            parser = LinkParser()

            try:
                parser.feed(text)
            except Exception:
                pass

            candidates = list(parser.links)

            for match in url_pattern.finditer(text):
                candidate = match.group(1) or match.group(2)
                if candidate:
                    candidates.append(candidate)

            hosts = set()

            for candidate in candidates:
                candidate = candidate.strip().strip("\"'<>(),;")

                if not candidate or candidate.startswith(
                    ("data:", "javascript:", "mailto:", "tel:", "#")
                ):
                    continue

                try:
                    if candidate.startswith("//"):
                        parsed = urlparse.urlparse("https:" + candidate)
                    elif "://" in candidate:
                        parsed = urlparse.urlparse(candidate)
                    elif "/" in candidate or "?" in candidate or "#" in candidate:
                        parsed = urlparse.urlparse(
                            urlparse.urljoin(base_url, candidate)
                        )
                    else:
                        parsed = urlparse.urlparse("//" + candidate)

                    host = (parsed.hostname or "").lower().rstrip(".")

                    if host and re.fullmatch(r"[a-z0-9.-]+", host):
                        if ".." not in host:
                            hosts.add(host)

                except (ValueError, TypeError):
                    continue

            return hosts

        queue = deque([(f"https://{self.domain}/", 0)])
        visited = set()

        while queue and len(visited) < self.MAX_PAGES:
            url, depth = queue.popleft()

            parsed_url = urlparse.urlparse(url)
            url = urlparse.urlunparse(
                parsed_url._replace(fragment="")
            )

            if url in visited:
                continue

            visited.add(url)

            try:
                with self.session.get(
                    url,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=True,
                    stream=True,
                ) as response:
                    self._log(
                        f"HTTP {response.status_code}: {response.url}"
                    )

                    if response.status_code >= 400:
                        continue

                    content_type = (
                        response.headers.get("Content-Type") or ""
                    ).lower()

                    if content_type and not any(
                        kind in content_type
                        for kind in ("html", "text", "javascript", "json")
                    ):
                        continue

                    chunks = []
                    total = 0

                    for chunk in response.iter_content(8192):
                        if not chunk:
                            continue

                        remaining = self.MAX_BYTES - total

                        if remaining <= 0:
                            break

                        if len(chunk) > remaining:
                            chunks.append(chunk[:remaining])
                            total += remaining
                            break

                        chunks.append(chunk)
                        total += len(chunk)

                    text = b"".join(chunks).decode(
                        response.encoding or "utf-8",
                        errors="replace",
                    )

                    final_url = response.url

            except requests.exceptions.RequestException as exc:
                self._log(
                    f"request failed: {type(exc).__name__}: {exc}"
                )
                continue

            hosts = extract_hosts(text, final_url)

            for host in sorted(hosts):
                self._add(host)

            self._log(
                f"page {len(visited)}: found "
                f"{len(hosts)} candidate hosts"
            )

            if depth >= self.MAX_DEPTH:
                continue

            parser = LinkParser()

            try:
                parser.feed(text)
            except Exception:
                continue

            for link in parser.links:
                absolute = urlparse.urljoin(final_url, link)
                parsed = urlparse.urlparse(absolute)

                if parsed.scheme not in ("http", "https"):
                    continue

                host = (parsed.hostname or "").lower().rstrip(".")

                if not (
                    host == self.domain
                    or host.endswith("." + self.domain)
                ):
                    continue

                if parsed.path.lower().endswith((
                    ".jpg", ".jpeg", ".png", ".gif", ".svg",
                    ".webp", ".ico", ".pdf", ".zip", ".gz",
                    ".mp4", ".mp3", ".woff", ".woff2",
                    ".ttf", ".css", ".map",
                )):
                    continue

                next_url = urlparse.urlunparse(
                    parsed._replace(fragment="")
                )

                if next_url not in visited:
                    queue.append((next_url, depth + 1))

        self._log(f"pages visited: {len(visited)}")
        self._log(f"total subdomains: {len(self.subdomains)}")

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
    "hackertarget":     HackerTargetEngine,
    "rapiddns":         RapidDNSEngine,
    "certspotter":      CertSpotterEngine,
    "urlscan":          URLScanEngine,
    "anubis":           AnubisEngine,
    "domainee":         DomaineeEngine,
    "crt":              CrtShEngine,
    "crtname":          CrtnameEngine,
    "scanmalware":      ScanMalwareEngine,
    "subdomaincenter":  SubdomainCenterEngine,
    "thc":              THCEngine,
    "blitzcrawler":     BlitzCrawlerEngine,
    # ── Keyed (optional) ──
    "virustotal":       VirusTotalEngine,
    "chaos":            ChaosEngine,
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
    "crtname",
    "scanmalware",
    "subdomaincenter",
    "thc",
    "blitzcrawler",

]


def get_engines(selected: Optional[Iterable[str]] = None) -> list[type[Engine]]:
    """
    Return a list of engine classes.

    - selected=None or empty  -> all keyless engines
    - selected=["all"]        -> every registered engine (incl. keyed)
    - selected=["working"]    -> same as default
    - selected=[...]          -> specific engines by name
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
