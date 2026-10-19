#!/usr/bin/env python3
"""
     subBlitz— Modern subdomain enumeration for Python 3.
────────────────────────────────────────────────────────────────────
                 ⚠  FOR AUTHORIZED USE ONLY
  Do not use this tool against domains you do not own or have
  written permission to test. Misuse is your responsibility.

  Author : Danish-Pentest  (github.com/danish-pentest)
  Version: 1.0 (first release)

  Pros:
    + Free, keyless engines out of the box
    + Fast multithreaded enumeration + optional port scan
  Cons:
    − No warranty; misuse is your responsibility
    − Relies on third-party APIs that may rate-limit or block
────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import argparse
import concurrent.futures
import re
import socket
import sys
import time
import urllib.parse as urlparse

from ui import (
    console, show_banner, section, info, success, warn, error,
    engine_status, subdomain_found, summary_table,
)
from engines import ALL_ENGINES, Engine, get_engines
from scanner import run_portscan
from bruteforce import bruteforce


VERSION = "1.0"
DOMAIN_RE = re.compile(
    r"^(?:https?://)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)


# ── CLI ──────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="subBlitz",
        description="subBlitz — fast multi-source subdomain enumeration.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  subBlitz -d example.com                 # all keyless engines\n"
            "  subBlitz -d example.com -e crt          # crt.sh only\n"
            "  subBlitz -d example.com -e all          # every registered engine\n"
            "  subBlitz -d example.com -b              # bruteforce only\n"
            "  subBlitz -d example.com -p 80,443       # scan apex only\n"
            "  subBlitz -d example.com -e crt -b -p 80 # crt + bruteforce + scan\n"
        ),
    )
    p.add_argument("-d", "--domain", required=True, help="Target domain")
    p.add_argument(
        "-e", "--engines",
        required=False,
        default=None,
        metavar="LIST",
        help="Comma-separated engine list, or 'all'. "
             f"Available: {', '.join(ALL_ENGINES)}. "
             "Omit -e to run all keyless engines (unless -b/-p is used).",
    )
    p.add_argument("-b", "--bruteforce", action="store_true",
                   help="Enable DNS bruteforce")
    p.add_argument("-p", "--ports",
                   help="Comma-separated TCP ports to scan on findings")
    p.add_argument("-t", "--threads", type=int, default=30,
                   help="Thread count for bruteforce (default: 30)")
    p.add_argument("-o", "--output", help="Save results to a text file")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="Suppress realtime subdomain output")
    p.add_argument("-v", "--version", action="version",
                   version=f"subBlitz {VERSION}")
    return p


# ── Orchestration ────────────────────────────────────────────
def enumerate_domain(
    domain: str,
    engine_classes: list[type[Engine]],
    quiet: bool = False,
) -> tuple[set[str], dict[str, int]]:
    """Run all engines in parallel; return (subdomains, engine_counts)."""
    engine_counts: dict[str, int] = {}
    all_found: set[str] = set()

    def on_found(engine_name: str, subdomain: str) -> None:
        if not quiet:
            subdomain_found(engine_name, subdomain)

    def run_engine(cls: type[Engine]) -> tuple[str, set[str]]:
        try:
            eng = cls(domain, on_found=on_found)
            found = eng.enumerate()
        except Exception as e:
            name = getattr(cls, "name", cls.__name__)
            if not quiet:
                warn(f"Engine {name} crashed: {type(e).__name__}: {e}")
            return name, set()
        return eng.name, set(found)

    section("Enumerating")
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max(1, len(engine_classes))
    ) as pool:
        futures = {pool.submit(run_engine, c): c for c in engine_classes}
        for fut in concurrent.futures.as_completed(futures):
            name, found = fut.result()
            engine_counts[name] = len(found)
            all_found |= found
            status = "ok" if found else "empty"
            engine_status(name, status)

    return all_found, engine_counts


def resolve_target(domain: str) -> list[str]:
    """Return the apex domain if it resolves, else empty list."""
    try:
        socket.gethostbyname(domain)
        return [domain]
    except OSError:
        return []


def save_results(path: str, subdomains: list[str]) -> None:
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(subdomains) + "\n")
        success(f"Results saved to [bold]{path}[/bold]")
    except OSError as e:
        error(f"Could not write {path}: {e}")


# ── Engine selection ─────────────────────────────────────────
def pick_engine_classes(raw: str | None) -> list[type[Engine]] | None:
    """
    Resolve the -e argument to a list of engine classes.

    raw is None      -> caller decides (see main)
    raw == "all"     -> every registered engine (keyless + keyed)
    raw == "x,y,z"   -> named engines only
    """
    if raw is None:
        return None

    if raw.strip().lower() == "all":
        return get_engines(["all"])

    selected = [e.strip() for e in raw.split(",") if e.strip()]
    unknown = [e for e in selected if e.lower() not in ALL_ENGINES]
    if unknown:
        warn(f"Unknown engines ignored: {', '.join(unknown)}")

    classes = get_engines(selected)
    return classes or None


# ── Entry point ──────────────────────────────────────────────
def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    show_banner(VERSION)

    raw = args.domain.strip()
    if not DOMAIN_RE.match(raw):
        error(f"Invalid domain: [bold]{raw}[/bold]")
        return 1

    parsed = urlparse.urlparse(raw if "://" in raw else f"http://{raw}")
    domain = (parsed.netloc or parsed.path).lower().strip(".")

    info(f"Target: [bold accent]{domain}[/bold accent]")

    want_brute = bool(args.bruteforce)
    want_scan  = bool(args.ports)
    explicit_e = args.engines is not None

    if explicit_e:
        engine_classes = pick_engine_classes(args.engines)
        if not engine_classes:
            error("No valid engines selected.")
            return 1
    elif want_brute or want_scan:
        engine_classes = None
    else:
        engine_classes = get_engines()  # keyless default

    if engine_classes:
        info(f"Engines: [engine]{', '.join(c.name for c in engine_classes)}[/engine]")
    else:
        info("Engines: [muted]skipped (use -e to enable)[/muted]")

    started = time.time()
    subdomains: set[str] = set()
    counts: dict[str, int] = {}

    # ── Passive enumeration ──────────────────────────────────
    if engine_classes:
        subdomains, counts = enumerate_domain(
            domain, engine_classes, quiet=args.quiet,
        )
    elif want_scan and not want_brute:
        # Pure -p run: seed the scan with the apex if it resolves.
        apex_hosts = resolve_target(domain)
        if apex_hosts:
            subdomains = set(apex_hosts)
            if not args.quiet:
                subdomain_found("target", domain)

    # ── Bruteforce (only if -b passed) ───────────────────────
    if want_brute:
        section("DNS Bruteforce")
        info("Running DNS bruteforce — this may take a while…")

        def on_subblitz_found(engine_name: str, subdomain: str) -> None:
            if not args.quiet:
                subdomain_found(engine_name, subdomain)

        try:
            bf = bruteforce(
                domain,
                threads=args.threads,
                known=subdomains,
                verbose=not args.quiet,
                on_found=on_subblitz_found,
            )
        except KeyboardInterrupt:
            warn("Bruteforce interrupted — keeping partial results")
            bf = set()

        new = bf - subdomains
        subdomains |= bf
        counts["subBlitz"] = len(bf)
        success(
            f"Bruteforce found {len(bf)} subdomain(s) "
            f"({len(new)} not seen by engines)"
        )

    elapsed = time.time() - started

    # ── Summary ──────────────────────────────────────────────
    ordered = sorted(subdomains)
    summary_table(ordered, counts)
    info(f"Finished in [bold]{elapsed:.2f}s[/bold]")

    if args.output and ordered:
        save_results(args.output, ordered)

    # ── Port scan ────────────────────────────────────────────
    if want_scan:
        ports: list[int] = []
        for p in args.ports.split(","):
            try:
                port = int(p.strip())
                if 1 <= port <= 65535:
                    ports.append(port)
                else:
                    warn(f"Ignoring out-of-range port: {p}")
            except ValueError:
                warn(f"Ignoring invalid port: {p}")

        if ports:
            if not ordered:
                warn("No hosts to scan — nothing was found and the "
                     "target did not resolve.")
            else:
                section(f"Port Scan ({len(ports)} ports)")
                try:
                    run_portscan(ordered, ports)
                except KeyboardInterrupt:
                    warn("Port scan interrupted")

    console.print()
    success("[bold]Done.[/bold]")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        console.print()
        warn("Interrupted by user.")
        sys.exit(130)
