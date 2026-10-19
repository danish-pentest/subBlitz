#!/usr/bin/env python3

from __future__ import annotations

import ipaddress
import os
import random
import threading
import uuid

from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterable

import dns.exception
import dns.resolver

from rich.progress import (
    Progress,
    BarColumn,
    TextColumn,
    TimeRemainingColumn,
    MofNCompleteColumn,
)


DEFAULT_RESOLVERS = [
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220",
]

QUERY_TYPES = ("A", "CNAME", "AAAA", "TXT", "MX", "NS")

WILDCARD_PROBES = 4
WILDCARD_THRESHOLD = 2

DNS_TIMEOUT = 2.0
DNS_LIFETIME = 4.0
MAX_THREADS = 100
BATCH_SIZE = 500


def _log(msg: str, verbose: bool) -> None:
    if not verbose:
        return

    try:
        from ui import console
        console.print(f"  [muted]   ↳ subBlitz: {msg}[/muted]")
    except Exception:
        print(f"   ↳ subBlitz: {msg}")


def _find(paths: Iterable[str]) -> str | None:
    for path in paths:
        if os.path.isfile(path):
            return path
    return None


def _read_lines(path: str) -> list[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [
                line.strip()
                for line in f
                if line.strip()
                and not line.lstrip().startswith("#")
            ]
    except OSError:
        return []


def _normalize_domain(domain: str) -> str:
    """Normalize a domain and reject invalid DNS labels."""
    domain = domain.strip().lower().rstrip(".")

    if not domain or len(domain) > 253:
        raise ValueError("Invalid domain length")

    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Invalid internationalized domain") from exc

    for label in domain.split("."):
        if (
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(c.isalnum() or c == "-" for c in label)
        ):
            raise ValueError(f"Invalid DNS domain: {domain}")

    return domain


def _normalize_nameservers(values: Iterable[str]) -> list[str]:
    """Keep unique, valid nameserver IP addresses."""
    result = []

    for value in values:
        try:
            address = str(ipaddress.ip_address(value.strip()))
        except ValueError:
            continue

        if address not in result:
            result.append(address)

    return result


def _make_resolver(nameserver: str) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [nameserver]
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_LIFETIME
    resolver.retry_servfail = False
    return resolver


def _discover_authoritative(
    domain: str,
    verbose: bool,
) -> list[str]:
    """Discover authoritative nameserver IPv4 addresses."""
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = list(DEFAULT_RESOLVERS)
    resolver.timeout = 3
    resolver.lifetime = 8
    resolver.retry_servfail = False

    try:
        answer = resolver.resolve(domain, "NS")
    except Exception as exc:
        _log(
            f"NS discovery failed: {type(exc).__name__}",
            verbose,
        )
        return []

    addresses = []

    for record in answer:
        hostname = str(record.target).rstrip(".")

        try:
            result = resolver.resolve(hostname, "A")
            addresses.extend(str(item) for item in result)
        except Exception:
            continue

    addresses = _normalize_nameservers(addresses)

    if addresses:
        _log(
            f"discovered {len(addresses)} authoritative nameserver IP(s)",
            verbose,
        )

    return addresses


def _answer_signature(answer) -> frozenset[str]:
    """Return a normalized signature for a DNS answer."""
    return frozenset(
        str(record).strip().lower()
        for record in answer
    )


def _detect_wildcards(
    domain: str,
    nameservers: list[str],
    verbose: bool,
) -> dict[str, set]:
    """
    Detect repeatable positive wildcard answers by record type.

    Empty answers and NXDOMAIN are not positive wildcard evidence.
    """
    signatures = {
        qtype: Counter()
        for qtype in QUERY_TYPES
    }

    if not nameservers:
        return {}

    for _ in range(WILDCARD_PROBES):
        host = f"{uuid.uuid4().hex}.{domain}"
        resolver = _make_resolver(random.choice(nameservers))

        for qtype in QUERY_TYPES:
            try:
                answer = resolver.resolve(
                    host,
                    qtype,
                    raise_on_no_answer=False,
                )
            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.resolver.NoNameservers,
                dns.resolver.LifetimeTimeout,
                dns.exception.Timeout,
            ):
                continue
            except Exception as exc:
                _log(
                    f"wildcard probe {qtype}: {type(exc).__name__}",
                    verbose,
                )
                continue

            if answer is None or len(answer) == 0:
                continue

            signatures[qtype][_answer_signature(answer)] += 1

    wildcard = {}

    for qtype, counts in signatures.items():
        repeated = {
            signature
            for signature, count in counts.items()
            if count >= WILDCARD_THRESHOLD
        }

        if not repeated:
            continue

        if qtype in ("A", "AAAA"):
            addresses = set()
            for signature in repeated:
                addresses.update(signature)

            wildcard[qtype] = addresses
        else:
            wildcard[qtype] = repeated

        _log(
            f"repeatable wildcard answer detected for {qtype}",
            verbose,
        )

    if not wildcard:
        _log("no repeatable positive wildcard answers detected", verbose)

    return wildcard


def _is_wildcard_answer(
    qtype: str,
    answer,
    wildcard: dict[str, set],
) -> bool:
    """Compare a positive answer with the detected wildcard baseline."""
    baseline = wildcard.get(qtype)

    if not baseline or answer is None or len(answer) == 0:
        return False

    signature = _answer_signature(answer)

    if qtype in ("A", "AAAA"):
        return signature.issubset(baseline)

    return signature in baseline


def bruteforce(
    domain: str,
    threads: int = 20,
    known: Iterable[str] = (),
    verbose: bool = False,
    on_found: Callable[[str, str], None] | None = None,
) -> set[str]:

    try:
        domain = _normalize_domain(domain)
    except ValueError as exc:
        _log(str(exc), verbose)
        return set()

    base = os.path.dirname(os.path.realpath(__file__))

    names_path = _find([
        os.path.join(base, "subBlitz", "names.txt"),
        os.path.join(base, "names.txt"),
    ])

    resolvers_path = _find([
        os.path.join(base, "subBlitz", "resolvers.txt"),
        os.path.join(base, "resolvers.txt"),
    ])

    if not names_path:
        _log(f"names.txt not found under {base}", verbose)
        return set()

    raw_names = _read_lines(names_path)
    names = []
    seen = set()

    for raw_name in raw_names:
        candidate = raw_name.strip().lower().rstrip(".")

        if candidate.endswith("." + domain):
            candidate = candidate[: -(len(domain) + 1)]

        if not candidate or len(candidate) > 253:
            continue

        try:
            candidate = candidate.encode("idna").decode("ascii")
        except UnicodeError:
            continue

        valid = True

        for label in candidate.split("."):
            if (
                not label
                or len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
                or not all(c.isalnum() or c == "-" for c in label)
            ):
                valid = False
                break

        if valid and candidate not in seen:
            names.append(candidate)
            seen.add(candidate)

    if not names:
        _log("no valid candidate names found", verbose)
        return set()

    _log(
        f"using names={names_path} ({len(names)} valid entries)",
        verbose,
    )

    nameservers = []

    if resolvers_path:
        nameservers = _normalize_nameservers(
            _read_lines(resolvers_path)
        )
        _log(
            f"loaded {len(nameservers)} valid resolver IP(s)",
            verbose,
        )

    if not nameservers:
        nameservers = _discover_authoritative(domain, verbose)

    if not nameservers:
        nameservers = list(DEFAULT_RESOLVERS)
        _log("using public resolver fallback", verbose)

    random.shuffle(nameservers)
    nameservers = nameservers[:30]

    wildcard = _detect_wildcards(domain, nameservers, verbose)

    known_set = set()

    for item in known or ():
        if not item:
            continue

        try:
            known_set.add(_normalize_domain(item))
        except ValueError:
            continue

    found: set[str] = set()
    found_lock = threading.Lock()
    resolver_lock = threading.Lock()
    resolver_local = threading.local()
    stop = threading.Event()
    next_resolver = 0

    def get_resolver() -> dns.resolver.Resolver:
        """Assign one nameserver to each worker thread."""
        nonlocal next_resolver

        resolver = getattr(resolver_local, "resolver", None)

        if resolver is None:
            with resolver_lock:
                ns = nameservers[next_resolver % len(nameservers)]
                next_resolver += 1

            resolver = _make_resolver(ns)
            resolver_local.resolver = resolver

        return resolver

    def query_with_retry(host: str, qtype: str):
        """Retry transient DNS failures using an alternate resolver."""
        resolver = get_resolver()

        try:
            answer = resolver.resolve(
                host,
                qtype,
                raise_on_no_answer=False,
            )
            return answer, "answer"

        except dns.resolver.NXDOMAIN:
            return None, "nxdomain"

        except dns.resolver.NoAnswer:
            return None, "nodata"

        except (
            dns.resolver.NoNameservers,
            dns.resolver.LifetimeTimeout,
            dns.exception.Timeout,
        ):
            pass

        except Exception as exc:
            _log(
                f"query error {host}/{qtype}: {type(exc).__name__}",
                verbose,
            )

        alternatives = [
            ns for ns in nameservers
            if ns not in resolver.nameservers
        ]

        if alternatives:
            fallback = _make_resolver(random.choice(alternatives))

            try:
                answer = fallback.resolve(
                    host,
                    qtype,
                    raise_on_no_answer=False,
                )
                return answer, "answer"

            except dns.resolver.NXDOMAIN:
                return None, "nxdomain"

            except dns.resolver.NoAnswer:
                return None, "nodata"

            except Exception:
                pass

        return None, "error"

    def has_record(host: str) -> bool:
        for qtype in QUERY_TYPES:
            if stop.is_set():
                return False

            answer, status = query_with_retry(host, qtype)

            if status == "nxdomain":
                return False

            if status != "answer":
                continue

            if answer is None or len(answer) == 0:
                continue

            if _is_wildcard_answer(qtype, answer, wildcard):
                continue

            return True

        return False

    def check(name: str) -> None:
        if stop.is_set():
            return

        host = f"{name}.{domain}".lower()

        if host in known_set:
            return

        try:
            if not has_record(host):
                return
        except Exception as exc:
            _log(
                f"worker failed for {host}: {type(exc).__name__}",
                verbose,
            )
            return

        with found_lock:
            if host in found:
                return
            found.add(host)

        if on_found is not None:
            try:
                on_found("subBlitz", host)
            except Exception as exc:
                _log(f"on_found callback failed: {exc}", verbose)

    workers = max(1, min(int(threads), MAX_THREADS))
    batch_size = max(workers, BATCH_SIZE)

    try:
        with Progress(
            TextColumn("  [muted]   ↳ subBlitz[/muted]"),
            BarColumn(bar_width=30),
            MofNCompleteColumn(),
            TextColumn("[muted]{task.fields[found]} found[/muted]"),
            TimeRemainingColumn(),
            transient=True,
        ) as progress:
            task = progress.add_task(
                "brute",
                total=len(names),
                found=0,
            )

            with ThreadPoolExecutor(max_workers=workers) as pool:
                for start in range(0, len(names), batch_size):
                    if stop.is_set():
                        break

                    batch = names[start:start + batch_size]
                    futures = [
                        pool.submit(check, name)
                        for name in batch
                    ]

                    for future in as_completed(futures):
                        try:
                            future.result()
                        except KeyboardInterrupt:
                            stop.set()
                            raise
                        except Exception as exc:
                            _log(
                                f"worker error: {type(exc).__name__}",
                                verbose,
                            )
                        finally:
                            progress.update(
                                task,
                                advance=1,
                                found=len(found),
                            )

    except KeyboardInterrupt:
        stop.set()
        _log("interrupted; returning partial results", verbose)

    _log(
        f"subBlitz added {len(found)} new subdomain(s)",
        verbose,
    )

    return found


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="DNS subdomain enumeration"
    )
    parser.add_argument(
        "domain",
        help="Domain you own or are authorized to test",
    )
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=20,
        help="Worker threads (default: 20)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable diagnostic output",
    )

    args = parser.parse_args()

    results = bruteforce(
        args.domain,
        threads=args.threads,
        verbose=args.verbose,
    )

    for hostname in sorted(results):
        print(hostname)

    print(f"\nTotal new subdomains: {len(results)}")
