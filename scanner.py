#!/usr/bin/env python3
"""subBlitz - threaded TCP port scanner."""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from ui import console


def _scan_one(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False


def scan_host(host: str, ports: list[int], workers: int = 50) -> list[int]:
    if not ports:
        return []
    workers = max(1, min(workers, len(ports)))
    open_ports: list[int] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_scan_one, host, p): p for p in ports}
        for fut in as_completed(futures):
            try:
                if fut.result():
                    open_ports.append(futures[fut])
            except Exception:
                pass
    return sorted(open_ports)


def run_portscan(hosts: list[str], ports: list[int]) -> dict[str, list[int]]:
    results: dict[str, list[int]] = {}
    if not hosts or not ports:
        return results

    def worker(host: str):
        opens = scan_host(host, ports)
        if opens:
            results[host] = opens
            console.print(
                f"  [success]▸[/success]  [subdomain]{host}[/subdomain]  "
                f"[muted]→[/muted]  [warning]{', '.join(map(str, opens))}[/warning]"
            )

    host_workers = max(1, min(len(hosts), 20))
    with ThreadPoolExecutor(max_workers=host_workers) as pool:
        futures = [pool.submit(worker, h) for h in hosts]
        for fut in as_completed(futures):
            try:
                fut.result()
            except Exception:
                pass
    return results
