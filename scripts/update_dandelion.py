#!/usr/bin/env python3
"""Generate a plain ASCII DNS blocklist for OPNsense from Dandelion Sprout."""
from __future__ import annotations

import ipaddress
import re
import urllib.request
from pathlib import Path

SOURCE = (
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/"
    "refs/heads/master/Alternate%20versions%20Anti-Malware%20List/"
    "AntiMalwareDomains.txt"
)
DEST = Path(__file__).resolve().parent.parent / "dandelion-domains.txt"
DOMAIN_RE = re.compile(
    r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


def main() -> None:
    request = urllib.request.Request(
        SOURCE, headers={"User-Agent": "opnsense-dns-blocklists/1.0"}
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        if response.status != 200:
            raise RuntimeError(f"Unexpected HTTP status: {response.status}")
        body = response.read(15_000_001)
    if len(body) > 15_000_000:
        raise RuntimeError("Upstream download exceeds 15 MB")
    raw = body.decode("utf-8-sig")

    domains: set[str] = set()
    for line in raw.splitlines():
        domain = line.partition("#")[0].strip().lower()
        if not domain or not domain.isascii() or not DOMAIN_RE.fullmatch(domain):
            continue
        try:
            ipaddress.ip_address(domain)
        except ValueError:
            domains.add(domain)

    if not 1000 <= len(domains) <= 250000:
        raise RuntimeError(f"Suspicious parsed domain count: {len(domains)}")

    output = "".join(f"{domain}\n" for domain in sorted(domains))
    if DEST.exists():
        previous = DEST.read_text(encoding="ascii")
        previous_count = len(previous.splitlines())
        if previous_count and len(domains) < previous_count // 2:
            raise RuntimeError("Refusing to publish a >50% drop in domains")
        if previous == output:
            print(f"Unchanged: {len(domains):,} domains")
            return

    DEST.write_text(output, encoding="ascii", newline="\n")
    print(f"Published {len(domains):,} domains from {len(raw.splitlines()):,} source lines")


if __name__ == "__main__":
    main()
