"""Shared helpers for network rules."""
from __future__ import annotations

import ipaddress
import math
from collections import Counter


INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",    # RFC 1918 + CGNAT
    "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128")]


def is_internal(ip: str) -> bool:
    """RFC 1918, CGNAT, loopback, link-local. Not `ipaddress.is_private`, which also counts
    the documentation ranges (192.0.2/24, 198.51.100/24, 203.0.113/24) and other reserved
    blocks that are not anybody's internal network."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in INTERNAL_NETS)


def entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values())


def parent_domain(d: str) -> str:
    parts = d.rstrip(".").lower().split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in ("co", "com", "net", "org", "ac", "gov"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def src(e) -> str:
    return e.host or e.source_ip
