"""Destination policy primitives; not an OS firewall or network sandbox."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from fnmatch import fnmatch
from urllib.parse import urlsplit


@dataclass(frozen=True)
class EgressDecision:
    allowed: bool
    normalized_host: str | None
    reason: str


def normalize_destination(destination: str) -> str:
    raw = destination.strip()
    parsed = urlsplit(raw if "://" in raw else "//" + raw)
    if parsed.username or parsed.password:
        raise ValueError("Credentials embedded in destinations are forbidden")
    host = (parsed.hostname or "").rstrip(".").lower()
    if not host:
        raise ValueError("Destination host is missing")
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
        raise ValueError("Local or internal hostname is forbidden")
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast or ip.is_reserved:
            raise ValueError("Non-public destination address is forbidden")
        return ip.compressed
    except ValueError as exc:
        if "forbidden" in str(exc):
            raise
    if any(not label or len(label) > 63 for label in host.split(".")) or len(host) > 253:
        raise ValueError("Invalid destination hostname")
    if "." not in host:
        raise ValueError("Single-label destinations are forbidden")
    return host


def evaluate_egress(destination: str, allowlist: tuple[str, ...] = (),
                    denylist: tuple[str, ...] = (), *, default_allow: bool = False) -> EgressDecision:
    try:
        host = normalize_destination(destination)
    except ValueError as exc:
        return EgressDecision(False, None, str(exc))
    if any(fnmatch(host, pattern.lower()) for pattern in denylist):
        return EgressDecision(False, host, "Destination matches denylist")
    allowed = any(fnmatch(host, pattern.lower()) for pattern in allowlist)
    if allowlist:
        return EgressDecision(allowed, host, "Destination allowlisted" if allowed else "Destination not allowlisted")
    return EgressDecision(default_allow, host, "Default allow" if default_allow else "No allowlist configured (fail-closed)")
