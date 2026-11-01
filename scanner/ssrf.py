from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
from urllib.parse import urlparse

SCAN_BLOCKED = "This address can't be scanned"
LOCAL_SCAN_ENV = "TRUSTMAP_ALLOW_LOCAL_SCAN"
ALLOWED_SCHEMES = frozenset({"http", "https"})
SCHEME_PORTS = {"http": 80, "https": 443}


class ScanBlockedError(Exception):
    def __init__(self) -> None:
        super().__init__(SCAN_BLOCKED)


def allow_local_scan() -> bool:
    return os.environ.get(LOCAL_SCAN_ENV, "").strip().lower() in {
        "1",
        "true",
        "yes",
    }


def is_blocked_ip(value: str) -> bool:
    addr = ipaddress.ip_address(value)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return bool(
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def parse_public_url(url: str, *, allow_local: bool | None = None) -> tuple[str, str, int, str]:
    """Return scheme, hostname, port, path-and-query. Raises ScanBlockedError."""
    allow_local = allow_local_scan() if allow_local is None else allow_local
    parsed = urlparse(url)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise ScanBlockedError()
    if parsed.username is not None or parsed.password is not None:
        raise ScanBlockedError()
    host = parsed.hostname
    if not host:
        raise ScanBlockedError()
    default_port = SCHEME_PORTS[parsed.scheme.lower()]
    port = parsed.port or default_port
    if port not in SCHEME_PORTS.values() and not allow_local:
        raise ScanBlockedError()
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return parsed.scheme.lower(), host, port, path


async def resolve_host(host: str) -> list[str]:
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(
            host, None, type=socket.SOCK_STREAM
        )
    except socket.gaierror as exc:
        raise ScanBlockedError() from exc
    addresses = []
    seen: set[str] = set()
    for info in infos:
        ip = info[4][0]
        if ip not in seen:
            seen.add(ip)
            addresses.append(ip)
    if not addresses:
        raise ScanBlockedError()
    return addresses


def refuse_blocked_ips(addresses: list[str], *, allow_local: bool | None = None) -> None:
    allow_local = allow_local_scan() if allow_local is None else allow_local
    if allow_local:
        return
    if any(is_blocked_ip(ip) for ip in addresses):
        raise ScanBlockedError()


def ip_url(scheme: str, ip: str, port: int, path: str) -> str:
    default = SCHEME_PORTS[scheme]
    host = f"[{ip}]" if ":" in ip else ip
    netloc = host if port == default else f"{host}:{port}"
    return f"{scheme}://{netloc}{path}"


def host_header(host: str, scheme: str, port: int) -> str:
    if port == SCHEME_PORTS[scheme]:
        return host
    return f"{host}:{port}"
