from __future__ import annotations

import json
import os
import sqlite3
import time
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote, urljoin

import dns.asyncresolver as dns_asyncresolver
import dns.exception as dns_exception
import dns.resolver as dns_resolver
import httpx

from scanner.config import (
    CACHE_TTL_S,
    CRTSH_TIMEOUT_S,
    DNS_TIMEOUT_S,
    HTTP_TIMEOUT_S,
    RDAP_BOOTSTRAP_URL,
    RDAP_FALLBACK_BASE,
)
from scanner.models import (
    BucketProbeResult,
    CertHistoryResult,
    DnsResult,
    RdapResult,
    WaybackResult,
)

S3_NOSUCH = "NoSuchBucket"
DnsQuery = Callable  # async (name, rdtype) -> list[str], raises NXDOMAIN


class LookupCache:
    def __init__(
        self,
        path: str | Path,
        ttl_s: int = CACHE_TTL_S,
        now: Callable[[], float] | None = None,
    ):
        self.path = Path(path)
        self.ttl_s = ttl_s
        self._now = now or time.time
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS lookup_cache (
                    key TEXT PRIMARY KEY,
                    body TEXT NOT NULL,
                    fetched_at REAL NOT NULL
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path)

    def get_json(self, key: str) -> Any | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT body, fetched_at FROM lookup_cache WHERE key = ?",
                (key,),
            ).fetchone()
        if row is None:
            return None
        body, fetched_at = row
        if self._now() - fetched_at > self.ttl_s:
            return None
        return json.loads(body)

    def set_json(self, key: str, value: Any) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO lookup_cache (key, body, fetched_at)
                VALUES (?, ?, ?)
                """,
                (key, json.dumps(value), self._now()),
            )


def default_cache() -> LookupCache:
    path = os.environ.get("TRUSTMAP_CACHE_DB", "trustmap.db")
    return LookupCache(path)


def _client(timeout: float = HTTP_TIMEOUT_S) -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=timeout, follow_redirects=True)


async def rdap(
    domain: str,
    *,
    client: httpx.AsyncClient | None = None,
    cache: LookupCache | None = None,
) -> RdapResult:
    """Look up a registrable domain. HTTP 404 means unregistered."""
    cache = cache or default_cache()
    key = f"rdap:{domain.lower()}"
    hit = cache.get_json(key)
    if hit is not None:
        return RdapResult.model_validate(hit)

    own_client = client is None
    client = client or _client()
    try:
        result = await _rdap_fetch(domain.lower(), client)
    finally:
        if own_client:
            await client.aclose()
    cache.set_json(key, result.model_dump(mode="json"))
    return result


async def _rdap_fetch(domain: str, client: httpx.AsyncClient) -> RdapResult:
    try:
        base = await _rdap_base_for(domain, client)
        url = urljoin(base if base.endswith("/") else base + "/", f"domain/{domain}")
        response = await client.get(url)
    except httpx.HTTPError:
        return RdapResult(domain=domain, status="unavailable")
    if response.status_code == 404:
        return RdapResult(domain=domain, status="unregistered")
    if response.status_code >= 400:
        return RdapResult(domain=domain, status="unavailable")
    try:
        payload = response.json()
    except ValueError:
        return RdapResult(domain=domain, status="unavailable")
    return _parse_rdap(domain, payload)


async def _rdap_base_for(domain: str, client: httpx.AsyncClient) -> str:
    try:
        response = await client.get(RDAP_BOOTSTRAP_URL)
        response.raise_for_status()
        bootstrap = response.json()
    except (httpx.HTTPError, ValueError):
        return RDAP_FALLBACK_BASE
    labels = domain.split(".")
    best = ""
    best_len = 0
    for service in bootstrap.get("services", []):
        if len(service) < 2:
            continue
        tlds, urls = service[0], service[1]
        if not urls:
            continue
        for tld in tlds:
            tld = str(tld).lower().lstrip(".")
            parts = tld.split(".")
            if labels[-len(parts) :] == parts and len(parts) > best_len:
                best = str(urls[0])
                best_len = len(parts)
    return best or RDAP_FALLBACK_BASE


def _parse_rdap(domain: str, payload: dict[str, Any]) -> RdapResult:
    statuses = [str(s) for s in payload.get("status") or []]
    registrar = _rdap_registrar(payload)
    expiry = _rdap_expiry(payload)
    days = None
    if expiry is not None:
        days = (expiry - datetime.now(timezone.utc).date()).days
    return RdapResult(
        domain=domain,
        status="registered",
        registrar=registrar,
        expiry=expiry,
        days_to_expiry=days,
        statuses=statuses,
    )


def _rdap_registrar(payload: dict[str, Any]) -> str | None:
    for entity in payload.get("entities") or []:
        roles = [str(r).lower() for r in entity.get("roles") or []]
        if "registrar" not in roles:
            continue
        vcard = entity.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) >= 2:
            for item in vcard[1]:
                if item and item[0] == "fn" and len(item) >= 4:
                    return str(item[3])
        if entity.get("handle"):
            return str(entity["handle"])
    return None


def _rdap_expiry(payload: dict[str, Any]) -> date | None:
    for event in payload.get("events") or []:
        if str(event.get("eventAction", "")).lower() != "expiration":
            continue
        raw = event.get("eventDate")
        if not raw:
            continue
        try:
            parsed = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        except ValueError:
            try:
                return date.fromisoformat(str(raw)[:10])
            except ValueError:
                continue
        return parsed.date()
    return None


async def dns(
    host: str,
    *,
    query: DnsQuery | None = None,
    cache: LookupCache | None = None,
) -> DnsResult:
    """Resolve the full host (not just the registrable domain)."""
    cache = cache or default_cache()
    key = f"dns:{host.lower()}"
    hit = cache.get_json(key)
    if hit is not None:
        return DnsResult.model_validate(hit)

    lookup = query or _dns_query
    result = await _dns_lookup(host, lookup)
    cache.set_json(key, result.model_dump(mode="json"))
    return result


async def _dns_query(name: str, rdtype: str) -> list[str]:
    resolver = dns_asyncresolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT_S
    answer = await resolver.resolve(name, rdtype)
    if rdtype.upper() == "CNAME":
        return [str(rr.target).rstrip(".") for rr in answer]
    return [rr.to_text().rstrip(".") for rr in answer]


async def _dns_lookup(host: str, query: DnsQuery) -> DnsResult:
    cnames: list[str] = []
    current = host
    try:
        for _ in range(10):
            try:
                names = await query(current, "CNAME")
            except dns_resolver.NXDOMAIN:
                return DnsResult(host=host, status="nxdomain", cnames=cnames)
            except (dns_resolver.NoAnswer, dns_resolver.NoNameservers):
                names = []
            except dns_exception.DNSException:
                return DnsResult(host=host, status="error", cnames=cnames)
            if not names:
                break
            current = names[0]
            cnames.append(current)
        addresses: list[str] = []
        for rdtype in ("A", "AAAA"):
            try:
                addresses.extend(await query(current, rdtype))
            except dns_resolver.NXDOMAIN:
                return DnsResult(
                    host=host, status="nxdomain", cnames=cnames, addresses=addresses
                )
            except (dns_resolver.NoAnswer, dns_resolver.NoNameservers):
                continue
            except dns_exception.DNSException:
                return DnsResult(host=host, status="error", cnames=cnames)
        status = "resolves" if addresses else "error"
        return DnsResult(host=host, status=status, addresses=addresses, cnames=cnames)
    except dns_resolver.NXDOMAIN:
        return DnsResult(host=host, status="nxdomain", cnames=cnames)
    except dns_exception.DNSException:
        return DnsResult(host=host, status="error", cnames=cnames)


async def bucket_probe(
    name: str,
    provider: str,
    *,
    client: httpx.AsyncClient | None = None,
    cache: LookupCache | None = None,
) -> BucketProbeResult:
    """HTTP GET only. Never PUT or create."""
    provider = provider.lower()
    cache = cache or default_cache()
    key = f"bucket:{provider}:{name}"
    hit = cache.get_json(key)
    if hit is not None:
        return BucketProbeResult.model_validate(hit)

    url = _bucket_url(name, provider)
    own_client = client is None
    client = client or _client()
    try:
        response = await client.get(url)
        result = BucketProbeResult(
            name=name,
            provider=provider,
            status=_bucket_status(provider, response),
            http_status=response.status_code,
        )
    except httpx.HTTPError:
        result = BucketProbeResult(
            name=name, provider=provider, status="error", http_status=None
        )
    finally:
        if own_client:
            await client.aclose()
    cache.set_json(key, result.model_dump(mode="json"))
    return result


def _bucket_url(name: str, provider: str) -> str:
    if provider == "gcs":
        return f"https://storage.googleapis.com/{quote(name)}"
    if provider == "s3":
        return f"https://{quote(name)}.s3.amazonaws.com/"
    raise ValueError(f"unknown bucket provider: {provider}")


def _bucket_status(provider: str, response: httpx.Response) -> str:
    body = response.text
    if provider == "s3" and S3_NOSUCH in body:
        return S3_NOSUCH
    if response.status_code in {200, 204, 206}:
        return "exists"
    if response.status_code in {401, 403}:
        return "access_denied"
    if response.status_code == 404:
        return S3_NOSUCH
    return "error"


async def cert_history(
    domain: str,
    *,
    client: httpx.AsyncClient | None = None,
    cache: LookupCache | None = None,
) -> CertHistoryResult:
    cache = cache or default_cache()
    key = f"crtsh:{domain.lower()}"
    hit = cache.get_json(key)
    if hit is not None:
        return CertHistoryResult.model_validate(hit)

    own_client = client is None
    client = client or _client(timeout=CRTSH_TIMEOUT_S)
    try:
        response = await client.get(
            "https://crt.sh/", params={"q": domain, "output": "json"}
        )
        response.raise_for_status()
        rows = response.json()
        issuers: list[str] = []
        first: date | None = None
        last: date | None = None
        if isinstance(rows, list):
            for row in rows:
                issuer = str(row.get("issuer_name") or "")
                if issuer and issuer not in issuers:
                    issuers.append(issuer)
                for field in ("not_before", "entry_timestamp"):
                    parsed = _parse_date(row.get(field))
                    if parsed and (first is None or parsed < first):
                        first = parsed
                for field in ("not_after", "entry_timestamp"):
                    parsed = _parse_date(row.get(field))
                    if parsed and (last is None or parsed > last):
                        last = parsed
        result = CertHistoryResult(
            domain=domain,
            status="ok",
            issuers=issuers[:8],
            first_seen=first,
            last_seen=last,
        )
    except (httpx.HTTPError, ValueError, TypeError):
        result = CertHistoryResult(domain=domain, status="unavailable")
    finally:
        if own_client:
            await client.aclose()
    cache.set_json(key, result.model_dump(mode="json"))
    return result


def _parse_date(value: Any) -> date | None:
    if not value:
        return None
    text = str(value)[:10]
    try:
        return date.fromisoformat(text)
    except ValueError:
        return None


async def wayback(
    url: str,
    *,
    client: httpx.AsyncClient | None = None,
    cache: LookupCache | None = None,
) -> WaybackResult:
    cache = cache or default_cache()
    key = f"wayback:{url}"
    hit = cache.get_json(key)
    if hit is not None:
        return WaybackResult.model_validate(hit)

    own_client = client is None
    client = client or _client()
    try:
        first = await _cdx(client, url, latest=False)
        last = await _cdx(client, url, latest=True)
        result = WaybackResult(
            url=url,
            status="ok" if first or last else "unavailable",
            first_snapshot=None if first is None else first[0],
            first_digest=None if first is None else first[1],
            last_snapshot=None if last is None else last[0],
            last_digest=None if last is None else last[1],
        )
    except httpx.HTTPError:
        result = WaybackResult(url=url, status="unavailable")
    finally:
        if own_client:
            await client.aclose()
    cache.set_json(key, result.model_dump(mode="json"))
    return result


async def _cdx(
    client: httpx.AsyncClient, url: str, *, latest: bool
) -> tuple[str, str] | None:
    params = {
        "url": url,
        "output": "json",
        "fl": "timestamp,digest",
        "limit": "1",
    }
    if latest:
        params["fastLatest"] = "true"
    response = await client.get("https://web.archive.org/cdx/search/cdx", params=params)
    response.raise_for_status()
    rows = response.json()
    if not isinstance(rows, list) or len(rows) < 2:
        return None
    timestamp, digest = rows[1][0], rows[1][1]
    return str(timestamp), str(digest)
