from __future__ import annotations

import asyncio
import json
import logging
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
    EXPIRY_INVESTIGATE_DAYS,
    HTTP_TIMEOUT_S,
    RDAP_BOOTSTRAP_URL,
    RDAP_FALLBACK_BASE,
    on_serverless,
)
from scanner.models import (
    BucketProbeResult,
    CertHistoryResult,
    DnsResult,
    GithubOwnerResult,
    GithubRepoResult,
    PlatformTakeoverResult,
    RdapResult,
    WaybackResult,
)

S3_NOSUCH = "NoSuchBucket"
BOOTSTRAP_CACHE_KEY = "rdap-bootstrap"
DnsQuery = Callable  # async (name, rdtype) -> list[str], raises NXDOMAIN
log = logging.getLogger("trustmap")


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
    # a serverless host (or any read-only app folder) can only write under /tmp
    writable = os.access(os.getcwd(), os.W_OK)
    fallback = "trustmap.db" if writable and not on_serverless() else "/tmp/trustmap.db"
    path = os.environ.get("TRUSTMAP_CACHE_DB") or fallback
    return LookupCache(path)


def _client(timeout: float = HTTP_TIMEOUT_S) -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=timeout, follow_redirects=True)


def consistent_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    """DNS that resolves means the domain is registered; never keep RDAP unregistered."""
    out = dict(evidence)
    rdap = out.get("rdap")
    dns = out.get("dns") or {}
    if not isinstance(rdap, dict):
        return out
    rdap = dict(rdap)
    if (
        str(rdap.get("status", "")).lower() == "unregistered"
        and str(dns.get("status", "")).lower() == "resolves"
    ):
        name = rdap.get("domain") or dns.get("host")
        log.warning(
            "RDAP unregistered contradicts DNS resolves for %s; treating RDAP as unknown",
            name,
        )
        rdap["status"] = "unknown"
        out["rdap"] = rdap
    elif rdap:
        out["rdap"] = rdap
    return out


_UNKNOWN = frozenset({"unavailable", "error", "timeout", "unknown", "blocked", "skipped"})


def _weight(name: str, value: Any) -> int:
    """2 = a risk signal, 1 = a known answer, 0 = no answer."""
    if not isinstance(value, dict):
        return 1
    status = str(value.get("status", "")).lower()
    if status in _UNKNOWN:
        return 0
    signal = (
        (name == "bucket_probe" and value.get("status") == "NoSuchBucket")
        or (name in {"github_owner", "github_repo"} and status in {"missing", "disabled"})
        or (name == "platform_takeover" and status == "unclaimed")
        or (name == "dns" and status == "nxdomain")
        or (name == "rdap" and status == "unregistered")
        or (
            name == "rdap"
            and isinstance(value.get("days_to_expiry"), int)
            and value["days_to_expiry"] <= EXPIRY_INVESTIGATE_DAYS
        )
        or (name == "live_fetch" and bool(value.get("parked") or value.get("for_sale")))
    )
    return 2 if signal else 1


def merge_evidence(items: list[dict[str, Any]]) -> dict[str, Any]:
    """One target's facts from several lookups (hosts or references).

    A known answer replaces no answer, and a risk signal is never replaced by a
    clean answer for another host, so the facts do not depend on which line of
    the repo happened to be read last."""
    merged: dict[str, Any] = {}
    for evidence in items:
        for name, value in (evidence or {}).items():
            if name not in merged or _weight(name, value) >= _weight(name, merged[name]):
                merged[name] = value
    return consistent_evidence(merged)


async def rdap(
    domain: str,
    *,
    client: httpx.AsyncClient | None = None,
    cache: LookupCache | None = None,
) -> RdapResult:
    """Look up a registrable domain via the TLD's IANA-bootstrap RDAP server."""
    cache = cache or default_cache()
    key = f"rdap:{domain.lower()}"
    hit = cache.get_json(key)
    if hit is not None:
        return RdapResult.model_validate(hit)

    own_client = client is None
    client = client or _client()
    try:
        result = await _rdap_fetch(domain.lower(), client, cache)
    finally:
        if own_client:
            await client.aclose()
    cache.set_json(key, result.model_dump(mode="json"))
    return result


def _rdap_url(base: str, domain: str) -> str:
    root = base if base.endswith("/") else base + "/"
    return urljoin(root, f"domain/{domain}")


def _is_rdap_fallback(url: str) -> bool:
    return url.rstrip("/").lower().startswith(RDAP_FALLBACK_BASE.rstrip("/").lower())


async def _rdap_fetch(
    domain: str, client: httpx.AsyncClient, cache: LookupCache
) -> RdapResult:
    bootstrap = await _rdap_bootstrap(client, cache)
    if bootstrap is None:
        return RdapResult(domain=domain, status="unknown")
    bases = [
        base for base in _rdap_bases_for(domain, bootstrap) if not _is_rdap_fallback(base)
    ]
    if not bases:
        return RdapResult(domain=domain, status="unknown")
    last_status = "unavailable"
    for base in bases:
        url = _rdap_url(base, domain)
        try:
            response = await client.get(url)
        except httpx.HTTPError:
            last_status = "unavailable"
            continue
        if response.status_code == 404:
            return RdapResult(domain=domain, status="unregistered")
        if response.status_code >= 400:
            last_status = "unavailable"
            continue
        try:
            payload = response.json()
        except ValueError:
            last_status = "unavailable"
            continue
        return _parse_rdap(domain, payload)
    return RdapResult(domain=domain, status=last_status)


async def _rdap_bootstrap(
    client: httpx.AsyncClient, cache: LookupCache
) -> dict[str, Any] | None:
    hit = cache.get_json(BOOTSTRAP_CACHE_KEY)
    if isinstance(hit, dict):
        return hit
    try:
        response = await client.get(RDAP_BOOTSTRAP_URL)
        response.raise_for_status()
        bootstrap = response.json()
    except (httpx.HTTPError, ValueError, TypeError):
        return None
    if not isinstance(bootstrap, dict):
        return None
    cache.set_json(BOOTSTRAP_CACHE_KEY, bootstrap)
    return bootstrap


def _rdap_bases_for(domain: str, bootstrap: dict[str, Any]) -> list[str]:
    labels = domain.lower().split(".")
    best: list[str] = []
    best_len = 0
    for service in bootstrap.get("services", []):
        if not isinstance(service, list) or len(service) < 2:
            continue
        tlds, urls = service[0], service[1]
        if not urls:
            continue
        for tld in tlds:
            tld = str(tld).lower().lstrip(".")
            parts = tld.split(".")
            if labels[-len(parts) :] != parts:
                continue
            if len(parts) > best_len:
                best = [str(url) for url in urls]
                best_len = len(parts)
    return best


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
    try:
        result = await asyncio.wait_for(
            _dns_lookup(host, lookup), timeout=DNS_TIMEOUT_S
        )
    except TimeoutError:
        result = DnsResult(host=host, status="timeout")
    cache.set_json(key, result.model_dump(mode="json"))
    return result


async def _dns_query(name: str, rdtype: str) -> list[str]:
    resolver = dns_asyncresolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT_S
    resolver.timeout = DNS_TIMEOUT_S
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
            except dns_exception.Timeout:
                return DnsResult(host=host, status="timeout", cnames=cnames)
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
            except dns_exception.Timeout:
                return DnsResult(host=host, status="timeout", cnames=cnames)
            except dns_exception.DNSException:
                return DnsResult(host=host, status="error", cnames=cnames)
        status = "resolves" if addresses else "error"
        return DnsResult(host=host, status=status, addresses=addresses, cnames=cnames)
    except dns_resolver.NXDOMAIN:
        return DnsResult(host=host, status="nxdomain", cnames=cnames)
    except dns_exception.Timeout:
        return DnsResult(host=host, status="timeout", cnames=cnames)
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

    if provider == "azure":
        host = f"{name}.blob.core.windows.net"
        dns_hit = await dns(host, cache=cache)
        if dns_hit.status == "nxdomain":
            status = S3_NOSUCH
        elif dns_hit.status == "resolves":
            status = "exists"
        else:
            status = "error"
        result = BucketProbeResult(
            name=name, provider=provider, status=status, http_status=None
        )
        cache.set_json(key, result.model_dump(mode="json"))
        return result

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
    if S3_NOSUCH in body:
        return S3_NOSUCH
    if "PermanentRedirect" in body or "AccessDenied" in body:
        return "exists"
    if response.status_code in {200, 204, 206, 301, 302, 307, 308, 401, 403}:
        return "exists"
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


async def platform_takeover(
    host: str,
    *,
    cnames: list[str] | None = None,
    dns_status: str | None = None,
    client: httpx.AsyncClient | None = None,
    cache: LookupCache | None = None,
) -> PlatformTakeoverResult:
    from scanner.tools.platform_takeover import matching_platform

    cache = cache or default_cache()
    key = f"platform:{host.lower()}"
    hit = cache.get_json(key)
    if hit is not None:
        return PlatformTakeoverResult.model_validate(hit)

    platform = matching_platform(host, cnames)
    if platform is None:
        return PlatformTakeoverResult(host=host, status="skipped")

    takeover = str(platform.get("takeover") or "edge case")
    name = str(platform["name"])
    nx = str(dns_status or "").lower() == "nxdomain"
    if platform.get("nxdomain"):
        if not dns_status or str(dns_status).lower() in {
            "timeout",
            "error",
            "unknown",
            "unavailable",
        }:
            result = PlatformTakeoverResult(
                host=host,
                status="error",
                platform=name,
                takeover=takeover,
            )
        else:
            result = PlatformTakeoverResult(
                host=host,
                status="unclaimed" if nx else "claimed",
                platform=name,
                takeover=takeover,
                signal="NXDOMAIN" if nx else None,
            )
        cache.set_json(key, result.model_dump(mode="json"))
        return result

    own_client = client is None
    client = client or _client()
    result = PlatformTakeoverResult(
        host=host, status="error", platform=name, takeover=takeover
    )
    try:
        for scheme in ("https", "http"):
            try:
                response = await client.get(f"{scheme}://{host}/")
            except httpx.HTTPError:
                continue
            body = response.text[:30000].lower()
            match = next(
                (
                    fp
                    for fp in platform.get("fingerprints") or []
                    if fp.lower() in body
                ),
                None,
            )
            if match:
                status = "unclaimed"
            elif response.status_code < 400:
                status = "claimed"
            else:
                status = "error_page"
            result = PlatformTakeoverResult(
                host=host,
                status=status,
                platform=name,
                takeover=takeover,
                signal=match,
                http_status=response.status_code,
            )
            cache.set_json(key, result.model_dump(mode="json"))
            return result
        if nx:
            result = PlatformTakeoverResult(
                host=host,
                status="unclaimed",
                platform=name,
                takeover=takeover,
                signal="NXDOMAIN",
            )
    finally:
        if own_client:
            await client.aclose()
    cache.set_json(key, result.model_dump(mode="json"))
    return result


def _github_headers(token: str | None) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


async def github_owner(
    owner: str,
    *,
    client: httpx.AsyncClient | None = None,
    cache: LookupCache | None = None,
) -> GithubOwnerResult:
    cache = cache or default_cache()
    key = f"github_owner:{owner.lower()}"
    hit = cache.get_json(key)
    if hit is not None:
        return GithubOwnerResult.model_validate(hit)

    token = os.environ.get("GITHUB_TOKEN", "").strip() or None
    own_client = client is None
    client = client or httpx.AsyncClient(timeout=HTTP_TIMEOUT_S, follow_redirects=False)
    try:
        if token:
            response = await client.get(
                f"https://api.github.com/users/{owner}",
                headers=_github_headers(token),
            )
            if response.status_code == 404:
                result = GithubOwnerResult(
                    owner=owner,
                    status="missing",
                    exists=False,
                    http_status=404,
                )
                cache.set_json(key, result.model_dump(mode="json"))
                return result
            if response.status_code == 200:
                payload = response.json()
                result = GithubOwnerResult(
                    owner=owner,
                    status="exists",
                    exists=True,
                    kind=payload.get("type"),
                    http_status=200,
                )
                cache.set_json(key, result.model_dump(mode="json"))
                return result
        response = await client.get(f"https://github.com/{owner}")
        if response.status_code == 404:
            result = GithubOwnerResult(
                owner=owner, status="missing", exists=False, http_status=404
            )
        elif response.status_code in {200, 301, 302}:
            result = GithubOwnerResult(
                owner=owner,
                status="exists",
                exists=True,
                http_status=response.status_code,
            )
        else:
            result = GithubOwnerResult(
                owner=owner, status="error", http_status=response.status_code
            )
    except httpx.HTTPError:
        result = GithubOwnerResult(owner=owner, status="error")
    finally:
        if own_client:
            await client.aclose()
    cache.set_json(key, result.model_dump(mode="json"))
    return result


_DISABLED_TEXT = ("this repository has been disabled", "repository access blocked", "repository unavailable due to")


def _disabled(status_code: int, body: str) -> bool:
    """GitHub keeps a disabled or blocked repo's name taken, and says so in
    words: the API with 403/451 "Repository access blocked", the web page with
    "This repository has been disabled". Read either the same way, so the same
    repo gets the same answer whichever endpoint answered."""
    text = body[:20000].lower()
    return status_code == 451 or any(needle in text for needle in _DISABLED_TEXT)


async def github_repo(
    owner: str,
    repo: str,
    *,
    client: httpx.AsyncClient | None = None,
    cache: LookupCache | None = None,
) -> GithubRepoResult:
    cache = cache or default_cache()
    key = f"github_repo:{owner.lower()}/{repo.lower()}"
    hit = cache.get_json(key)
    if hit is not None:
        return GithubRepoResult.model_validate(hit)

    token = os.environ.get("GITHUB_TOKEN", "").strip() or None
    own_client = client is None
    client = client or httpx.AsyncClient(timeout=HTTP_TIMEOUT_S, follow_redirects=False)
    try:
        if token:
            response = await client.get(
                f"https://api.github.com/repos/{owner}/{repo}",
                headers=_github_headers(token),
            )
            if response.status_code == 404:
                result = GithubRepoResult(
                    owner=owner,
                    repo=repo,
                    status="missing",
                    exists=False,
                    http_status=404,
                )
                cache.set_json(key, result.model_dump(mode="json"))
                return result
            if response.status_code == 200:
                result = GithubRepoResult(
                    owner=owner,
                    repo=repo,
                    status="exists",
                    exists=True,
                    http_status=200,
                )
                cache.set_json(key, result.model_dump(mode="json"))
                return result
            if response.status_code in {403, 451} and _disabled(response.status_code, response.text):
                result = GithubRepoResult(
                    owner=owner,
                    repo=repo,
                    status="disabled",
                    exists=True,
                    http_status=response.status_code,
                )
                cache.set_json(key, result.model_dump(mode="json"))
                return result
        response = await client.get(f"https://github.com/{owner}/{repo}")
        if response.status_code != 404 and _disabled(response.status_code, response.text):
            result = GithubRepoResult(
                owner=owner,
                repo=repo,
                status="disabled",
                exists=True,
                http_status=response.status_code,
            )
        elif response.status_code == 404:
            result = GithubRepoResult(
                owner=owner,
                repo=repo,
                status="missing",
                exists=False,
                http_status=404,
            )
        elif response.status_code in {200, 301, 302}:
            result = GithubRepoResult(
                owner=owner,
                repo=repo,
                status="exists",
                exists=True,
                http_status=response.status_code,
            )
        else:
            result = GithubRepoResult(
                owner=owner,
                repo=repo,
                status="error",
                http_status=response.status_code,
            )
    except httpx.HTTPError:
        result = GithubRepoResult(owner=owner, repo=repo, status="error")
    finally:
        if own_client:
            await client.aclose()
    cache.set_json(key, result.model_dump(mode="json"))
    return result


async def nameservers(
    host: str,
    *,
    cache: LookupCache | None = None,
    query: DnsQuery | None = None,
) -> list[str]:
    cache = cache or default_cache()
    key = f"ns:{host.lower()}"
    hit = cache.get_json(key)
    if isinstance(hit, list):
        return [str(item) for item in hit]
    lookup = query or _dns_query
    try:
        names = await asyncio.wait_for(lookup(host, "NS"), timeout=DNS_TIMEOUT_S)
    except Exception:
        names = []
    cache.set_json(key, names)
    return names
