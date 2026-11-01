from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from scanner.config import HTTP_TIMEOUT_S
from scanner.models import LiveFetchResult
from scanner.ssrf import ScanBlockedError

# Parked / for-sale signals ported from jwang2007/trustline (app/investigate.py).
NAME = "live_fetch"
LIVE_TIMEOUT_S = min(5.0, HTTP_TIMEOUT_S)
LIVE_MAX_BYTES = 1_000_000
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
FOR_SALE_RE = re.compile(
    r"(?i)(this domain (?:name )?(?:is|may be) for sale|domain (?:name )?is for sale|"
    r"buy this domain|is available for purchase)"
)
PARKED_TEXT_RE = re.compile(
    r"(?i)(domain is parked|parked free|parked domain|this domain has expired|"
    r"domain has expired)"
)
PARKING_NS_NEEDLES = (
    "sedoparking",
    "bodis",
    "parkingcrew",
    "above.com",
    "above.net",
    "hugedomains",
    "undeveloped",
    "domainmarket",
)
MARKETPLACE_HOSTS = (
    "dan.com",
    "afternic.com",
    "sedo.com",
    "sedoparking.com",
    "hugedomains.com",
    "auctions.godaddy.com",
)


def definition() -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": NAME,
            "description": (
                "GET a URL with the same safe fetcher used for websites "
                "(http/https on 80/443 only, private IPs blocked, no JS). "
                "Returns status, final URL, title, and parked/for-sale facts. "
                "Never executes scripts. Detection only."
            ),
            "parameters": {
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
                "additionalProperties": False,
            },
        },
    }


def _host(url: str) -> str:
    return (urlparse(url).hostname or "").lower().rstrip(".")


def _marketplace_host(host: str) -> str | None:
    for needle in MARKETPLACE_HOSTS:
        if host == needle or host.endswith("." + needle):
            return needle
    if host.endswith("godaddy.com") and "auction" in host:
        return "godaddy auction"
    return None


def _parking_ns(nameservers: list[str]) -> str | None:
    for ns in nameservers:
        lowered = ns.lower()
        for needle in PARKING_NS_NEEDLES:
            if needle in lowered:
                return ns.rstrip(".")
    return None


def _title(body: str) -> str:
    match = TITLE_RE.search(body)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()[:200]


async def _nameservers(host: str, ctx: Any) -> list[str]:
    lookup = getattr(ctx, "nameservers", None)
    if lookup is None:
        return []
    try:
        result = lookup(host, cache=ctx.cache)
        if hasattr(result, "__await__"):
            result = await result
        if isinstance(result, list):
            return [str(item) for item in result]
    except Exception:
        return []
    return []


async def run(args: dict[str, Any], ctx: Any) -> dict[str, Any]:
    url = args["url"]
    cache = ctx.cache
    key = f"live_fetch:{url}"
    hit = cache.get_json(key) if cache is not None else None
    if hit is not None:
        return hit
    from scanner.website import safe_get

    fetch = getattr(ctx, "fetch", None) or safe_get
    try:
        page = await fetch(url, max_bytes=LIVE_MAX_BYTES, timeout=LIVE_TIMEOUT_S)
    except ScanBlockedError as exc:
        result = LiveFetchResult(url=url, final_url=url, status="blocked")
        dumped = result.model_dump(mode="json")
        dumped["error"] = str(exc)
        if cache is not None:
            cache.set_json(key, dumped)
        return dumped
    except Exception:
        result = LiveFetchResult(url=url, final_url=url, status="error")
        dumped = result.model_dump(mode="json")
        if cache is not None:
            cache.set_json(key, dumped)
        return dumped

    host = _host(page.url)
    nameservers = await _nameservers(host, ctx)
    parked = False
    for_sale = False
    signal = None

    ns_hit = _parking_ns(nameservers)
    if ns_hit:
        parked = True
        signal = ns_hit

    chain = list(page.redirect_chain) + [page.url]
    for hop in chain:
        market = _marketplace_host(_host(hop))
        if market:
            for_sale = True
            signal = market
            break

    sale_text = FOR_SALE_RE.search(page.body)
    parked_text = PARKED_TEXT_RE.search(page.body)
    if sale_text:
        for_sale = True
        signal = sale_text.group(1)
    elif parked_text and not for_sale:
        parked = True
        if signal is None:
            signal = parked_text.group(1)

    result = LiveFetchResult(
        url=url,
        final_url=page.url,
        status="ok",
        http_status=page.status_code,
        redirect_chain=list(page.redirect_chain),
        title=_title(page.body),
        parked=parked,
        for_sale=for_sale,
        signal=signal,
        nameservers=nameservers,
    )
    dumped = result.model_dump(mode="json")
    if cache is not None:
        cache.set_json(key, dumped)
    return dumped
