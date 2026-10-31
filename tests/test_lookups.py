from datetime import date

import dns.resolver as dns_resolver
import httpx
import pytest

from scanner.lookups import (
    LookupCache,
    bucket_probe,
    cert_history,
    dns,
    rdap,
    wayback,
)

BOOTSTRAP = {"services": [[["com"], ["https://rdap.test/com/"]]]}


def _rdap_transport() -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        url = str(request.url)
        if "data.iana.org/rdap/dns.json" in url:
            return httpx.Response(200, json=BOOTSTRAP)
        if url.endswith("/domain/gone.com"):
            return httpx.Response(404)
        if url.endswith("/domain/live.com"):
            return httpx.Response(
                200,
                json={
                    "status": ["active"],
                    "entities": [
                        {
                            "roles": ["registrar"],
                            "vcardArray": [
                                "vcard",
                                [["fn", {}, "text", "Example Registrar"]],
                            ],
                        }
                    ],
                    "events": [
                        {
                            "eventAction": "expiration",
                            "eventDate": "2099-01-01T00:00:00Z",
                        }
                    ],
                },
            )
        return httpx.Response(500, text="unexpected " + url)

    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_rdap_404_is_unregistered(tmp_path):
    cache = LookupCache(tmp_path / "c.db")
    async with httpx.AsyncClient(transport=_rdap_transport()) as client:
        gone = await rdap("gone.com", client=client, cache=cache)
        live = await rdap("live.com", client=client, cache=cache)
    assert gone.status == "unregistered"
    assert live.status == "registered"
    assert live.registrar == "Example Registrar"
    assert live.expiry == date(2099, 1, 1)
    assert live.days_to_expiry is not None
    assert live.days_to_expiry > 0


@pytest.mark.asyncio
async def test_cache_expires_after_ttl(tmp_path):
    clock = [1_000_000.0]
    cache = LookupCache(tmp_path / "c.db", ttl_s=24 * 60 * 60, now=lambda: clock[0])
    async with httpx.AsyncClient(transport=_rdap_transport()) as client:
        first = await rdap("gone.com", client=client, cache=cache)
        assert first.status == "unregistered"
        clock[0] += 23 * 60 * 60
        cached = await rdap("gone.com", client=client, cache=cache)
        assert cached.status == "unregistered"
        clock[0] += 2 * 60 * 60
        async with httpx.AsyncClient(transport=_rdap_transport()) as client2:
            again = await rdap("gone.com", client=client2, cache=cache)
        assert again.status == "unregistered"


@pytest.mark.asyncio
async def test_dns_nxdomain_and_cname_chain(tmp_path):
    cache = LookupCache(tmp_path / "c.db")

    async def query(name: str, rdtype: str) -> list[str]:
            if name == "gone.example":
                raise dns_resolver.NXDOMAIN()
            if name == "www.shop.test" and rdtype == "CNAME":
                return ["cdn.shop.test"]
            if name == "cdn.shop.test" and rdtype == "CNAME":
                raise dns_resolver.NoAnswer()
            if name == "cdn.shop.test" and rdtype == "A":
                return ["203.0.113.9"]
            if rdtype == "AAAA":
                raise dns_resolver.NoAnswer()
            raise dns_resolver.NoAnswer()

    gone = await dns("gone.example", query=query, cache=cache)
    ok = await dns("www.shop.test", query=query, cache=cache)
    assert gone.status == "nxdomain"
    assert ok.status == "resolves"
    assert ok.cnames == ["cdn.shop.test"]
    assert ok.addresses == ["203.0.113.9"]


@pytest.mark.asyncio
async def test_bucket_probe_s3_and_gcs_get_only(tmp_path):
    cache = LookupCache(tmp_path / "c.db")
    methods: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        methods.append(request.method)
        url = str(request.url)
        if "missing.s3.amazonaws.com" in url:
            return httpx.Response(
                404, text="<Error><Code>NoSuchBucket</Code></Error>"
            )
        if "private.s3.amazonaws.com" in url:
            return httpx.Response(403, text="<Error><Code>AccessDenied</Code></Error>")
        if "redirect.s3.amazonaws.com" in url:
            return httpx.Response(
                301, text="<Error><Code>PermanentRedirect</Code></Error>"
            )
        if "storage.googleapis.com/gone-gcs" in url:
            return httpx.Response(404, text="Not Found")
        if "storage.googleapis.com/live-gcs" in url:
            return httpx.Response(200, text="ok")
        return httpx.Response(500)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        missing = await bucket_probe("missing", "s3", client=client, cache=cache)
        denied = await bucket_probe("private", "s3", client=client, cache=cache)
        redirected = await bucket_probe("redirect", "s3", client=client, cache=cache)
        gcs_gone = await bucket_probe("gone-gcs", "gcs", client=client, cache=cache)
        gcs_live = await bucket_probe("live-gcs", "gcs", client=client, cache=cache)
    assert set(methods) == {"GET"}
    assert missing.status == "NoSuchBucket"
    assert denied.status == "exists"
    assert redirected.status == "exists"
    assert gcs_gone.status == "NoSuchBucket"
    assert gcs_live.status == "exists"


@pytest.mark.asyncio
async def test_cert_history_unavailable_on_failure(tmp_path):
    cache = LookupCache(tmp_path / "c.db")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(504, text="timeout")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await cert_history("example.com", client=client, cache=cache)
    assert result.status == "unavailable"


@pytest.mark.asyncio
async def test_wayback_first_and_last(tmp_path):
    cache = LookupCache(tmp_path / "c.db")

    def handler(request: httpx.Request) -> httpx.Response:
        latest = request.url.params.get("fastLatest")
        if latest:
            return httpx.Response(
                200, json=[["timestamp", "digest"], ["20200101000000", "bbb"]]
            )
        return httpx.Response(
            200, json=[["timestamp", "digest"], ["20100101000000", "aaa"]]
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await wayback("https://shop.example/x", client=client, cache=cache)
    assert result.status == "ok"
    assert result.first_snapshot == "20100101000000"
    assert result.first_digest == "aaa"
    assert result.last_snapshot == "20200101000000"
    assert result.last_digest == "bbb"
