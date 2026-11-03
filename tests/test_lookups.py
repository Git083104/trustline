import asyncio
from datetime import date

import dns.resolver as dns_resolver
import httpx
import pytest

from scanner.agent import has_hard_signal
from scanner.lookups import (
    LookupCache,
    bucket_probe,
    cert_history,
    consistent_evidence,
    dns,
    github_owner,
    github_repo,
    platform_takeover,
    rdap,
    wayback,
)
from scanner.models import DnsResult
from eval.run_eval import baseline_severity
from scanner.report import evidence_line, is_claimable

BOOTSTRAP = {"services": [[["com"], ["https://rdap.verisign.com/com/v1/"]]]}


def _rdap_transport() -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        url = str(request.url)
        if "data.iana.org/rdap/dns.json" in url:
            return httpx.Response(200, json=BOOTSTRAP)
        if url.endswith("/domain/gone.com") or url.endswith(
            "/domain/cdn-assets-trustmap-7f3k2.com"
        ):
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
        if "rdap.org" in url:
            return httpx.Response(404)
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
async def test_rdap_ro_without_service_is_unknown(tmp_path):
    cache = LookupCache(tmp_path / "c.db")
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        seen.append(url)
        if "data.iana.org/rdap/dns.json" in url:
            return httpx.Response(200, json=BOOTSTRAP)
        if "rdap.org" in url:
            return httpx.Response(404)
        return httpx.Response(500, text="unexpected " + url)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await rdap("ionelmc.ro", client=client, cache=cache)
    assert result.status == "unknown"
    assert not any("rdap.org" in url for url in seen)


@pytest.mark.asyncio
async def test_rdap_verisign_com_404_is_unregistered(tmp_path):
    cache = LookupCache(tmp_path / "c.db")
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        seen.append(url)
        if "data.iana.org/rdap/dns.json" in url:
            return httpx.Response(200, json=BOOTSTRAP)
        if "rdap.verisign.com/com/v1/domain/cdn-assets-trustmap-7f3k2.com" in url:
            return httpx.Response(404)
        if "rdap.org" in url:
            return httpx.Response(404)
        return httpx.Response(500, text="unexpected " + url)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await rdap(
            "cdn-assets-trustmap-7f3k2.com", client=client, cache=cache
        )
    assert result.status == "unregistered"
    assert any("rdap.verisign.com" in url for url in seen)
    assert not any("rdap.org" in url for url in seen)


def test_dns_resolves_and_rdap_404_is_not_unregistered(caplog):
    caplog.set_level("WARNING", logger="trustmap")
    evidence = consistent_evidence(
        {
            "dns": {"status": "resolves", "host": "ionelmc.ro"},
            "rdap": {"status": "unregistered", "domain": "ionelmc.ro"},
        }
    )
    assert evidence["rdap"]["status"] == "unknown"
    assert not has_hard_signal(evidence)
    assert not is_claimable(evidence)
    assert baseline_severity(evidence) == "low"
    line = evidence_line(
        {
            "target": "ionelmc.ro",
            "rows": [],
            "evidence": {
                "dns": {"status": "resolves", "host": "ionelmc.ro"},
                "rdap": {"status": "unregistered", "domain": "ionelmc.ro"},
            },
        }
    )
    assert "not registered" not in line
    assert "DNS resolves" in line
    assert "contradicts DNS resolves" in caplog.text


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
async def test_dns_timeout_status(tmp_path, monkeypatch):
    monkeypatch.setattr("scanner.lookups.DNS_TIMEOUT_S", 0.05)

    async def query(name: str, rdtype: str) -> list[str]:
        await asyncio.sleep(1)
        return ["203.0.113.9"]

    result = await dns("slow.example", query=query, cache=LookupCache(tmp_path / "c.db"))
    assert result.status == "timeout"


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
async def test_azure_bucket_probe_from_dns_cache(tmp_path):
    cache = LookupCache(tmp_path / "c.db")
    cache.set_json(
        "dns:goneacct.blob.core.windows.net",
        DnsResult(host="goneacct.blob.core.windows.net", status="nxdomain").model_dump(
            mode="json"
        ),
    )
    cache.set_json(
        "dns:liveacct.blob.core.windows.net",
        DnsResult(
            host="liveacct.blob.core.windows.net",
            status="resolves",
            addresses=["203.0.113.9"],
        ).model_dump(mode="json"),
    )
    gone = await bucket_probe("goneacct", "azure", cache=cache)
    live = await bucket_probe("liveacct", "azure", cache=cache)
    assert gone.status == "NoSuchBucket"
    assert gone.provider == "azure"
    assert live.status == "exists"


@pytest.mark.asyncio
async def test_platform_takeover_skips_and_matches_fingerprint(tmp_path):
    cache = LookupCache(tmp_path / "c.db")
    skipped = await platform_takeover("cdn.example.com", cache=cache)
    assert skipped.status == "skipped"
    methods: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        methods.append(request.method)
        return httpx.Response(404, text="There isn't a GitHub Pages site here")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        hit = await platform_takeover(
            "gone.github.io", client=client, cache=LookupCache(tmp_path / "p.db")
        )
    assert set(methods) == {"GET"}
    assert hit.status == "unclaimed"
    assert hit.takeover == "vulnerable"
    assert hit.platform == "GitHub Pages"
    nx = await platform_takeover(
        "missing.azurewebsites.net",
        dns_status="nxdomain",
        cache=LookupCache(tmp_path / "n.db"),
    )
    assert nx.status == "unclaimed"
    assert nx.takeover == "vulnerable"
    assert nx.signal == "NXDOMAIN"


@pytest.mark.asyncio
async def test_github_owner_missing_with_token(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghs_testtoken_not_a_secret_value")
    seen_auth: list[bool] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_auth.append("Authorization" in request.headers)
        assert request.method == "GET"
        if "api.github.com" in str(request.url):
            return httpx.Response(404, json={"message": "Not Found"})
        return httpx.Response(500)

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), follow_redirects=False
    ) as client:
        result = await github_owner(
            "missing-org", client=client, cache=LookupCache(tmp_path / "g.db")
        )
    assert result.status == "missing"
    assert result.exists is False
    assert seen_auth == [True]


@pytest.mark.asyncio
async def test_github_repo_missing_with_token(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghs_testtoken_not_a_secret_value")

    def handler(request: httpx.Request) -> httpx.Response:
        assert "Authorization" in request.headers
        assert request.method == "GET"
        assert "/repos/actions/gone" in str(request.url)
        return httpx.Response(404, json={"message": "Not Found"})

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), follow_redirects=False
    ) as client:
        result = await github_repo(
            "actions", "gone", client=client, cache=LookupCache(tmp_path / "r.db")
        )
    assert result.status == "missing"
    assert result.exists is False


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


def test_default_cache_lives_in_tmp_on_serverless_hosts(monkeypatch):
    import scanner.lookups as lookups

    monkeypatch.setattr(lookups, "LookupCache", lambda path: path)
    monkeypatch.delenv("TRUSTMAP_CACHE_DB", raising=False)
    monkeypatch.delenv("TRUSTMAP_SERVERLESS", raising=False)
    monkeypatch.delenv("VERCEL", raising=False)
    assert lookups.default_cache() == "trustmap.db"
    monkeypatch.setenv("VERCEL", "1")
    assert lookups.default_cache() == "/tmp/trustmap.db"
    monkeypatch.setenv("TRUSTMAP_CACHE_DB", "/var/data/trustmap.db")
    assert lookups.default_cache() == "/var/data/trustmap.db"


def test_default_cache_moves_to_tmp_when_the_app_folder_is_read_only(monkeypatch):
    import scanner.lookups as lookups

    monkeypatch.setattr(lookups, "LookupCache", lambda path: path)
    monkeypatch.delenv("TRUSTMAP_CACHE_DB", raising=False)
    monkeypatch.delenv("TRUSTMAP_SERVERLESS", raising=False)
    monkeypatch.delenv("VERCEL", raising=False)
    monkeypatch.setattr(lookups.os, "access", lambda path, mode: False)
    assert lookups.default_cache() == "/tmp/trustmap.db"


@pytest.mark.asyncio
async def test_github_repo_disabled_reads_the_same_from_api_and_web(tmp_path, monkeypatch):
    # Element's CI uses an Action whose repo GitHub has disabled. The API says
    # "Repository access blocked"; the web page says "This repository has been
    # disabled." Both must give one answer, or the same scan flips between runs.
    def api(request: httpx.Request) -> httpx.Response:
        if "api.github.com" in str(request.url):
            return httpx.Response(403, json={"message": "Repository access blocked", "block": {"reason": "tos"}})
        return httpx.Response(500)

    def web(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html><h2>This repository has been disabled.</h2></html>")

    answers = []
    monkeypatch.setenv("GITHUB_TOKEN", "ghs_testtoken_not_a_secret_value")
    async with httpx.AsyncClient(transport=httpx.MockTransport(api), follow_redirects=False) as client:
        answers.append(await github_repo("actions-cool", "maintain-one-comment", client=client, cache=LookupCache(tmp_path / "a.db")))
    monkeypatch.delenv("GITHUB_TOKEN")
    async with httpx.AsyncClient(transport=httpx.MockTransport(web), follow_redirects=False) as client:
        answers.append(await github_repo("actions-cool", "maintain-one-comment", client=client, cache=LookupCache(tmp_path / "b.db")))
    assert [item.status for item in answers] == ["disabled", "disabled"]
    assert all(item.exists is True for item in answers)
