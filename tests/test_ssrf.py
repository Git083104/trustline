import pytest

from scanner.ssrf import (
    SCAN_BLOCKED,
    ScanBlockedError,
    is_blocked_ip,
    parse_public_url,
    refuse_blocked_ips,
)
from scanner.website import safe_get

BLOCKED_URLS = [
    "http://localhost/",
    "http://127.0.0.1/",
    "http://10.0.0.1/",
    "http://169.254.169.254/",
    "http://[::1]/",
]


def test_blocked_ip_classes():
    for ip in (
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "::1",
        "::ffff:10.0.0.1",
        "224.0.0.1",
        "0.0.0.0",
        "240.0.0.1",
    ):
        assert is_blocked_ip(ip), ip
    assert not is_blocked_ip("8.8.8.8")


def test_credentials_and_ports_refused(monkeypatch):
    monkeypatch.delenv("TRUSTMAP_ALLOW_LOCAL_SCAN", raising=False)
    with pytest.raises(ScanBlockedError) as caught:
        parse_public_url("http://user:pass@example.com/")
    assert str(caught.value) == SCAN_BLOCKED
    with pytest.raises(ScanBlockedError):
        parse_public_url("http://example.com:8080/")
    with pytest.raises(ScanBlockedError):
        parse_public_url("ftp://example.com/")
    scheme, host, port, path = parse_public_url("https://Example.com/a?b=1")
    assert (scheme, host, port, path) == ("https", "example.com", 443, "/a?b=1")


@pytest.mark.asyncio
async def test_loopback_and_private_urls_refused(monkeypatch):
    monkeypatch.delenv("TRUSTMAP_ALLOW_LOCAL_SCAN", raising=False)

    async def send(*_args, **_kwargs):
        raise AssertionError("must not connect")

    for url in BLOCKED_URLS:
        with pytest.raises(ScanBlockedError) as caught:
            await safe_get(url, send=send)
        assert str(caught.value) == SCAN_BLOCKED
        assert "127" not in str(caught.value)
        assert "169.254" not in str(caught.value)


@pytest.mark.asyncio
async def test_hostname_resolving_to_private_refused(monkeypatch):
    monkeypatch.delenv("TRUSTMAP_ALLOW_LOCAL_SCAN", raising=False)

    async def resolve(_host):
        return ["10.0.0.1"]

    async def send(*_args, **_kwargs):
        raise AssertionError("must not connect")

    with pytest.raises(ScanBlockedError) as caught:
        await safe_get("https://evil.example/", resolve=resolve, send=send)
    assert str(caught.value) == SCAN_BLOCKED


@pytest.mark.asyncio
async def test_redirect_to_private_ip_refused(monkeypatch):
    monkeypatch.delenv("TRUSTMAP_ALLOW_LOCAL_SCAN", raising=False)

    async def resolve(host):
        if host in {"10.0.0.1", "127.0.0.1"}:
            return [host]
        return ["93.184.216.34"]

    async def send(_method, connect_url, _headers, **_kwargs):
        if "93.184.216.34" in connect_url:
            return 302, {"location": "http://10.0.0.1/secret"}, b""
        raise AssertionError(f"must not fetch {connect_url}")

    with pytest.raises(ScanBlockedError) as caught:
        await safe_get("https://public.example/", resolve=resolve, send=send)
    assert str(caught.value) == SCAN_BLOCKED


def test_mixed_resolved_addresses_refused(monkeypatch):
    monkeypatch.delenv("TRUSTMAP_ALLOW_LOCAL_SCAN", raising=False)
    with pytest.raises(ScanBlockedError):
        refuse_blocked_ips(["8.8.8.8", "10.0.0.1"])
