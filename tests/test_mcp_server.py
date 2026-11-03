import pytest

from scanner.lookups import LookupCache
from scanner.mcp_server import READONLY, create_server
from scanner.models import DnsResult, Finding, RdapResult
from scanner.tools import ToolContext


@pytest.mark.asyncio
async def test_mcp_tools_are_readonly_lookups_plus_scan(tmp_path):
    ctx = ToolContext(cache=LookupCache(tmp_path / "c.db"))
    server = create_server(ctx=ctx)
    tools = {item.name: item for item in await server.list_tools()}
    assert set(tools) == {
        "dns",
        "rdap",
        "bucket_probe",
        "cert_history",
        "wayback",
        "platform_takeover",
        "github_owner",
        "live_fetch",
        "scan",
        "propose_fix",
    }
    assert tools["propose_fix"].annotations is not None
    assert tools["propose_fix"].annotations.readOnlyHint is False
    for name, item in tools.items():
        if name == "propose_fix":
            continue
        assert item.annotations is not None
        assert item.annotations.readOnlyHint is True
        assert item.annotations.destructiveHint is False
    assert READONLY.readOnlyHint is True


@pytest.mark.asyncio
async def test_lookup_tools_use_injected_context(tmp_path):
    async def fake_dns(host, cache=None):
        return DnsResult(host=host, status="nxdomain")

    async def fake_rdap(domain, cache=None):
        return RdapResult(domain=domain, status="unregistered")

    ctx = ToolContext(
        cache=LookupCache(tmp_path / "c.db"),
        dns=fake_dns,
        rdap=fake_rdap,
    )
    server = create_server(ctx=ctx)
    dns_out = await server.call_tool("dns", {"host": "cdn-assets-trustmap-7f3k2.com"})
    rdap_out = await server.call_tool(
        "rdap", {"domain": "cdn-assets-trustmap-7f3k2.com"}
    )
    assert _payload(dns_out)["status"] == "nxdomain"
    assert _payload(rdap_out)["status"] == "unregistered"


@pytest.mark.asyncio
async def test_scan_tool_does_not_call_live_api(tmp_path):
    async def fake_scan(target: str):
        return [
            Finding(
                target=target,
                kind="domain",
                references=["index.html:7"],
                severity="critical",
                model_severity="critical",
                final_severity="critical",
                classified_blast_radius=3,
                ranked_blast_radius=3,
                risk="Unregistered host.",
                fix="Remove this reference.",
            )
        ]

    ctx = ToolContext(cache=LookupCache(tmp_path / "c.db"))
    server = create_server(ctx=ctx, scan_fn=fake_scan)
    out = await server.call_tool("scan", {"target": "cdn-assets-trustmap-7f3k2.com"})
    payload = _payload(out)
    assert payload["findings"][0]["severity"] == "critical"
    assert payload["findings"][0]["target"] == "cdn-assets-trustmap-7f3k2.com"


def _payload(result):
    if isinstance(result, dict):
        return result
    if isinstance(result, tuple) and result:
        structured = result[-1]
        if isinstance(structured, dict):
            return structured
        first = result[0]
        if isinstance(first, dict):
            return first
        if isinstance(first, list) and first:
            text = getattr(first[0], "text", None)
            if text:
                import json

                return json.loads(text)
    raise AssertionError(f"unexpected tool result: {result!r}")
