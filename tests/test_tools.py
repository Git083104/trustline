import pytest

from scanner.lookups import LookupCache
from scanner.models import RdapResult
from scanner.tools import ToolContext, definitions, run


def test_definitions_include_lookup_tools_and_done():
    names = {item["function"]["name"] for item in definitions()}
    assert names == {
        "rdap",
        "dns",
        "bucket_probe",
        "cert_history",
        "wayback",
        "done",
    }


@pytest.mark.asyncio
async def test_run_done_and_unknown_tool(tmp_path):
    ctx = ToolContext(cache=LookupCache(tmp_path / "c.db"))
    result = await run("done", {"summary": "ok"}, ctx)
    assert result == {"done": True, "summary": "ok"}
    with pytest.raises(KeyError):
        await run("nope", {}, ctx)


@pytest.mark.asyncio
async def test_run_rdap_uses_context(tmp_path):
    async def fake_rdap(domain, cache=None):
        return RdapResult(domain=domain, status="unregistered")

    ctx = ToolContext(cache=LookupCache(tmp_path / "c.db"), rdap=fake_rdap)
    result = await run("rdap", {"domain": "cdn-assets-trustmap-7f3k2.com"}, ctx)
    assert result["status"] == "unregistered"
