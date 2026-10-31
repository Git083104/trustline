import os
from pathlib import Path

import pytest
from dotenv import load_dotenv

from scanner.lookups import LookupCache, bucket_probe, dns, rdap

load_dotenv(Path(__file__).resolve().parents[1] / ".env", override=True)

pytestmark = pytest.mark.slow


@pytest.mark.asyncio
async def test_live_rdap_unregistered_trustmap_com(tmp_path):
    result = await rdap(
        "cdn-assets-trustmap-7f3k2.com", cache=LookupCache(tmp_path / "c.db")
    )
    assert result.status == "unregistered"


@pytest.mark.asyncio
async def test_live_dns_known_good_and_nxdomain(tmp_path):
    cache = LookupCache(tmp_path / "c.db")
    good = await dns("example.com", cache=cache)
    gone = await dns(
        "cdn.this-host-does-not-resolve-trustmap.invalid", cache=cache
    )
    assert good.status == "resolves"
    assert gone.status == "nxdomain"


@pytest.mark.asyncio
async def test_live_rdap_known_registered(tmp_path):
    result = await rdap("example.com", cache=LookupCache(tmp_path / "c.db"))
    assert result.status == "registered"


@pytest.mark.asyncio
async def test_live_s3_bucket_from_env(tmp_path, capsys):
    live = os.environ.get("TRUSTMAP_BUCKET_LIVE")
    gone = os.environ.get("TRUSTMAP_BUCKET_GONE")
    if not live or not gone:
        pytest.skip("TRUSTMAP_BUCKET_LIVE and TRUSTMAP_BUCKET_GONE are not set")
    cache = LookupCache(tmp_path / "c.db")
    exists = await bucket_probe(live, "s3", cache=cache)
    missing = await bucket_probe(gone, "s3", cache=cache)
    print(f"LIVE {live}: status={exists.status} http_status={exists.http_status}")
    print(f"GONE {gone}: status={missing.status} http_status={missing.http_status}")
    assert exists.status == "exists"
    assert missing.status == "NoSuchBucket"
