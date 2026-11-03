import json
from pathlib import Path

from scanner.classify import (
    classify,
    classify_by_rule,
    runs_in_mismatch_table,
    type_mismatch_table,
)
from scanner.extract import actionable, extract
from scanner.llm import FakeModelClient, RawCompletion
from scanner.lookups import LookupCache
from scanner.models import Reference

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "demo_repo"
EXPECTED_PATH = Path(__file__).parent / "fixtures" / "expected.json"


def _expected_by_loc() -> dict[tuple[str, int], dict]:
    rows = json.loads(EXPECTED_PATH.read_text())["references"]
    return {(row["file"], row["line"]): row for row in rows}


def _handler_from_expected(request):
    payload = json.loads(request["user"].split("\n", 1)[1])
    expected = _expected_by_loc()
    items = []
    for ref in payload["references"]:
        exp = expected[(ref["file"], ref["line"])]
        items.append(
            {
                "id": ref["id"],
                "type": exp["type"],
                "runs_in": exp["runs_in"],
                "blast_radius": 0 if exp["type"] in {"docs", "test"} else 2,
                "confidence": 0.9,
                "reason": f"{exp['type']} at {ref['file']}",
            }
        )
    return {"items": items}


def test_classify_by_rule_covers_obvious_shapes():
    bucket = Reference(
        file="deploy/infra.yaml",
        line=3,
        raw="s3://missing",
        host_or_bucket="missing",
        context="bucket: s3://missing",
    )
    uses = Reference(
        file=".github/workflows/ci.yml",
        line=7,
        raw="actions/checkout@v4",
        host_or_bucket="github.com/actions/checkout",
        context="        uses: actions/checkout@v4",
        action_owner="actions",
        action_repo="checkout",
        action_ref="v4",
    )
    docker = Reference(
        file="Dockerfile",
        line=2,
        raw="https://bootstrap.install.example.com/get-pip.py",
        host_or_bucket="bootstrap.install.example.com",
        context="ADD https://bootstrap.install.example.com/get-pip.py /tmp/get-pip.py",
    )
    script = Reference(
        file="index.html",
        line=7,
        raw="https://cdn.example.net/lib.js",
        host_or_bucket="cdn.example.net",
        context='<script src="https://cdn.example.net/lib.js">',
        tag="script",
    )
    assert classify_by_rule(bucket).type == "bucket"
    assert classify_by_rule(uses).runs_in == "ci"
    assert classify_by_rule(docker).runs_in == "build"
    assert classify_by_rule(script).type == "script"
    ambiguous = Reference(
        file="backend/settings.py",
        line=2,
        raw="https://billing.vendor.example.net/api",
        host_or_bucket="billing.vendor.example.net",
        context="BILLING_URL = 'https://billing.vendor.example.net/api'",
    )
    assert classify_by_rule(ambiguous) is None
    docs = Reference(
        file="README.md",
        line=3,
        raw="https://handbook.acme-demo.example.org/setup",
        host_or_bucket="handbook.acme-demo.example.org",
        context="See https://handbook.acme-demo.example.org/setup",
    )
    assert classify_by_rule(docs).runs_in == "docs_only"
    npm = Reference(
        file="package.json",
        line=4,
        raw="https://registry.npmjs.org/left-pad/-/left-pad-1.0.0.tgz",
        host_or_bucket="registry.npmjs.org",
        domain="npmjs.org",
    )
    assert classify_by_rule(npm) is not None
    allowlisted = Reference(
        file="public/index.html",
        line=1,
        raw="http://www.w3.org/1999/xhtml",
        host_or_bucket="www.w3.org",
        domain="w3.org",
    )
    assert classify_by_rule(allowlisted).runs_in == "docs_only"
    config_api = Reference(
        file="src/config.js",
        line=4,
        raw="https://api.stripe.com",
        host_or_bucket="api.stripe.com",
        domain="stripe.com",
        context="STRIPE_API = 'https://api.stripe.com'",
    )
    assert classify_by_rule(config_api).type == "api"
    s3_url = Reference(
        file="deploy/infra.yaml",
        line=9,
        raw="https://my-bucket.s3.amazonaws.com/app.zip",
        host_or_bucket="my-bucket.s3.amazonaws.com",
        domain="amazonaws.com",
    )
    assert classify_by_rule(s3_url).type == "bucket"


def test_classify_model_batches_are_at_most_five(tmp_path):
    refs = [
        Reference(
            file="app.py",
            line=i + 1,
            raw=f"https://api{i}.vendor.example.net/v1",
            host_or_bucket=f"api{i}.vendor.example.net",
        )
        for i in range(12)
    ]
    sizes: list[int] = []

    def handler(request):
        payload = json.loads(request["user"].split("\n", 1)[1])
        sizes.append(len(payload["references"]))
        return {
            "items": [
                {
                    "id": item["id"],
                    "type": "api",
                    "runs_in": "server",
                    "blast_radius": 1,
                    "confidence": 0.5,
                    "reason": "api",
                }
                for item in payload["references"]
            ]
        }

    got = classify(
        refs,
        client=FakeModelClient(handler),
        include_filtered=True,
        cache=LookupCache(tmp_path / "c.db"),
    )
    assert len(got) == 12
    assert sizes
    assert max(sizes) <= 5
    assert len(sizes) >= 3


def test_classify_defaults_to_actionable_only(tmp_path):
    refs = extract(str(FIXTURE_ROOT))
    client = FakeModelClient(_handler_from_expected)
    got = classify(refs, client=client, cache=LookupCache(tmp_path / "c.db"))
    assert len(got) == len(actionable(refs))
    assert {item.host_or_bucket for item in got} <= {
        ref.host_or_bucket for ref in actionable(refs)
    }
    # obvious buckets, Actions uses:, and script URLs are classified in code
    for call in client.calls:
        payload = json.loads(call["user"].split("\n", 1)[1])
        for item in payload["references"]:
            assert not str(item["raw"]).lower().startswith("s3://")


def test_include_filtered_fixture_type_accuracy(tmp_path):
    refs = extract(str(FIXTURE_ROOT))
    expected = json.loads(EXPECTED_PATH.read_text())["references"]
    logs = []
    client = FakeModelClient(_handler_from_expected)
    got = classify(
        refs,
        client=client,
        include_filtered=True,
        cache=LookupCache(tmp_path / "c.db"),
        logs=logs,
    )
    assert len(got) == len(expected)
    mismatches = type_mismatch_table(got, expected)
    runs_m = runs_in_mismatch_table(got, expected)
    print("type mismatches:")
    if not mismatches:
        print("(none)")
    for file, line, exp, actual in mismatches:
        print(f"  {file}:{line} expected={exp} got={actual}")
    matched = len(expected) - len(mismatches)
    assert matched / len(expected) >= 0.9
    assert len(runs_m) == 0
    if logs:
        assert logs[0].api_usage is not None


def test_wrong_ids_are_retried(tmp_path):
    refs = [
        Reference(file="a.py", line=1, raw="https://kept.example.net/x", host_or_bucket="kept.example.net")
    ]
    attempts = {"n": 0}

    def handler(request):
        attempts["n"] += 1
        payload = json.loads(request["user"].split("\n", 1)[1])
        ref_id = payload["references"][0]["id"]
        item = {
            "id": "nope" if attempts["n"] == 1 else ref_id,
            "type": "api",
            "runs_in": "server",
            "blast_radius": 1,
            "confidence": 0.5,
            "reason": "api",
        }
        return {"items": [item]}

    got = classify(
        refs,
        client=FakeModelClient(handler),
        include_filtered=True,
        cache=LookupCache(tmp_path / "c.db"),
    )
    assert attempts["n"] == 2
    assert got[0].id == "0"


def test_context_is_redacted_before_model(tmp_path):
    refs = [
        Reference(
            file="a.py",
            line=1,
            raw="https://api.vendor.example.net/v1",
            host_or_bucket="api.vendor.example.net",
            context="headers = {token=supersecrettokenvalue1234}",
        )
    ]

    def handler(request):
        assert "supersecrettokenvalue1234" not in request["user"]
        assert "token=[REDACTED]" in request["user"]
        return {
            "items": [
                {
                    "id": "0",
                    "type": "api",
                    "runs_in": "server",
                    "blast_radius": 1,
                    "confidence": 0.8,
                    "reason": "api base url",
                }
            ]
        }

    classify(
        refs,
        client=FakeModelClient(handler),
        include_filtered=True,
        cache=LookupCache(tmp_path / "c.db"),
    )


def test_fake_client_never_needs_api_key(tmp_path):
    client = FakeModelClient(
        lambda request: RawCompletion(
            text=json.dumps(
                {
                    "items": [
                        {
                            "id": "0",
                            "type": "bucket",
                            "runs_in": "build",
                            "blast_radius": 3,
                            "confidence": 1,
                            "reason": "s3",
                        }
                    ]
                }
            ),
            usage={"input_tokens": 20, "output_tokens": 8, "cost": 0.0001},
        )
    )
    refs = [
        Reference(
            file="settings.py",
            line=3,
            raw="https://billing.vendor.example.net/api",
            host_or_bucket="billing.vendor.example.net",
        )
    ]
    logs = []
    classify(
        refs,
        client=client,
        include_filtered=True,
        cache=LookupCache(tmp_path / "c.db"),
        logs=logs,
    )
    assert logs[0].api_usage is not None
    assert "cost" in logs[0].api_usage
    assert logs[0].cost_usd == cost_from_tokens(20, 8)


def cost_from_tokens(inp: int, out: int) -> float:
    from scanner.llm import cost_usd

    return cost_usd("muse-spark-1.3", inp, out)
