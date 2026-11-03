from scanner.events import finding_public, summarize
from scanner.models import Finding


def test_summarize_truncates_and_redacts():
    long = summarize({"pad": "x" * 500})
    assert len(long) <= 403
    assert long.endswith("...")
    redacted = summarize("api_key=sk-live-abcdefghijklmnopqrstuvwxyz")
    assert "sk-live" not in redacted
    assert summarize({"ok": True}) == '{"ok": true}'


def test_finding_public_fields():
    item = Finding(
        target="gone-bucket",
        kind="bucket",
        references=["deploy/infra.yaml:3"],
        severity="critical",
        model_severity="high",
        final_severity="critical",
        classified_blast_radius=2,
        ranked_blast_radius=3,
        risk="claimable",
        fix="Remove or replace this reference.",
        floor_reason="NoSuchBucket",
        evidence_line="Evidence: bucket does not exist",
        cost_usd=0.01,
    )
    public = finding_public(item)
    assert public["references"] == ["deploy/infra.yaml:3"]
    with_loc = item.model_copy(
        update={
            "locations": [
                {
                    "page_url": "https://shop.example/",
                    "file": "https://shop.example/",
                    "line": 7,
                    "tag": "script",
                    "attribute": "src",
                    "raw": "https://cdn.polyfill.io/v3/polyfill.min.js",
                    "sri": False,
                    "loaded_by": "html",
                }
            ]
        }
    )
    assert finding_public(with_loc)["references"][0]["page_url"] == "https://shop.example/"
    assert public["tranco_rank"] is None
    assert public["parked"] is False
    assert public["for_sale"] is False
    for key in (
        "evidence",
        "floor_applied",
        "tranco_rank",
        "action_ref",
        "action_sha_pinned",
    ):
        assert key in public


def _ref(**kwargs):
    from scanner.models import Reference

    base = {"file": "index.html", "line": 1, "raw": "https://cdn.acme.dev/a.js", "host_or_bucket": "cdn.acme.dev", "domain": "acme.dev"}
    return Reference(**{**base, **kwargs})


def test_gather_public_groups_by_target_and_counts_what_was_set_aside():
    from scanner.events import gather_public

    refs = [
        _ref(),
        _ref(file="app.js", line=4, host_or_bucket="api.acme.dev"),
        _ref(file="infra.yaml", line=2, raw="s3://gone-bucket", host_or_bucket="gone-bucket", domain=""),
        _ref(line=9, raw="https://docs.example.com/x", host_or_bucket="docs.example.com", domain="example.com", filter_reason="reserved_domain"),
        _ref(line=10, raw="api_key=sk-live-abcdefghijklmnopqrstuvwxyz https://x.acme.dev", host_or_bucket="x.acme.dev"),
    ]
    out = gather_public(refs)
    rows = {row["target"]: row for row in out["targets"]}
    assert rows["acme.dev"]["refs"] == 3
    assert rows["acme.dev"]["files"] == 2
    assert rows["gone-bucket"]["kind"] == "bucket"
    assert out["targets_total"] == 2
    assert out["set_aside"] == {"reserved_domain": {"count": 1, "examples": ["docs.example.com"]}}
    assert all("sk-live" not in row["first"]["raw"] for row in out["targets"])


def test_classified_public_lists_only_actionable_references():
    from scanner.events import classified_public
    from scanner.models import Classification

    keep = _ref()
    noise = _ref(line=2, host_or_bucket="docs.example.com", domain="example.com", filter_reason="reserved_domain")

    def cl(ref, **kw):
        return Classification(id="0", file=ref.file, line=ref.line, host_or_bucket=ref.host_or_bucket,
                              type=kw.get("type", "script"), runs_in="browser", blast_radius=3,
                              confidence=0.8, reason="loaded by a script tag")

    out = classified_public([(keep, cl(keep)), (noise, cl(noise))])
    assert out["total"] == 1
    assert out["items"][0]["target"] == "acme.dev"
    assert out["items"][0]["blast_radius"] == 3


def test_classified_public_counts_where_every_reference_runs():
    # the page lists the first LIST_LIMIT references, but its summary counts all of them
    from scanner.events import LIST_LIMIT, classified_public
    from scanner.models import Classification

    pairs = []
    for i in range(LIST_LIMIT + 20):
        ref = _ref(line=i + 1)
        runs = "ci" if i < LIST_LIMIT else "browser"
        pairs.append((ref, Classification(id=str(i), file=ref.file, line=ref.line, host_or_bucket=ref.host_or_bucket,
                                          type="script", runs_in=runs, blast_radius=2, confidence=0.9, reason="x")))
    out = classified_public(pairs)
    assert len(out["items"]) == LIST_LIMIT
    assert out["total"] == LIST_LIMIT + 20
    assert out["runs_in"] == {"ci": LIST_LIMIT, "browser": 20}
