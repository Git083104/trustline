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
    assert set(public) == {
        "target",
        "kind",
        "severity",
        "model_severity",
        "floor_reason",
        "risk",
        "fix",
        "evidence_line",
        "references",
        "cost_usd",
    }
    assert "evidence" not in public
