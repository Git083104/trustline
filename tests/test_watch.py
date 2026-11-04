from scanner.copy import decorate
from scanner.models import Finding
from scanner.watch import (
    ISSUE_MARKER,
    apply_issue_state,
    find_watch_issue,
    issue_title,
    slack_text,
)


def _finding() -> Finding:
    return decorate(
        Finding(
            target="gone-bucket",
            kind="bucket",
            references=["deploy.yml:1"],
            severity="critical",
            model_severity="critical",
            final_severity="critical",
            classified_blast_radius=3,
            ranked_blast_radius=3,
            risk="NoSuchBucket",
            fix="re-register what you abandoned",
            evidence={"bucket_probe": {"status": "NoSuchBucket"}},
            locations=[{"file": "deploy.yml", "line": 1}],
        )
    )


def test_watch_opens_and_closes_one_issue():
    finding = _finding()
    created = apply_issue_state(existing=None, count=1, findings=[finding])
    assert created["action"] == "create"
    assert created["title"] == issue_title(1)
    assert ISSUE_MARKER in created["body"]
    assert finding.headline in created["body"]
    updated = apply_issue_state(
        existing={"number": 9, "title": created["title"]},
        count=2,
        findings=[finding, finding],
    )
    assert updated["action"] == "update"
    assert updated["number"] == 9
    assert updated["state"] == "open"
    closed = apply_issue_state(
        existing={"number": 9},
        count=0,
        findings=[],
    )
    assert closed["action"] == "close"
    assert closed["state"] == "closed"
    assert apply_issue_state(existing=None, count=0, findings=[])["action"] == "none"


def test_watch_finds_marked_issue_and_slack_copy():
    hit = find_watch_issue(
        [{"title": "other", "body": ""}, {"title": "Tether: 1 takeover risks", "body": ISSUE_MARKER}]
    )
    assert hit and hit["title"].startswith("Tether:")
    assert "2 takeover risks" in slack_text(count=2, issue_url="https://example/issue/1")
    assert "0 takeover risks" in slack_text(count=0, issue_url="https://example/issue/1")
