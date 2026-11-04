from scanner.classify import classify_by_rule
from scanner.llm import FakeModelClient
from scanner.models import Reference
from scanner.report import (
    LINK_CLICK_RISK,
    evidence_line,
    floor_decision,
    group_by_target,
    rank,
)
from scanner.sanity import has_proven_fact, unexplained_tranco_fix_today
from scanner.tools.platform_takeover import takeover_is_proven
from tests.test_report import _cl, _inv, _rank_ok


def _pages_body_fact(host: str) -> dict:
    return {
        "status": "unclaimed",
        "platform": "GitHub Pages",
        "takeover": "vulnerable",
        "signal": "There isn't a GitHub Pages site here",
        "host": host,
        "dns_proof": False,
    }


def test_body_fingerprint_without_dns_is_not_a_fact():
    evidence = {
        "platform_takeover": _pages_body_fact("disqus.com"),
        "dns": {"host": "disqus.com", "status": "resolves", "cnames": [], "addresses": []},
    }
    assert takeover_is_proven(evidence) is False
    assert has_proven_fact(evidence, ["disqus.com"]) is False


def test_github_io_suffix_is_dns_proof():
    evidence = {
        "github_owner": {"status": "missing", "exists": False},
        "platform_takeover": {
            "status": "unclaimed",
            "platform": "GitHub Pages",
            "takeover": "vulnerable",
            "host": "trustline-demo-chat.github.io",
            "dns_proof": True,
        },
    }
    assert takeover_is_proven(evidence) is True
    ref = Reference(
        file="index.html",
        line=12,
        raw="https://trustline-demo-chat.github.io/widget.js",
        host_or_bucket="trustline-demo-chat.github.io",
        domain="trustline-demo-chat.github.io",
        tag="script",
    )
    group = {
        "target": "trustline-demo-chat.github.io",
        "kind": "domain",
        "rows": [(ref, _cl(ref, type="script", runs_in="browser"), _inv(ref, evidence))],
        "evidence": evidence,
    }
    level, _reason = floor_decision(group)
    assert level == "critical"
    line = evidence_line(group)
    assert "on trustline-demo-chat.github.io" in line


def test_group_does_not_copy_platform_fact_across_hosts():
    parent = Reference(
        file="layout/comment.ejs",
        line=4,
        raw="https://disqus.com/embed.js",
        host_or_bucket="disqus.com",
        domain="disqus.com",
        tag="script",
    )
    child = Reference(
        file="layout/other.ejs",
        line=8,
        raw="https://hexo-theme.github.io/widget.js",
        host_or_bucket="hexo-theme.github.io",
        domain="hexo-theme.github.io",
        tag="script",
    )
    child_ev = {
        "dns": {
            "host": "hexo-theme.github.io",
            "status": "resolves",
            "cnames": ["hexo-theme.github.io"],
        },
        "platform_takeover": {
            "status": "unclaimed",
            "platform": "GitHub Pages",
            "takeover": "vulnerable",
            "host": "hexo-theme.github.io",
            "dns_proof": True,
        },
    }
    parent_ev = {
        "dns": {"host": "disqus.com", "status": "resolves", "cnames": []},
        "platform_takeover": child_ev["platform_takeover"],
    }
    groups = group_by_target(
        [
            (parent, _cl(parent, type="script", runs_in="browser"), _inv(parent, parent_ev)),
            (child, _cl(child, type="script", runs_in="browser"), _inv(child, child_ev)),
        ]
    )
    by_target = {group["target"]: group for group in groups}
    assert "disqus.com" in by_target
    disqus = by_target["disqus.com"]["evidence"].get("platform_takeover") or {}
    assert disqus.get("host") != "hexo-theme.github.io"
    assert takeover_is_proven(by_target["disqus.com"]["evidence"]) is False
    elm = Reference(
        file="demo/page.html",
        line=10,
        raw="https://package.elm-lang.org/docs",
        host_or_bucket="package.elm-lang.org",
        domain="elm-lang.org",
        tag="a",
    )
    elm_ev = {
        "dns": {
            "host": "package.elm-lang.org",
            "status": "resolves",
            "cnames": [],
            "addresses": ["203.0.113.8"],
        },
        "platform_takeover": _pages_body_fact("package.elm-lang.org"),
    }
    groups = group_by_target(
        [(elm, _cl(elm, type="link", runs_in="browser"), _inv(elm, elm_ev))]
    )
    assert groups[0]["target"] == "elm-lang.org"
    assert takeover_is_proven(groups[0]["evidence"]) is False


def test_imgur_heroku_body_is_not_high():
    ref = Reference(
        file="assets/img/imgur.svg",
        line=1,
        raw="https://i.imgur.com/logo.png",
        host_or_bucket="i.imgur.com",
        domain="imgur.com",
        tag="img",
    )
    evidence = {
        "dns": {"host": "i.imgur.com", "status": "resolves", "cnames": []},
        "platform_takeover": {
            "status": "unclaimed",
            "platform": "Heroku",
            "takeover": "edge case",
            "signal": "No such app",
            "host": "i.imgur.com",
            "dns_proof": False,
        },
    }
    group = {
        "target": "imgur.com",
        "kind": "domain",
        "rows": [(ref, _cl(ref, type="asset", runs_in="browser"), _inv(ref, evidence))],
        "evidence": evidence,
    }
    assert takeover_is_proven(evidence) is False
    assert floor_decision(group) == (None, "")


def test_lbryshare_share_url_is_medium_link():
    ref = Reference(
        file="ui/component/settingShareUrl/view.jsx",
        line=59,
        raw="https://lbryshare.com",
        host_or_bucket="lbryshare.com",
        domain="lbryshare.com",
        context='href={shareUrl} const shareUrl = "https://lbryshare.com"',
    )
    classified = classify_by_rule(ref)
    assert classified is not None
    assert classified.type == "link"
    evidence = {
        "rdap": {"domain": "lbryshare.com", "status": "unregistered"},
        "dns": {"host": "lbryshare.com", "status": "nxdomain"},
    }
    group_rows = [
        (ref, classified, _inv(ref, evidence)),
    ]
    findings = rank(
        group_rows,
        client=FakeModelClient(
            handler=lambda request: _rank_ok(
                severity="critical",
                risk="Anyone can claim lbryshare.com and serve malware.",
            )
        ),
    )
    assert findings[0].severity == "medium"
    assert findings[0].severity not in {"critical", "high"}
    expected = LINK_CLICK_RISK.format(domain="lbryshare.com")
    assert expected in findings[0].risk
    assert findings[0].fix


def test_tranco_top10k_without_proof_is_not_fix_today(monkeypatch):
    ref = Reference(
        file="src/pay.js",
        line=3,
        raw="https://js.stripe.com/v3/",
        host_or_bucket="js.stripe.com",
        domain="stripe.com",
        tag="script",
    )
    evidence = {
        "dns": {"host": "js.stripe.com", "status": "resolves"},
        "rdap": {"domain": "stripe.com", "status": "registered", "days_to_expiry": 400},
        "tranco_rank": 204,
    }
    monkeypatch.setattr("scanner.report.skip_model_rank", lambda group: False)
    findings = rank(
        [(ref, _cl(ref, type="script", runs_in="browser"), _inv(ref, evidence))],
        client=FakeModelClient(
            handler=lambda request: _rank_ok(
                severity="critical",
                risk="Stripe could be taken over.",
            )
        ),
    )
    assert findings[0].severity not in {"critical", "high"}
    bad = unexplained_tranco_fix_today(findings)
    assert bad == []


def test_sanity_gate_prints_unexplained_tranco():
    finding = {
        "target": "stripe.com",
        "severity": "critical",
        "evidence": {"dns": {"status": "resolves"}, "rdap": {"status": "registered"}},
    }
    bad = unexplained_tranco_fix_today([finding])
    assert bad
    assert "stripe.com" in bad[0]
