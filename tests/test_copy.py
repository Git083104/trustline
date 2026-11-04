from scanner.copy import OWNED_COPY, assistant_prompt, decorate, issue_markdown, set_owned_names
from scanner.models import Finding


def test_decorate_writes_code_headlines_and_steps():
    item = Finding(
        target="trustline-demo-cartkit.com",
        kind="domain",
        references=["index.html:9"],
        severity="critical",
        model_severity="critical",
        final_severity="critical",
        classified_blast_radius=3,
        ranked_blast_radius=3,
        risk="Model sentence about takeover.",
        fix="remove dead reference",
        explained_by="model",
        evidence={"rdap": {"status": "unregistered"}},
        locations=[
            {
                "file": "index.html",
                "line": 9,
                "runs_in": "browser",
                "tag": "script",
                "raw": "https://trustline-demo-cartkit.com/v2/cart.js",
            }
        ],
    )
    out = decorate(item)
    assert out.headline == "Your website loads code from a domain anyone can register"
    assert out.why == "Model sentence about takeover."
    assert out.steps[0].startswith("Open index.html:9")
    title, body = issue_markdown(out)
    assert title.startswith("Tether:")
    assert "Do not register" in body
    prompt = assistant_prompt(out)
    assert "index.html:9" in prompt
    assert "Do not register" in prompt


def test_what_to_do_lists_executing_location_before_docs():
    item = Finding(
        target="polyfill.io",
        kind="domain",
        references=["README.md:4", "index.html:8"],
        severity="critical",
        model_severity="critical",
        final_severity="critical",
        classified_blast_radius=3,
        ranked_blast_radius=3,
        risk="compromised",
        fix="replace with maintained source",
        evidence={},
        locations=[
            {"file": "README.md", "line": 4, "runs_in": "docs_only"},
            {"file": "index.html", "line": 8, "runs_in": "browser", "tag": "script"},
        ],
    )
    out = decorate(item)
    assert out.steps[0].startswith("Open index.html:8")


def _owned_finding(**kwargs) -> Finding:
    base = dict(
        references=["deploy.yml:1"],
        severity="critical",
        model_severity="critical",
        final_severity="critical",
        classified_blast_radius=3,
        ranked_blast_radius=3,
        risk="claimable",
        fix="re-register what you abandoned",
        locations=[{"file": "deploy.yml", "line": 1, "runs_in": "deploy"}],
    )
    base.update(kwargs)
    return Finding(**base)


def test_owned_bucket_keeps_severity_and_rewrites_copy():
    set_owned_names(["gone-bucket"])
    try:
        item = _owned_finding(
            target="gone-bucket",
            kind="bucket",
            evidence={"bucket_probe": {"status": "NoSuchBucket", "name": "gone-bucket"}},
        )
        out = decorate(item)
        assert out.severity == "critical"
        assert out.final_severity == "critical"
        assert out.headline == OWNED_COPY
        assert out.fix == OWNED_COPY
    finally:
        set_owned_names([])


def test_owned_domain_keeps_severity_and_rewrites_copy():
    set_owned_names(["old.example"])
    try:
        item = _owned_finding(
            target="old.example",
            kind="domain",
            evidence={"rdap": {"status": "unregistered", "domain": "old.example"}},
            locations=[{"file": "app.js", "line": 4, "runs_in": "browser", "tag": "script"}],
        )
        out = decorate(item)
        assert out.severity == "critical"
        assert out.headline == OWNED_COPY
        assert out.fix == OWNED_COPY
    finally:
        set_owned_names([])
