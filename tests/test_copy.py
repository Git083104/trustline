from scanner.copy import assistant_prompt, decorate, issue_markdown
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
