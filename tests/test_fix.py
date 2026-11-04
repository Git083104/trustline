from pathlib import Path

from scanner.fix import propose_fixes, sri_hash, template_pr
from scanner.models import Finding

SHA = "8f4b7f84864484a7bf31766abe9204da3cbe65b3"
POLYFILL = '<script src="https://cdn.polyfill.io/v3/polyfill.min.js"></script>'
VERSIONED = '<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js"></script>'


def _finding(**kwargs) -> Finding:
    return Finding(
        target=kwargs.get("target", "example.com"),
        kind=kwargs.get("kind", "domain"),
        references=kwargs.get("references", ["index.html:1"]),
        severity=kwargs.get("severity", "critical"),
        model_severity="critical",
        final_severity="critical",
        classified_blast_radius=3,
        ranked_blast_radius=3,
        risk=kwargs.get("risk", "A stranger can claim this."),
        fix="remove dead reference",
        evidence=kwargs.get("evidence", {}),
        evidence_line=kwargs.get("evidence_line", "Evidence: domain not registered"),
        locations=kwargs.get("locations", []),
        action_ref=kwargs.get("action_ref", ""),
        action_sha_pinned=kwargs.get("action_sha_pinned"),
    )


def test_pins_github_action_to_sha():
    files = {
        ".github/workflows/ci.yml": "jobs:\n  x:\n    steps:\n      - uses: actions/checkout@v4\n"
    }
    item = _finding(
        target="github.com/actions/checkout",
        references=[".github/workflows/ci.yml:4"],
        action_ref="v4",
        action_sha_pinned=False,
        locations=[
            {
                "file": ".github/workflows/ci.yml",
                "line": 4,
                "runs_in": "ci",
                "raw": "actions/checkout@v4",
                "action_owner": "actions",
                "action_repo": "checkout",
            }
        ],
        evidence={"github_repo": {"status": "ok"}},
    )
    plan = propose_fixes(
        [item],
        files,
        resolve_sha=lambda o, r, ref: SHA,
    )
    assert plan.edits[0].kind == "pin-sha"
    assert SHA in plan.files[".github/workflows/ci.yml"]
    assert "# v4" in plan.files[".github/workflows/ci.yml"]
    assert "uses: actions/checkout@" + SHA in plan.files[".github/workflows/ci.yml"]


def test_swaps_polyfill_url():
    files = {"index.html": f"<html><body>{POLYFILL}</body></html>\n"}
    item = _finding(
        target="polyfill.io",
        locations=[
            {
                "file": "index.html",
                "line": 1,
                "tag": "script",
                "runs_in": "browser",
                "raw": "https://cdn.polyfill.io/v3/polyfill.min.js",
                "sri": False,
            }
        ],
        evidence={"dns": {"status": "resolves"}},
    )
    plan = propose_fixes([item], files)
    assert plan.edits[0].kind == "polyfill"
    assert "cdnjs.cloudflare.com/polyfill/v3/polyfill.min.js" in plan.files["index.html"]
    assert "polyfill.io" not in plan.files["index.html"]


def test_adds_sri_hash_from_fetched_bytes():
    body = b"/* jquery */"
    files = {"index.html": f"<html>{VERSIONED}</html>\n"}
    item = _finding(
        target="cdnjs.cloudflare.com",
        severity="info",
        locations=[
            {
                "file": "index.html",
                "line": 1,
                "tag": "script",
                "runs_in": "browser",
                "raw": "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js",
                "sri": False,
            }
        ],
        evidence={"rdap": {"status": "registered"}, "dns": {"status": "resolves"}},
    )
    plan = propose_fixes([item], files, fetch_body=lambda url: body)
    digest = sri_hash(body)
    assert plan.edits[0].kind == "sri"
    assert digest in plan.files["index.html"]
    assert 'crossorigin="anonymous"' in plan.files["index.html"]


def test_comments_js_with_slashes():
    files = {
        "src/config.js": 'export const PRODUCT_IMAGES = "https://gone.blob.core.windows.net/x";\n'
    }
    item = _finding(
        target="gone",
        locations=[
            {
                "file": "src/config.js",
                "line": 1,
                "runs_in": "deploy",
                "raw": "https://gone.blob.core.windows.net/x",
            }
        ],
        evidence={"bucket_probe": {"status": "NoSuchBucket"}},
    )
    plan = propose_fixes([item], files)
    assert not plan.edits
    assert plan.files["src/config.js"] == files["src/config.js"]


def test_comments_out_claimable_script():
    line = '<script src="https://trustline-demo-cartkit.com/v2/cart.js"></script>'
    files = {"index.html": f"<html>{line}</html>\n"}
    item = _finding(
        target="trustline-demo-cartkit.com",
        locations=[
            {
                "file": "index.html",
                "line": 1,
                "tag": "script",
                "runs_in": "browser",
                "raw": "https://trustline-demo-cartkit.com/v2/cart.js",
            }
        ],
        evidence={"rdap": {"status": "unregistered"}},
    )
    plan = propose_fixes([item], files)
    assert plan.edits[0].kind == "comment"
    assert "TETHER: trustline-demo-cartkit.com" in plan.files["index.html"]
    assert "<!--" in plan.files["index.html"]


def test_comments_ci_step_and_yaml_still_parses():
    files = {
        ".github/workflows/ci.yml": (
            "jobs:\n  x:\n    steps:\n      - uses: gone-owner/tools@v1\n"
        )
    }
    item = _finding(
        target="github.com/gone-owner/tools",
        references=[".github/workflows/ci.yml:4"],
        action_ref="v1",
        action_sha_pinned=False,
        locations=[
            {
                "file": ".github/workflows/ci.yml",
                "line": 4,
                "runs_in": "ci",
                "raw": "gone-owner/tools@v1",
                "action_owner": "gone-owner",
                "action_repo": "tools",
            }
        ],
        evidence={"github_owner": {"status": "missing"}},
    )
    plan = propose_fixes([item], files, resolve_sha=lambda *a: None)
    text = plan.files[".github/workflows/ci.yml"]
    assert "TETHER:" in text
    import yaml

    yaml.safe_load(text)


def test_skips_fixtures_and_docs_only():
    files = {
        "tests/fixtures/demo.html": POLYFILL + "\n",
        "index.html": POLYFILL + "\n",
    }
    fixture = _finding(
        target="polyfill.io",
        locations=[
            {
                "file": "tests/fixtures/demo.html",
                "line": 1,
                "tag": "script",
                "runs_in": "browser",
                "raw": "https://cdn.polyfill.io/v3/polyfill.min.js",
            }
        ],
    )
    docs = _finding(
        target="polyfill.io",
        locations=[
            {
                "file": "index.html",
                "line": 1,
                "tag": "script",
                "runs_in": "docs_only",
                "raw": "https://cdn.polyfill.io/v3/polyfill.min.js",
            }
        ],
    )
    plan = propose_fixes([fixture, docs], files)
    assert plan.edits == []
    assert files["tests/fixtures/demo.html"] == plan.files["tests/fixtures/demo.html"]


def test_syntax_reparse_rejects_broken_html_edit(tmp_path: Path):
    files = {"index.html": "<html><script src='https://cdn.polyfill.io/v3/x.js'></script></html>\n"}
    item = _finding(
        target="polyfill.io",
        locations=[
            {
                "file": "index.html",
                "line": 1,
                "tag": "script",
                "runs_in": "browser",
                "raw": "https://cdn.polyfill.io/v3/x.js",
            }
        ],
    )
    plan = propose_fixes([item], files)
    assert "</html>" in plan.files["index.html"]
    title, body = template_pr(plan, [item])
    assert "polyfill.io" in body
    assert title.startswith("Tether:")


def test_clawdbot_test_and_source_files_are_not_edited():
    files = {
        "src/gateway.ts": 'fetch("https://cdn.polyfill.io/v3/polyfill.min.js");\n',
        "test/gateway.test.ts": 'const url = "https://cdn.polyfill.io/v3/polyfill.min.js";\n',
    }
    item = _finding(
        target="polyfill.io",
        locations=[
            {
                "file": "src/gateway.ts",
                "line": 1,
                "runs_in": "server",
                "raw": "https://cdn.polyfill.io/v3/polyfill.min.js",
            },
            {
                "file": "test/gateway.test.ts",
                "line": 1,
                "runs_in": "test",
                "raw": "https://cdn.polyfill.io/v3/polyfill.min.js",
            },
        ],
    )
    plan = propose_fixes([item], files)
    assert plan.edits == []
    assert plan.patch == ""


def test_patch_applies_and_yaml_reparses(tmp_path: Path):
    import subprocess

    repo = tmp_path / "repo"
    repo.mkdir()
    workflow = repo / ".github" / "workflows"
    workflow.mkdir(parents=True)
    before = "jobs:\n  x:\n    steps:\n      - uses: actions/checkout@v4\n"
    (workflow / "ci.yml").write_text(before)
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
    files = {".github/workflows/ci.yml": before}
    item = _finding(
        target="github.com/actions/checkout",
        references=[".github/workflows/ci.yml:4"],
        action_ref="v4",
        action_sha_pinned=False,
        locations=[
            {
                "file": ".github/workflows/ci.yml",
                "line": 4,
                "runs_in": "ci",
                "raw": "actions/checkout@v4",
                "action_owner": "actions",
                "action_repo": "checkout",
            }
        ],
    )
    plan = propose_fixes(
        [item], files, resolve_sha=lambda *_args: "8f4b7f84864484a7bf31766abe9204da3cbe65b3"
    )
    patch_path = tmp_path / "tether.patch"
    patch_path.write_text(plan.patch)
    check = subprocess.run(
        ["git", "apply", "--check", str(patch_path)],
        cwd=repo,
        capture_output=True,
        text=True,
    )
    assert check.returncode == 0, check.stderr
    import yaml

    yaml.safe_load(plan.files[".github/workflows/ci.yml"])
