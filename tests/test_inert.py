from pathlib import Path

from scanner.extract import extract, extract_scan
from scanner.inert import is_inert_path, is_source_code, load_ignore_globs
from scanner.models import Classification, Finding, Investigation, Reference
from scanner.report import executing_runs_in, floor_decision


def _ref(path: str, host: str = "gone.example-not-real.test") -> Reference:
    return Reference(
        file=path,
        line=1,
        raw="https://" + host + "/x.js",
        host_or_bucket=host,
        domain=host,
    )


def test_inert_paths():
    assert is_inert_path("tests/test_api.py")
    assert is_inert_path("docs/index.html")
    assert is_inert_path("README.md")
    assert is_inert_path("api/demo_scan.json")
    assert is_inert_path("design/compare/home.png")
    assert is_inert_path("examples/demo.js")
    assert not is_inert_path("package.json")
    assert not is_inert_path(".github/workflows/ci.yml")
    assert not is_inert_path("src/app.py")
    assert is_source_code("src/app.py")
    assert not is_source_code(".github/workflows/ci.yml")


def test_tether_yml_ignore(tmp_path: Path):
    (tmp_path / ".tether.yml").write_text("ignore:\n  - design/reference/**\n  - api/demo_scan.json\n")
    (tmp_path / "design" / "reference").mkdir(parents=True)
    (tmp_path / "design" / "reference" / "note.html").write_text(
        '<script src="https://cdn.polyfill.io/v3/x.js"></script>\n'
    )
    (tmp_path / "api").mkdir()
    (tmp_path / "api" / "demo_scan.json").write_text('{"x": "https://cdn.polyfill.io/v3/x.js"}\n')
    (tmp_path / "app.js").write_text('fetch("https://cdn-assets-trustmap-7f3k2.com/v1")\n')
    found = extract(str(tmp_path))
    hosts = {ref.host_or_bucket for ref in found}
    assert "cdn.polyfill.io" not in hosts
    assert "cdn-assets-trustmap-7f3k2.com" in hosts
    assert load_ignore_globs(tmp_path)


def test_inert_rows_are_not_executing():
    ref = _ref("tests/fixtures/demo.html", "cdn.polyfill.io")
    cl = Classification(
        id="1",
        file=ref.file,
        line=1,
        host_or_bucket=ref.host_or_bucket,
        type="script",
        runs_in="browser",
        blast_radius=3,
        confidence=1,
        reason="test",
    )
    inv = Investigation(file=ref.file, line=1, host_or_bucket=ref.host_or_bucket, status="done")
    assert executing_runs_in([(ref, cl, inv)]) is False


def test_extract_counts_ignored_non_hosts(tmp_path: Path):
    (tmp_path / "app.js").write_text(
        "\n".join(
            [
                'const a = "https://${GATEWAY_HOST}/hook";',
                'const b = "https://{{host}}/api";',
                'const c = "https://127.0.0.1/x";',
                'const d = "https://example.com/x";',
                'const e = "https://svc.local/health";',
                'const f = "https://cdn-assets-trustmap-7f3k2.com/v1";',
            ]
        )
        + "\n"
    )
    result = extract_scan(str(tmp_path))
    hosts = {ref.host_or_bucket for ref in result.references}
    assert "cdn-assets-trustmap-7f3k2.com" in hosts
    assert result.coverage.ignored_non_hosts >= 5
    assert "example.com" not in hosts
    assert "127.0.0.1" not in hosts
