import json
from pathlib import Path

from scanner.config import ALLOWLIST_DOMAINS
from scanner.extract import actionable, extract

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "demo_repo"
EXPECTED_PATH = Path(__file__).parent / "fixtures" / "expected.json"


def test_extract_finds_every_expected_reference():
    expected = json.loads(EXPECTED_PATH.read_text())["references"]
    found = extract(str(FIXTURE_ROOT))
    keys = {(ref.file, ref.line, ref.host_or_bucket) for ref in found}
    missing = [
        ref
        for ref in expected
        if (ref["file"], ref["line"], ref["host_or_bucket"]) not in keys
    ]
    assert missing == [], f"missing {missing}"
    by_key = {(ref.file, ref.line, ref.host_or_bucket): ref for ref in found}
    for ref in expected:
        got = by_key[(ref["file"], ref["line"], ref["host_or_bucket"])]
        assert ref["raw"] == got.raw
        assert got.context
        assert got.filter_reason == ref["filter_reason"]
    assert any(
        ref.filter_reason is None
        and ref.host_or_bucket == "cdn-assets-trustmap-7f3k2.com"
        for ref in found
    )


def test_keep_allowlisted_with_filter_reason_but_keep_buckets(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "\n".join(
            [
                "DOCS = 'https://github.com/acme/widgets'",
                "W3 = 'https://www.w3.org/ns/activitystreams'",
                "BUCKET = 's3://my-orphan-bucket'",
                "GCS = 'https://storage.googleapis.com/my-gcs-bucket'",
            ]
        )
        + "\n"
    )
    found = extract(str(tmp_path))
    by_name = {ref.host_or_bucket: ref for ref in found}
    assert by_name["github.com"].filter_reason == "allowlisted"
    assert by_name["www.w3.org"].filter_reason == "allowlisted"
    assert by_name["my-orphan-bucket"].filter_reason is None
    assert by_name["my-gcs-bucket"].filter_reason is None
    assert {ref.host_or_bucket for ref in actionable(found)} == {
        "my-orphan-bucket",
        "my-gcs-bucket",
    }


def test_extract_azure_and_github_owner_shapes(tmp_path: Path):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "run: curl https://raw.githubusercontent.com/missing-org/tools/main/install.sh | sh\n"
        "docs: https://github.com/acme/widgets\n"
    )
    (tmp_path / "infra.yaml").write_text(
        "azure: https://trustmapdemoassets.blob.core.windows.net/public\n"
        "pages: https://trustmap-demo-pages.github.io/widget.js\n"
    )
    found = extract(str(tmp_path))
    by_name = {ref.host_or_bucket: ref for ref in found}
    assert by_name["trustmapdemoassets"].filter_reason is None
    assert by_name["github.com/missing-org"].filter_reason is None
    assert by_name["github.com"].filter_reason == "allowlisted"
    assert by_name["trustmap-demo-pages.github.io"].filter_reason is None
    assert "example.com" not in ALLOWLIST_DOMAINS


def test_skips_node_modules_and_git(tmp_path: Path):
    (tmp_path / "ok.py").write_text('URL = "https://kept.example.net/v1"\n')
    nested = tmp_path / "node_modules" / "pkg"
    nested.mkdir(parents=True)
    (nested / "index.js").write_text('fetch("https://hidden.example.net/x")\n')
    git = tmp_path / ".git"
    git.mkdir()
    (git / "config").write_text('url = "https://also-hidden.example.net/"\n')
    found = extract(str(tmp_path))
    assert {(ref.host_or_bucket, ref.file) for ref in found} == {
        ("kept.example.net", "ok.py")
    }


def test_skips_lockfiles_minified_and_sourcemaps(tmp_path: Path):
    (tmp_path / "app.js").write_text('fetch("https://kept.example.net/v1")\n')
    (tmp_path / "package-lock.json").write_text(
        '{"resolved": "https://noise.example.net/pkg.tgz"}\n'
    )
    (tmp_path / "lib.min.js").write_text('fetch("https://minified.example.net/x")\n')
    (tmp_path / "lib.js.map").write_text('{"file": "https://map.example.net/x"}\n')
    found = extract(str(tmp_path))
    assert {(ref.host_or_bucket, ref.file) for ref in found} == {
        ("kept.example.net", "app.js")
    }


def test_license_schema_and_noise_hosts_get_filter_reasons(tmp_path: Path):
    (tmp_path / "note.txt").write_text(
        "\n".join(
            [
                "https://opensource.org/licenses/MIT",
                "http://www.apache.org/licenses/LICENSE-2.0",
                "http://schemas.xmlsoap.org/soap/envelope/",
                "https://kept.example.net/api",
                "https://127.0.0.1/health",
                "https://8.8.8.8/dns",
                "https://{host}/x",
                "https://cdn.dead-host.invalid/a.js",
                "https://no-suffix-at-all/x",
            ]
        )
        + "\n"
    )
    found = {ref.host_or_bucket: ref.filter_reason for ref in extract(str(tmp_path))}
    assert found["opensource.org"] == "allowlisted"
    assert found["www.apache.org"] == "allowlisted"
    assert found["schemas.xmlsoap.org"] == "allowlisted"
    assert found["kept.example.net"] == "reserved_domain"
    assert found["127.0.0.1"] == "ip_address"
    assert found["8.8.8.8"] == "ip_address"
    assert found["{host}"] == "placeholder"
    assert found["cdn.dead-host.invalid"] == "reserved_tld"
    assert found["no-suffix-at-all"] == "no_public_suffix"


def test_github_url_uses_shallow_clone(tmp_path: Path):
    repo = tmp_path / "cloned"
    repo.mkdir()
    (repo / "main.py").write_text('API = "https://api.cloned.example.com/"\n')

    def fake_clone(url: str, dest_parent: Path) -> Path:
        assert "github.com/acme/widgets" in url
        return repo

    found = extract("https://github.com/acme/widgets", clone_github=fake_clone)
    assert found[0].host_or_bucket == "api.cloned.example.com"
