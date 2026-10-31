import json
from pathlib import Path

from scanner.config import ALLOWLIST_DOMAINS
from scanner.extract import extract

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


def test_allowlist_drops_github_but_keeps_buckets(tmp_path: Path):
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
    names = {ref.host_or_bucket for ref in found}
    assert "github.com" not in {ref.domain for ref in found}
    assert "w3.org" not in {ref.domain for ref in found}
    assert "my-orphan-bucket" in names
    assert "my-gcs-bucket" in names
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


def test_drops_license_and_schema_namespace_hosts(tmp_path: Path):
    (tmp_path / "note.txt").write_text(
        "\n".join(
            [
                "https://opensource.org/licenses/MIT",
                "http://www.apache.org/licenses/LICENSE-2.0",
                "http://schemas.xmlsoap.org/soap/envelope/",
                "https://kept.example.net/api",
            ]
        )
        + "\n"
    )
    found = extract(str(tmp_path))
    assert {ref.domain for ref in found} == {"example.net"}


def test_github_url_uses_shallow_clone(tmp_path: Path):
    repo = tmp_path / "cloned"
    repo.mkdir()
    (repo / "main.py").write_text('API = "https://api.cloned.example.com/"\n')

    def fake_clone(url: str, dest_parent: Path) -> Path:
        assert "github.com/acme/widgets" in url
        return repo

    found = extract("https://github.com/acme/widgets", clone_github=fake_clone)
    assert found[0].host_or_bucket == "api.cloned.example.com"
