import json
import subprocess
from pathlib import Path

import pytest

from scanner.config import ALLOWLIST_DOMAINS, GITHUB_CLONE_TIMEOUT_S
from scanner.extract import (
    CloneError,
    actionable,
    extract,
    extract_scan,
    _clone_github,
)

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


def test_extract_github_actions_uses(tmp_path: Path):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "\n".join(
            [
                "jobs:",
                "  demo:",
                "    steps:",
                "      - uses: ./local",
                "      - uses: docker://alpine:3.19",
                "      - uses: gone-owner/tools@v1",
                "      - uses: actions/missing-repo@main",
                "      - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3",
                "      - uses: owner/repo/path@v1",
            ]
        )
        + "\n"
    )
    (tmp_path / "action.yml").write_text("runs:\n  using: composite\n  steps:\n    - uses: other/tool@v2\n")
    found = extract(str(tmp_path))
    by_raw = {ref.raw: ref for ref in found}
    assert "./local" not in by_raw
    assert "docker://alpine:3.19" not in by_raw
    gone = by_raw["gone-owner/tools@v1"]
    assert gone.host_or_bucket == "github.com/gone-owner/tools"
    assert gone.action_owner == "gone-owner"
    assert gone.action_sha_pinned is False
    assert gone.file == ".github/workflows/ci.yml"
    missing = by_raw["actions/missing-repo@main"]
    assert missing.action_repo == "missing-repo"
    sha = by_raw["actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3"]
    assert sha.action_sha_pinned is True
    nested = by_raw["owner/repo/path@v1"]
    assert nested.action_repo == "repo"
    composite = by_raw["other/tool@v2"]
    assert composite.file == "action.yml"


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


def test_skips_files_over_one_megabyte(tmp_path: Path):
    (tmp_path / "ok.js").write_text('fetch("https://kept.example.net/v1")\n')
    huge = tmp_path / "huge.js"
    huge.write_bytes(b"x" * (1_000_000 + 1) + b'https://too-big.example.net/x\n')
    found = extract(str(tmp_path))
    assert {(ref.host_or_bucket, ref.file) for ref in found} == {
        ("kept.example.net", "ok.js")
    }


def test_prioritizes_html_over_docs_when_capped(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("TRUSTMAP_MAX_SCAN_FILES", "1")
    (tmp_path / "README.md").write_text('See https://docs-only.example.net/x\n')
    (tmp_path / "index.html").write_text(
        '<script src="https://app.example.net/app.js"></script>\n'
    )
    result = extract_scan(str(tmp_path))
    assert result.coverage.truncated is True
    assert result.coverage.reason == "file_cap"
    assert result.coverage.files_scanned == 1
    assert result.coverage.files_total == 2
    assert {ref.host_or_bucket for ref in result.references} == {"app.example.net"}


def test_byte_cap_truncates_without_error(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("TRUSTMAP_MAX_SCAN_BYTES", "40")
    (tmp_path / "a.js").write_text('fetch("https://first.example.net/a")\n')
    (tmp_path / "b.js").write_text('fetch("https://second.example.net/b")\n' * 4)
    result = extract_scan(str(tmp_path))
    assert result.coverage.truncated is True
    assert result.coverage.reason == "byte_cap"
    assert result.coverage.files_scanned >= 1
    assert result.coverage.files_scanned < result.coverage.files_total


def test_github_clone_uses_blob_size_filter(monkeypatch, tmp_path: Path):
    seen: list[list[str]] = []

    def fake_run(argv, check, timeout):
        seen.append(argv)
        dest = Path(argv[-1])
        dest.mkdir()
        (dest / "ok.js").write_text('fetch("https://cloned.example.net/x")\n')
        return None

    monkeypatch.setattr("scanner.extract.subprocess.run", fake_run)
    dest = _clone_github("https://github.com/acme/widgets", tmp_path)
    assert "--depth" in seen[0]
    assert "1" in seen[0]
    assert "--filter=blob:limit=1m" in seen[0]
    assert dest.exists()


def test_github_url_uses_shallow_clone(tmp_path: Path):
    repo = tmp_path / "cloned"
    repo.mkdir()
    (repo / "main.py").write_text('API = "https://api.cloned.example.com/"\n')

    def fake_clone(url: str, dest_parent: Path) -> Path:
        assert "github.com/acme/widgets" in url
        return repo

    found = extract("https://github.com/acme/widgets", clone_github=fake_clone)
    assert found[0].host_or_bucket == "api.cloned.example.com"


def test_clone_failure_reports_a_readable_reason(monkeypatch, tmp_path: Path):
    def boom(*args, **kwargs):
        raise subprocess.CalledProcessError(128, args[0] if args else "git")

    monkeypatch.setattr(subprocess, "run", boom)
    with pytest.raises(CloneError) as caught:
        _clone_github("https://github.com/acme/widgets", tmp_path)
    message = str(caught.value)
    assert "acme/widgets" in message
    assert "private or renamed" in message
    assert "git clone" not in message


def test_missing_git_binary_is_named_plainly(monkeypatch, tmp_path: Path):
    def missing(*args, **kwargs):
        raise FileNotFoundError("git")

    monkeypatch.setattr(subprocess, "run", missing)
    with pytest.raises(CloneError, match="git is not installed"):
        _clone_github("https://github.com/acme/widgets", tmp_path)


def test_clone_timeout_names_the_limit(monkeypatch, tmp_path: Path):
    def slow(*args, **kwargs):
        raise subprocess.TimeoutExpired("git", GITHUB_CLONE_TIMEOUT_S)

    monkeypatch.setattr(subprocess, "run", slow)
    with pytest.raises(CloneError, match=str(GITHUB_CLONE_TIMEOUT_S)):
        _clone_github("https://github.com/acme/widgets", tmp_path)
