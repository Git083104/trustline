import json
from pathlib import Path

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "demo_repo"
EXPECTED_PATH = Path(__file__).parent / "fixtures" / "expected.json"

REQUIRED_KEYS = {"file", "line", "raw", "host_or_bucket", "type", "runs_in"}
TYPES = {"script", "api", "asset", "config", "bucket", "ci", "docs", "test"}
RUNS_IN = {"browser", "server", "build", "ci", "docs_only"}


def test_expected_json_is_valid_and_complete():
    data = json.loads(EXPECTED_PATH.read_text())
    refs = data["references"]
    assert 15 <= len(refs) <= 20

    seen = set()
    host_or_buckets = []
    for ref in refs:
        missing = REQUIRED_KEYS - ref.keys()
        assert not missing, f"missing keys {missing} in {ref}"
        assert ref["type"] in TYPES
        assert ref["runs_in"] in RUNS_IN
        assert isinstance(ref["line"], int) and ref["line"] >= 1
        assert ref["raw"]
        assert ref["host_or_bucket"]

        path = FIXTURE_ROOT / ref["file"]
        assert path.is_file(), f"missing fixture file {ref['file']}"
        lines = path.read_text().splitlines()
        assert ref["line"] <= len(lines), f"{ref['file']}:{ref['line']} past EOF"
        line = lines[ref["line"] - 1]
        assert ref["raw"] in line, f"{ref['file']}:{ref['line']} missing {ref['raw']!r}"

        key = (ref["host_or_bucket"], ref["file"], ref["line"])
        assert key not in seen, f"duplicate {key}"
        seen.add(key)
        host_or_buckets.append(ref["host_or_bucket"])

    joined = " ".join(host_or_buckets)
    assert "BUCKET_DEMO_CLAIMABLE" in joined
    assert "BUCKET_DEMO_LIVE" in joined
    assert any("invalid" in h for h in host_or_buckets)
    assert any(h.endswith(".com") and "example.com" not in h for h in host_or_buckets)
