import json
from pathlib import Path

import pytest

from scanner.ci import (
    SKIP_NO_SECRET,
    added_lines_from_diff,
    build_prompt,
    candidates_in_text,
    comment_body,
    floor_groups_for_refs,
    floors_from_groups,
    has_critical,
    has_critical_floor,
    main,
    muse_argv,
    muse_settings,
    parse_muse_output,
    references_from_diff,
    secret_available,
    skip_message,
    CiFinding,
    CiReport,
)
from scanner.lookups import LookupCache
from scanner.models import DnsResult, RdapResult
from scanner.report import CLAIMABLE_FIX
from scanner.tools import ToolContext

SAMPLE_DIFF = """\
diff --git a/app.html b/app.html
index 111..222 100644
--- a/app.html
+++ b/app.html
@@ -1,4 +1,5 @@
 <html>
+  <script src="https://cdn-assets-trustmap-7f3k2.com/lib.js"></script>
   <script src="https://old.example.com/gone.js"></script>
-  <script src="https://should-not-keep.example/x.js"></script>
 </html>
+s3://trustmap-demo-gone/app
"""


def test_added_lines_only_plus_not_headers():
    added = added_lines_from_diff(SAMPLE_DIFF)
    assert "cdn-assets-trustmap-7f3k2.com" in added
    assert "s3://trustmap-demo-gone/app" in added
    assert "should-not-keep.example" not in added
    assert "+++ b/app.html" not in added
    assert "old.example.com" not in added
    assert "should-not-keep.example" not in added


def test_candidates_and_empty():
    added = added_lines_from_diff(SAMPLE_DIFF)
    found = candidates_in_text(added)
    assert any("cdn-assets-trustmap-7f3k2.com" in item for item in found)
    assert any(item.startswith("s3://") for item in found)
    assert candidates_in_text("just a comment") == []


def test_secret_skip_does_not_fail(monkeypatch):
    assert secret_available("sk-test")
    assert not secret_available("")
    assert not secret_available("  ")
    assert not secret_available(None)
    assert skip_message() == SKIP_NO_SECRET
    monkeypatch.delenv("MODEL_API_KEY", raising=False)
    assert main(["access-check"]) == 0
    monkeypatch.setenv("MODEL_API_KEY", "sk-test")
    assert main(["access-check"]) == 0


def test_muse_argv_never_yolo_and_keeps_sandbox_restricted():
    argv = muse_argv(prompt_file="/tmp/p", schema_file="/tmp/s")
    joined = " ".join(argv)
    assert "--yolo" not in argv
    assert "--disable-shell" in argv
    assert "--disable-write" in argv
    assert "--disable-approval" in argv
    assert "--sandbox-network" in argv
    assert argv[argv.index("--sandbox-network") + 1] == "restricted"
    assert "--disable-sandbox" not in argv
    assert 'run.toolset=["mcp__trustmap__*"]' in argv
    assert "--prompt-file" in argv
    assert "--output-schema" in argv
    assert "yolo" not in joined.lower()


def test_settings_use_mcpServers_for_1_4_14():
    body = muse_settings("/usr/bin/python3")
    assert body["schema_version"] == 1
    assert "mcpServers" in body
    assert "mcp_servers" not in body
    server = body["mcpServers"]["trustmap"]
    assert server["transport"] == "stdio"
    assert server["args"] == ["-m", "scanner.mcp_server"]
    assert server["env"]["MODEL_API_KEY"] == "${MODEL_API_KEY}"


def test_parse_findings_json_and_wrapped():
    raw = {
        "findings": [
            {
                "target": "cdn-assets-trustmap-7f3k2.com",
                "kind": "domain",
                "severity": "critical",
                "risk": "Unregistered.",
                "fix": "Remove it.",
                "evidence_line": "nxdomain",
                "references": ["index.html:7"],
            }
        ],
        "notes": "",
    }
    report = parse_muse_output(json.dumps(raw))
    assert has_critical(report)
    wrapped = parse_muse_output("noise\n" + json.dumps({"result": raw}) + "\n")
    assert wrapped.findings[0].target == "cdn-assets-trustmap-7f3k2.com"
    jsonl = json.dumps(
        {
            "payload_type": "run.terminal.completed",
            "payload": {
                "kind": "run_terminal",
                "text": json.dumps(raw),
            },
        }
    )
    from_jsonl = parse_muse_output(jsonl + "\n")
    assert from_jsonl.findings[0].severity == "critical"
    with pytest.raises(ValueError):
        parse_muse_output("not json at all")


SCRIPT_DIFF = """\
diff --git a/index.html b/index.html
--- a/index.html
+++ b/index.html
@@ -1,2 +1,3 @@
 <html>
+  <script src="https://cdn-assets-trustmap-7f3k2.com/lib.js"></script>
 </html>
"""

DOCS_DIFF = """\
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@ -1,2 +1,3 @@
 # docs
+See https://cdn-assets-trustmap-7f3k2.com/lib.js
"""


def _unregistered_ctx(tmp_path: Path) -> ToolContext:
    async def fake_dns(host, cache=None):
        return DnsResult(host=host, status="nxdomain")

    async def fake_rdap(domain, cache=None):
        return RdapResult(domain=domain, status="unregistered")

    return ToolContext(
        cache=LookupCache(tmp_path / "c.db"),
        dns=fake_dns,
        rdap=fake_rdap,
    )


@pytest.mark.asyncio
async def test_gate_uses_floor_not_muse_severity(tmp_path: Path):
    ctx = _unregistered_ctx(tmp_path)
    script_refs = references_from_diff(SCRIPT_DIFF)
    docs_refs = references_from_diff(DOCS_DIFF)
    script_floors = floors_from_groups(
        await floor_groups_for_refs(script_refs, cache=ctx.cache, ctx=ctx)
    )
    docs_floors = floors_from_groups(
        await floor_groups_for_refs(docs_refs, cache=ctx.cache, ctx=ctx)
    )
    muse_low = CiReport(
        findings=[
            CiFinding(
                target="cdn-assets-trustmap-7f3k2.com",
                kind="domain",
                severity="low",
                risk="Muse says this is low.",
                fix="ignore it",
            )
        ]
    )
    muse_critical = CiReport(
        findings=[
            CiFinding(
                target="cdn-assets-trustmap-7f3k2.com",
                kind="domain",
                severity="critical",
                risk="Muse says this is critical.",
                fix="panic",
            )
        ]
    )
    assert muse_low.findings[0].severity == "low"
    assert has_critical_floor(script_floors)
    assert not has_critical(muse_low)
    assert muse_critical.findings[0].severity == "critical"
    assert not has_critical_floor(docs_floors)
    assert has_critical(muse_critical)


def test_gate_cli_uses_cached_floor(tmp_path: Path, monkeypatch):
    script_diff = tmp_path / "script.diff"
    docs_diff = tmp_path / "docs.diff"
    script_diff.write_text(SCRIPT_DIFF)
    docs_diff.write_text(DOCS_DIFF)
    cache = tmp_path / "gate.db"
    LookupCache(cache).set_json(
        "dns:cdn-assets-trustmap-7f3k2.com",
        DnsResult(host="cdn-assets-trustmap-7f3k2.com", status="nxdomain").model_dump(
            mode="json"
        ),
    )
    LookupCache(cache).set_json(
        "rdap:cdn-assets-trustmap-7f3k2.com",
        RdapResult(
            domain="cdn-assets-trustmap-7f3k2.com", status="unregistered"
        ).model_dump(mode="json"),
    )
    monkeypatch.setenv("TRUSTMAP_CACHE_DB", str(cache))
    assert main(["gate", "--diff-file", str(script_diff)]) == 1
    assert main(["gate", "--diff-file", str(docs_diff)]) == 0


def test_comment_redacts_and_empty():
    empty = comment_body(CiReport(findings=[]))
    assert "no takeover risks" in empty.lower()
    body = comment_body(
        parse_muse_output(
            json.dumps(
                {
                    "findings": [
                        {
                            "target": "x.com",
                            "kind": "domain",
                            "severity": "low",
                            "risk": "token=supersecret",
                            "fix": "ok",
                            "evidence_line": "",
                            "references": [],
                        }
                    ],
                    "notes": "",
                }
            )
        )
    )
    assert "supersecret" not in body
    assert "[REDACTED]" in body


def test_comment_fix_comes_from_choose_fix_not_muse():
    muse_fix = "Delete the script tag or vendor lib.js locally."
    body = comment_body(
        CiReport(
            findings=[
                CiFinding(
                    target="cdn-assets-trustmap-7f3k2.com",
                    kind="abandoned-domain",
                    severity="critical",
                    risk="Anyone can register the domain.",
                    fix=muse_fix,
                    references=["dns:status=nxdomain", "rdap:status=unregistered"],
                )
            ]
        )
    )
    assert CLAIMABLE_FIX in body
    assert muse_fix not in body
    assert "Anyone can register the domain." in body
    jsonl = "\n".join(
        [
            json.dumps(
                {
                    "payload_type": "tool.result",
                    "payload": {
                        "kind": "tool_result",
                        "text": json.dumps(
                            {
                                "domain": "cdn-assets-trustmap-7f3k2.com",
                                "status": "unregistered",
                            }
                        ),
                        "correlation_facts": {"tool_name": "mcp__trustmap__rdap"},
                    },
                }
            ),
            json.dumps(
                {
                    "payload_type": "run.terminal.completed",
                    "payload": {
                        "text": json.dumps(
                            {
                                "findings": [
                                    {
                                        "target": "cdn-assets-trustmap-7f3k2.com",
                                        "kind": "domain",
                                        "severity": "critical",
                                        "risk": "Unregistered host.",
                                        "fix": muse_fix,
                                        "evidence_line": "",
                                        "references": [],
                                    }
                                ],
                                "notes": "",
                            }
                        )
                    },
                }
            ),
        ]
    )
    from_tools = comment_body(parse_muse_output(jsonl))
    assert CLAIMABLE_FIX in from_tools
    assert muse_fix not in from_tools


def test_prompt_contains_added_lines():
    text = build_prompt("https://cdn-assets-trustmap-7f3k2.com/x")
    assert "Do not call scan" in text
    assert "cdn-assets-trustmap-7f3k2.com" in text


def test_workflow_file_matches_policy():
    text = Path(".github/workflows/trustmap.yml").read_text()
    assert "refusing to run muse with --yolo" in text
    assert SKIP_NO_SECRET in text
    assert "mkdtemp" in text
    assert "github.event.pull_request.base.sha" in text
    assert "| sh" not in text
    assert 'bash "$RUNNER_TEMP/muse-install.sh"' in text
    assert "META_API_KEY: ${{ secrets.MODEL_API_KEY }}" in text
    assert "XDG_CONFIG_HOME" in text
    assert "redacted muse.out" in text
    assert "HOME: ${{ runner.temp }}/muse-home" not in text
    assert "--disable-sandbox" not in Path("scanner/ci.py").read_text().split("muse_argv")[1][:800]
    assert "github/codeql-action/upload-sarif" in text
    assert "--format sarif" in text


def test_write_schema_and_cli_roundtrip(tmp_path: Path):
    schema = tmp_path / "s.json"
    assert main(["write-schema", "--out", str(schema)]) == 0
    body = json.loads(schema.read_text())
    assert body["required"] == ["findings", "notes"]
    diff = tmp_path / "d.diff"
    diff.write_text(added_lines_from_diff(SAMPLE_DIFF) + "\n")
    assert main(["has-candidates", "--diff-file", str(diff)]) == 0
    empty = tmp_path / "e.diff"
    empty.write_text("no urls\n")
    assert main(["has-candidates", "--diff-file", str(empty)]) == 2
