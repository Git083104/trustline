import socket
import threading
import time
import pytest
import uvicorn
from playwright.sync_api import sync_playwright

from api.limits import LimitsStore
from api.main import create_app
from scanner.copy import decorate
from scanner.llm import FakeModelClient
from scanner.models import Finding
from scanner.report import ScanOutcome

POLYFILL_HTML = """<!doctype html>
<html><head>
<script src="https://cdn.polyfill.io/v3/polyfill.min.js"></script>
</head><body></body></html>
"""


def _finding(**kwargs) -> Finding:
    return decorate(
        Finding(
            target=kwargs.get("target", "polyfill.io"),
            kind="domain",
            references=[kwargs.get("ref", "index.html:2")],
            severity=kwargs.get("severity", "critical"),
            model_severity="critical",
            final_severity=kwargs.get("severity", "critical"),
            classified_blast_radius=3,
            ranked_blast_radius=3,
            risk=kwargs.get("risk", "polyfill.io is abandoned."),
            fix="replace with maintained source",
            evidence=kwargs.get(
                "evidence",
                {"compromised": {"status": "compromised", "host": "polyfill.io"}},
            ),
            locations=kwargs.get(
                "locations",
                [
                    {
                        "file": "index.html",
                        "line": 3,
                        "tag": "script",
                        "runs_in": "browser",
                        "raw": "https://cdn.polyfill.io/v3/polyfill.min.js",
                    }
                ],
            ),
        )
    )


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


@pytest.fixture()
def fix_ui_url(tmp_path):
    async def runner(source, **kwargs):
        url = str(source)
        if url.endswith("/none"):
            return ScanOutcome(findings=[])
        if url.endswith("/noedit"):
            return ScanOutcome(
                findings=[
                    _finding(
                        target="gone-assets",
                        kind="bucket",
                        ref="src/config.js:1",
                        risk="The bucket is gone.",
                        evidence={
                            "bucket_probe": {
                                "status": "NoSuchBucket",
                                "name": "gone-assets",
                                "http_status": 404,
                            }
                        },
                        locations=[
                            {
                                "file": "src/config.js",
                                "line": 1,
                                "runs_in": "server",
                                "raw": "s3://gone-assets",
                            }
                        ],
                    )
                ],
                file_texts={"src/config.js": 'BUCKET = "s3://gone-assets"\n'},
            )
        return ScanOutcome(
            findings=[_finding()],
            file_texts={"index.html": POLYFILL_HTML},
        )

    app = create_app(
        model_client=FakeModelClient(handler=lambda r: {}),
        runner=runner,
        limits=LimitsStore(tmp_path / "limits.db", ip_per_hour=50, daily_cap=100),
    )
    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(50):
        if server.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=5)


def _scan(page, base: str, path: str) -> None:
    page.goto(base + "/", wait_until="networkidle")
    page.fill("#target", f"https://example.org{path}")
    page.locator("#scan-btn").click()
    page.wait_for_selector("#screen-results", state="visible", timeout=20_000)


def test_fix_it_hidden_when_nothing_to_fix(fix_ui_url):
    with sync_playwright() as playwright:
        page = playwright.chromium.launch().new_page()
        _scan(page, fix_ui_url, "/none")
        assert page.locator("#fix-it").is_hidden()
        assert page.locator("#fix-panel").is_hidden()
        assert page.locator("#fix-download").is_hidden()
        page.close()


def test_fix_it_plan_without_patch_when_no_edits(fix_ui_url):
    with sync_playwright() as playwright:
        page = playwright.chromium.launch().new_page()
        _scan(page, fix_ui_url, "/noedit")
        with page.expect_response(lambda res: "/fix" in res.url and "patch" not in res.url):
            page.get_by_role("button", name="Fix it").click()
        page.wait_for_selector("#fix-panel", state="visible")
        page.wait_for_selector("#fix-no-edits:not([hidden])")
        assert page.get_by_text("Fix plan").is_visible()
        assert page.get_by_text("No safe automatic edits; follow the steps above.").is_visible()
        assert page.locator("#fix-download").is_hidden()
        page.close()


def test_fix_it_opens_panel_and_patch_when_edits_exist(fix_ui_url):
    with sync_playwright() as playwright:
        page = playwright.chromium.launch().new_page()
        _scan(page, fix_ui_url, "/edits")
        button = page.get_by_role("button", name="Fix it")
        assert button.is_visible()
        with page.expect_response(lambda res: "/fix" in res.url and "patch" not in res.url):
            button.click()
        page.wait_for_selector("#fix-panel", state="visible")
        page.wait_for_selector("#fix-download:not([hidden])")
        assert page.get_by_text("Fix plan").is_visible()
        assert page.get_by_role("link", name="Download .patch").is_visible()
        page.close()
