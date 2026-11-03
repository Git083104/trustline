#!/usr/bin/env python3
"""Playwright click-through of home → scanning → results. Screenshots in design/compare/."""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "design" / "compare"
PORT = 8765


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    server = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "api.main:app",
            "--factory",
            "--host",
            "127.0.0.1",
            "--port",
            str(PORT),
        ],
        cwd=ROOT,
    )
    try:
        time.sleep(1.2)
        errors: list[str] = []
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            for width, height, label in ((1440, 900, "1440"), (390, 844, "390")):
                page = browser.new_page(viewport={"width": width, "height": height})
                page.on("console", lambda msg: errors.append(f"{label} {msg.type} {msg.text}") if msg.type == "error" else None)
                page.on("pageerror", lambda err: errors.append(f"{label} pageerror {err}"))
                page.goto(f"http://127.0.0.1:{PORT}/", wait_until="networkidle")
                page.screenshot(path=str(OUT / f"home-{label}.png"), full_page=True)
                page.get_by_role("button", name="Watch the demo").click()
                page.wait_for_selector("#screen-scanning", state="visible")
                page.screenshot(path=str(OUT / f"scanning-{label}.png"), full_page=True)
                page.wait_for_selector("#screen-results", state="visible", timeout=120_000)
                page.screenshot(path=str(OUT / f"results-{label}.png"), full_page=True)
                details = page.get_by_role("button", name="Details")
                if details.count():
                    details.first.click()
                copy = page.get_by_role("button", name="Copy")
                if copy.count():
                    copy.first.click()
                page.screenshot(path=str(OUT / f"results-details-{label}.png"), full_page=True)
                page.get_by_role("button", name="Show the work").click()
                for name in ("Fix first", "All targets", "Agent trace", "Raw JSON"):
                    page.get_by_role("tab", name=name).click()
                    page.screenshot(
                        path=str(OUT / f"tab-{name.split()[0].lower()}-{label}.png"),
                        full_page=True,
                    )
                page.close()
            browser.close()
        if errors:
            print("console errors:")
            print("\n".join(errors))
            return 1
        print(f"screenshots wrote to {OUT}")
        return 0
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()


if __name__ == "__main__":
    raise SystemExit(main())
