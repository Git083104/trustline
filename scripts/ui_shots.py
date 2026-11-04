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

LAYOUT_JS = """
({ minRatio, maxLines }) => {
  const fails = [];
  const width = window.innerWidth;
  const findings = [...document.querySelectorAll('.finding')].filter((card) => {
    const box = card.getBoundingClientRect();
    return box.width > 0 && box.height > 0;
  });
  for (const card of findings) {
    const text = card.querySelector('.finding-main');
    if (!text) {
      fails.push('finding missing .finding-main');
      continue;
    }
    const cardW = card.getBoundingClientRect().width;
    const textW = text.getBoundingClientRect().width;
    if (cardW > 0 && textW / cardW < minRatio) {
      fails.push(
        `text column ${textW.toFixed(0)}px is ${(100 * textW / cardW).toFixed(1)}% of card ${cardW.toFixed(0)}px`
      );
    }
  }
  const nodes = [...document.querySelectorAll('body *')];
  for (const node of nodes) {
    const rect = node.getBoundingClientRect();
    if (rect.width < 1 || rect.height < 1) continue;
    if (rect.right > width + 1) {
      fails.push(
        `overflow ${node.tagName}.${node.className} right=${rect.right.toFixed(0)} vw=${width}`
      );
      break;
    }
  }
  if (document.documentElement.scrollWidth > width + 1) {
    fails.push(`document scrollWidth ${document.documentElement.scrollWidth} > ${width}`);
  }
  if (maxLines != null) {
    for (const p of document.querySelectorAll('.finding p, .finding-risk')) {
      const style = getComputedStyle(p);
      let lh = parseFloat(style.lineHeight);
      if (!Number.isFinite(lh)) lh = parseFloat(style.fontSize) * 1.5;
      const lines = lh > 0 ? p.getBoundingClientRect().height / lh : 0;
      if (lines >= maxLines) {
        fails.push(`paragraph ${lines.toFixed(1)} lines (>= ${maxLines}): ${p.textContent.slice(0, 60)}`);
      }
    }
  }
  return fails.slice(0, 8);
}
"""


def _assert_layout(page, *, width: int, label: str, errors: list[str]) -> None:
    min_ratio = 0.60 if width >= 1000 else 0.85
    max_lines = 6 if width >= 1000 else None
    fails = page.evaluate(LAYOUT_JS, {"minRatio": min_ratio, "maxLines": max_lines})
    if fails:
        errors.extend(f"{label}: {item}" for item in fails)
    else:
        print(f"PASS  layout {label}  findings text column + no overflow")


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
                page.on(
                    "console",
                    lambda msg, label=label: errors.append(f"{label} {msg.type} {msg.text}")
                    if msg.type == "error"
                    else None,
                )
                page.on("pageerror", lambda err, label=label: errors.append(f"{label} pageerror {err}"))
                page.goto(f"http://127.0.0.1:{PORT}/", wait_until="networkidle")
                page.wait_for_selector("text=Websites to try")
                page.wait_for_selector("text=Repos to try")
                page.wait_for_selector("text=See the full scan")
                page.wait_for_selector("text=Demo storefront")
                page.screenshot(path=str(OUT / f"home-{label}.png"), full_page=True)
                _assert_layout(page, width=width, label=f"home-{label}", errors=errors)

                page.get_by_role("button", name="Watch the demo").click()
                page.wait_for_selector("#screen-scanning", state="visible")
                page.wait_for_timeout(1800)
                page.screenshot(path=str(OUT / f"scanning-{label}.png"), full_page=True)
                _assert_layout(page, width=width, label=f"scanning-{label}", errors=errors)

                page.wait_for_selector("#skip-report:not([disabled])", timeout=15_000)
                page.get_by_role("button", name="Skip to report").click()
                page.wait_for_selector("#screen-results", state="visible", timeout=15_000)
                page.wait_for_selector("#screen-results .finding")
                page.screenshot(path=str(OUT / f"results-{label}.png"), full_page=True)
                _assert_layout(page, width=width, label=f"results-{label}", errors=errors)

                details = page.get_by_role("button", name="Details")
                if details.count():
                    details.first.click()
                copy = page.get_by_role("button", name="Copy")
                if copy.count():
                    copy.first.click()
                page.screenshot(path=str(OUT / f"results-details-{label}.png"), full_page=True)
                _assert_layout(page, width=width, label=f"results-details-{label}", errors=errors)

                page.get_by_role("button", name="Fix it").click()
                page.wait_for_selector("#fix-panel", state="visible")
                page.wait_for_selector("text=Fix plan")
                page.wait_for_selector("text=Copy as GitHub issue")
                page.wait_for_selector("text=Copy prompt for your coding assistant")
                page.get_by_role("button", name="Copy as GitHub issue").first.click()
                page.screenshot(path=str(OUT / f"fix-it-{label}.png"), full_page=True)
                _assert_layout(page, width=width, label=f"fix-it-{label}", errors=errors)

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
            print("layout / console errors:")
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
