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


HOME_ONLY_JS = """
() => {
  const fails = [];
  const width = window.innerWidth;
  for (const node of document.querySelectorAll('.repo-chip-name')) {
    if (node.scrollWidth > node.clientWidth + 1) {
      fails.push(`truncated title: ${node.textContent}`);
    }
  }
  const text = document.body.innerText;
  if (!text.includes('Demo storefront (ours)')) fails.push('missing storefront title');
  if (!text.includes('4 problems planted on purpose')) fails.push('missing storefront line');
  if (!text.includes('wikipedia.org')) fails.push('missing wikipedia title');
  if ((text.match(/Control: should come back clean/g) || []).length !== 1) {
    fails.push('wikipedia control line should appear once');
  }
  if (document.documentElement.scrollWidth > width + 1) {
    fails.push(`document scrollWidth ${document.documentElement.scrollWidth} > ${width}`);
  }
  return fails;
}
"""


def main() -> int:
    home_only = "--home-only" in sys.argv
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
                page.wait_for_selector("#hero-canvas")
                page.wait_for_selector("text=Demo storefront")
                canvas = page.locator("#hero-canvas")
                box = canvas.bounding_box()
                before = page.evaluate("() => window.heroStats && window.heroStats.frames")
                if box:
                    page.mouse.move(box["x"] + box["width"] * 0.4, box["y"] + box["height"] * 0.5)
                    page.mouse.down()
                    page.mouse.move(box["x"] + box["width"] * 0.7, box["y"] + box["height"] * 0.45, steps=8)
                    page.mouse.up()
                page.wait_for_timeout(400)
                after = page.evaluate("() => window.heroStats || {}")
                frames_after = after.get("frames") or 0
                if before is not None and frames_after <= before:
                    errors.append(f"{label} hero: drag did not produce a new frame")
                else:
                    print(
                        f"PASS  hero drag {label}  avgMs={after.get('avgMs')} frames={frames_after}"
                    )
                page.screenshot(path=str(OUT / f"home-{label}.png"), full_page=True)
                _assert_layout(page, width=width, label=f"home-{label}", errors=errors)
                home_fails = page.evaluate(HOME_ONLY_JS)
                if home_fails:
                    errors.extend(f"{label} home: {item}" for item in home_fails)
                else:
                    print(f"PASS  home copy {label}")
                if home_only:
                    page.close()
                    continue

                page.get_by_role("button", name="Watch the demo").click()
                page.wait_for_selector("#screen-scanning", state="visible")
                page.wait_for_selector("text=Now checking")
                page.wait_for_timeout(1800)
                page.get_by_role("button", name="Tether").click()
                page.wait_for_selector("#page-home", state="visible")
                page.wait_for_selector("text=Scan in progress")
                page.get_by_role("button", name="View").click()
                page.wait_for_selector("#screen-scanning", state="visible")
                page.go_back()
                page.wait_for_selector("#page-home", state="visible")
                page.go_forward()
                page.wait_for_selector("#screen-scanning", state="visible")
                print(f"PASS  navigation {label}")
                page.screenshot(path=str(OUT / f"scanning-{label}.png"), full_page=True)
                _assert_layout(page, width=width, label=f"scanning-{label}", errors=errors)

                page.wait_for_selector("#screen-results", state="visible", timeout=120_000)
                page.wait_for_selector("#screen-results .finding")
                if page.locator("#badge-copy").count():
                    page.screenshot(path=str(OUT / f"results-badge-{label}.png"), full_page=True)
                page.screenshot(path=str(OUT / f"results-{label}.png"), full_page=True)
                _assert_layout(page, width=width, label=f"results-{label}", errors=errors)
                page.reload(wait_until="networkidle")
                page.wait_for_selector("#screen-results", state="visible", timeout=15_000)
                print(f"PASS  results reload {label}")

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
                page.get_by_role("tab", name="Agent trace").click()
                if page.locator(".feed-k").count():
                    page.wait_for_selector("text=Question")
                page.screenshot(path=str(OUT / f"tab-agent-{label}.png"), full_page=True)
                later = page.get_by_text("never run, so there's nothing to fix")
                if later.count():
                    page.screenshot(path=str(OUT / f"review-later-{label}.png"), full_page=True)
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
