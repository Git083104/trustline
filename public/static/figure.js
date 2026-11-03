// The file tray in the right-hand box: Riffle from @lucasmarkes/hairline 0.5.1 (MIT,
// see vendor/hairline-LICENSE.txt), rebuilt as vendor/trustline-tray.js (source:
// design/tray.ts). Eight cards, back to front: the five layers, Run details, Repos
// to try, About. A layer under the pointer or keyboard stands its card up, the scan
// stands up the layer it is on, and between scans the cards take turns.
import { mountTray } from "./vendor/trustline-tray.js";

const NAMES = ["01 Gather", "02 Classify", "03 Investigate", "04 Reason", "05 Report", "Run details", "Repos to try", "About"];
const STEP_MS = 1100;   // each card's turn between scans
const REST_MS = 2600;   // the pause after the last card
const IDLE_MS = 1600;   // quiet time before the turns start again

const host = document.getElementById("files");
const caption = document.getElementById("files-cap");
const stackCell = document.querySelector(".stack-cell");
const items = Array.from(document.querySelectorAll("#stack-list li"));
const slabs = Array.from(document.querySelectorAll(".slab"));

if (host && caption && stackCell) {
  const still = window.matchMedia("(prefers-reduced-motion: reduce)");
  let hovered = -1;   // a layer under the pointer or keyboard focus
  let running = -1;   // the layer the scan is on
  let turn = -1;      // whose turn it is between scans
  let onTray = false; // the pointer is over the tray itself
  let keys = false;   // the tray has keyboard focus
  let timer = 0;
  let seen = true;

  const hot = (index) => {
    [items, slabs].forEach((list) => list.forEach((el) => {
      if (Number(el.getAttribute("data-layer")) - 1 === index) { el.setAttribute("data-hot", ""); }
      else { el.removeAttribute("data-hot"); }
    }));
  };

  const tray = mountTray(host, {
    names: NAMES,
    label: "Shortcuts: eight cards. Arrow keys pick one, Enter opens it: layers 01 to 05, Run details, Repos to try, About.",
    onShow: (index) => {
      caption.textContent = index >= 0 ? NAMES[index] : "";
      // a card picked on the tray points back at its layer in the stack
      hot((onTray || keys) && index >= 0 && index < 5 ? index : -1);
    },
    onPick: (index) => document.dispatchEvent(new CustomEvent("trustline:card", { detail: index })),
  });

  const show = () => tray.pull(hovered >= 0 ? hovered : running >= 0 ? running : turn);

  const schedule = (ms) => {
    clearTimeout(timer);
    timer = window.setTimeout(step, ms);
  };
  function step() {
    if (hovered >= 0 || running >= 0 || onTray || keys || still.matches || !seen || document.hidden) {
      turn = -1;
      show();
      schedule(IDLE_MS);
      return;
    }
    turn = turn >= NAMES.length - 1 ? -1 : turn + 1;
    show();
    schedule(turn < 0 ? REST_MS : STEP_MS);
  }

  const point = (index) => () => { hovered = index; turn = -1; show(); schedule(IDLE_MS); };
  [items, slabs].forEach((list) => list.forEach((el) => {
    const index = Number(el.getAttribute("data-layer")) - 1;
    el.addEventListener("mouseenter", point(index));
    el.addEventListener("mouseleave", point(-1));
    el.addEventListener("focusin", point(index));
    el.addEventListener("focusout", point(-1));
  }));
  host.addEventListener("pointerenter", () => { onTray = true; turn = -1; show(); });
  host.addEventListener("pointerleave", () => { onTray = false; hot(-1); schedule(IDLE_MS); });
  // keys walk the cards from the back; the turns wait until focus leaves
  host.addEventListener("focus", () => { keys = true; turn = -1; show(); });
  host.addEventListener("blur", () => { keys = false; hot(-1); schedule(IDLE_MS); });

  // the layer a scan is on stands up its card until the next one starts
  const follow = () => {
    const live = items.find((li) => li.getAttribute("data-state") === "running");
    running = live && stackCell.getAttribute("data-scan") === "running" ? Number(live.getAttribute("data-layer")) - 1 : -1;
    show();
  };
  const watch = new MutationObserver(follow);
  items.forEach((li) => watch.observe(li, { attributes: true, attributeFilter: ["data-state"] }));
  watch.observe(stackCell, { attributes: true, attributeFilter: ["data-scan"] });

  // no turns while the tray is off screen or the tab is in the background
  if ("IntersectionObserver" in window) {
    new IntersectionObserver((entries) => { seen = entries.some((entry) => entry.isIntersecting); }).observe(host);
  }
  follow();
  schedule(IDLE_MS);
}
