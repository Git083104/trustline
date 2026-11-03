// The file tray beside the layers: the Riffle figure from @lucasmarkes/hairline 0.5.1,
// MIT licensed (see vendor/hairline-LICENSE.txt). It riffles its cards on its own, answers
// the pointer, and riffles harder while a scan is running.
import { riffle } from "./vendor/hairline-riffle.js";

const host = document.getElementById("riffle");
const cell = document.querySelector(".stack-cell");
if (host && cell) {
  const figure = riffle(host, { play: true, intensity: 0.5, theme: "light", label: "A tray of file cards, lifting one at a time" });
  const sync = () => figure.update({ intensity: cell.getAttribute("data-scan") === "running" ? 0.9 : 0.5 });
  new MutationObserver(sync).observe(cell, { attributes: true, attributeFilter: ["data-scan"] });
  sync();
}
