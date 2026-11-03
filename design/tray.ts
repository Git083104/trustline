// Source of public/static/vendor/trustline-tray.js. To rebuild: unpack the
// sources of @lucasmarkes/hairline 0.5.1 (sourcesContent in dist/index.js.map)
// into design/hairline/src, then from design/ run esbuild 0.24:
//   npx esbuild@0.24 tray.ts --bundle --format=esm --minify --legal-comments=none
//     --outfile=../public/static/vendor/trustline-tray.js
// and put back the attribution banner the current bundle starts with.
/*!
 * Trustline's file tray: the Riffle figure from @lucasmarkes/hairline 0.5.1
 * (MIT License, Copyright (c) 2026 Lucas Marques, https://github.com/lucasmarkes/hairline;
 * full license in hairline-LICENSE.txt), changed for Trustline:
 * - no reflection under the tray, and the drawing scaled to fill its box;
 * - cards numbered back to front, so card 1 sits highest, like layer 01;
 * - the page can pull a card (pull), and a click or Enter picks one (onPick).
 */
import { clamp, rad, type Vec2 } from "hairline/src/core/iso";
import { tdone, tset, tval, tween, type Tween } from "hairline/src/core/motion";
import { BACK, FWD, G, H, LIFT, N, REST, TH, W, X0, X1, Y0, Y1, card, pose, scene, tray as trayPaths } from "hairline/src/figures/riffle-geometry";
import { disposer, mk, place, pointer, register } from "hairline/src/core/stage";
import { inject } from "hairline/src/core/styles";

type Card = {
  t0: number; shape: Vec2[];
  back: SVGPathElement; face: SVGPathElement; head: SVGPathElement; rules: SVGPathElement;
  punch: SVGCircleElement[];
  a: Tween; z: Tween;
};

export type TrayOptions = {
  /** One name per card, back card first. */
  names: string[];
  label: string;
  /** ms between neighbouring cards as they lean; Riffle's default is 40. */
  stagger?: number;
  /** A card was clicked, tapped, or chosen with Enter. */
  onPick?: (index: number) => void;
  /** The card standing up changed (-1: none). */
  onShow?: (index: number) => void;
};

export type Tray = {
  /** Stand card i up from outside (-1 lets it back down). The pointer and keys win over this. */
  pull(index: number): void;
  destroy(): void;
};

export function mountTray(el: HTMLElement, o: TrayOptions): Tray {
  inject(document);
  el.setAttribute("data-hairline", "riffle");
  el.setAttribute("data-hairline-theme", "light");
  el.setAttribute("role", "group");
  el.setAttribute("tabindex", "0");
  el.setAttribute("aria-label", o.label);
  const svg = mk("svg", { viewBox: "0 0 400 320", "aria-hidden": "true" }, el);
  const live = document.createElement("span");
  live.setAttribute("data-hairline-live", "");
  live.setAttribute("aria-live", "polite");
  el.appendChild(live);

  const bag = disposer();
  const stag = o.stagger ?? 40;
  const { P, front, outer, inner } = scene();
  const paths = trayPaths(P, front, outer, inner);

  // Riffle leaves room around the tray for its reflection; without one, scale the
  // drawing (every pose, a lifted card included) to fill the box instead.
  const reach = [[X0, Y0, 0], [X1, Y1, -8], [X1, Y0, 0], [X0, Y1, 0], [X0, Y0, H + TH], [X1, Y0, H + TH + LIFT]].map(([x, y, z]) => P(x, y, z));
  const xs = reach.map((q) => q[0]), ys = reach.map((q) => q[1]);
  const minX = Math.min(...xs), minY = Math.min(...ys), spanX = Math.max(...xs) - minX, spanY = Math.max(...ys) - minY;
  const k = Math.min((400 * 0.9) / spanX, (320 * 0.9) / spanY);
  const tx = 200 - k * (minX + spanX / 2), ty = 160 - k * (minY + spanY / 2);
  const g = mk("g", { transform: `translate(${tx.toFixed(2)} ${ty.toFixed(2)}) scale(${k.toFixed(4)})` }, svg);
  for (const [d, cls] of paths.far) mk("path", { d, class: cls }, g);

  const cards: Card[] = [];
  for (let i = 0; i < N; i++) {
    const { t0, shape } = card(i);
    const grp = mk("g", {}, g);
    const back = mk("path", { class: "lo" }, grp), face = mk("path", { class: "sil" }, grp);
    const head = mk("path", { class: "nf" }, grp), rules = mk("path", { class: "nf lo" }, grp);
    // the card's number, punched in a 4 × 2 grid on its tab: card i is number i + 1
    const punch: SVGCircleElement[] = [];
    for (let k = 0; k < 8; k++) punch.push(mk("circle", { r: 1.05, class: "dot " + (k === i ? "m" : "off") }, grp));
    cards.push({ t0, shape, back, face, head, rules, punch, a: tween(REST), z: tween(0) });
  }
  for (const [d, cls] of paths.near) mk("path", { d, class: cls }, g);

  // hit bands: oblique strips along the RESTING top edges. They never move.
  const top = (i: number) => P(W / 2, i * G + H * Math.sin(rad(REST)), H * Math.cos(rad(REST)));
  const c0 = top(0), c1 = top(1), d = [c1[0] - c0[0], c1[1] - c0[1]];
  const px0 = P(0, 0, 0), px1 = P(1, 0, 0), ex = [px1[0] - px0[0], px1[1] - px0[1]];
  const HALF = W / 2 + 6, det = d[0] * ex[1] - d[1] * ex[0];

  function hit([vx, vy]: Vec2) {
    // from the box's coordinates back into the drawing's
    const x = (vx - tx) / k, y = (vy - ty) / k;
    const qx = x - c0[0], qy = y - c0[1];
    const s = (qx * ex[1] - qy * ex[0]) / det, r = (d[0] * qy - d[1] * qx) / det;
    if (Math.abs(r) > HALF || s < -0.5 || s > N + 1) return -1;
    return clamp(Math.round(s), 0, N - 1);
  }

  const at = (e: MouseEvent): Vec2 => {
    const r = el.getBoundingClientRect();
    return [((e.clientX - r.left) / r.width) * 400, ((e.clientY - r.top) / r.height) * 320];
  };

  function draw(i: number, th: number, lift: number) {
    const cd = cards[i], q = pose(P, i, cd.t0, cd.shape, th, lift);
    cd.back.setAttribute("d", q.back);
    cd.face.setAttribute("d", q.face);
    cd.head.setAttribute("d", q.head);
    cd.rules.setAttribute("d", q.rules);
    cd.punch.forEach((dot, k) => place(dot, q.punch[k]));
  }

  const B = register(el, (_dt, now) => {
    let moving = false;
    cards.forEach((cd, i) => { draw(i, tval(cd.a, now), tval(cd.z, now)); if (!tdone(cd.a, now) || !tdone(cd.z, now)) moving = true; });
    return moving;
  });
  bag.add(B.unregister);

  /* who stands a card up: the pointer, then the keys, then the page */
  let act = -1, hover = -1, keyed = -1, outside = -1;
  function setActive(a: number) {
    if (a === act) return;
    const now = performance.now(), from = a >= 0 ? a : act;
    act = a;
    cards.forEach((cd, i) => {
      const delay = Math.abs(i - from) * stag;
      const th = a < 0 ? REST : i < a ? BACK : i > a ? FWD : 0;
      tset(cd.a, th, now, delay); tset(cd.z, a === i ? LIFT : 0, now, delay);
      cd.face.classList.toggle("hi", i === a); cd.head.classList.toggle("hi", i === a); cd.punch[i].classList.toggle("m", i !== a);
    });
    if (keyed >= 0 || hover >= 0) live.textContent = a >= 0 ? o.names[a] : "";
    B.wake();
    o.onShow?.(a);
  }
  const show = () => setActive(hover >= 0 ? hover : keyed >= 0 ? keyed : outside);

  bag.add(pointer(el, {
    move: (p) => { hover = hit(p); el.style.cursor = hover >= 0 ? "pointer" : ""; show(); },
    leave: () => { hover = -1; el.style.cursor = ""; show(); },
  }));
  bag.on(el, "click", (e: MouseEvent) => {
    const i = hit(at(e));
    if (i >= 0) o.onPick?.(i);
  });
  bag.on(el, "keydown", (e: KeyboardEvent) => {
    const k = e.key;
    if (k === "ArrowRight" || k === "ArrowDown") { keyed = act < 0 ? 0 : Math.min(N - 1, act + 1); show(); e.preventDefault(); }
    else if (k === "ArrowLeft" || k === "ArrowUp") { keyed = act < 0 ? 0 : Math.max(0, act - 1); show(); e.preventDefault(); }
    else if ((k === "Enter" || k === " ") && act >= 0) { o.onPick?.(act); e.preventDefault(); }
    else if (k === "Escape" && keyed >= 0) { keyed = -1; show(); e.preventDefault(); }
  });
  bag.on(el, "blur", () => { keyed = -1; show(); });
  bag.add(() => { svg.remove(); live.remove(); });

  return {
    pull: (index: number) => { outside = index; show(); },
    destroy: bag.dispose,
  };
}
