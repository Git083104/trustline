# Trustline design

A Swiss-grid page: paper background, thin salmon cell rules, a big grotesk title, mono
"prompt" text, cobalt blocks for the main action and for alerts, a stack of five slabs
for the layers, and a Win95-style dialog for errors.

- Fonts: Inter Tight (display), Inter (body), IBM Plex Mono (mono), from Google Fonts.
- Tokens: `:root` in `public/static/app.css` (paper `#F3F2EE`, ink `#111111`, rules
  `#E9B6AA`, cobalt `#1D3BD1`).
- Layout: a five-column grid that collapses to one column under 860px.
- Look: `docs/screenshot.png`.

Every number and label on the page comes from the API. Report text is written by the
scanned code and by the model, so it only reaches the page through `textContent`, and
report targets never become links.

The file tray next to the layers is Riffle from `@lucasmarkes/hairline` 0.5.1 (MIT,
`public/static/vendor/hairline-LICENSE.txt`), rebuilt from `design/tray.ts`: no
reflection, cards numbered back to front, and hooks so a layer can stand its card up and
a card can be clicked. Cards 1 to 5 jump to the layers, 6 opens Run details, 7 Repos to
try, 8 About.
