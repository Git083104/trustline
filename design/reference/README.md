# Trustline design reference (unpacked from the Claude Design export)

- home.png / scanning.png / results.png (desktop 1440 + mobile 390): the exact target look. Match these.
- home.html / scanning.html / results.html: the rendered DOM of each screen, with inline styles and CSS tokens. Copy the markup and styles from these; scripts and embedded fonts were removed. The bottom "Home / Scanning / Results" switcher is a design-tool control, not part of the site.
- design-source.html: the original design-tool source (x-dc template + logic) for reference only. Don't ship it.
- Fonts: Inter (body/headings) and JetBrains Mono (mono). Load them from Google Fonts.
- All data shown is demo data. The real app must render from the API.
