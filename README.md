# Tether

Tether finds the parts of your code a stranger could take over.

Live: [https://trustline-cxqq.onrender.com](https://trustline-cxqq.onrender.com)

Demo video: `<VIDEO_URL>`

## The problem

In 2024 the `polyfill.io` domain was sold. Sites that still loaded the old CDN — more than 100,000 of them — started receiving malware from a name they had trusted for years. The same pattern shows up as abandoned S3 buckets (anyone can create the missing name) and deleted GitHub accounts (repojacking: a stranger registers the handle and the old URLs start serving their code). Your repo can keep pointing at all of that long after you stopped meaning to.

## What it does

- Scans a **GitHub repository** or a **website** for hosts, buckets, and accounts the code still trusts.
- Labels each finding **Proven** (checked directly) or **Likely**, with a plain-language **Fix plan**: a GitHub issue, a prompt for a coding assistant, and a safe patch when an edit is automatic.
- Runs on **pull requests** via the checked-in workflow.
- Works in **Muse Code over MCP** (read-only lookup tools plus scan).
- Ships a **README badge**: `GET /api/badge?repo=<url>` renders `Tether | 0 claimable` (green) or `N claimable` (red) from the latest cached scan only. It never starts a scan.

## How it works

```
extract → code checks (DNS, RDAP, bucket probes, GitHub, Pages with DNS proof, Tranco, compromised list)
       → Muse Spark agent (plan → tool → observe)
       → code floors set the minimum severity
       → plain-language report and Fix plan
```

**Code produces the facts; the model explains them and never decides alone what's true.**

## Results

Scored with the **revised rubric** (3 Nov 2026): expiry-only names are not Fix-today, and an NXDOMAIN subdomain of a registered parent is not a stranger takeover. Labels were not rewritten; scoring remaps them. See `eval/rubric.md`.

Latest eval (`eval/results.md`, **2026-11-04 (revised rubric)**):

| system | real threats caught | false alarms |
|---|---|---|
| baseline (original labels) | 3/3 | 46 |
| baseline (revised labels) | 3/3 | 10 |
| Tether | **3/3** | **0** |

Human-labeled only: Tether 3/3 real threats, 0 false alarms; revised baseline 3/3 with 2 false alarms.

Some repos withheld pending maintainer notification.

## Try it

On the home page, **Repos to try** and **Websites to try** are public examples with an expected result from the last production warm run.

The demo storefront is ours. Its risky names are planted on purpose and blocked by Content-Security-Policy, so they do not run in a visitor's browser.

## Run locally

Python 3.12 and [uv](https://docs.astral.sh/uv/):

```bash
uv sync --group dev
uv run pytest -q -m 'not slow'
uv run uvicorn api.main:app --factory --host 127.0.0.1 --port 8000
```

```bash
uv run trustmap scan https://github.com/owner/repo
uv run trustmap scan https://example.com
uv run trustmap fix ./path/to/repo
```

Environment variables (names only): `MODEL_API_KEY`, `GITHUB_TOKEN`, and the `TRUSTMAP_*` limits (`TRUSTMAP_DAILY_CAP_USD`, `TRUSTMAP_IP_SCANS_PER_HOUR`, `TRUSTMAP_MAX_CONCURRENT_SCANS`, `TRUSTMAP_TRUSTED_PROXY_HOPS`, `TRUSTMAP_SCAN_DEADLINE_S`, `TRUSTMAP_CACHE_DB`, `TRUSTMAP_ALLOW_LOCAL_SCAN`, `TRUSTMAP_CORS_ORIGINS`, `TRUSTMAP_CLONE_TIMEOUT_S`, `TRUSTMAP_MAX_SCAN_FILES`, `TRUSTMAP_MAX_SCAN_BYTES`, `TRUSTMAP_ADMIN_TOKEN`). Keep `TRUSTMAP_ALLOW_LOCAL_SCAN` unset or `0` unless you are running tests.

Muse Code / MCP: [docs/muse-code.md](docs/muse-code.md).

CI on pull requests: [.github/workflows/trustmap.yml](.github/workflows/trustmap.yml).

## Safety and ethics

Detection only. Tether never registers a domain, never claims a bucket, and never writes to someone else's account. The only bucket ever claimed in a demo is one we created.

Website scans refuse private and link-local targets (SSRF protection). The demo storefront uses CSP so planted scripts do not execute. The hosted app has per-IP and daily spend limits. After the hackathon, issues we did not plant will be disclosed to maintainers before they are named in public write-ups.

## Where this goes next

Continuous monitoring and alerts; a GitHub App for whole orgs; an "is this ours?" allowlist; expiry warnings; website script inventory (PCI DSS 6.4.3); SARIF / code scanning; npm and PyPI maintainer-domain checks.

## Built with

Meta Muse Spark (Meta Model API), Muse Code, FastAPI, Render.

## Credits and acknowledgements

- [jwang2007/trustline](https://github.com/jwang2007/trustline): the original Trustline project, interface and visual design this work builds on.
- [jwang2007/trustline-merged](https://github.com/jwang2007/trustline-merged): the merged team fork; we took its temperature-0 repeatability, agent fixes, isometric layers, tray illustration, favicons/logo and "Repos to try".
- [matthewL687/trustline-merged](https://github.com/matthewL687/trustline-merged): the scan-budgets branch, whose per-IP limit and code-only fallback ideas we adopted.
- [jwang2007/paperplane-shop](https://github.com/jwang2007/paperplane-shop): the demo repository and storefront.

### Team

- Ben Bischoff ([@Git083104](https://github.com/Git083104)): `<ROLE>`
- jwang ([@jwang2007](https://github.com/jwang2007)): `<ROLE>`
- Matthew ([@matthewL687](https://github.com/matthewL687)): `<ROLE>`

### Third-party data and code

- [Tranco](https://tranco-list.eu/) top-sites list ID `7462X`, created 2026-10-31 (daily list 2026-10-02–2026-10-31). File and notes: `scanner/data/README.md`.
- polyfill.io / related compromised-domain list from [Censys, July 2024](https://www.censys.com/blog/july-2-polyfill-io-supply-chain-attack-digging-into-the-web-of-compromised-domains), stored in `scanner/compromised.json`.
- Vendored [hairline](https://github.com/lucasmarkes/hairline) Riffle (`api/static/vendor/`, MIT, `api/static/vendor/hairline-LICENSE.txt`). The live scanning screen no longer mounts the tray; the vendor files remain.
- Hosting-platform takeover fingerprints ported from [jwang2007/trustline](https://github.com/jwang2007/trustline) `app/platforms.py` into `scanner/tools/platform_takeover.py`.

## Hackathon

Built for the Meta Global AI Developer Hackathon (Cerebral Valley), Indie track.

## Code name

Code name: trustmap (formerly Trustline). `TRUSTMAP_*` env vars and the `trustmap` CLI keep that name.

## License

License: TBD
