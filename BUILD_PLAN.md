# Trustmap — Build Plan

You are building Trustmap for the Meta Global AI Developer Hackathon (deadline Wed Nov 4, 9 PM ET).
Work through the phases below IN ORDER. At the end of each phase: run the tests, show me the
acceptance check passing, commit with a clear message, and STOP for my review before starting the
next phase. If a step needs something only I can do (create an account, a bucket, a secret), stop
and tell me exactly what to do.

## What Trustmap does

Software trusts outside infrastructure it doesn't own: scripts loaded from other domains, API base
URLs, cloud storage buckets in deploy configs. When that infrastructure is abandoned (a domain
expires, a bucket is deleted), a stranger can claim it and inherit the trust. This happened with
Polyfill.io (100,000+ sites served malware after the domain was sold) and with ~150 abandoned S3
buckets that watchTowr re-registered for $420 and received 8M+ requests on.

Trustmap takes a repository, finds every outside reference, checks who owns each one now, and
returns a ranked list of what a stranger could take over, with a plain-English explanation and a
specific fix for each.

## Non-negotiable rules

1. **Code produces every fact.** Dates, DNS results, HTTP statuses, expiry math, counts, hashes:
   always deterministic code. Never ask a model to compute, parse or remember these.
2. **Muse models only classify and judge**, always returning JSON validated with Pydantic. Reject
   and retry invalid output (max 2 retries).
3. **Every number in a model-written explanation must match the evidence JSON.** Enforce with a
   check; regenerate on mismatch.
4. All model calls go through `scanner/llm.py` so the provider can be swapped by config.
5. Every network lookup has a timeout and is cached in SQLite.
6. Every module has pytest tests. Live network tests are marked `@pytest.mark.slow`.
7. **Safety:** never write code that registers, claims or writes to any bucket or domain. Detection
   only. The only bucket ever claimed is one I create myself for the demo.
8. Never commit `.env`, keys or tokens. Never print secrets in logs.

## Stack

- Python 3.12 managed with `uv`. Libraries: openai, httpx, dnspython, tldextract, pydantic,
  python-dotenv, pytest, pytest-asyncio, typer (CLI), fastapi, uvicorn.
- Web: Next.js (App Router, TypeScript, Tailwind) in `web/`, deployed to Vercel.
- Backend API: FastAPI in `api/`, deployable to Modal.
- Storage: SQLite (`trustmap.db`) for cache and scan results.

## Patterns to copy from Meta's own workshop repo

Meta's Agents 101/102 workshop (github.com/meta-models/legal-agent-workshop) shows the structure
judges will recognize. Follow it:
- **Agent loop:** each turn the model sees the instructions plus everything so far and picks ONE
  tool; code runs it for real and sends the result back; progress is saved every turn; the loop
  stops when a tool says the run is over or at a turn limit. The model chooses every tool call:
  never hard-code which tool runs when.
- **One file per tool** in `scanner/tools/`, each defining what the model sees and what happens
  when it's called, exposed through `tools.definitions()` and `tools.run()`.
- **Verification layer outside the agent's control:** checks in `scanner/verification/`, each with
  `run_verification(ctx, work) -> {"passed": bool, "feedback": ...}`, called by the tools at fixed
  points so the agent can't skip them. A failed check refuses the action and sends feedback back to
  the model; after 3 refusals, escalate to a person (`needs_review`).
- **Plan / act / observe trace:** log each turn as plan (the model's decision and tokens), act (the
  tool and arguments), observe (the result, green or refused). The web app shows this timeline.
- **Preflight:** on startup, call `GET /v1/models` and confirm the key can use the configured models.
- **Offline tests** use a fake model client so they never call the live API.

## Muse configuration (put in `scanner/config.py`, read from env)

- Meta Model API: OpenAI SDK, `base_url="https://api.meta.ai/v1"`, key `MODEL_API_KEY`. The
  workshop uses the Responses API (`client.responses.create`); Chat Completions also works.
- Default to `reasoning_effort="low"`. Fireworks' workshop measured Muse doing as well or better at
  low effort than at high on simple tasks, and `max` sometimes ran out of output tokens.
- `CLASSIFY_MODEL = "muse-spark-1.3"`, `reasoning_effort="low"`
- `AGENT_MODEL = "muse-spark-1.3"`, `reasoning_effort="low"` (raise only if the eval says so)
- `RANK_MODEL = "muse-spark-1.3"`, `reasoning_effort="medium"`; allow override to Muse Wonder via
  env `WONDER_MODEL_ID` (I will supply the ID; don't guess it). Make effort configurable and let
  the Phase 6 eval pick the best level per step.
- Open-weight provider (Phase 9): Baseten, model `meta-models/muse-spark-open-1026`. Confirm the
  base URL from Baseten's docs before using it; key `BASETEN_API_KEY`.
- Use structured outputs / JSON schema where supported; keep system prompts byte-identical across
  calls so prompt caching applies.

## Repository layout

```
CLAUDE.md
BUILD_PLAN.md
scanner/
  config.py      env + model settings
  models.py      Pydantic types (Reference, Evidence, Classification, Finding)
  extract.py     find references (no model)
  lookups.py     RDAP, DNS, bucket probe, crt.sh, Wayback (no model)
  llm.py         single Muse client wrapper
  classify.py    Muse classification
  agent.py       Muse tool-calling investigator
  report.py      ranking, self-check, fixes
  cli.py         `trustmap <path-or-github-url>`
  mcp_server.py  lookups exposed as MCP tools (Phase 7)
  fixer.py       fix PR generation (Phase 8)
api/             FastAPI app
web/             Next.js app
eval/            labeled set + eval scripts
tests/
  fixtures/demo_repo/
  fixtures/expected.json
```

---

## Phase 0 — Fixtures (answer key first)

Create `tests/fixtures/demo_repo/`, a small fake web app containing 15–20 outside references with
known answers:
- `<script src>` tags in HTML (including one from a domain that does not resolve)
- API base URLs in Python and JS/TS source
- an S3 bucket in a deploy config (`s3://`, `*.s3.amazonaws.com`, and path-style forms)
- a GCS URL (`storage.googleapis.com/...`)
- a URL in `.github/workflows/*.yml` and in a `Dockerfile`
- a link in `README.md`, a URL in a test file, and one in a code comment

Write `tests/fixtures/expected.json`: every reference with file, line, raw string, host or bucket,
and expected `type` and `runs_in`. Demo S3 bucket names come from env
`TRUSTMAP_BUCKET_LIVE` and `TRUSTMAP_BUCKET_GONE`.

**Accept when:** fixture exists, expected.json is valid and complete. No scanner code yet.

## Phase 1 — Extractor

`scanner/extract.py`:
- Accept a local path or a GitHub URL (shallow clone to a temp dir).
- Skip `.git`, `node_modules`, `vendor`, `dist`, `build`, binaries, files > 1 MB.
- Find `https?://` URLs and bucket references (`s3://name`, `name.s3.amazonaws.com`,
  `s3.amazonaws.com/name`, `s3.<region>.amazonaws.com/name`, `storage.googleapis.com/name`).
- Reduce hosts to registrable domains with tldextract.
- Drop an allowlist of large-platform domains (github.com, githubusercontent.com, googleapis.com
  root, amazonaws.com root, npmjs.com, pypi.org, w3.org, schema.org, localhost, example.com only
  outside the fixture) — keep the list in config.
- Deduplicate by (host-or-bucket, file, line); keep 10 lines of context.

**Accept when:** 100% of references in expected.json are found on the fixture; test passes.

## Phase 2 — Evidence lookups

`scanner/lookups.py`, all async with timeouts and SQLite cache, each returning a Pydantic model:
- `rdap(domain)`: status, registrar, expiry date, days_to_expiry (computed in code). Use the IANA
  bootstrap file to find the TLD's RDAP server. Only a 404 from that server is unregistered;
  missing TLD RDAP or rdap.org-only answers are unknown. DNS that resolves is never unregistered.
- `dns(host)`: resolves / NXDOMAIN / other error, plus CNAME chain.
- `bucket_probe(name, provider)`: exists / NoSuchBucket (claimable) / access denied, from a plain
  HTTP GET. Never PUT or create.
- `cert_history(domain)`: crt.sh JSON, recent issuers and first/last seen dates; 15 s timeout,
  failures return `unavailable`, not an error.
- `wayback(url)`: CDX API first and last snapshot dates and digests.

**Accept when:** unit tests with mocked HTTP pass; slow live tests pass for a known-good domain
and a known-nonexistent one.

## Phase 3 — Muse wrapper + classifier

`scanner/llm.py`: `call_json(model, system, user, schema, reasoning_effort)` → validated Pydantic
object; retries on invalid JSON; logs tokens and latency per call (needed for the demo's
model-usage panel).

`scanner/classify.py`: batches of 20 references with context →
`type` (script, api, asset, config, bucket, ci, docs, test), `runs_in` (browser, server, build, ci,
docs_only), `blast_radius` 0–3, `confidence`, one-line reason.

**Accept when:** on the fixture, `type` matches expected.json for ≥ 90% of references; print a
table of mismatches.

## Phase 4 — Investigator agent

`scanner/agent.py`: Muse tool calling with the Phase 2 functions as tools. Code first runs free
deterministic checks on every actionable reference (`dns` + `rdap` for hosts, `bucket_probe` for
buckets). A hard signal (`NoSuchBucket`, NXDOMAIN, RDAP unregistered, or expiry within 90 days)
always sends the reference to the agent, even if `blast_radius` is 0. `blast_radius` ≥ 1 still
selects references without a hard signal, and is used later for ranking. The model then chooses
follow-up lookups (max 6 calls) and emits `done(summary)`. Log every tool call with arguments and
result.

**Accept when:** the agent investigates every fixture reference with a hard signal or
blast_radius ≥ 1, and the claimable demo bucket and the non-resolving script domain both appear
in its evidence.

## Phase 5 — Ranking, self-check, CLI

`scanner/report.py`: group investigations by target (bucket name or registrable domain) and rank
once per target. Muse (RANK_MODEL) sees classification plus merged evidence and returns
`severity`, `risk`, `fix`, `uncertain_about`, and `blast_radius` (may override classify; record
when it does). Code floors severity: claimable-now (NoSuchBucket, RDAP unregistered) in an
executing position is at least critical; other hard signals (NXDOMAIN on a registered domain,
expiry ≤ 90 days) are at least high. Self-check: every date, number and status word in `risk`
must appear in the evidence JSON; regenerate on mismatch (max 2), else `needs_review`. Sort by
severity then ranked blast radius.

`scanner/cli.py`: `uv run trustmap <path-or-url> [--json out.json]` prints a ranked table.

**Accept when:** the three claimable targets (S3 `acme-legacy-uploads` with 2 refs,
`cdn-assets-trustmap-7f3k2.com`, GCS `trustmap-demo-assets`) are the top three and all critical.
Live S3 `acme-static-assets` is low or info. README/test references are low/info. The `.invalid`
host is filtered (`reserved_tld`) and must not rank.

## Phase 6 — Evaluation

`eval/`:
- `label.py`: extract + free lookups only; group by target; cap 25 per repo (hard signals first,
  then random sample seed 42); `--auto` labels fact-decided targets (`source=auto`), then
  hand-label the rest (`source=human`) into `eval/labels.jsonl`. Resume keeps existing labels.
  `eval/repos.txt` is the default list. Labels file is gitignored.
- `run_eval.py`: baseline (claimable-now → critical, NXDOMAIN/expiry≤90 → high, else low) vs
  Trustmap full scan ($3 cap). Metrics only on labeled targets, reported for all labels and
  human-labeled only. Precision@10, recall of critical/high, confusion table, model cost,
  budget skips. Writes `eval/results.md`.

**Accept when:** offline tests pass and `run_eval.py` prints one comparison table on canned labels.

## Phase 7 — Web app

- `api/`: FastAPI with `POST /scan {repo_url}` → job id, `GET /scan/{id}/events` (server-sent
  events streaming progress and tool calls), `GET /scan/{id}` (final report). Add a Modal deploy
  file. Pre-compute and cache the demo repo's scan so it loads instantly.
- `web/`: one input page (paste a GitHub URL) and one report page with:
  - a **trust map**: the repo as a central node, each outside dependency around it, coloured by
    severity (use a force-directed graph);
  - the ranked findings list with risk, fix and evidence (expandable);
  - a live agent timeline during scanning, one row each for plan, act and observe per turn
    (like the workshop's Agent Console);
  - a "models used" panel: which Muse model ran each step, tokens and latency.
- Deploy web to Vercel.

**Accept when:** I can paste the fixture's GitHub URL and watch the scan stream to a finished map.

## Phase 8 — Muse Code integration

- `scanner/mcp_server.py`: expose the Phase 2 lookups as an MCP server over stdio using the
  official Python MCP SDK.
- Tell me the exact `mcpServers` block to add to `~/.config/muse/settings.json`, and a test
  prompt to run in Muse Code that lists the tools.
- `.github/workflows/trustmap.yml`: on pull_request, run a read-only scan of the diff's new
  references with `muse exec` (read-only: no approvals needed) and post findings as a PR comment.
  Use repository secrets for keys; tell me which to add.

**Accept when:** I can run the MCP server in Muse Code and the workflow runs on a test PR.

## Phase 9 — Fix PRs and open-weight mode

- `scanner/fixer.py`: for findings whose fix is "remove dead reference" or "pin with SRI",
  generate a patch and open a PR on the demo repo with `gh`. SRI hashes must be computed from a
  known-good copy (Wayback snapshot), NEVER from what a possibly taken-over host serves now.
  After the PR, rescan and show the finding resolved.
- Open-weight mode: `--provider fireworks` (or `baseten`) switches `llm.py` to Muse Spark Open.
- **Fine-tuned Muse Glimmer classifier** (follow the Fireworks workshop's router notebook:
  github.com/sinanuozdemir/ai-experiments/tree/main/experiments/meta-hackathon-muse, which took
  Glimmer from 22.5% to 90% route accuracy with LoRA SFT on 600 examples):
  - Build training data from Phase 3 classifications I've reviewed plus my Phase 6 labels.
  - LoRA SFT Muse Glimmer 30B with the Fireworks Serverless Training API (`fw-ai/cookbook` Muse
    Glimmer starter). Fireworks says LoRA SFT is free for jobs started before Dec 1, 2026;
    evaluation is billed per token and deployments per GPU-hour, so delete the deployment after.
  - Compare base Glimmer, tuned Glimmer and Muse Spark on held-out references: accuracy, cost,
    latency. Training is slow, so start it as soon as the labels exist and tell me when.
- Run the Phase 6 eval on every provider and print one comparison table.

**Accept when:** a fix PR exists on the demo repo, and the eval table shows Spark, Spark Open,
base Glimmer and tuned Glimmer side by side.

## Phase 10 — Then-vs-now screenshots (stretch)

Playwright screenshots of today's page at a flagged host and its last Wayback snapshot; Muse Spark
vision answers "same service, parked/for-sale page, or different content?" with a reason. Show
both images in the finding.

## Phase 11 — Public repo scan (stretch, headline impact number)

Scan 500–1,000 popular public repos with extraction + cheap checks only (dns, bucket_probe,
rdap), and run the agent only on hits. Output aggregate counts only — never publish repo names or
bucket names. Write findings to a private file so I can notify maintainers.

## Finally — README

Write README.md: what Trustmap does (one paragraph), the Polyfill.io and watchTowr context, how
each Muse model is used and why, architecture diagram (Mermaid), eval results table, how to run it
locally, the safety rules above, and a clear statement that everything was built during the
hackathon (Oct 27–Nov 4, 2026).
