# Trustline scan API

Base URL is the FastAPI app (`uvicorn api.main:app --factory`). All JSON events are
SSE frames `data: {json}\n\n`. Every event object has `type`, `scan_id`, and `ts`.

Jobs live in process memory. A restart forgets them.

## `POST /api/scan`

Start a scan. `kind` is inferred from `target` (`repo` = GitHub URL, `path` = existing
local path, `website` = other `http(s)` URL) and may be set explicitly.

```json
{"target": "https://github.com/acme/widgets"}
```

```json
{"scan_id": "7c2e1a9b", "kind": "repo", "target": "https://github.com/acme/widgets"}
```

Website targets are fetched once (no JS execution). Private, loopback, link-local,
multicast, reserved, and unspecified addresses are refused with:

```json
{"type": "error", "message": "This address can't be scanned"}
```

```json
POST /api/scan
{"target": "https://example.com"}

{"scan_id": "7c2e1a9b", "kind": "website", "target": "https://example.com"}
```

Public-safety limits (demo routes are exempt):

- Daily model-spend cap (`TRUSTMAP_DAILY_CAP_USD`, default 10). Each accepted scan
  reserves the per-scan cap (`SCAN_COST_CAP_USD`, default 1) against the day, then
  reconciles to actual spend when the job ends.
- Per-IP cap (`TRUSTMAP_IP_SCANS_PER_HOUR`, default 5). Client `X-Forwarded-For` is
  ignored unless `TRUSTMAP_TRUSTED_PROXY_HOPS` is set (0 locally, 1 on Render).
- Concurrent jobs (`TRUSTMAP_MAX_CONCURRENT_SCANS`, default 3) → 429
  `"Busy, try again in a minute"`.

When the daily cap is hit:

```json
429
{"error": "Daily limit reached, try the demo"}
```

Unknown `scan_id` on later GETs → 404.

If `MODEL_API_KEY` is not set (and no test client is injected):

```json
503
{"error": "Live scans aren't configured; try the demo"}
```

No job is created. Demo routes do not need the key.

## `GET /api/scan/{id}/events`

Replay buffered events, then live ones, then close on `done` or `error`.

| `type` | When | Payload |
|---|---|---|
| `started` | job accepted | `kind`, `target`, `cost_cap_usd` |
| `extracted` | after extract | `references`, `actionable`, `filtered`, `coverage` (`files_scanned`, `files_total`, `truncated`, `reason`) |
| `precheck` | after lookups for one target | `target`, `kind` (bucket/domain), `hard_signal` |
| `plan` / `act` / `observe` | each agent turn | `target`, `tool`, `args`, `result_summary`, `tokens`, `cost_usd` |
| `ranked` | each finding after rank | public finding fields (see report JSON) |
| `done` | finished | `finding_count`, `cost_usd`, `classify_cost_usd`, `agent_cost_usd`, `rank_cost_usd`, `budget_targets`, `partial`, `skipped_targets` |
| `error` | failure | `message` (no secrets) |

Live scans are not paced. Demo replay is (see below).

## `GET /api/scan/{id}`

Final report. **409** if still running, **404** if unknown, **500** if the job failed.

```json
{
  "scan_id": "7c2e1a9b",
  "kind": "repo",
  "target": "https://github.com/acme/widgets",
  "status": "done",
  "cost_usd": 0.12,
  "classify_cost_usd": 0.04,
  "agent_cost_usd": 0.06,
  "rank_cost_usd": 0.02,
  "budget_targets": [],
  "partial": false,
  "skipped_targets": [],
  "coverage": {
    "files_scanned": 12,
    "files_total": 12,
    "truncated": false,
    "reason": ""
  },
  "findings": [
    {
      "target": "cdn-assets-trustmap-7f3k2.com",
      "kind": "domain",
      "severity": "critical",
      "model_severity": "high",
      "floor_reason": "RDAP unregistered in executing position (browser) is at least critical",
      "floor_applied": "critical",
      "risk": "...",
      "fix": "Remove or replace this reference. If this was yours, re-create it in your own account to reclaim the name.",
      "evidence_line": "Evidence: DNS does not resolve · domain not registered",
      "evidence": {
        "dns": {"status": "nxdomain"},
        "rdap": {"status": "unregistered"},
        "tranco_rank": null,
        "live_fetch": {
          "parked": false,
          "for_sale": false,
          "signal": null,
          "final_url": "https://cdn-assets-trustmap-7f3k2.com/lib.js",
          "status": "ok"
        }
      },
      "tranco_rank": null,
      "parked": false,
      "for_sale": false,
      "live_signal": null,
      "action_ref": "",
      "action_sha_pinned": null,
      "references": ["index.html:7"],
      "cost_usd": 0.02
    }
  ]
}
```

Extra finding fields:

- `tranco_rank`: int or null (popularity; never lowers a code floor)
- `floor_reason` / `floor_applied`: UI floor note, e.g. "Domain is listed for sale → raised to high."
- `evidence.live_fetch`: `final_url`, `http_status`, `redirect_chain`, `title`, `parked`, `for_sale`, `signal`
- `action_ref` / `action_sha_pinned`: GitHub Actions `uses:` pin (full 40-char SHA or not)
- `evidence.github_repo`: `exists` / `missing` for `owner/repo` actions
- `evidence_level`: `proven` (claimable now, `reregistered_after_reference`, or compromised list) or `likely` (only supporting signals). Empty when neither applies. Floors use proven facts only.
- `evidence.changed_hands`: code-produced dates. `reregistered_after_reference` is true when RDAP registration or GitHub `created_at` is newer than the line's blame date (or `file existed since` from the commits API). `supporting` may list RDAP transfer/last-changed, nameserver drift, a CT gap then a new issuer org, or Wayback content that flipped. The model cannot assert an ownership change without one of these facts.

Website findings put page locations in `references` (`page_url`, `tag`, `attribute`,
`line`, `sri`, `raw`) instead of `file:line`.

Jobs are in-process only: `GET /api/scan/{id}` works for a finished scan until the
process restarts. Shareable `?scan=<id>` is valid for that lifetime.

## `GET /api/health`

```json
{"ok": true}
```

## Demo (no models)

Saved fixture scan from `tests/fixtures/demo_repo` with `FakeModelClient`, checked in as
`api/demo_scan.json`.

- `GET /api/scan/demo` → finished report JSON (no model calls).
- `GET /api/scan/demo/events` → SSE replay of that file.

Replay pacing: **150 ms** between events by default (`DEMO_EVENT_GAP_MS`). Override with
`?speed=` as milliseconds (`?speed=0` for tests). The first event is sent immediately.

Register `/demo` before `/{id}`.
