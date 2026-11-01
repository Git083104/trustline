# Trustmap scan API

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

Unknown `scan_id` on later GETs → 404.

## `GET /api/scan/{id}/events`

Replay buffered events, then live ones, then close on `done` or `error`.

| `type` | When | Payload |
|---|---|---|
| `started` | job accepted | `kind`, `target`, `cost_cap_usd` |
| `extracted` | after extract | `references`, `actionable`, `filtered` |
| `precheck` | after lookups for one target | `target`, `kind` (bucket/domain), `hard_signal` |
| `plan` / `act` / `observe` | each agent turn | `target`, `tool`, `args`, `result_summary`, `tokens`, `cost_usd` |
| `ranked` | each finding after rank | `target`, `kind`, `severity`, `model_severity`, `floor_reason`, `risk`, `fix`, `evidence_line`, `references`, `cost_usd` |
| `done` | finished | `finding_count`, `cost_usd`, `classify_cost_usd`, `agent_cost_usd`, `rank_cost_usd`, `budget_targets` |
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
  "findings": [
    {
      "target": "cdn-assets-trustmap-7f3k2.com",
      "kind": "domain",
      "severity": "critical",
      "model_severity": "high",
      "floor_reason": "RDAP unregistered in executing position (browser) is at least critical",
      "risk": "...",
      "fix": "Remove or replace this reference. If this was yours, re-create it in your own account to reclaim the name.",
      "evidence_line": "Evidence: DNS does not resolve · domain not registered",
      "references": ["index.html:7"],
      "cost_usd": 0.02
    }
  ]
}
```

Website findings put page locations in `references` (`page_url`, `tag`, `attribute`,
`line`, `sri`, `raw`) instead of `file:line`.

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
