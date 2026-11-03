# Tether

Code name: trustmap. Formerly Trustline.

Finds abandoned outside infrastructure a repository or website still trusts (expired
domains, claimable buckets, dangling hosts). Detection only: it never registers or
claims names.

Lookup, classification, and parked/for-sale live-fetch signals draw on
[jwang2007/trustline](https://github.com/jwang2007/trustline).

## Run locally

Python 3.12, [uv](https://docs.astral.sh/uv/):

```bash
uv sync --group dev
uv run pytest -q -m 'not slow'
uv run uvicorn api.main:app --factory --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000/ — **Watch the demo** streams `/api/scan/demo/events` (no
model key). Live scans need `MODEL_API_KEY` in a local `.env` or the environment. Keep
`TRUSTMAP_ALLOW_LOCAL_SCAN` unset or `0`.

Scanning a repository shallow-clones it, so `git` has to be on the host.

## Deploy

The app is a long-lived server, not a set of functions: a scan runs as a background task
in the process that accepted it, streams Server-Sent Events while it works, and caches
lookups in SQLite on disk. It needs a host that keeps a process running and gives it a
writable volume — Render, Fly, Railway, a VM. It does not fit a serverless platform
(Vercel, Netlify Functions, Lambda) without moving job state and the cache out of the
process.

### Render (the checked-in blueprint)

`render.yaml` describes the whole service: Docker runtime, Starter plan, a 1GB disk at
`/var/data` for the lookup cache and spend ledger, and a health check on `/api/health`.

1. Push this repository to GitHub.
2. In Render: **New → Blueprint**, pick the repository, apply `render.yaml`.
3. Set the two secrets it leaves blank: `MODEL_API_KEY` and `GITHUB_TOKEN`.

Everything else — the spend and rate caps, `TRUSTMAP_TRUSTED_PROXY_HOPS=1`, the cache
path — is already in the blueprint. Check the build locally first with:

```bash
docker build -t tether . && docker run --rm -p 8000:8000 tether
```

### What does not survive a restart

Jobs live in process memory. `GET /api/scan/{id}` and the `?scan=<id>` share link work
until the process restarts; after that the id is gone (404) and the scan has to be run
again. The demo is a checked-in fixture and always works.

The Starter disk at `/var/data` keeps the SQLite cache and spend ledger across
restarts.
