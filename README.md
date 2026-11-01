# Trustmap

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

Open http://127.0.0.1:8000/ — **Try the demo** streams `/api/scan/demo/events` (no model key).
Live scans need `MODEL_API_KEY` in the environment. Keep `TRUSTMAP_ALLOW_LOCAL_SCAN` unset or `0`.

## Deploy

See the Phase F notes in chat for Render (Starter plan, disk at `/var/data`, secret
`MODEL_API_KEY`). Blueprint file: `render.yaml`.
