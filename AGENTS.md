# Trustmap agent rules

Build only the phase the user asks for, then stop and report the files changed, commands run, and limitations.

Write the smallest readable code that works.

Never open `.env` or print keys. Never commit `.env`, keys, or tokens.

Do not call the live Meta API unless the user explicitly says `live test`. Use the fake model client for tests.

Work through `BUILD_PLAN.md` in order. At the end of each phase: run the tests, show the acceptance check passing, commit with a clear message, and stop for review. If a step needs something only the user can do (account, bucket, secret), stop and say exactly what they should do.

## Non-negotiable

1. Code produces every fact (dates, DNS, HTTP statuses, expiry math, counts, hashes). Never ask a model to compute, parse, or remember these.
2. Muse models only classify and judge, always returning JSON validated with Pydantic. Reject and retry invalid output (max 2 retries).
3. Every number in a model-written explanation must match the evidence JSON. Enforce with a check; regenerate on mismatch.
4. All model calls go through `scanner/llm.py`.
5. Every network lookup has a timeout and is cached in SQLite.
6. Every module has pytest tests. Live network tests are marked `@pytest.mark.slow`.
7. Detection only. Never register, claim, or write to any bucket or domain. The only bucket ever claimed is one the user creates for the demo.
8. Never print secrets in logs.
