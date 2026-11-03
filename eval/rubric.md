# Eval rubric

Labels in `eval/labels.jsonl` were collected under the original rubric. Scoring can replay
that rubric or apply the revision in `run_eval.py --rubric revised` without editing the file.

## Original

A target is **critical** or **high** when a stranger could take it over soon:

- claimable now (NoSuchBucket, RDAP unregistered)
- DNS does not resolve (NXDOMAIN)
- registration expires within 90 days

Expiry alone was treated as a warning because a lapsed name can be registered by someone else.

## Revised

Expiry within 90 days is **not** a warning by itself. It counts only with abandonment signs:

- DNS does not resolve, or
- the owner has shut down (claimable now)

A registered, resolving, actively used domain that happens to renew soon is routine. Auto-labeling
already treated that case as info; this revision applies the same rule to every label, including
human ones, at eval time.

### 3 Nov 2026 — subdomain NXDOMAIN is not a stranger-takeover

A non-resolving subdomain of a registered, resolving apex is not claimable by outsiders; label it
review/low. If the apex expires within 90 days, it is a watch item, not a real threat. Example:
`forum.lbry.tech` under `lbry.tech` (NXDOMAIN child, RDAP registered parent, 70 days to expiry).
Only the registrant of `lbry.tech` can recreate the name. Applied to every row in
`eval/labels.jsonl` at eval time (`--rubric revised`); the file is not rewritten.

## Why it changed

The original rule inflated gold critical/high with healthy names (for example `quandl.com`:
DNS resolves, RDAP registered, 80 days to expiry). Trustmap and the revised baseline correctly
leave those as info. Scoring against the old gold made that look like a miss.
