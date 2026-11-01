# Muse Code (Trustline)

Verified against **Muse Code 1.4.14** (`1.4.14-R7309.1`, `muse --version`).

## settings.json format

Muse 1.4.14 reads `~/.config/muse/settings.json` with `"schema_version": 1`. MCP servers go under **`mcpServers`** (camelCase).

That matches the cookbook. `muse mcp --help` and `muse exec -c` both address `mcpServers.<name>`. An older extending-Muse-Code snippet used `mcp_servers`; do not use that key on 1.4.14.

```json
{
  "schema_version": 1,
  "mcpServers": {
    "trustmap": {
      "transport": "stdio",
      "command": "uv",
      "args": ["run", "--directory", "/ABS/PATH/TO/MetaHack", "python", "-m", "scanner.mcp_server"],
      "env": {
        "MODEL_API_KEY": "${MODEL_API_KEY}"
      },
      "mode": "optional"
    }
  }
}
```

`MODEL_API_KEY` must be a whole-value `${VAR}` substitution (Muse 1.4.14 refuses other secret shapes). Export the key in the environment; do not paste it into the file.

Start Muse from the Trustline repo (or keep `--directory` as above). Verify with `/mcp` in the TUI; you should see `mcp__trustmap__dns`, `rdap`, `bucket_probe`, `cert_history`, `wayback`, `platform_takeover`, `github_owner`, and `scan`. Every tool is registered with `readOnlyHint: true`. Detection only: nothing claims a bucket or domain.

Demo prompt:

> scan this repo with the trustmap tools and explain the top risk

That may call `scan` with the repo path. CI does **not** call `scan`; it only passes added PR lines and lookup tools.

## Sandbox network

`--sandbox-network restricted` (Muse 1.4.14 modes: `restricted` | `enabled` | `proxy-only`). Keep it **restricted**. The MCP process is not sandboxed, so DNS/RDAP/HTTP lookups still run in Trustline. Do not open Muse's sandbox network unless a future change needs the model itself to fetch URLs (this workflow does not).

## CI (never run Muse in the PR checkout)

`.github/workflows/trustmap.yml`:

1. If `MODEL_API_KEY` is empty (typical for **fork PRs**), skip with a success message. Do not fail.
2. `git diff base...head`, keep **added lines only** (workflow/Python, not the model).
3. If those lines have no `http(s)` or `s3://` candidates, comment and succeed without calling Muse.
4. Install Muse with `bash` (not `sh`: Ubuntu dash trips on `[[` and reports `refusing to install into ~/.local/bin`). Create `$HOME/.local/bin` first, put it on `PATH` / `GITHUB_PATH`, and set `MUSE_INSTALL_DIR` to that directory. Headless auth is **`META_API_KEY`** (`muse login --help`: it always wins over browser login). The workflow copies the `MODEL_API_KEY` secret into both `META_API_KEY` (Muse) and `MODEL_API_KEY` (Trustline MCP, env `MODEL_API_KEY`); never echo it. `muse auth set --api-key-stdin` also works; CI uses the env var.
5. Write `settings.json` into a temp `HOME`/`XDG_CONFIG_HOME` (do not override `HOME` for the whole job step; Muse reads `XDG_CONFIG_HOME` first). Start `muse exec` with `cwd` set to a **new temp directory** (not the checkout). Pass the diff as `--prompt-file`. `--output-schema` is the findings JSON schema. Toolset: `run.toolset=["mcp__trustmap__*"]`. Flags: `--disable-shell --disable-write --disable-approval --disable-web-tools --approval-mode never --sandbox-network restricted`. **No `--yolo`.** `--json` is JSONL; Python unwraps `run.terminal.completed` `payload.text`. On `muse exec` failure, print redacted `muse.out` plus `muse --version` and `muse exec --help`.
6. Python validates Muse stdout as JSON. `gh pr comment` uses Muse text only as the explanation; **Fix** is `choose_fix`. The job fails **only** if Trustline `precheck` + `floor_decision` on added-diff targets is `critical` (cached lookups, no model). Muse's severity is ignored for the gate. Invalid JSON fails the job as a broken check, not as a finding.

The MCP server is started from the installed checkout Python so lookups can run; Muse's own workspace is the empty temp dir.

## Local test (no CI)

1. `uv sync --group dev`
2. `export MODEL_API_KEY=...` (already in your environment if you use the CLI)
3. Merge the `mcpServers` block above into `~/.config/muse/settings.json`
4. From this repo: `python -m scanner.mcp_server` is what Muse launches; or run Muse and `/mcp`
5. Offline checks (no live Muse, no live Meta API):

```bash
uv run pytest tests/test_ci.py tests/test_mcp_server.py -q
```

6. Optional headless dry-run of the **flags** (echo provider, no Meta API, no MCP needed):

```bash
EMPTY=$(mktemp -d)
SCHEMA=$(mktemp)
PROMPT=$(mktemp)
uv run python -m scanner.ci write-schema --out "$SCHEMA"
printf 'no urls here\n' > "$PROMPT"
cd "$EMPTY"
muse exec --provider echo --disable-shell --disable-write --disable-approval \
  --sandbox-network restricted --prompt-file "$PROMPT" --output-schema "$SCHEMA" \
  -c 'run.toolset=["mcp__trustmap__*"]'
```

Expect an unavailable-tool / untrusted-workspace warning, not a sandbox-network error. Do not use `--yolo`.

Live `muse exec` against Meta is not part of this phase unless you later say `live test`.

## CI test

1. Add repo secret **`MODEL_API_KEY`** (same Meta Model API key as local scans).
2. Open a PR that adds a script tag or URL to the unregistered demo host `cdn-assets-trustmap-7f3k2.com` (see `tests/fixtures/demo_repo/index.html`).
3. Same-repo PR: the Trustline check should comment and, if Muse marks that host **critical**, fail. High/medium/low/info should comment and pass.
4. Fork PR without the secret: the check should **skip** with the `MODEL_API_KEY is not available` message and stay green.
