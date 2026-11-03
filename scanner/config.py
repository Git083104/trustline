"""Scanner settings. Model keys are read in later phases; do not load .env here."""

# Registrable domains we never flag. Bucket matches on Amazon/Google hosts are kept.
ALLOWLIST_DOMAINS: frozenset[str] = frozenset(
    {
        "github.com",
        "githubusercontent.com",
        "googleapis.com",
        "amazonaws.com",
        "npmjs.com",
        "pypi.org",
        "w3.org",
        "schema.org",
        "localhost",
        # License text, not runtime trust
        "opensource.org",
        "spdx.org",
        "apache.org",
        "gnu.org",
        "creativecommons.org",
        # XML / JSON schema namespaces
        "xmlsoap.org",
        "xml.org",
        "json-schema.org",
    }
)

SKIP_DIR_NAMES: frozenset[str] = frozenset(
    {".git", "node_modules", "vendor", "dist", "build"}
)
SKIP_FILE_NAMES: frozenset[str] = frozenset(
    {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "pnpm-lock.yml",
        "bun.lock",
        "bun.lockb",
        "poetry.lock",
        "pipfile.lock",
        "cargo.lock",
        "composer.lock",
        "gemfile.lock",
        "go.sum",
        "uv.lock",
    }
)
RESERVED_TLDS: frozenset[str] = frozenset(
    {"invalid", "test", "example", "localhost", "local"}
)
RFC2606_DOMAINS: frozenset[str] = frozenset(
    {"example.com", "example.net", "example.org"}
)

SKIP_NAME_SUFFIXES: tuple[str, ...] = (
    ".min.js",
    ".min.mjs",
    ".min.cjs",
    ".min.css",
    ".js.map",
    ".css.map",
    ".min.js.map",
    ".min.css.map",
    ".map",
)
MAX_FILE_BYTES = 1_000_000
MAX_SCAN_FILES = 5_000
MAX_SCAN_BYTES = 50 * 1024 * 1024
CONTEXT_LINES = 10
GITHUB_CLONE_TIMEOUT_S = 20
HTTP_TIMEOUT_S = 10.0
WEBSITE_PAGE_MAX_BYTES = 5 * 1024 * 1024
WEBSITE_JS_MAX_BYTES = 2 * 1024 * 1024
WEBSITE_MAX_JS_FILES = 10
CRTSH_TIMEOUT_S = 15.0
DNS_TIMEOUT_S = 5.0
CACHE_TTL_S = 24 * 60 * 60
RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
RDAP_FALLBACK_BASE = "https://rdap.org/"

META_BASE_URL = "https://api.meta.ai/v1"
CLASSIFY_MODEL = "muse-spark-1.3"
AGENT_MODEL = "muse-spark-1.3"
RANK_MODEL = "muse-spark-1.3"
CLASSIFY_REASONING_EFFORT = "low"
AGENT_REASONING_EFFORT = "low"
RANK_REASONING_EFFORT = "low"
LLM_MAX_RETRIES = 1
LLM_REQUEST_TIMEOUT_S = 20.0
LLM_HTTP_MAX_RETRIES = 1
CLASSIFY_BATCH_SIZE = 5
CLASSIFY_CONCURRENCY = 8
MAX_AGENT_TOOL_CALLS = 3
SCAN_DEADLINE_S = 75.0
REPORT_RESERVE_S = 10.0
AGENT_RESERVE_S = 8.0
RANK_RESERVE_S = 12.0
MAX_INVESTIGATION_CONCURRENCY = 4
PRECHECK_CONCURRENCY = 8
RANK_CONCURRENCY = 8
SCAN_COST_CAP_USD = 1.00
DAILY_CAP_USD = 10.0
IP_SCANS_PER_HOUR = 5
MAX_CONCURRENT_SCANS = 3
TRUSTED_PROXY_HOPS = 0
DEMO_EVENT_GAP_MS = 150
EVAL_SCAN_COST_CAP_USD = 3.00
EVAL_TARGET_CAP = 25
EVAL_SAMPLE_SEED = 42
EVAL_LOOKUP_CONCURRENCY = 10
EXPIRY_INVESTIGATE_DAYS = 90
OWNERSHIP_BLAME_BUDGET_S = 10.0
CT_GAP_DAYS = 365
# USD per million tokens
MODEL_PRICES: dict[str, dict[str, float]] = {
    "muse-spark-1.3": {"input": 1.25, "output": 4.25},
}
