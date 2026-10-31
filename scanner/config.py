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
CONTEXT_LINES = 10
GITHUB_CLONE_TIMEOUT_S = 60
HTTP_TIMEOUT_S = 10.0
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
RANK_REASONING_EFFORT = "medium"
LLM_MAX_RETRIES = 2
CLASSIFY_BATCH_SIZE = 20
MAX_AGENT_TOOL_CALLS = 6
MAX_INVESTIGATION_CONCURRENCY = 4
SCAN_COST_CAP_USD = 1.00
EXPIRY_INVESTIGATE_DAYS = 90
# USD per million tokens
MODEL_PRICES: dict[str, dict[str, float]] = {
    "muse-spark-1.3": {"input": 1.25, "output": 4.25},
}
