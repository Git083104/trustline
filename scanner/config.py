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
