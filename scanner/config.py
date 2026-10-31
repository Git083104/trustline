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
    }
)

SKIP_DIR_NAMES: frozenset[str] = frozenset(
    {".git", "node_modules", "vendor", "dist", "build"}
)
MAX_FILE_BYTES = 1_000_000
CONTEXT_LINES = 10
GITHUB_CLONE_TIMEOUT_S = 60
