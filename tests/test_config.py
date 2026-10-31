from scanner.config import ALLOWLIST_DOMAINS, SKIP_FILE_NAMES, SKIP_NAME_SUFFIXES


def test_allowlist_is_generic_platform_roots():
    assert "example.com" not in ALLOWLIST_DOMAINS
    assert "github.com" in ALLOWLIST_DOMAINS
    assert "amazonaws.com" in ALLOWLIST_DOMAINS
    assert "googleapis.com" in ALLOWLIST_DOMAINS
    assert "opensource.org" in ALLOWLIST_DOMAINS
    assert "xmlsoap.org" in ALLOWLIST_DOMAINS


def test_skip_rules_cover_lockfiles_minified_and_sourcemaps():
    assert "package-lock.json" in SKIP_FILE_NAMES
    assert "yarn.lock" in SKIP_FILE_NAMES
    assert ".min.js" in SKIP_NAME_SUFFIXES
    assert ".map" in SKIP_NAME_SUFFIXES
