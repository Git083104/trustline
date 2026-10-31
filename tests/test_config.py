from scanner.config import ALLOWLIST_DOMAINS


def test_allowlist_is_generic_platform_roots():
    assert "example.com" not in ALLOWLIST_DOMAINS
    assert "github.com" in ALLOWLIST_DOMAINS
    assert "amazonaws.com" in ALLOWLIST_DOMAINS
    assert "googleapis.com" in ALLOWLIST_DOMAINS
