from scanner.compromised import (
    POLYFILL_HOSTS,
    compromised_status,
    is_polyfill_host,
)


def test_compromised_table_and_polyfill():
    assert compromised_status("cdn.polyfill.io") == "compromised"
    assert compromised_status("bootcss.com") == "compromised"
    assert compromised_status("bootcdn.net") == "associated"
    assert compromised_status("staticfile.org") == "associated"
    assert compromised_status("example.com") is None
    assert compromised_status("bootcdn.net", "cdn.polyfill.io") == "compromised"
    assert is_polyfill_host("polyfill.io")
    assert POLYFILL_HOSTS == {"cdn.polyfill.io", "polyfill.io", "polyfill.com"}
