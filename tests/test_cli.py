import pytest

from scanner.cli import main


def test_help_exits_without_calling_live_api():
    with pytest.raises(SystemExit) as exited:
        main(["--help"])
    assert exited.value.code == 0


def test_fix_help_exits_without_calling_live_api():
    with pytest.raises(SystemExit) as exited:
        main(["fix", "--help"])
    assert exited.value.code == 0


def test_scan_help_lists_sarif():
    import io
    from contextlib import redirect_stdout

    buf = io.StringIO()
    with pytest.raises(SystemExit) as exited, redirect_stdout(buf):
        main(["scan", "--help"])
    assert exited.value.code == 0
    assert "sarif" in buf.getvalue()
