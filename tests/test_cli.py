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
