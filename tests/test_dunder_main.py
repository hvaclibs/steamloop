"""Tests for python -m steamloop execution."""

from __future__ import annotations

import subprocess
import sys


def test_can_run_as_python_module() -> None:
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "steamloop", "--help"],
        check=True,
        capture_output=True,
    )
    assert result.returncode == 0
    assert b"Thermostat" in result.stdout
