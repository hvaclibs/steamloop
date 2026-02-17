"""Tests for pairing file save/load."""

from __future__ import annotations

import hashlib
import stat
from pathlib import Path

from steamloop.connection import (
    _pairing_path,
    load_pairing,
    save_pairing,
)


def test_pairing_path_uses_md5() -> None:
    ip = "192.168.1.100"
    expected_md5 = hashlib.md5(ip.encode()).hexdigest()  # noqa: S324
    path = _pairing_path(ip, Path("/tmp"))  # noqa: S108
    assert path.name == f"pairing_{expected_md5}.json"


def test_pairing_path_custom_directory(tmp_path: Path) -> None:
    path = _pairing_path("10.0.0.1", tmp_path)
    assert path.parent == tmp_path


def test_pairing_path_default_is_cwd() -> None:
    path = _pairing_path("10.0.0.1")
    assert path.parent == Path.cwd()


async def test_save_and_load_round_trip(tmp_path: Path) -> None:
    ip = "192.168.1.50"
    data = {
        "secret_key": "abc123",
        "device_type": "automation",
        "device_id": "module",
    }
    await save_pairing(ip, data, tmp_path)
    loaded = await load_pairing(ip, tmp_path)
    assert loaded == data


async def test_load_not_found_returns_none(tmp_path: Path) -> None:
    result = await load_pairing("1.2.3.4", tmp_path)
    assert result is None


async def test_save_file_permissions(tmp_path: Path) -> None:
    ip = "192.168.1.50"
    await save_pairing(ip, {"secret_key": "s"}, tmp_path)
    path = _pairing_path(ip, tmp_path)
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600
