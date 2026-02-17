"""Tests for constants and enums."""

from __future__ import annotations

from steamloop.const import (
    BACKOFF_FACTOR,
    CONNECT_TIMEOUT,
    DEFAULT_PORT,
    HEARTBEAT_INTERVAL,
    PAIRING_TIMEOUT,
    RECONNECT_DELAY,
    RECONNECT_MAX,
    RESPONSE_TIMEOUT,
    FanMode,
    HoldType,
    ZoneMode,
)


def test_zone_mode_values() -> None:
    assert ZoneMode.OFF == 0
    assert ZoneMode.AUTO == 1
    assert ZoneMode.COOL == 2
    assert ZoneMode.HEAT == 3


def test_fan_mode_values() -> None:
    assert FanMode.AUTO == 1
    assert FanMode.ALWAYS_ON == 2
    assert FanMode.CIRCULATE == 3


def test_hold_type_values() -> None:
    assert HoldType.UNDEFINED == 0
    assert HoldType.MANUAL == 1
    assert HoldType.SCHEDULE == 2
    assert HoldType.HOLD == 3


def test_default_constants() -> None:
    assert DEFAULT_PORT == 7878
    assert HEARTBEAT_INTERVAL == 55
    assert CONNECT_TIMEOUT == 10
    assert PAIRING_TIMEOUT == 120
    assert RESPONSE_TIMEOUT == 10
    assert RECONNECT_DELAY == 5
    assert RECONNECT_MAX == 300
    assert BACKOFF_FACTOR == 2
