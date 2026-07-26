"""Tests for data models."""

from __future__ import annotations

import pytest

from steamloop.const import FanMode, HoldType, HVACActivity, ZoneMode
from steamloop.models import ThermostatState, Zone


def test_zone_defaults() -> None:
    zone = Zone(zone_id="1")
    assert zone.zone_id == "1"
    assert zone.name == ""
    assert zone.mode == ZoneMode.OFF
    assert zone.indoor_temperature == ""
    assert zone.heat_setpoint == ""
    assert zone.cool_setpoint == ""
    assert zone.deadband == ""
    assert zone.hold_type == HoldType.UNDEFINED


def test_thermostat_state_defaults() -> None:
    state = ThermostatState()
    assert state.zones == {}
    assert state.supported_modes == []
    assert state.fan_mode == FanMode.AUTO
    assert state.emergency_heat == ""
    assert state.relative_humidity == ""
    assert state.cooling_active == ""
    assert state.heating_active == ""


def test_zone_mutable() -> None:
    zone = Zone(zone_id="1")
    zone.name = "Upstairs"
    zone.mode = ZoneMode.COOL
    zone.indoor_temperature = "74"
    assert zone.name == "Upstairs"
    assert zone.mode == ZoneMode.COOL
    assert zone.indoor_temperature == "74"


def test_state_zones_independent() -> None:
    """Each ThermostatState instance has its own zones dict."""
    s1 = ThermostatState()
    s2 = ThermostatState()
    s1.zones["1"] = Zone(zone_id="1")
    assert "1" not in s2.zones


# --- Typed accessors ---


def test_zone_typed_setpoints() -> None:
    zone = Zone(
        zone_id="1",
        indoor_temperature="74",
        heat_setpoint="68.5",
        cool_setpoint="76",
        deadband="3",
    )
    assert zone.indoor_temperature_f == 74.0
    assert zone.heat_setpoint_f == 68.5
    assert zone.cool_setpoint_f == 76.0
    assert zone.deadband_f == 3.0


def test_zone_typed_defaults_are_none() -> None:
    """Empty wire strings parse to None, not a crash."""
    zone = Zone(zone_id="1")
    assert zone.indoor_temperature_f is None
    assert zone.heat_setpoint_f is None
    assert zone.cool_setpoint_f is None
    assert zone.deadband_f is None


def test_zone_typed_invalid_is_none() -> None:
    zone = Zone(zone_id="1", indoor_temperature="--")
    assert zone.indoor_temperature_f is None


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("1", True), ("0", False), ("", None), ("2", None)],
)
def test_emergency_heat_on(raw: str, expected: bool | None) -> None:
    assert ThermostatState(emergency_heat=raw).emergency_heat_on is expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("0", HVACActivity.INACTIVE),
        ("1", HVACActivity.IDLE),
        ("2", HVACActivity.ACTIVE),
        ("", None),
        ("9", None),
    ],
)
def test_activity_accessors(raw: str, expected: HVACActivity | None) -> None:
    state = ThermostatState(cooling_active=raw, heating_active=raw)
    assert state.cooling is expected
    assert state.heating is expected


def test_relative_humidity_pct() -> None:
    assert ThermostatState(relative_humidity="45").relative_humidity_pct == 45
    assert ThermostatState(relative_humidity="").relative_humidity_pct is None
