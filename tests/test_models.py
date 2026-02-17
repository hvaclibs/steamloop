"""Tests for data models."""

from __future__ import annotations

from steamloop.const import FanMode, HoldType, ZoneMode
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
