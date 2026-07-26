"""Data models for thermostat events, responses, and state."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TypedDict

from .const import FanMode, HoldType, HVACActivity, ZoneMode


def _parse_float(value: str) -> float | None:
    """Parse a wire string into a float, or None if empty/invalid."""
    try:
        return float(value)
    except (ValueError, TypeError):
        return None


def _parse_activity(value: str) -> HVACActivity | None:
    """Parse a raw activity string ("0"/"1"/"2") into HVACActivity, or None."""
    try:
        return HVACActivity(int(value))
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Event TypedDicts — match the wire format exactly (all string values)
# ---------------------------------------------------------------------------


class ZoneAddedEvent(TypedDict):
    """A new zone was discovered."""

    zone_id: str


class ZoneNameUpdatedEvent(TypedDict):
    """A zone's name changed."""

    zone_id: str
    zone_name: str


class IndoorTemperatureUpdatedEvent(TypedDict):
    """A zone's indoor temperature changed."""

    zone_id: str
    indoor_temperature: str


class _TemperatureSetpointRequired(TypedDict):
    zone_id: str


class TemperatureSetpointUpdatedEvent(_TemperatureSetpointRequired, total=False):
    """
    A zone's temperature setpoints changed.

    Only zone_id is guaranteed; other fields may be absent
    when only a subset of setpoints changed.
    """

    heat_setpoint: str
    cool_setpoint: str
    deadband: str
    hold_type: str


class ZoneModeUpdatedEvent(TypedDict):
    """A zone's HVAC mode changed."""

    zone_id: str
    zone_mode: str


class SupportedZoneModesUpdatedEvent(TypedDict):
    """The list of supported zone modes was received."""

    modes: str


class FanModeUpdatedEvent(TypedDict):
    """The fan mode changed."""

    fan_mode: str


class EmergencyHeatUpdatedEvent(TypedDict):
    """Emergency heat status changed."""

    emergency_heat: str


class IndoorRelativeHumidityUpdatedEvent(TypedDict):
    """Indoor humidity changed."""

    relative_humidity: str


class CoolingStatusUpdatedEvent(TypedDict):
    """Cooling compressor status changed."""

    cooling_active: str


class HeatingStatusUpdatedEvent(TypedDict):
    """Heating system status changed."""

    heating_active: str


# ---------------------------------------------------------------------------
# Response TypedDicts
# ---------------------------------------------------------------------------


class LoginResponse(TypedDict):
    """Login response from the thermostat."""

    status: str


class ErrorResponse(TypedDict):
    """Error response from the thermostat."""

    error_type: str
    description: str


class SetSecretKeyRequest(TypedDict):
    """Secret key sent by the thermostat during pairing."""

    secret_key: str


# ---------------------------------------------------------------------------
# State dataclasses
# ---------------------------------------------------------------------------


@dataclass
class Zone:
    """State of a single thermostat zone."""

    zone_id: str
    name: str = ""
    mode: ZoneMode = ZoneMode.OFF
    indoor_temperature: str = ""
    heat_setpoint: str = ""
    cool_setpoint: str = ""
    deadband: str = ""
    hold_type: HoldType = HoldType.UNDEFINED

    @property
    def indoor_temperature_f(self) -> float | None:
        """Indoor temperature in °F, or None if unknown."""
        return _parse_float(self.indoor_temperature)

    @property
    def heat_setpoint_f(self) -> float | None:
        """Heat setpoint in °F, or None if unknown."""
        return _parse_float(self.heat_setpoint)

    @property
    def cool_setpoint_f(self) -> float | None:
        """Cool setpoint in °F, or None if unknown."""
        return _parse_float(self.cool_setpoint)

    @property
    def deadband_f(self) -> float | None:
        """Minimum gap between heat and cool setpoints, or None if unknown."""
        return _parse_float(self.deadband)


@dataclass
class ThermostatState:
    """Aggregated state of the thermostat and all zones."""

    zones: dict[str, Zone] = field(default_factory=dict)
    supported_modes: list[ZoneMode] = field(default_factory=list)
    fan_mode: FanMode = FanMode.AUTO
    emergency_heat: str = ""
    relative_humidity: str = ""
    cooling_active: str = ""
    heating_active: str = ""

    @property
    def emergency_heat_on(self) -> bool | None:
        """Whether emergency heat is on, or None if unknown."""
        if self.emergency_heat == "1":
            return True
        if self.emergency_heat == "0":
            return False
        return None

    @property
    def cooling(self) -> HVACActivity | None:
        """Live cooling activity, or None if unknown."""
        return _parse_activity(self.cooling_active)

    @property
    def heating(self) -> HVACActivity | None:
        """Live heating activity, or None if unknown."""
        return _parse_activity(self.heating_active)

    @property
    def relative_humidity_pct(self) -> int | None:
        """Indoor relative humidity as a percentage, or None if unknown."""
        parsed = _parse_float(self.relative_humidity)
        return int(parsed) if parsed is not None else None
