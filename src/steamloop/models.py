"""Data models for thermostat events, responses, and state."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TypedDict

from .const import FanMode, HoldType, ZoneMode


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
    """A zone's temperature setpoints changed.

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
