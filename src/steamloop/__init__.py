"""Local control for thermostat devices over mTLS."""

__version__ = "1.2.3"

from .connection import ThermostatConnection, load_pairing, save_pairing
from .const import DEFAULT_PORT, FanMode, HoldType, HVACActivity, ZoneMode
from .exceptions import (
    AuthenticationError,
    CommandError,
    PairingError,
    SteamloopConnectionError,
    SteamloopError,
)
from .models import ThermostatState, Zone

__all__ = [
    "DEFAULT_PORT",
    "AuthenticationError",
    "CommandError",
    "FanMode",
    "HVACActivity",
    "HoldType",
    "PairingError",
    "SteamloopConnectionError",
    "SteamloopError",
    "ThermostatConnection",
    "ThermostatState",
    "Zone",
    "ZoneMode",
    "load_pairing",
    "save_pairing",
]
