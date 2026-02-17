"""Local control for thermostat devices over mTLS."""

__version__ = "1.1.0"

from .connection import ThermostatConnection, load_pairing, save_pairing
from .const import DEFAULT_PORT, FanMode, HoldType, ZoneMode
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
