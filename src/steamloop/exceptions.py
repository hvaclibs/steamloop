"""Exception classes for steamloop."""


class SteamloopError(Exception):
    """Base exception for steamloop."""


class SteamloopConnectionError(SteamloopError):
    """Connection to the thermostat failed."""


class AuthenticationError(SteamloopError):
    """Authentication with the thermostat failed."""


class PairingError(SteamloopError):
    """Pairing with the thermostat failed."""


class CommandError(SteamloopError):
    """A command sent to the thermostat was rejected."""
