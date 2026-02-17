"""Tests for exception hierarchy."""

from __future__ import annotations

from steamloop.exceptions import (
    AuthenticationError,
    CommandError,
    PairingError,
    SteamloopConnectionError,
    SteamloopError,
)


def test_exception_hierarchy() -> None:
    assert issubclass(SteamloopConnectionError, SteamloopError)
    assert issubclass(AuthenticationError, SteamloopError)
    assert issubclass(PairingError, SteamloopError)
    assert issubclass(CommandError, SteamloopError)
    assert issubclass(SteamloopError, Exception)


def test_exceptions_are_catchable() -> None:
    with __import__("pytest").raises(SteamloopError):
        raise SteamloopConnectionError("test")

    with __import__("pytest").raises(SteamloopError):
        raise AuthenticationError("test")

    with __import__("pytest").raises(SteamloopError):
        raise PairingError("test")

    with __import__("pytest").raises(SteamloopError):
        raise CommandError("test")
