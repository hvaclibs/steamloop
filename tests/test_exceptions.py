"""Tests for exception hierarchy."""

from __future__ import annotations

import pytest

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


@pytest.mark.parametrize(
    "exc_class",
    [SteamloopConnectionError, AuthenticationError, PairingError, CommandError],
)
def test_exceptions_are_catchable(exc_class: type[SteamloopError]) -> None:
    with pytest.raises(SteamloopError):
        raise exc_class("test")
