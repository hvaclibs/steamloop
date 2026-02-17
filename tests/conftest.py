"""Shared fixtures for steamloop tests."""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock

import pytest

from steamloop.connection import ThermostatConnection, ThermostatProtocol


@pytest.fixture
def mock_transport() -> MagicMock:
    """Return a mock asyncio.Transport."""
    return MagicMock(spec=asyncio.Transport)


@pytest.fixture
def connection() -> ThermostatConnection:
    """Return a ThermostatConnection with mock protocol/transport wired up.

    The connection is in the "connected" state with a real
    ThermostatProtocol backed by a mock transport, ready for
    send/dispatch testing without any real I/O.
    """
    conn = ThermostatConnection("192.168.1.100", secret_key="test-key")
    transport = MagicMock(spec=asyncio.Transport)
    protocol = ThermostatProtocol(conn)
    protocol.connection_made(transport)
    conn._protocol = protocol
    conn._transport = transport
    conn._connected = True
    return conn


@pytest.fixture
def disconnected_connection() -> ThermostatConnection:
    """Return a ThermostatConnection that is not connected."""
    return ThermostatConnection("192.168.1.100", secret_key="test-key")


def make_event(event_type: str, data: dict[str, Any]) -> dict[str, Any]:
    """Build a wire-format event message."""
    return {"Event": {event_type: data}}
