"""Tests for ThermostatProtocol message framing and I/O."""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock

import orjson
import pytest

from steamloop.connection import ThermostatProtocol, _encode_message
from steamloop.exceptions import SteamloopConnectionError


def _make_protocol() -> tuple[ThermostatProtocol, MagicMock, MagicMock]:
    """Create a protocol with mock connection and transport."""
    mock_conn = MagicMock()
    protocol = ThermostatProtocol(mock_conn)
    transport = MagicMock(spec=asyncio.Transport)
    protocol.connection_made(transport)
    return protocol, mock_conn, transport


def test_connection_made_stores_transport() -> None:
    mock_conn = MagicMock()
    protocol = ThermostatProtocol(mock_conn)
    transport = MagicMock(spec=asyncio.Transport)
    assert protocol._transport is None
    protocol.connection_made(transport)
    assert protocol._transport is transport


def test_data_received_single_message() -> None:
    protocol, mock_conn, _ = _make_protocol()
    msg = {"Event": {"ZoneAdded": {"zone_id": "1"}}}
    protocol.data_received(orjson.dumps(msg) + b" \x00")
    mock_conn._on_message.assert_called_once_with(msg)


def test_data_received_multiple_messages() -> None:
    protocol, mock_conn, _ = _make_protocol()
    msg1 = {"Event": {"ZoneAdded": {"zone_id": "1"}}}
    msg2 = {"Event": {"ZoneAdded": {"zone_id": "2"}}}
    data = orjson.dumps(msg1) + b" \x00" + orjson.dumps(msg2) + b" \x00"
    protocol.data_received(data)
    assert mock_conn._on_message.call_count == 2
    mock_conn._on_message.assert_any_call(msg1)
    mock_conn._on_message.assert_any_call(msg2)


def test_data_received_partial_then_complete() -> None:
    protocol, mock_conn, _ = _make_protocol()
    msg: dict[str, dict[str, str]] = {"Heartbeat": {}}
    full = orjson.dumps(msg) + b" \x00"
    mid = len(full) // 2
    protocol.data_received(full[:mid])
    mock_conn._on_message.assert_not_called()
    protocol.data_received(full[mid:])
    mock_conn._on_message.assert_called_once_with(msg)


def test_data_received_empty_segment() -> None:
    protocol, mock_conn, _ = _make_protocol()
    # Two null bytes with nothing in between
    protocol.data_received(b"\x00\x00")
    mock_conn._on_message.assert_not_called()


def test_data_received_malformed_json() -> None:
    protocol, mock_conn, _ = _make_protocol()
    protocol.data_received(b"{bad json}\x00")
    mock_conn._on_message.assert_not_called()


def test_data_received_no_json_braces() -> None:
    protocol, mock_conn, _ = _make_protocol()
    protocol.data_received(b"no braces here\x00")
    mock_conn._on_message.assert_not_called()


def test_send_writes_encoded_message() -> None:
    protocol, _, transport = _make_protocol()
    msg: dict[str, Any] = {"Heartbeat": {}}
    protocol.send(msg)
    expected = _encode_message(msg)
    transport.write.assert_called_once_with(expected)


def test_send_not_connected_raises() -> None:
    mock_conn = MagicMock()
    protocol = ThermostatProtocol(mock_conn)
    # No transport set
    with pytest.raises(SteamloopConnectionError, match="Not connected"):
        protocol.send({"Heartbeat": {}})


def test_send_request_wraps_in_request() -> None:
    protocol, _, transport = _make_protocol()
    protocol.send_request("Login", {"secret_key": "abc"})
    written = transport.write.call_args[0][0]
    parsed = orjson.loads(written.rstrip(b" \x00"))
    assert parsed == {"Request": {"Login": {"secret_key": "abc"}}}


def test_close_clears_transport_and_buffer() -> None:
    protocol, _, transport = _make_protocol()
    protocol._buf.extend(b"leftover data")
    protocol.close()
    assert protocol._transport is None
    assert len(protocol._buf) == 0
    transport.close.assert_called_once()


def test_connection_lost_notifies_connection() -> None:
    protocol, mock_conn, _ = _make_protocol()
    exc = ConnectionResetError("reset")
    protocol.connection_lost(exc)
    mock_conn._on_connection_lost.assert_called_once_with(exc)


def test_connection_lost_without_exception() -> None:
    protocol, mock_conn, _ = _make_protocol()
    protocol.connection_lost(None)
    mock_conn._on_connection_lost.assert_called_once_with(None)


def test_encode_message() -> None:
    msg: dict[str, Any] = {"Heartbeat": {}}
    encoded = _encode_message(msg)
    assert encoded.endswith(b" \x00")
    assert orjson.loads(encoded[:-2]) == msg
