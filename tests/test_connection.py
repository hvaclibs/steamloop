"""Tests for ThermostatConnection."""

from __future__ import annotations

import asyncio
import ssl
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock, patch

import orjson
import pytest

from steamloop.connection import ThermostatConnection, ThermostatProtocol
from steamloop.const import (
    DEFAULT_PORT,
    FanMode,
    HoldType,
    ZoneMode,
)
from steamloop.exceptions import (
    AuthenticationError,
    PairingError,
    SteamloopConnectionError,
)
from steamloop.models import ThermostatState, Zone

from .conftest import make_event

# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------


def test_constructor_defaults() -> None:
    conn = ThermostatConnection("10.0.0.1", secret_key="sk")
    assert conn._ip == "10.0.0.1"
    assert conn._port == DEFAULT_PORT
    assert conn.secret_key == "sk"
    assert conn._device_type == "automation"
    assert conn._device_id == "module"
    assert conn.connected is False
    assert isinstance(conn.state, ThermostatState)


def test_connected_property(connection: ThermostatConnection) -> None:
    assert connection.connected is True
    connection._connected = False
    assert connection.connected is False


def test_secret_key_property() -> None:
    conn = ThermostatConnection("10.0.0.1", secret_key="my-secret")
    assert conn.secret_key == "my-secret"


# ---------------------------------------------------------------------------
# Event callbacks
# ---------------------------------------------------------------------------


def test_add_event_callback_receives_messages(
    connection: ThermostatConnection,
) -> None:
    received: list[dict[str, Any]] = []
    connection.add_event_callback(received.append)
    msg: dict[str, Any] = {"Heartbeat": {}}
    connection._on_message(msg)
    assert received == [msg]


def test_remove_event_callback(connection: ThermostatConnection) -> None:
    received: list[dict[str, Any]] = []
    remove = connection.add_event_callback(received.append)
    remove()
    connection._on_message({"Heartbeat": {}})
    assert received == []


def test_remove_callback_idempotent(connection: ThermostatConnection) -> None:
    remove = connection.add_event_callback(lambda msg: None)
    remove()
    remove()  # Should not raise


def test_callback_exception_logged_not_raised(
    connection: ThermostatConnection,
) -> None:
    def bad_callback(msg: dict[str, Any]) -> None:
        raise RuntimeError("boom")

    connection.add_event_callback(bad_callback)
    # Should not raise
    connection._on_message({"Heartbeat": {}})


# ---------------------------------------------------------------------------
# Event dispatch — all 11 handlers
# ---------------------------------------------------------------------------


def test_event_zone_added(connection: ThermostatConnection) -> None:
    connection._dispatch(make_event("ZoneAdded", {"zone_id": "1"}))
    assert "1" in connection.state.zones
    assert connection.state.zones["1"].zone_id == "1"


def test_event_zone_added_existing(connection: ThermostatConnection) -> None:
    connection.state.zones["1"] = Zone(zone_id="1", name="Main")
    connection._dispatch(make_event("ZoneAdded", {"zone_id": "1"}))
    assert connection.state.zones["1"].name == "Main"  # Not overwritten


def test_event_zone_name_updated(connection: ThermostatConnection) -> None:
    connection._dispatch(
        make_event("ZoneNameUpdated", {"zone_id": "1", "zone_name": "Living"})
    )
    assert connection.state.zones["1"].name == "Living"


def test_event_indoor_temperature_updated(
    connection: ThermostatConnection,
) -> None:
    connection._dispatch(
        make_event(
            "IndoorTemperatureUpdated",
            {"zone_id": "1", "indoor_temperature": "72"},
        )
    )
    assert connection.state.zones["1"].indoor_temperature == "72"


def test_event_temperature_setpoint_updated(
    connection: ThermostatConnection,
) -> None:
    connection._dispatch(
        make_event(
            "TemperatureSetpointUpdated",
            {
                "zone_id": "1",
                "heat_setpoint": "68",
                "cool_setpoint": "76",
                "deadband": "3",
                "hold_type": "1",
            },
        )
    )
    zone = connection.state.zones["1"]
    assert zone.heat_setpoint == "68"
    assert zone.cool_setpoint == "76"
    assert zone.deadband == "3"
    assert zone.hold_type == HoldType.MANUAL


def test_event_temperature_setpoint_partial(
    connection: ThermostatConnection,
) -> None:
    connection.state.zones["1"] = Zone(
        zone_id="1", heat_setpoint="65", cool_setpoint="78"
    )
    connection._dispatch(
        make_event(
            "TemperatureSetpointUpdated",
            {"zone_id": "1", "heat_setpoint": "70"},
        )
    )
    zone = connection.state.zones["1"]
    assert zone.heat_setpoint == "70"
    assert zone.cool_setpoint == "78"  # Unchanged


def test_event_zone_mode_updated(connection: ThermostatConnection) -> None:
    connection._dispatch(
        make_event("ZoneModeUpdated", {"zone_id": "1", "zone_mode": "2"})
    )
    assert connection.state.zones["1"].mode == ZoneMode.COOL


def test_event_supported_zone_modes(
    connection: ThermostatConnection,
) -> None:
    connection._dispatch(make_event("SupportedZoneModesUpdated", {"modes": "0,1,2,3"}))
    assert connection.state.supported_modes == [
        ZoneMode.OFF,
        ZoneMode.AUTO,
        ZoneMode.COOL,
        ZoneMode.HEAT,
    ]


def test_event_supported_zone_modes_invalid_skipped(
    connection: ThermostatConnection,
) -> None:
    connection._dispatch(make_event("SupportedZoneModesUpdated", {"modes": "0,99,2"}))
    assert connection.state.supported_modes == [ZoneMode.OFF, ZoneMode.COOL]


def test_event_fan_mode_updated(connection: ThermostatConnection) -> None:
    connection._dispatch(make_event("FanModeUpdated", {"fan_mode": "3"}))
    assert connection.state.fan_mode == FanMode.CIRCULATE


def test_event_emergency_heat_updated(
    connection: ThermostatConnection,
) -> None:
    connection._dispatch(make_event("EmergencyHeatUpdated", {"emergency_heat": "1"}))
    assert connection.state.emergency_heat == "1"


def test_event_indoor_relative_humidity_updated(
    connection: ThermostatConnection,
) -> None:
    connection._dispatch(
        make_event("IndoorRelativeHumidityUpdated", {"relative_humidity": "45"})
    )
    assert connection.state.relative_humidity == "45"


def test_event_cooling_status_updated(
    connection: ThermostatConnection,
) -> None:
    connection._dispatch(make_event("CoolingStatusUpdated", {"cooling_active": "2"}))
    assert connection.state.cooling_active == "2"


def test_event_heating_status_updated(
    connection: ThermostatConnection,
) -> None:
    connection._dispatch(make_event("HeatingStatusUpdated", {"heating_active": "1"}))
    assert connection.state.heating_active == "1"


def test_event_unknown_ignored(connection: ThermostatConnection) -> None:
    connection._dispatch(make_event("SomeNewEvent", {"foo": "bar"}))
    # No crash, no state change


def test_event_malformed_data_logged(
    connection: ThermostatConnection,
) -> None:
    # Missing required field — should log warning, not crash
    connection._dispatch(make_event("ZoneModeUpdated", {"bad": "data"}))


# ---------------------------------------------------------------------------
# Sending commands
# ---------------------------------------------------------------------------


def test_send_not_connected_raises(
    disconnected_connection: ThermostatConnection,
) -> None:
    with pytest.raises(SteamloopConnectionError, match="Not connected"):
        disconnected_connection.send({"Heartbeat": {}})


def test_send_request_not_connected_raises(
    disconnected_connection: ThermostatConnection,
) -> None:
    with pytest.raises(SteamloopConnectionError, match="Not connected"):
        disconnected_connection.send_request("Login", {"key": "val"})


def _get_sent_message(connection: ThermostatConnection) -> dict[str, Any]:
    """Extract the last message written to the mock transport."""
    assert connection._protocol is not None
    transport = cast("MagicMock", connection._protocol._transport)
    written: bytes = transport.write.call_args[0][0]
    return orjson.loads(written.rstrip(b" \x00"))


def test_set_temperature_setpoint_with_zone(
    connection: ThermostatConnection,
) -> None:
    connection.state.zones["1"] = Zone(
        zone_id="1",
        heat_setpoint="68",
        cool_setpoint="76",
        deadband="3",
    )
    connection.set_temperature_setpoint("1", heat_setpoint="72")
    msg = _get_sent_message(connection)
    req = msg["Request"]["UpdateTemperatureSetpoint"]
    assert req["heat_setpoint"] == "72"
    assert req["cool_setpoint"] == "76"
    assert req["deadband"] == "3"
    assert req["hold_type"] == "1"  # MANUAL


def test_set_temperature_setpoint_defaults(
    connection: ThermostatConnection,
) -> None:
    connection.set_temperature_setpoint("99")
    msg = _get_sent_message(connection)
    req = msg["Request"]["UpdateTemperatureSetpoint"]
    assert req["heat_setpoint"] == "55"
    assert req["cool_setpoint"] == "75"
    assert req["deadband"] == "3"


def test_set_fan_mode(connection: ThermostatConnection) -> None:
    connection.set_fan_mode(FanMode.CIRCULATE)
    msg = _get_sent_message(connection)
    assert msg["Request"]["UpdateFanMode"]["fan_mode"] == "3"


def test_set_zone_mode(connection: ThermostatConnection) -> None:
    connection.set_zone_mode("1", ZoneMode.HEAT)
    msg = _get_sent_message(connection)
    req = msg["Request"]["UpdateZoneMode"]
    assert req["zone_id"] == "1"
    assert req["zone_mode"] == "3"


def test_set_emergency_heat_on(connection: ThermostatConnection) -> None:
    connection.set_emergency_heat(True)
    msg = _get_sent_message(connection)
    assert msg["Request"]["UpdateEmergencyHeat"]["emergency_heat"] == "1"


def test_set_emergency_heat_off(connection: ThermostatConnection) -> None:
    connection.set_emergency_heat(False)
    msg = _get_sent_message(connection)
    assert msg["Request"]["UpdateEmergencyHeat"]["emergency_heat"] == "2"


def test_heartbeat(connection: ThermostatConnection) -> None:
    connection.heartbeat()
    msg = _get_sent_message(connection)
    assert msg == {"Heartbeat": {}}


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------


async def _feed_response(
    conn: ThermostatConnection,
    msg: dict[str, Any],
    delay: float = 0.01,
) -> None:
    """Simulate a thermostat response arriving via the protocol."""
    await asyncio.sleep(delay)
    conn._on_message(msg)


async def test_login_success(connection: ThermostatConnection) -> None:
    resp = {"Response": {"LoginResponse": {"status": "1"}}}
    asyncio.get_event_loop().call_soon(lambda: connection._on_message(resp))
    # Need a small delay for the queue to process
    task = asyncio.create_task(_feed_response(connection, resp))
    result = await connection.login()
    assert result["status"] == "1"
    await task


async def test_login_auth_failure(connection: ThermostatConnection) -> None:
    resp = {"Response": {"LoginResponse": {"status": "0"}}}
    task = asyncio.create_task(_feed_response(connection, resp))
    with pytest.raises(AuthenticationError, match="Authentication failed"):
        await connection.login()
    await task


async def test_login_error_response(
    connection: ThermostatConnection,
) -> None:
    resp = {"Response": {"Error": {"error_type": "AUTH", "description": "bad key"}}}
    task = asyncio.create_task(_feed_response(connection, resp))
    with pytest.raises(AuthenticationError, match="AUTH"):
        await connection.login()
    await task


async def test_login_timeout(connection: ThermostatConnection) -> None:
    with (
        patch("steamloop.connection.RESPONSE_TIMEOUT", 0.05),
        pytest.raises(AuthenticationError, match="No login response"),
    ):
        await connection.login()


# ---------------------------------------------------------------------------
# Pairing
# ---------------------------------------------------------------------------


async def test_pair_success(connection: ThermostatConnection) -> None:
    async def _feed() -> None:
        await asyncio.sleep(0.01)
        connection._on_message({"Response": {"LoginResponse": {"status": "1"}}})
        await asyncio.sleep(0.01)
        connection._on_message(
            {"Request": {"SetSecretKey": {"secret_key": "new-key-123"}}}
        )

    task = asyncio.create_task(_feed())
    result = await connection.pair()
    assert result["secret_key"] == "new-key-123"
    assert connection.secret_key == "new-key-123"
    await task


async def test_pair_sends_confirmation(
    connection: ThermostatConnection,
) -> None:
    assert connection._protocol is not None
    transport = cast("MagicMock", connection._protocol._transport)

    async def _feed() -> None:
        await asyncio.sleep(0.01)
        connection._on_message({"Request": {"SetSecretKey": {"secret_key": "abc"}}})

    task = asyncio.create_task(_feed())
    await connection.pair()
    await task

    # Check that SecretKeyUpdated confirmation was sent
    calls = transport.write.call_args_list
    for c in calls:
        written = orjson.loads(c[0][0].rstrip(b" \x00"))
        if "Response" in written and "SecretKeyUpdated" in written["Response"]:
            assert written["Response"]["SecretKeyUpdated"]["secret_key"] == "abc"
            return
    pytest.fail("SecretKeyUpdated confirmation not sent")


async def test_pair_rejected(connection: ThermostatConnection) -> None:
    resp = {"Response": {"LoginResponse": {"status": "0"}}}
    task = asyncio.create_task(_feed_response(connection, resp))
    with pytest.raises(PairingError, match="rejected"):
        await connection.pair()
    await task


async def test_pair_error_response(
    connection: ThermostatConnection,
) -> None:
    resp = {"Response": {"Error": {"error_type": "PAIR", "description": "not ready"}}}
    task = asyncio.create_task(_feed_response(connection, resp))
    with pytest.raises(PairingError, match="PAIR"):
        await connection.pair()
    await task


async def test_pair_timeout(connection: ThermostatConnection) -> None:
    with (
        patch("steamloop.connection.PAIRING_TIMEOUT", 0.05),
        pytest.raises(PairingError, match="timeout"),
    ):
        await connection.pair()


# ---------------------------------------------------------------------------
# Context manager
# ---------------------------------------------------------------------------


async def test_aenter_aexit() -> None:
    conn = ThermostatConnection("10.0.0.1", secret_key="sk")
    with (
        patch.object(conn, "connect", new_callable=AsyncMock) as mock_connect,
        patch.object(conn, "login", new_callable=AsyncMock) as mock_login,
        patch.object(conn, "start_background_tasks") as mock_start,
        patch.object(conn, "disconnect", new_callable=AsyncMock) as mock_disconnect,
    ):
        async with conn as c:
            assert c is conn
        mock_connect.assert_called_once()
        mock_login.assert_called_once()
        mock_start.assert_called_once()
        mock_disconnect.assert_called_once()


async def test_aenter_login_fails_closes_transport() -> None:
    conn = ThermostatConnection("10.0.0.1", secret_key="sk")
    with (
        patch.object(conn, "connect", new_callable=AsyncMock),
        patch.object(
            conn,
            "login",
            new_callable=AsyncMock,
            side_effect=AuthenticationError("bad"),
        ),
        patch.object(conn, "_close_transport") as mock_close,
    ):
        with pytest.raises(AuthenticationError):
            async with conn:
                pass
        mock_close.assert_called_once()


# ---------------------------------------------------------------------------
# Connection lifecycle
# ---------------------------------------------------------------------------


async def test_connect_tries_cert_sets_on_failure() -> None:
    conn = ThermostatConnection("10.0.0.1", secret_key="sk")
    call_count = 0

    async def _mock_connect(cert_set: Any) -> None:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise SteamloopConnectionError("first failed")
        conn._connected = True

    with patch.object(conn, "_connect_with_cert_set", side_effect=_mock_connect):
        await conn.connect()
    assert call_count == 2
    assert conn.connected


async def test_connect_all_fail_raises() -> None:
    conn = ThermostatConnection("10.0.0.1", secret_key="sk")
    with (
        patch.object(
            conn,
            "_connect_with_cert_set",
            new_callable=AsyncMock,
            side_effect=SteamloopConnectionError("fail"),
        ),
        pytest.raises(SteamloopConnectionError, match="Could not connect"),
    ):
        await conn.connect()


async def test_connect_with_specified_cert_set() -> None:
    from steamloop.certs import CertSet

    cert = CertSet(name="test", chain_data="dummy")
    conn = ThermostatConnection("10.0.0.1", secret_key="sk", cert_set=cert)
    with patch.object(conn, "_connect_with_cert_set", new_callable=AsyncMock) as mock:
        await conn.connect()
    mock.assert_called_once_with(cert)


async def test_connect_closes_existing(
    connection: ThermostatConnection,
) -> None:
    assert connection.connected
    with patch.object(connection, "_connect_with_cert_set", new_callable=AsyncMock):
        await connection.connect()


async def test_connect_with_cert_set_success() -> None:
    """Test _connect_with_cert_set sets _connected and clears event."""
    from steamloop.certs import CertSet

    conn = ThermostatConnection("10.0.0.1", secret_key="sk")
    cert = CertSet(name="test", chain_data="dummy")
    mock_transport = MagicMock(spec=asyncio.Transport)
    mock_protocol = MagicMock(spec=ThermostatProtocol)

    with (
        patch("steamloop.connection.create_ssl_context", return_value=MagicMock()),
        patch(
            "steamloop.connection.asyncio.wait_for",
            new_callable=AsyncMock,
            return_value=(mock_transport, mock_protocol),
        ),
        patch("asyncio.get_running_loop") as mock_loop,
    ):
        mock_loop.return_value.run_in_executor = AsyncMock(return_value=MagicMock())
        await conn._connect_with_cert_set(cert)
    assert conn._connected is True
    assert conn._transport is mock_transport
    assert conn._protocol is mock_protocol
    assert not conn._connection_lost_event.is_set()


async def test_connect_ssl_error() -> None:
    conn = ThermostatConnection("10.0.0.1", secret_key="sk")
    from steamloop.certs import CertSet

    cert = CertSet(name="test", chain_data="dummy")
    conn._cert_set = cert
    with (
        patch("steamloop.connection.create_ssl_context", return_value=MagicMock()),
        patch(
            "asyncio.get_running_loop",
        ) as mock_loop,
        pytest.raises(SteamloopConnectionError, match="TLS handshake"),
    ):
        loop = mock_loop.return_value
        loop.run_in_executor = AsyncMock(return_value=MagicMock())
        loop.time = MagicMock(return_value=0)
        future: asyncio.Future[Any] = asyncio.Future()
        future.set_exception(ssl.SSLError(1, "handshake fail"))
        loop.create_connection = MagicMock(return_value=future)
        await conn._connect_with_cert_set(cert)


async def test_connect_timeout() -> None:
    conn = ThermostatConnection("10.0.0.1", secret_key="sk")
    from steamloop.certs import CertSet

    cert = CertSet(name="test", chain_data="dummy")
    with (
        patch("steamloop.connection.create_ssl_context", return_value=MagicMock()),
        patch(
            "steamloop.connection.asyncio.wait_for",
            new_callable=AsyncMock,
            side_effect=TimeoutError(),
        ),
        patch("asyncio.get_running_loop") as mock_loop,
        pytest.raises(SteamloopConnectionError, match="timed out"),
    ):
        mock_loop.return_value.run_in_executor = AsyncMock(return_value=MagicMock())
        await conn._connect_with_cert_set(cert)


async def test_connect_os_error() -> None:
    conn = ThermostatConnection("10.0.0.1", secret_key="sk")
    from steamloop.certs import CertSet

    cert = CertSet(name="test", chain_data="dummy")
    with (
        patch("steamloop.connection.create_ssl_context", return_value=MagicMock()),
        patch(
            "steamloop.connection.asyncio.wait_for",
            new_callable=AsyncMock,
            side_effect=OSError("refused"),
        ),
        patch("asyncio.get_running_loop") as mock_loop,
        pytest.raises(SteamloopConnectionError, match="TCP connect"),
    ):
        mock_loop.return_value.run_in_executor = AsyncMock(return_value=MagicMock())
        await conn._connect_with_cert_set(cert)


# ---------------------------------------------------------------------------
# Background tasks
# ---------------------------------------------------------------------------


async def test_disconnect_cancels_run_task(
    connection: ThermostatConnection,
) -> None:
    connection._run_task = asyncio.create_task(asyncio.sleep(100))
    await connection.disconnect()
    assert connection._run_task is None


def test_on_connection_lost_sets_event(
    connection: ThermostatConnection,
) -> None:
    assert not connection._connection_lost_event.is_set()
    connection._on_connection_lost(ConnectionResetError("reset"))
    assert connection._connection_lost_event.is_set()
    assert connection.connected is False


def test_on_connection_lost_without_exception(
    connection: ThermostatConnection,
) -> None:
    connection._on_connection_lost(None)
    assert connection._connection_lost_event.is_set()
    assert connection.connected is False


# ---------------------------------------------------------------------------
# Message queue interaction
# ---------------------------------------------------------------------------


def test_on_message_queues_when_queue_set(
    connection: ThermostatConnection,
) -> None:
    queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
    connection._message_queue = queue
    msg: dict[str, Any] = {"Heartbeat": {}}
    connection._on_message(msg)
    assert queue.get_nowait() == msg
    connection._message_queue = None


def test_on_message_no_queue(connection: ThermostatConnection) -> None:
    # Should not raise when no queue set
    connection._on_message({"Heartbeat": {}})


# ---------------------------------------------------------------------------
# Login — skips non-Response messages
# ---------------------------------------------------------------------------


async def test_login_skips_non_response(
    connection: ThermostatConnection,
) -> None:
    """Login ignores Event messages while waiting for Response."""

    async def _feed() -> None:
        await asyncio.sleep(0.01)
        # First an event (should be skipped by login)
        connection._on_message({"Event": {"ZoneAdded": {"zone_id": "1"}}})
        await asyncio.sleep(0.01)
        # Then the actual response
        connection._on_message({"Response": {"LoginResponse": {"status": "1"}}})

    task = asyncio.create_task(_feed())
    result = await connection.login()
    assert result["status"] == "1"
    await task


# ---------------------------------------------------------------------------
# SSLCertVerificationError
# ---------------------------------------------------------------------------


async def test_connect_ssl_cert_verification_error() -> None:
    from steamloop.certs import CertSet

    conn = ThermostatConnection("10.0.0.1", secret_key="sk")
    cert = CertSet(name="test", chain_data="dummy")
    with (
        patch("steamloop.connection.create_ssl_context", return_value=MagicMock()),
        patch(
            "steamloop.connection.asyncio.wait_for",
            new_callable=AsyncMock,
            side_effect=ssl.SSLCertVerificationError("verify fail"),
        ),
        patch("asyncio.get_running_loop") as mock_loop,
        pytest.raises(SteamloopConnectionError, match="cert verification"),
    ):
        mock_loop.return_value.run_in_executor = AsyncMock(return_value=MagicMock())
        await conn._connect_with_cert_set(cert)


# ---------------------------------------------------------------------------
# Protocol close when already None
# ---------------------------------------------------------------------------


def test_close_transport_when_already_none() -> None:
    conn = ThermostatConnection("10.0.0.1", secret_key="sk")
    conn._close_transport()  # Should not raise


def test_protocol_close_when_transport_none() -> None:
    conn = ThermostatConnection("10.0.0.1", secret_key="sk")
    protocol = ThermostatProtocol(conn)
    # transport is None
    protocol.close()
    assert protocol._transport is None


# ---------------------------------------------------------------------------
# Heartbeat loop
# ---------------------------------------------------------------------------


async def test_heartbeat_loop_sends_heartbeat(
    connection: ThermostatConnection,
) -> None:
    assert connection._protocol is not None
    transport = cast("MagicMock", connection._protocol._transport)
    with patch("steamloop.connection.HEARTBEAT_INTERVAL", 0.01):
        task = asyncio.create_task(connection._heartbeat_loop())
        await asyncio.sleep(0.05)
        connection._connected = False
        await asyncio.sleep(0.02)
        task.cancel()
        with __import__("contextlib").suppress(asyncio.CancelledError):
            await task
    assert transport.write.call_count >= 1


# ---------------------------------------------------------------------------
# Run loop — reconnect with backoff
# ---------------------------------------------------------------------------


async def test_run_loop_reconnects_on_connection_lost() -> None:
    conn = ThermostatConnection("10.0.0.1", secret_key="sk")
    conn._connected = True

    connect_count = 0

    async def mock_connect() -> None:
        nonlocal connect_count
        connect_count += 1
        conn._connected = True
        conn._connection_lost_event.clear()

    async def mock_login() -> dict[str, str]:
        return {"status": "1"}

    with (
        patch.object(conn, "connect", side_effect=mock_connect),
        patch.object(conn, "login", side_effect=mock_login),
        patch("steamloop.connection.RECONNECT_DELAY", 0.01),
        patch("steamloop.connection.HEARTBEAT_INTERVAL", 100),
    ):
        conn._connection_lost_event.clear()
        task = asyncio.create_task(conn._run_loop())
        await asyncio.sleep(0.01)
        # Simulate connection loss
        conn._connection_lost_event.set()
        await asyncio.sleep(0.1)
        task.cancel()
        with __import__("contextlib").suppress(asyncio.CancelledError):
            await task
    assert connect_count >= 1


async def test_run_loop_backoff_on_reconnect_failure() -> None:
    conn = ThermostatConnection("10.0.0.1", secret_key="sk")
    conn._connected = True

    connect_count = 0

    async def mock_connect() -> None:
        nonlocal connect_count
        connect_count += 1
        if connect_count <= 2:
            raise SteamloopConnectionError("fail")
        conn._connected = True
        conn._connection_lost_event.clear()

    async def mock_login() -> dict[str, str]:
        return {"status": "1"}

    with (
        patch.object(conn, "connect", side_effect=mock_connect),
        patch.object(conn, "login", side_effect=mock_login),
        patch("steamloop.connection.RECONNECT_DELAY", 0.01),
        patch("steamloop.connection.RECONNECT_MAX", 0.05),
        patch("steamloop.connection.HEARTBEAT_INTERVAL", 100),
    ):
        task = asyncio.create_task(conn._run_loop())
        await asyncio.sleep(0.01)
        conn._connection_lost_event.set()
        await asyncio.sleep(0.3)
        task.cancel()
        with __import__("contextlib").suppress(asyncio.CancelledError):
            await task
    assert connect_count >= 3


# ---------------------------------------------------------------------------
# start_background_tasks
# ---------------------------------------------------------------------------


async def test_start_background_tasks(
    connection: ThermostatConnection,
) -> None:
    connection.start_background_tasks()
    assert connection._run_task is not None
    connection._run_task.cancel()
    with __import__("contextlib").suppress(asyncio.CancelledError):
        await connection._run_task


# ---------------------------------------------------------------------------
# set_temperature_setpoint — both setpoints provided
# ---------------------------------------------------------------------------


def test_set_temperature_setpoint_both_provided(
    connection: ThermostatConnection,
) -> None:
    connection.state.zones["1"] = Zone(
        zone_id="1", heat_setpoint="68", cool_setpoint="76", deadband="3"
    )
    connection.set_temperature_setpoint("1", heat_setpoint="70", cool_setpoint="78")
    msg = _get_sent_message(connection)
    req = msg["Request"]["UpdateTemperatureSetpoint"]
    assert req["heat_setpoint"] == "70"
    assert req["cool_setpoint"] == "78"
    assert req["deadband"] == "3"


# ---------------------------------------------------------------------------
# Deadband auto-adjustment
# ---------------------------------------------------------------------------


def test_deadband_heat_raises_cool(
    connection: ThermostatConnection,
) -> None:
    """Setting heat close to cool auto-raises cool."""
    connection.state.zones["1"] = Zone(
        zone_id="1", heat_setpoint="68", cool_setpoint="72", deadband="3"
    )
    connection.set_temperature_setpoint("1", heat_setpoint="71")
    msg = _get_sent_message(connection)
    req = msg["Request"]["UpdateTemperatureSetpoint"]
    assert req["heat_setpoint"] == "71"
    assert req["cool_setpoint"] == "74"  # 71 + 3


def test_deadband_cool_lowers_heat(
    connection: ThermostatConnection,
) -> None:
    """Setting cool close to heat auto-lowers heat."""
    connection.state.zones["1"] = Zone(
        zone_id="1", heat_setpoint="70", cool_setpoint="76", deadband="3"
    )
    connection.set_temperature_setpoint("1", cool_setpoint="72")
    msg = _get_sent_message(connection)
    req = msg["Request"]["UpdateTemperatureSetpoint"]
    assert req["cool_setpoint"] == "72"
    assert req["heat_setpoint"] == "69"  # 72 - 3


def test_deadband_no_adjustment_needed(
    connection: ThermostatConnection,
) -> None:
    """No adjustment when setpoints already satisfy deadband."""
    connection.state.zones["1"] = Zone(
        zone_id="1", heat_setpoint="68", cool_setpoint="80", deadband="3"
    )
    connection.set_temperature_setpoint("1", heat_setpoint="70")
    msg = _get_sent_message(connection)
    req = msg["Request"]["UpdateTemperatureSetpoint"]
    assert req["heat_setpoint"] == "70"
    assert req["cool_setpoint"] == "80"  # Unchanged


def test_deadband_both_provided_raises_cool(
    connection: ThermostatConnection,
) -> None:
    """When both setpoints are provided and violate deadband, cool is raised."""
    connection.state.zones["1"] = Zone(
        zone_id="1", heat_setpoint="68", cool_setpoint="76", deadband="3"
    )
    connection.set_temperature_setpoint("1", heat_setpoint="72", cool_setpoint="73")
    msg = _get_sent_message(connection)
    req = msg["Request"]["UpdateTemperatureSetpoint"]
    assert req["heat_setpoint"] == "72"
    assert req["cool_setpoint"] == "75"  # 72 + 3


def test_deadband_no_zone_uses_defaults(
    connection: ThermostatConnection,
) -> None:
    """With no zone state, defaults (55 heat, 75 cool, 3 db) are used."""
    connection.set_temperature_setpoint("99", heat_setpoint="74")
    msg = _get_sent_message(connection)
    req = msg["Request"]["UpdateTemperatureSetpoint"]
    assert req["heat_setpoint"] == "74"
    assert req["cool_setpoint"] == "77"  # 74 + 3 (default 75 violated)


def test_deadband_exact_gap_no_adjustment(
    connection: ThermostatConnection,
) -> None:
    """Exactly equal to deadband — no adjustment needed."""
    connection.state.zones["1"] = Zone(
        zone_id="1", heat_setpoint="68", cool_setpoint="73", deadband="3"
    )
    connection.set_temperature_setpoint("1", heat_setpoint="70")
    msg = _get_sent_message(connection)
    req = msg["Request"]["UpdateTemperatureSetpoint"]
    assert req["heat_setpoint"] == "70"
    assert req["cool_setpoint"] == "73"  # 73 - 70 = 3, exactly meets deadband
