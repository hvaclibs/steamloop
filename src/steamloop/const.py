"""Constants and enums for the steamloop thermostat protocol."""

from __future__ import annotations

from enum import IntEnum


class ZoneMode(IntEnum):
    """HVAC zone operating mode."""

    OFF = 0
    AUTO = 1
    COOL = 2
    HEAT = 3


class FanMode(IntEnum):
    """Fan operating mode."""

    AUTO = 1
    ALWAYS_ON = 2
    CIRCULATE = 3


class HVACActivity(IntEnum):
    """
    Live HVAC activity for heating/cooling, as reported by the thermostat.

    INACTIVE: System is off — not heating/cooling.
    IDLE: System is on but not currently running (setpoint satisfied).
    ACTIVE: System is actively heating/cooling right now.
    """

    INACTIVE = 0
    IDLE = 1
    ACTIVE = 2


class HoldType(IntEnum):
    """
    Temperature hold type.

    UNDEFINED: No hold type set.
    MANUAL: Manual override by user (permanent hold).
    SCHEDULE: Following the programmed schedule.
    HOLD: Hold until next scheduled period.
    """

    UNDEFINED = 0
    MANUAL = 1
    SCHEDULE = 2
    HOLD = 3


DEFAULT_PORT = 7878
HEARTBEAT_INTERVAL = 55  # seconds (thermostat expects every 60s)
CONNECT_TIMEOUT = 10
PAIRING_TIMEOUT = 120
RESPONSE_TIMEOUT = 10
INITIAL_STATE_TIMEOUT = 1  # seconds to wait for initial state after login
RECONNECT_DELAY = 5  # initial delay before first reconnect attempt
RECONNECT_MAX = 300  # max delay between reconnect attempts (5 minutes)
BACKOFF_FACTOR = 2  # multiply delay by this on each failure
DEFAULT_HEAT_SETPOINT = "55"  # str for wire format
DEFAULT_COOL_SETPOINT = "75"  # str for wire format
