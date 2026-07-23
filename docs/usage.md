(usage)=

# Usage

Assuming you've followed the {ref}`installation steps <installation>`, you're
ready to use `steamloop` either from the command line or as an async library.

## Command line

The package installs a `steamloop` console script for pairing with and
monitoring a thermostat over its local mTLS interface (port 7878 by default).

```bash
steamloop --help
```

```text
usage: steamloop [-h] [--port PORT] [--pair] [--key KEY] [--debug] ip
```

| Argument  | Description                                          |
| --------- | ---------------------------------------------------- |
| `ip`      | Thermostat IP address (required).                    |
| `--port`  | TCP port to connect to (default: `7878`).            |
| `--pair`  | Enter pairing mode to obtain a secret key.           |
| `--key`   | Secret key from a previous pairing (skips the file). |
| `--debug` | Enable debug logging.                                |

### Pairing

Put the thermostat in pairing mode (on the device: _Menu > Settings > Network >
Advanced Setup > Remote Connection > Pair_), then run:

```bash
steamloop 192.168.1.100 --pair
```

On success the secret key is saved to a pairing file in the current directory
and the CLI drops straight into monitoring mode.

### Monitoring

If the thermostat has already been paired from this directory, connect with just
the IP:

```bash
steamloop 192.168.1.100
```

To skip the pairing file and supply the secret key directly:

```bash
steamloop 192.168.1.100 --key YOUR_SECRET_KEY
```

### Interactive commands

Once connected, the CLI streams thermostat events and accepts commands on
stdin. Type `help` at any time to list them:

| Command                         | Description                               |
| ------------------------------- | ----------------------------------------- |
| `status`                        | Show the current thermostat state.        |
| `zone <id>`                     | Select the active zone for zone commands. |
| `heat <temp>`                   | Set the heat setpoint.                    |
| `cool <temp>`                   | Set the cool setpoint.                    |
| `setpoint <heat> <cool>`        | Set both setpoints at once.               |
| `hold <manual\|schedule\|hold>` | Set the hold type.                        |
| `mode <off\|auto\|cool\|heat>`  | Set the zone HVAC mode.                   |
| `fan <auto\|on\|circulate>`     | Set the fan mode.                         |
| `eheat <on\|off>`               | Toggle emergency heat.                    |
| `raw <json>`                    | Send a raw JSON message.                  |
| `ping`                          | Send a heartbeat.                         |
| `quit`                          | Disconnect and exit.                      |

## Library

`steamloop` is an `asyncio` library. `ThermostatConnection` manages the
connection lifecycle and keeps a live copy of thermostat state that you read
directly.

```python
import asyncio
from steamloop import ThermostatConnection, ZoneMode, FanMode


async def main():
    conn = ThermostatConnection(
        "192.168.1.100",
        secret_key="your-secret-key-from-pairing",
    )
    async with conn:
        # State is populated automatically from thermostat events.
        for zone_id, zone in conn.state.zones.items():
            print(f"{zone.name}: {zone.indoor_temperature}°F")

        # Commands are synchronous — they write to the transport, no await.
        conn.set_temperature_setpoint("1", heat_setpoint="72")
        conn.set_zone_mode("1", ZoneMode.COOL)
        conn.set_fan_mode(FanMode.AUTO)


asyncio.run(main())
```

Using `async with` connects, logs in, and starts the heartbeat and
auto-reconnect background tasks on entry, then disconnects on exit. To manage
the lifecycle by hand, call `connect()`, `login()`, `start_background_tasks()`,
and `disconnect()` yourself.

### Pairing programmatically

`pair()` returns the secret key directly, so you can store it however you like:

```python
from steamloop import ThermostatConnection


async def pair(ip: str) -> str:
    conn = ThermostatConnection(ip, secret_key="")
    try:
        await conn.connect()
        ssk = await conn.pair()
        return ssk["secret_key"]  # store in a database, config entry, etc.
    finally:
        await conn.disconnect()
```

Or use the built-in file helpers to persist pairing data to disk:

```python
from steamloop import ThermostatConnection, save_pairing, load_pairing

# Save after pairing.
await save_pairing(ip, {
    "secret_key": secret_key,
    "device_type": "automation",
    "device_id": "module",
})

# Load later.
pairing = await load_pairing(ip)
conn = ThermostatConnection(ip, secret_key=pairing["secret_key"])
```

### Event callbacks

Register a callback to be notified whenever the thermostat pushes an update.
`add_event_callback()` returns a function that unregisters it:

```python
def on_event(msg):
    print("Received:", msg)


remove = conn.add_event_callback(on_event)
# later: remove() to unregister.
```

See the {doc}`API reference <steamloop>` for the full list of methods, enums,
and state attributes.
