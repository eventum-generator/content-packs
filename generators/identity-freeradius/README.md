# FreeRADIUS Linelog Authentication Generator

Produces ECS JSON events with FreeRADIUS 4.0 `linelog` authentication and accounting messages in `event.original`. The message shapes follow the vendor's example `log_auth_access_accept`, `log_auth_access_reject`, and the accounting Start/Stop configuration.

## Event Types

| Native message | Routine frequency | Category |
|---|---:|---|
| `Login OK` | 70% of routine authentication attempts | Authentication |
| `Login incorrect` | 30% of routine authentication attempts | Authentication |
| `Connect` | Follows a routine success; also in the chain | Accounting |
| `Disconnect` | Follows `Connect` | Accounting |

These weights are synthetic, not measured production rates. When anomaly mode is enabled, a six-event chain follows every 250 routine authentication attempts.

## Anomaly Chain

The same user `admin01`, calling station `02-AA-BB-CC-DD-EE`, NAS client `wifi-controller-01`, and NAS port `12` produce three `Login incorrect` records, then `Login OK`, `Connect`, and `Disconnect`. The records appear on successive timestamps. A detector can correlate repeated rejects followed by acceptance and an active session using the user, `Calling-Station-Id`, NAS client, and NAS port.

`anomaly_mode` defaults to `true`. Set it to `false` for only routine authentication and paired accounting records.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
|---|---|---|
| `anomaly_mode` | `true` | Include or omit the anomaly chain |
| `anomaly_interval_events` | `250` | Routine attempts between chains |
| `radius_host` | `radius-01` | RADIUS server hostname |
| `nas_client` | `wifi-controller-01` | Configured RADIUS client short name |
| `ordinary_user` | `employee01` | Routine user |
| `ordinary_station` | `02-11-22-33-44-55` | Routine `Calling-Station-Id` |
| `unusual_user` | `admin01` | Correlated chain user |
| `unusual_station` | `02-AA-BB-CC-DD-EE` | Correlated chain `Calling-Station-Id` |
| `nas_port` | `12` | NAS port |
| `called_station` | `02-66-77-88-99-AA` | Accounting `Called-Station-Id` |

### Output Parameters

The shipped configuration writes `output/events.json` and needs no output parameters or secrets. To send events to another destination, replace the `output` block with the chosen plugin and use its `${params.*}` and `${secrets.*}` placeholders for endpoint settings and credentials.

## Usage

From the content-packs repository root:

```bash
eventum generate --path generators/identity-freeradius/generator.yml --id freeradius --live-mode false
eventum generate --path generators/identity-freeradius/generator.yml --id freeradius --live-mode true
```

Batch mode runs continuously until interrupted. Live mode emits one record per second.

## Sample Output

This complete event was copied from a generator run:

```json
{"@timestamp": "2026-09-25T12:32:17+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "accept", "category": ["authentication"], "dataset": "freeradius.linelog", "kind": "event", "module": "freeradius", "original": "Login OK: [admin01] (from wifi-controller-01 port 12 cli 02-AA-BB-CC-DD-EE)", "outcome": "success", "type": ["start"]}, "host": {"name": "radius-01"}, "message": "Login OK: [admin01] (from wifi-controller-01 port 12 cli 02-AA-BB-CC-DD-EE)", "radius": {"calling_station_id": "02-AA-BB-CC-DD-EE", "client_shortname": "wifi-controller-01", "nas_port": 12}, "service": {"name": "radiusd"}, "source": {"mac": "02-AA-BB-CC-DD-EE"}, "user": {"name": "admin01"}}
```

## Source and Scope

The [FreeRADIUS 4.0 linelog configuration](https://www.freeradius.org/documentation/freeradius-server/4.0.0/reference/raddb/mods-available/linelog.html) documents the emitted message text and `%{User-Name}`, `%client(shortname)`, `%{NAS-Port}`, `%{Calling-Station-Id}`, and failure-message substitutions. This pack assumes those `linelog` instances are configured; it does not model every FreeRADIUS default logfile or packet attribute. No source-specific Elastic integration sample is used. All five selected native substitutions appear in generated records.

The [KUMA 4.0 source table](https://support.kaspersky.com/kuma/4.0/en-US/255782.htm) names FreeRADIUS 3.0 Syslog. This pack follows the vendor's 4.0 linelog examples, so compatibility with that KUMA normalizer has not been verified. Use a SIEM parser configured for these message patterns.
