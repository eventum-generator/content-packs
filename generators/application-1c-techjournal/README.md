# 1C:Enterprise Technological Log Generator

Produces ECS JSON events that carry the documented 1C:Enterprise 8.3 technological log JSON record in `event.original` and `one_c.techjournal`. This is the **technological log** for platform calls and lock diagnostics, separate from the 1C event log generator.

## Event Types

| Native `name` | Routine frequency | Category |
|---|---:|---|
| `SCALL` | 80% | Outbound server call |
| `CALL` | 18% | Incoming server call |
| `TLOCK` | 2% | Managed transaction lock check |
| `TTIMEOUT` | Chain only | Lock timeout |
| `EXCP` | Chain only | Platform exception |

Routine weights are synthetic defaults, not measured 1C production rates. The FSM emits a four-event chain after every 200 routine events when anomaly mode is on.

## Anomaly Chain

The user `batch_admin` and client `92` make a slower `CALL`, encounter a `TLOCK` wait on `Document.SalesOrder`, then emit `TTIMEOUT` and `EXCP`. All four records share `ClientID`, `SessionID`, `OSThread`, `Usr`, and infobase. Each remote call gets a bounded, increasing `CallID`. Durations rise above routine calls while staying within consecutive generated timestamps. A detector can correlate a slow call, lock wait, timeout, and exception for the same session and thread.

`anomaly_mode` defaults to `true`. Set it to `false` for only routine `SCALL`, `CALL`, and `TLOCK` records.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
|---|---|---|
| `anomaly_mode` | `true` | Include or omit the lock-failure chain |
| `anomaly_interval_events` | `200` | Routine events between chains |
| `host_name` | `onec-app-01` | 1C application host |
| `infobase` | `accounting` | Infobase name |
| `process_name` | `rphost` | 1C process name |
| `routine_user` | `accountant01` | Routine actor |
| `unusual_user` | `batch_admin` | Chain actor |
| `routine_client_id` | `8` | Routine client identifier |
| `unusual_client_id` | `92` | Chain client identifier |

### Output Parameters

The shipped configuration writes `output/events.json` and needs no output parameters or secrets. Replace the `output` block to deliver elsewhere, using that plugin's `${params.*}` and `${secrets.*}` placeholders for endpoint settings and credentials.

## Usage

From the content-packs repository root:

```bash
eventum generate --path generators/application-1c-techjournal/generator.yml --id onec-techjournal --live-mode false
eventum generate --path generators/application-1c-techjournal/generator.yml --id onec-techjournal --live-mode true
```

Batch mode runs continuously until interrupted. Live mode emits one record per second.

## Sample Output

This complete event was copied from a generator run:

```json
{"@timestamp": "2026-09-25T12:25:32+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "TTIMEOUT", "category": ["database"], "dataset": "1c.techjournal", "kind": "event", "original": "{\"ClientID\": \"92\", \"OSThread\": \"15968\", \"Regions\": \"Document.SalesOrder\", \"SessionID\": \"421\", \"Usr\": \"batch_admin\", \"WaitConnections\": \"ClientID=88\", \"depth\": \"0\", \"duration\": \"900000\", \"level\": \"ERROR\", \"name\": \"TTIMEOUT\", \"p:processName\": \"accounting\", \"process\": \"rphost\", \"ts\": \"2026-09-25T12:25:32.000000\"}", "type": ["error"]}, "host": {"name": "onec-app-01"}, "one_c": {"techjournal": {"ClientID": "92", "OSThread": "15968", "Regions": "Document.SalesOrder", "SessionID": "421", "Usr": "batch_admin", "WaitConnections": "ClientID=88", "depth": "0", "duration": "900000", "level": "ERROR", "name": "TTIMEOUT", "p:processName": "accounting", "process": "rphost", "ts": "2026-09-25T12:25:32.000000"}}, "process": {"name": "rphost"}, "user": {"name": "batch_admin"}}
```

## Source and Scope

The [1C:Enterprise 8.3.27 technological-log file specification](https://kb.1ci.com/1C_Enterprise_Platform/Guides/Administrator_Guides/1C_Enterprise_8.3.27_Administrator_Guide/Appendix_3._Description_and_location_of_internal_files/3.24._logcfg.xml/3.24.3._Technological_log_files/) gives the JSON keys `ts`, `duration`, `name`, `depth`, `level`, and source properties. The [logcfg.xml event and property catalog](https://kb.1ci.com/1C_Enterprise_Platform/Guides/Administrator_Guides/1C_Enterprise_8.3.22_Administrator_Guide/Appendix_3._Description_and_location_of_internal_files/3.22._logcfg.xml/3.22.2._Configuration_file_structure/) documents `CALL`, `SCALL`, `TLOCK`, `TTIMEOUT`, `EXCP`, and their properties. This pack assumes `log.format=json` and appropriate event/property selection in `logcfg.xml`. It covers all 14 keys in the vendor's selected `SCALL` JSON sample, plus the lock and exception properties used in this scenario. It does not cover the full technological-log event catalog.

The [KUMA 4.0 source table](https://support.kaspersky.com/kuma/4.0/en-US/255782.htm) lists a regexp normalizer for 1C TechJournal. This pack uses the vendor-documented 8.3.27 JSON format, so compatibility with that KUMA normalizer has not been verified. Use a parser configured for the JSON format.
