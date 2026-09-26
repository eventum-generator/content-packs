# 1C:Enterprise Technological Log Generator

Generates synthetic 1C:Enterprise 8.3.27 **technological-log JSON** records inside an ECS envelope. This platform diagnostic log is separate from the 1C EventJournal registration log.

## Event Types

| Native `name` | Background frequency | Meaning |
|---|---:|---|
| `SCALL` | 79% | Outgoing remote call |
| `CALL` | 17% | Incoming remote call |
| `TLOCK` | 3% | Managed transaction lock operation or wait |
| `EXCP` | 1% | Platform exception |

The frequencies are synthetic workload settings, not measured 1C rates. The source profile assumes `log.format=json` and `logcfg.xml` configured to record these four event types and their selected properties. Native values are JSON strings, including `duration` in microseconds, as in the [8.3.27 specification](https://1c-dn.com/library/tutorials/1c_enterprise_administrator_guide_file_mode_8_3_27/).

## Anomaly Chain

About every `anomaly_interval_hours` (default: 2), the `batch_admin` session waits for another connection's managed lock on `InfoRg42.DIMS` (`TLOCK`, `t:connectID=16`, `WaitConnections=17`). It then records an `EXCP` whose description identifies a managed-lock wait timeout, followed by the completed `CALL`. The three records share `Usr`, `SessionID`, `OSThread`, `t:clientID`, `t:connectID`, infobase, and execution context. The `CALL` completes last and its duration spans the lock wait. Each episode uses a fresh `CallID` and rotates the document key within the same ordinary lock region. A detector can correlate the prolonged wait and exception with the enclosing call by session and connection.

The background contains the same users, persistent client sessions, event names, document keys, lock region, and context, but never this complete three-record sequence. The chain recurs after the configured interval, waiting until its thread has been idle long enough for the enclosing call to start. The two client sessions may remain open across a working day; episode identity comes from time, document and fresh CallID rather than a fabricated session restart. `anomaly_mode` defaults to `true`; set it to `false` for background only.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
|---|---|---|
| `anomaly_mode` | `true` | Include periodic lock-wait episodes |
| `anomaly_interval_hours` | `2` | Positive hours between episode eligibility; actual start waits for a free thread |
| `host_name` | `onec-app-01` | Server host |
| `infobase` | `accounting` | Infobase name (`p:processName`) |
| `process_name` | `rphost` | 1C process |
| `routine_user` | `accountant01` | First background session |
| `contending_user` | `batch_admin` | Second background session and chain participant |
| `routine_client_id` | `518` | First session's `t:clientID` |
| `contending_client_id` | `592` | Second session's `t:clientID` |

### Output Parameters

The shipped configuration writes `output/events.json` and needs no endpoint parameters or secrets. To send events elsewhere, replace the `output` block with the desired plugin and its `${params.*}` and `${secrets.*}` placeholders.

## Usage

From the content-packs repository root, set `input[0].cron.start` and `input[0].cron.end` for a finite batch run. For example, `2026-09-25T00:00:00+00:00` and `2026-09-25T04:05:00+00:00` produce 14,701 records, including two complete default episodes.

```bash
uv run --project ../eventum eventum generate --path generators/application-1c-techjournal/generator.yml --id onec-techjournal --live-mode false
```

For a continuous stream, leave `end` unset and use live mode:

```bash
uv run --project ../eventum eventum generate --path generators/application-1c-techjournal/generator.yml --id onec-techjournal --live-mode true
```

## Sample Output

This synthetic event was copied from the first episode in a four-hour finite generator run. It is not a vendor-captured record.

```json
{"@timestamp": "2026-09-25T02:00:03.672540+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "TLOCK", "dataset": "1c.techjournal", "kind": "event", "original": "{\"ts\":\"2026-09-25T02:00:03.672540\",\"duration\":\"2000000\",\"name\":\"TLOCK\",\"depth\":\"5\",\"level\":\"INFO\",\"process\":\"rphost\",\"p:processName\":\"accounting\",\"OSThread\":\"15968\",\"t:clientID\":\"592\",\"t:applicationName\":\"1CV8C\",\"t:computerName\":\"client-01\",\"t:connectID\":\"16\",\"SessionID\":\"421\",\"Usr\":\"batch_admin\",\"AppID\":\"1CV8C\",\"Regions\":\"InfoRg42.DIMS\",\"Locks\":\"InfoRg42.DIMS Exclusive Fld43=\\\"DOC-0042\\\"\",\"WaitConnections\":\"17\",\"Context\":\"\u041e\u0431\u0449\u0438\u0439\u041c\u043e\u0434\u0443\u043b\u044c.\u0417\u0430\u043f\u0438\u0441\u044c\u0414\u043e\u043a\u0443\u043c\u0435\u043d\u0442\u043e\u0432.\u041c\u043e\u0434\u0443\u043b\u044c : 81 : \u041d\u0430\u0431\u043e\u0440\u0417\u0430\u043f\u0438\u0441\u0435\u0439.\u0417\u0430\u043f\u0438\u0441\u0430\u0442\u044c();\"}", "type": ["info"]}, "host": {"name": "onec-app-01"}, "one_c": {"techjournal": {"AppID": "1CV8C", "Context": "\u041e\u0431\u0449\u0438\u0439\u041c\u043e\u0434\u0443\u043b\u044c.\u0417\u0430\u043f\u0438\u0441\u044c\u0414\u043e\u043a\u0443\u043c\u0435\u043d\u0442\u043e\u0432.\u041c\u043e\u0434\u0443\u043b\u044c : 81 : \u041d\u0430\u0431\u043e\u0440\u0417\u0430\u043f\u0438\u0441\u0435\u0439.\u0417\u0430\u043f\u0438\u0441\u0430\u0442\u044c();", "Locks": "InfoRg42.DIMS Exclusive Fld43=\"DOC-0042\"", "OSThread": "15968", "Regions": "InfoRg42.DIMS", "SessionID": "421", "Usr": "batch_admin", "WaitConnections": "17", "depth": "5", "duration": "2000000", "level": "INFO", "name": "TLOCK", "p:processName": "accounting", "process": "rphost", "t:applicationName": "1CV8C", "t:clientID": "592", "t:computerName": "client-01", "t:connectID": "16", "ts": "2026-09-25T02:00:03.672540"}}, "process": {"name": "rphost"}, "user": {"name": "batch_admin"}}
```

`event.original` contains the native JSON object encoded as a string; `one_c.techjournal` contains the parsed native fields. The emitted file itself is ECS JSON, so a consumer must extract `event.original` to ingest it as a native 1C JSON log.

## Source and Scope

The [1C 8.3.27 Administrator Guide](https://1c-dn.com/library/tutorials/1c_enterprise_administrator_guide_file_mode_8_3_27/) defines JSON technological-log format, event names, property meanings, and a complete 14-field `SCALL` JSON record. The [1C ITS `CALL` sample](https://its.1c.ru/db/content/metod8dev/src/developers/scalability/troubleshooting/i8105860.htm), [1C ITS lock investigation with `TLOCK` and `EXCP` records](https://its.1c.ru/db/content/metod8dev/src/developers/scalability/troubleshooting/i8106006.htm), and [1C ITS managed-lock exception description](https://its.1c.ru/db/content/metod8dev/src/developers/scalability/methods/i8105809.htm) ground the field choices and lock sequence. The selected properties, user sessions, and event frequencies remain synthetic.

**BLOCKED_RAW_EVIDENCE:** complete first-party JSON records for `CALL`, `TLOCK`, and `EXCP` have not been found. Their shapes follow the vendor's text examples and text-to-JSON rule; exact per-event 8.3.27 JSON field sets remain unverified. `TTIMEOUT` is documented in the event catalog but excluded because no complete first-party raw record was found. This pack does not claim production fidelity for that event.

The [KUMA 4.0 source table](https://support.kaspersky.com/kuma/4.0/en-US/255782.htm) lists a regexp normalizer for 1C TechJournal. That text normalizer's compatibility with this JSON profile is unverified; configure a parser for the JSON profile. The generator does not cover the complete technological-log catalog.
