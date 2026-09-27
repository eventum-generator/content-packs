# 1C:Enterprise Technological Log Generator

Generates synthetic 1C:Enterprise 8.3.27 **technological-log JSON** records of one `rphost` process inside an ECS envelope. The records come from fourteen client and service sessions of one infobase working in parallel. This platform diagnostic log is separate from the 1C EventJournal registration log.

## Event Types

Measured in a 5 h 10 min background-only run (`anomaly_mode: false`, 16,372 records):

| Native `name` | Share | Category | Meaning |
|---|---:|---|---|
| `SCALL` | 70.2% | Remote call | Outgoing call of the server process, for example to the lock service |
| `CALL` | 20.3% | Remote call | Incoming client call; written when the call ends, `duration` spans the whole call |
| `TLOCK` | 9.3% | Lock | Managed transaction lock; 96-99% are granted at once with empty `WaitConnections` |
| `EXCP` | 0.1% | Error | Managed-lock wait timeout exception |

The shares and rates are synthetic workload settings, not measured 1C rates. In the background-only runs, volume varied from 3,100 to 3,700 records per hour. The source profile assumes `log.format=json` and `logcfg.xml` configured to record these four event types and their selected properties. Native values are JSON strings, including `duration` in microseconds, as in the [8.3.27 specification](https://1c-dn.com/library/tutorials/1c_enterprise_administrator_guide_file_mode_8_3_27/).

## Background

Each session alternates server calls and think time (mostly seconds, sometimes minutes of pause). A call runs on a free worker thread (`OSThread`) and writes its `SCALL`, `TLOCK` and `EXCP` records in order, then its `CALL`. About one read call in a hundred is a report that runs for minutes without locks.

About a third of the calls write to the information register `InfoRg42.DIMS`. They take exclusive or shared managed locks on document keys `DOC-0031`-`DOC-0060`, some of which are much busier than others.

- **Lock requests.** A request is granted at once when it is compatible with every current holder. Otherwise it waits: `WaitConnections` names the `t:connectID` of a session whose running call holds a conflicting lock.
- **Holding.** Locks are held until the call ends or an exception rolls the transaction back.
- **Release.** When a holder releases, waiting requests are granted in arrival order if they are compatible with the remaining holders. The others go on waiting and name a remaining holder.
- **Long transactions.** Some write calls pause for about 30-60 seconds after their first lock. They are more frequent during busy periods, which alternate at random with calm ones.
- **Timeouts.** A request still waiting after 20 seconds times out: the platform writes the `TLOCK` with its 20-second wait and then the `EXCP`. Then either:
  - the code handles the exception: the transaction is rolled back and its locks released, and the operation is often retried as a new transaction;
  - or the exception ends the call after zero to two rollback `SCALL`s, and the user sometimes repeats the operation on the same document within seconds.

Background-only runs of 5 h 10 min held 17-34 timeouts (default configuration) and 5-18 in 3 h 10 min (custom configuration). Most lock holds cause no timeout, some cause one, and a few cause two to four. Across eight background-only runs (35 h), holds with 0, 1, 2, 3 and 4 timed-out sessions numbered 10,878, 122, 13, 2 and 1.

## Anomaly Chain

With `anomaly_mode: true` the generator adds a **lock convoy**: one very long write transaction that blocks a busy document key until six distinct sessions have timed out on it.

- **The blocker.** An ordinary session starts a write call and takes its lock, exclusive or shared as drawn for any write. It then holds the key for minutes: 6-22 min measured, never more than 30 min. It is released about 15 s after the sixth distinct session has timed out.
- **The key.** An exclusive blocker takes one of the two busiest keys. A shared blocker takes the busiest key, because only exclusive requests conflict with it.
- **The victims.** Nothing is forced on other sessions. The victims are ordinary requests for that key that arrive during the hold. Each waits the full 20 seconds, writes a `TLOCK` whose `WaitConnections` names the blocker, then the `EXCP`, and goes on like any other timeout.
- **Why it is rare.** Ordinary long transactions end within about a minute. Most of their holds cause no timeout, a few cause two to four. Six or more distinct timed-out sessions on one hold do not occur in the background-only runs. A Poisson estimate from their lock holds puts the natural rate at about 0.004 per day.

**Detection.** Count distinct timed-out sessions per blocking connection and key within one of its calls; six or more is a convoy. Two to five distinct timeouts on one key and blocker are partial convoys. Groups of two to four were measured in background (five is possible but was not observed); they occur at the rates above, so the order of such timeouts alone does not identify an episode. The count within one hold does. With short custom intervals, episodes take a larger part of the run, so partial-convoy counts rise accordingly.

**Recurrence.** The first episode is due `anomaly_interval_hours` after the run starts. When it is due, the idle session whose next call comes first becomes the blocker (never the previous blocker). The episode starts with its call, and the next episode is due one interval after that actual start. There is no catch-up: after a pause in input only one episode is due. Measured start delays were 0-81 s, so start times drift later.

Episodes add no records of their own, apart from the blocker's long pause and the timeouts it causes. They do change later traffic: the victims' calls fail or retry, and other requests for the key wait. `anomaly_mode` defaults to `true`; set it to `false` for background only.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
|---|---|---|
| `anomaly_mode` | `true` | Include recurring lock convoys |
| `anomaly_interval_hours` | `2` | Hours between episodes, 0.5-8760; the next episode is due one interval after the previous actual start |
| `host_name` | `onec-app-01` | Server host; also `t:computerName` of background jobs |
| `infobase` | `accounting` | Infobase name (`p:processName`) |
| `process_name` | `rphost` | 1C process |

Sessions come from `samples/sessions.json`. Each entry holds a user, client computer, `t:clientID`, `t:connectID`, `SessionID`, `SCALL` `ClientID`, application (`1CV8C`, `WebClient`, `COMConnection` or `BackgroundJob`) and a think-time factor `pace`. Edit it to change the session pool (8-64 sessions, distinct identifiers). Fewer sessions mean fewer requests per key, so episodes take longer to reach six victims.

### Output Parameters

The shipped configuration writes `output/events.json` and needs no endpoint parameters or secrets. To send events elsewhere, replace the `output` block with the desired plugin and its `${params.*}` and `${secrets.*}` placeholders.

## Usage

For a finite batch run, set `input[0].cron.start` and `input[0].cron.end`. For example, the window `2026-09-25T00:00:00+00:00` to `2026-09-25T05:10:00+00:00` produced 16,400-18,800 records, and two episodes in the default mode.

```bash
eventum generate --path generators/application-1c-techjournal/generator.yml --id onec-techjournal --live-mode false
```

For a continuous stream, leave `end` unset and use live mode:

```bash
eventum generate --path generators/application-1c-techjournal/generator.yml --id onec-techjournal --live-mode true
```

## Sample Output

The first victim's timed-out `TLOCK` in the first episode of a five-hour default run. It is synthetic, not a vendor-captured record.

```json
{"@timestamp": "2026-09-25T02:01:52.133783+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "TLOCK", "dataset": "1c.techjournal", "kind": "event", "original": "{\"ts\":\"2026-09-25T02:01:52.133783\",\"duration\":\"20003092\",\"name\":\"TLOCK\",\"depth\":\"5\",\"level\":\"INFO\",\"process\":\"rphost\",\"p:processName\":\"accounting\",\"OSThread\":\"18860\",\"t:clientID\":\"552\",\"t:applicationName\":\"1CV8C\",\"t:computerName\":\"client-11\",\"t:connectID\":\"26\",\"SessionID\":\"125\",\"Usr\":\"manager_sales01\",\"AppID\":\"1CV8C\",\"Regions\":\"InfoRg42.DIMS\",\"Locks\":\"InfoRg42.DIMS Exclusive Fld43=\\\"DOC-0046\\\"\",\"WaitConnections\":\"19\",\"Context\":\"\u0414\u043e\u043a\u0443\u043c\u0435\u043d\u0442.\u041f\u043e\u0441\u0442\u0443\u043f\u043b\u0435\u043d\u0438\u0435\u0422\u043e\u0432\u0430\u0440\u043e\u0432\u0423\u0441\u043b\u0443\u0433.\u041c\u043e\u0434\u0443\u043b\u044c\u041e\u0431\u044a\u0435\u043a\u0442\u0430 : 188 : \u0411\u043b\u043e\u043a\u0438\u0440\u043e\u0432\u043a\u0430\u0414\u0430\u043d\u043d\u044b\u0445.\u0417\u0430\u0431\u043b\u043e\u043a\u0438\u0440\u043e\u0432\u0430\u0442\u044c();\"}", "type": ["info"]}, "host": {"name": "onec-app-01"}, "one_c": {"techjournal": {"AppID": "1CV8C", "Context": "\u0414\u043e\u043a\u0443\u043c\u0435\u043d\u0442.\u041f\u043e\u0441\u0442\u0443\u043f\u043b\u0435\u043d\u0438\u0435\u0422\u043e\u0432\u0430\u0440\u043e\u0432\u0423\u0441\u043b\u0443\u0433.\u041c\u043e\u0434\u0443\u043b\u044c\u041e\u0431\u044a\u0435\u043a\u0442\u0430 : 188 : \u0411\u043b\u043e\u043a\u0438\u0440\u043e\u0432\u043a\u0430\u0414\u0430\u043d\u043d\u044b\u0445.\u0417\u0430\u0431\u043b\u043e\u043a\u0438\u0440\u043e\u0432\u0430\u0442\u044c();", "Locks": "InfoRg42.DIMS Exclusive Fld43=\"DOC-0046\"", "OSThread": "18860", "Regions": "InfoRg42.DIMS", "SessionID": "125", "Usr": "manager_sales01", "WaitConnections": "19", "depth": "5", "duration": "20003092", "level": "INFO", "name": "TLOCK", "p:processName": "accounting", "process": "rphost", "t:applicationName": "1CV8C", "t:clientID": "552", "t:computerName": "client-11", "t:connectID": "26", "ts": "2026-09-25T02:01:52.133783"}}, "process": {"name": "rphost"}, "user": {"name": "manager_sales01"}}
```

`event.original` contains the native JSON object encoded as a string; `one_c.techjournal` contains the parsed native fields. The emitted file itself is ECS JSON, so a consumer must extract `event.original` to ingest it as a native 1C JSON log.

## Limits

- **Slot cap.** Each second offers 32 record slots; a record that misses them moves to the next free slot. Measured peaks were 25-39 records per second.
- **Stationary rates.** There is no working-day or weekly cycle.
- **Sessions.** They stay connected for the whole run; session start and end records are not generated.
- **Database work.** Work inside a call is not logged (`SDBL` and `DBMSSQL` are outside the profile), so long transactions and reports show as pauses between records.
- **Timeout records.** A timed-out wait is written as `TLOCK` with a duration of about 20 seconds, then `EXCP`. `TTIMEOUT`, which 1C writes for the timeout itself, is not generated.
- **Deadlocks.** `TDEADLOCK` is not generated. Mutual waits end in two timeouts.
- **Timeout value.** The 20-second value is an assumption. It is widely reported as the default "Data lock timeout" infobase setting, but no first-party 1C statement of the default was found.
- **Depth.** `depth` is fixed per event type (`TLOCK` 5); the ITS examples show 4 and 5.
- **Synthetic configuration.** `Context` values, module names and document keys describe a synthetic configuration.
- **First episode.** It comes only after one full interval.
- **Exit code.** The CLI can exit with code 0 on render errors; check the log and the record count.

## Source and Scope

The [1C 8.3.27 Administrator Guide](https://1c-dn.com/library/tutorials/1c_enterprise_administrator_guide_file_mode_8_3_27/) defines the JSON technological-log format, event names, property meanings, and a complete 14-field `SCALL` JSON record. The field choices and lock semantics rest on three 1C ITS pages:

- the [`CALL` sample](https://its.1c.ru/db/content/metod8dev/src/developers/scalability/troubleshooting/i8105860.htm);
- the [lock investigation with `TLOCK` and `EXCP` records](https://its.1c.ru/db/content/metod8dev/src/developers/scalability/troubleshooting/i8106006.htm);
- the [managed-lock methodology](https://its.1c.ru/db/content/metod8dev/src/developers/scalability/methods/i8105809.htm).

The ITS lock records show `WaitConnections` empty for a lock granted at once, and set to the other connection for a wait of about two seconds. The exception description follows the managed-lock timeout text of the same methodology.

**BLOCKED_RAW_EVIDENCE:** complete first-party JSON records for `CALL`, `TLOCK` and `EXCP` have not been found. Their shapes follow the vendor's text examples and text-to-JSON rule; exact per-event 8.3.27 JSON field sets remain unverified. `TTIMEOUT` is documented in the event catalog but excluded, because no complete first-party raw record was found. This pack does not claim production fidelity for that event.

No Elastic integration exists for 1C (checked against the `elastic/integrations` package list, September 2026). The [KUMA 4.0 source table](https://support.kaspersky.com/kuma/4.0/en-US/255782.htm) lists a regexp normalizer for 1C TechJournal. That text normalizer's compatibility with this JSON profile is unverified; configure a parser for the JSON profile. The generator does not cover the complete technological-log catalog.
