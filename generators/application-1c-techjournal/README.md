# 1C:Enterprise Technological Log Generator

Generates synthetic 1C:Enterprise 8.3.27 **technological-log JSON** records of one `rphost` process inside an ECS envelope. The records come from fourteen client and service sessions of one infobase working in parallel. This platform diagnostic log is separate from the 1C EventJournal registration log.

## Volume and Timing

About 44,000 records per day (±3% from day to day), following a working day in UTC:

| Hours (UTC) | Interactive sessions | Background jobs | All records |
|---|---:|---:|---:|
| 09:00-13:00, 14:00-17:00 | about 47 per minute | about 12 per minute | about 58 per minute |
| 08:00-09:00, 13:00-14:00, 17:00-18:00 | about 29 per minute | about 11 per minute | about 40 per minute |
| 07:00-08:00, 18:00-20:00 | about 11 per minute | about 10 per minute | about 21 per minute |
| 20:00-07:00 | about 2.5 per minute | about 10 per minute | about 13 per minute |

Interactive sessions are the users of the `1CV8C`, `1CV8` and `WebClient` clients: at night they make about 5% of their daytime calls. The background jobs `batch_admin` (`BackgroundJob`) and `exchange_service` (`COMConnection`) work around the clock at nearly the same rate. Each record carries the time of the operation it describes: the records of one server call follow each other within milliseconds, and a lock wait, a transaction or a timeout spans exactly the time its `duration` states.

## Event Types

Shares in ten days of background-only output (`anomaly_mode: false`):

| Native `name` | Share | Category | Meaning |
|---|---:|---|---|
| `SCALL` | 67% | Remote call | Outgoing call of the server process, for example to the lock service |
| `CALL` | 18% | Remote call | Incoming client call; written when the call ends, `duration` spans the whole call |
| `TLOCK` | 14% | Lock | Managed transaction lock; about 95% are granted at once with empty `WaitConnections` |
| `EXCP` | 0.3% | Error | Managed-lock wait timeout exception |

The `TLOCK` and `EXCP` shares vary from day to day with the posting workload.

The shares and rates are synthetic workload settings, not measured 1C rates. The source profile assumes `log.format=json` and `logcfg.xml` configured to record these four event types and their selected properties. Native values are JSON strings, including `duration` in microseconds, as in the [8.3.27 specification](https://1c-dn.com/library/tutorials/1c_enterprise_administrator_guide_file_mode_8_3_27/).

## Background

Each session alternates server calls and think time (mostly seconds, sometimes minutes of pause). Interactive users pause far longer outside office hours, so their calls follow the working day; the background jobs keep the same pace day and night. A call runs on a free worker thread (`OSThread`) and writes its `SCALL`, `TLOCK` and `EXCP` records in order, then its `CALL`. About one read call in a hundred is a report that runs for minutes without locks.

Write calls take exclusive or shared managed locks on document keys `DOC-0031`-`DOC-0060` of the information register `InfoRg42.DIMS`; some keys are much busier than others. Most users write in about 40% of their calls; `auditor` and `hr_specialist` only read.

- **Lock requests.** A request is granted at once when it is compatible with every current holder. Otherwise it waits: `WaitConnections` names the `t:connectID` of a session whose running call holds a conflicting lock.
- **Holding.** Locks are held until the call ends or an exception rolls the transaction back.
- **Release.** When a holder releases, waiting requests are granted in arrival order if they are compatible with the remaining holders. The others go on waiting and name a remaining holder.
- **Postings.** Four sessions post documents: the background job `batch_admin`, the data exchange `exchange_service`, and `storekeeper01` and `storekeeper02`. They write in 75-80% of their calls and hold their first lock while the posting runs: about 10 seconds for an ordinary posting, 35-75 seconds for a long one, and a few minutes for one long posting in ten (a large document). Long postings are more frequent in busy periods, which alternate at random with calm ones, and on busy days: the posting workload differs from day to day. Waits of other sessions therefore name mostly these four connections.
- **Timeouts.** A request still waiting after 20 seconds times out: the platform writes the `TLOCK` with its 20-second wait and then the `EXCP`. Then either:
  - the code handles the exception: the transaction is rolled back and its locks released, and the operation is often retried as a new transaction;
  - or the exception ends the call after zero to two rollback `SCALL`s, and the user sometimes repeats the operation on the same document within seconds.

Timeouts average about 120-150 per day, about 1.7% of calls and 2% of lock requests, and vary with the day's posting workload, from under 100 to over 250 per day. They follow the working day: about 8 to 16 per hour from 09:00 to 17:00, and one to two per hour at night, where most are background jobs waiting on each other. Most lock holds cause no timeout; a long posting sometimes times out one to three sessions, and a posting of a few minutes rarely four or five. At most five distinct sessions time out on one key naming one connection within 50 minutes.

## Anomaly Chain

With `anomaly_mode: true` the generator adds a **lock convoy**: one very long posting that blocks a busy document key until six distinct sessions have timed out on it within 50 minutes.

- **The blocker.** The first of the four posting sessions to start a call at the episode's time, never the blocker of the previous episode, starts a write call and takes its lock, exclusive or shared as drawn for any write. The busier posting sessions therefore block more often, as they post more in the background. It then holds the key until the sixth distinct session has timed out, and releases it about 15 seconds later: from about two minutes to about half an hour, typically about 11 minutes in the default configuration. Requests for the key in those last seconds, including an immediate retry of the sixth session, wait for the release; none of them times out naming the blocker.
- **The key.** An exclusive blocker takes one of the two busiest keys, a shared blocker the busiest key, because only exclusive requests conflict with it. If the key is taken when the blocker requests it, the blocker takes a free key among the five busiest.
- **The victims.** Nothing is forced on other sessions. The victims are ordinary requests for that key that arrive during the hold. Each waits the full 20 seconds, writes a `TLOCK` whose `WaitConnections` names the blocker, then the `EXCP`, and goes on like any other timeout.

**Detection.** Count distinct timed-out sessions per blocking connection and key within 50 minutes; six is a convoy. Groups of two to five distinct timeouts on one key and connection are common in the background, from long postings, so the order and number of timeouts below six does not identify an episode. Each episode adds its own records on top of the background, so there are about six more timeouts and about one more timeout group of two to five per episode with `anomaly_mode: true`; with short custom intervals the difference grows accordingly.

**Recurrence.** A convoy needs many working users, so episodes start only between 08:00 and 17:00 UTC. The first episode starts within `min(anomaly_interval_hours, 24 h)` of the run start, at a time weighted by the interactive activity of each hour. Each later one starts within ±w/2 of its due time, one interval after the previous actual start, where w = min(interval / 4, 6 h), at a time weighted by the square of that activity. A window with no hour between 08:00 and 17:00 has no episode, and the next one is due one interval after it. The episode starts with the next posting session's call after that time, usually within seconds. There is no catch-up: after a pause only one episode is due. With the default two-hour interval there are four or five episodes per day, the first soon after 08:00 and the next ones a little over two hours apart, and none at night.

`anomaly_mode` defaults to `true`; set it to `false` for background only.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
|---|---|---|
| `anomaly_mode` | `true` | Include recurring lock convoys |
| `anomaly_interval_hours` | `2` | Hours between episodes, 0.5-8760; the next episode is due one interval after the previous actual start, and episodes fall between 08:00 and 17:00 UTC |
| `host_name` | `onec-app-01` | Server host; also `t:computerName` of background jobs |
| `infobase` | `accounting` | Infobase name (`p:processName`) |
| `process_name` | `rphost` | 1C process |

Sessions come from `samples/sessions.json`. Each entry holds a user, client computer, `t:clientID`, `t:connectID`, `SessionID`, `SCALL` `ClientID`, application (`1CV8C`, `1CV8` and `WebClient` sessions follow office hours, `COMConnection` and `BackgroundJob` sessions work around the clock), a think-time factor `pace`, the share of write calls `writes` (0-1) and a long-posting factor `long_tx` (0-1; 0 for sessions that never post for long). Edit it to change the session pool (8-64 sessions, distinct identifiers); at least one session needs `long_tx` above 0 for episodes to occur.

### Output Parameters

The shipped configuration writes `output/events.json` and needs no endpoint parameters or secrets. To send events elsewhere, replace the `output` block with the desired plugin and its `${params.*}` and `${secrets.*}` placeholders.

## Usage

Continuous stream in live mode (a record carries the time of the operation it describes and is written usually one to two minutes later):

```bash
eventum generate --path generators/application-1c-techjournal/generator.yml --id onec-techjournal --live-mode true
```

For a finite batch, set `start` and `end` of the `oscillator` in every file under `patterns/`, with `start` at midnight UTC so that the office hours stay in place (for example `start: "2026-09-14T00:00:00+00:00"` and `end: "2026-09-17T00:00:00+00:00"`, which gives about 132,000 records and 15 episodes in the default mode), then run:

```bash
eventum generate --path generators/application-1c-techjournal/generator.yml --id onec-techjournal --live-mode false
```

Performance: about 2,400 records per second in batch mode on one core (14 days, 616,792 records, in 256 s of CPU time).

## Sample Output

The first victim's timed-out `TLOCK` of the first episode in three days of default output. It is synthetic, not a vendor-captured record.

```json
{"@timestamp": "2026-09-14T08:03:32.989296+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "TLOCK", "dataset": "1c.techjournal", "kind": "event", "original": "{\"ts\":\"2026-09-14T08:03:32.989296\",\"duration\":\"20000235\",\"name\":\"TLOCK\",\"depth\":\"5\",\"level\":\"INFO\",\"process\":\"rphost\",\"p:processName\":\"accounting\",\"OSThread\":\"23200\",\"t:clientID\":\"552\",\"t:applicationName\":\"1CV8C\",\"t:computerName\":\"client-11\",\"t:connectID\":\"26\",\"SessionID\":\"125\",\"Usr\":\"manager_sales01\",\"AppID\":\"1CV8C\",\"Regions\":\"InfoRg42.DIMS\",\"Locks\":\"InfoRg42.DIMS Exclusive Fld43=\\\"DOC-0031\\\"\",\"WaitConnections\":\"16\",\"Context\":\"\u0414\u043e\u043a\u0443\u043c\u0435\u043d\u0442.\u0420\u0435\u0430\u043b\u0438\u0437\u0430\u0446\u0438\u044f\u0422\u043e\u0432\u0430\u0440\u043e\u0432\u0423\u0441\u043b\u0443\u0433.\u041c\u043e\u0434\u0443\u043b\u044c\u041e\u0431\u044a\u0435\u043a\u0442\u0430 : 214 : \u0411\u043b\u043e\u043a\u0438\u0440\u043e\u0432\u043a\u0430\u0414\u0430\u043d\u043d\u044b\u0445.\u0417\u0430\u0431\u043b\u043e\u043a\u0438\u0440\u043e\u0432\u0430\u0442\u044c();\"}", "type": ["info"]}, "host": {"name": "onec-app-01"}, "one_c": {"techjournal": {"AppID": "1CV8C", "Context": "\u0414\u043e\u043a\u0443\u043c\u0435\u043d\u0442.\u0420\u0435\u0430\u043b\u0438\u0437\u0430\u0446\u0438\u044f\u0422\u043e\u0432\u0430\u0440\u043e\u0432\u0423\u0441\u043b\u0443\u0433.\u041c\u043e\u0434\u0443\u043b\u044c\u041e\u0431\u044a\u0435\u043a\u0442\u0430 : 214 : \u0411\u043b\u043e\u043a\u0438\u0440\u043e\u0432\u043a\u0430\u0414\u0430\u043d\u043d\u044b\u0445.\u0417\u0430\u0431\u043b\u043e\u043a\u0438\u0440\u043e\u0432\u0430\u0442\u044c();", "Locks": "InfoRg42.DIMS Exclusive Fld43=\"DOC-0031\"", "OSThread": "23200", "Regions": "InfoRg42.DIMS", "SessionID": "125", "Usr": "manager_sales01", "WaitConnections": "16", "depth": "5", "duration": "20000235", "level": "INFO", "name": "TLOCK", "p:processName": "accounting", "process": "rphost", "t:applicationName": "1CV8C", "t:clientID": "552", "t:computerName": "client-11", "t:connectID": "26", "ts": "2026-09-14T08:03:32.989296"}}, "process": {"name": "rphost"}, "user": {"name": "manager_sales01"}}
```

`event.original` contains the native JSON object encoded as a string; `one_c.techjournal` contains the parsed native fields. The emitted file itself is ECS JSON, so a consumer must extract `event.original` to ingest it as a native 1C JSON log.

## Limits

- **Workload.** Every day follows the same working-day curve in UTC, weekends included; there is no weekly cycle, no holidays and no time-zone offset. Busy and calm periods and the day-to-day posting workload vary at random.
- **Sessions.** They stay connected for the whole run; session start and end records are not generated.
- **Database work.** Work inside a call is not logged (`SDBL` and `DBMSSQL` are outside the profile), so postings and reports show as pauses between records.
- **Timeout records.** A timed-out wait is written as `TLOCK` with a duration of about 20 seconds, then `EXCP`. `TTIMEOUT`, which 1C writes for the timeout itself, is not generated.
- **Deadlocks.** `TDEADLOCK` is not generated. Mutual waits end in two timeouts.
- **Timeout value.** The 20-second value is an assumption. It is widely reported as the default "Data lock timeout" infobase setting, but no first-party 1C statement of the default was found.
- **Wait connections.** `WaitConnections` names one connection, even when several hold a conflicting lock.
- **Depth.** `depth` is fixed per event type (`TLOCK` 5); the ITS examples show 4 and 5.
- **Synthetic configuration.** `Context` values, module names and document keys describe a synthetic configuration.
- **Episode records.** With `anomaly_mode: true` each episode adds its own six timeouts, so counts of timeouts and of timeout groups on one key and connection are about one per episode higher than with `anomaly_mode: false`.
- **Convoy size.** Six distinct sessions timed out on one key naming one connection within 50 minutes occur only with `anomaly_mode: true`, once per episode; without episodes such groups stop at five.
- **After a convoy.** Within 30 minutes after a convoy's blocker releases the key, a request waits on that connection for that key in about 5% of cases; after an ordinary group of two or more timeouts, in about 40%.

## Source and Scope

The [1C 8.3.27 Administrator Guide](https://1c-dn.com/library/tutorials/1c_enterprise_administrator_guide_file_mode_8_3_27/) defines the JSON technological-log format, event names, property meanings, and a complete 14-field `SCALL` JSON record. The field choices and lock semantics rest on three 1C ITS pages:

- the [`CALL` sample](https://its.1c.ru/db/content/metod8dev/src/developers/scalability/troubleshooting/i8105860.htm);
- the [lock investigation with `TLOCK` and `EXCP` records](https://its.1c.ru/db/content/metod8dev/src/developers/scalability/troubleshooting/i8106006.htm);
- the [managed-lock methodology](https://its.1c.ru/db/content/metod8dev/src/developers/scalability/methods/i8105809.htm).

The ITS lock records show `WaitConnections` empty for a lock granted at once, and set to the other connection for a wait of about two seconds. The exception description follows the managed-lock timeout text of the same methodology.

Complete first-party JSON records for `CALL`, `TLOCK` and `EXCP` have not been found. Their shapes follow the vendor's text examples and text-to-JSON rule; exact per-event 8.3.27 JSON field sets remain unverified. `TTIMEOUT` is documented in the event catalog but excluded, because no complete first-party raw record was found. This pack does not claim production fidelity for that event.

No Elastic integration exists for 1C (checked against the `elastic/integrations` package list, September 2026). The [KUMA 4.0 source table](https://support.kaspersky.com/kuma/4.0/en-US/255782.htm) lists a regexp normalizer for 1C TechJournal. That text normalizer's compatibility with this JSON profile is unverified; configure a parser for the JSON profile. The generator does not cover the complete technological-log catalog.
