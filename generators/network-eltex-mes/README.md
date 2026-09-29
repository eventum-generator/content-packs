# Eltex MES Switch Syslog

Generates syslog messages of one Eltex MES5324 access switch as ECS JSON: HTTPS logins of administrators and automation accounts, interface speed and link changes, MAC table notifications and logging configuration changes. The native message body is kept verbatim in `event.original` and `message`, in the forms of the official [MES23xx/MES33xx/MES35xx/MES5324 syslog message catalog](https://eltex.ru/storage/upload_center/files/46/MES23xx_MES33xx_MES35xx_MES5324_Log_reference.pdf). Eltex ESR router logs are a separate stream.

## Volume and Timing

About 900 messages an hour (±5% from hour to hour) at random moments around the clock; the switch has no daily cycle. MAC table notifications make up almost all of them. Messages the switch writes at one moment (a Down and the MAC removals it causes, a speed change and the link drop that follows) appear in order a few seconds apart (median 2.8 s between consecutive messages).

## Event Types

Typical shares with the default settings (`anomaly_mode: true`). All classes also occur with `anomaly_mode: false`.

| Native class | `event.action` | Share | Category |
|---|---|---:|---|
| `BRG_MACNTFY-I-MAC_CHANGED` (`Removed`) | `mac_removed` | 48.79% | network |
| `BRG_MACNTFY-I-MAC_CHANGED` (`learnt`) | `mac_learned` | 48.77% | network |
| `AAA-I-CONNECT` | `login_accepted` | 0.89% | authentication |
| `AAA-I-DISCONNECT` | `session_terminated` | 0.89% | authentication |
| `LINK-W-Down` | `interface_down` | 0.19% | network |
| `LINK-W-Up` | `interface_up` | 0.19% | network |
| `LINK-N-PortConfRecover` | `interface_speed_changed` | 0.11% | configuration, network |
| `AAA-W-REJECT` | `login_rejected` | 0.09% | authentication |
| `SYSLOG-N-CLEARLOGGINGFILE` | `logging_file_cleared` | 0.04% | configuration |
| `SYSLOG-N-NOSYSLOGSERVER` | `syslog_server_deleted` | 0.02% | configuration |
| `SYSLOG-N-NEWSYSLOGSERVER` | `syslog_server_added` | 0.02% | configuration |

The switch has 24 ports: twenty access ports (`te1/0/1`-`te1/0/4`, `te1/0/9`-`te1/0/24`, 64 MAC addresses each) and four dual-rate 1G/10G server ports (`te1/0/5`-`te1/0/8`, three MAC addresses each, configured for 10G). Every endpoint, port and administrator follows its own random schedule; there is no fixed period, rotation or global wave.

- **MAC table.** Each MAC address is learnt and later removed (aging) after lognormal present and absent times. A Down removes every present address of that port one by one; after Up the addresses are learnt again.
- **Links.** Ports flap on their own (Down, then Up after seconds to minutes); administrators also shut ports down and re-enable them.
- **Automation.** Two service accounts log in over HTTPS from their own addresses and change nothing: `nms-backup` fetches the configuration about every hour, `nms-poll` polls status about every ten minutes (each cycle a few percent early or late). They make up most logins and almost never fail.
- **Administrators.** Six people-facing accounts log in over HTTPS (`samples/admins.json`). The two shared accounts `admin` and `noc-duty` are used by several NOC engineers and log in about every one and a half hours each; the four personal accounts log in about twice a day. Mistyped passwords come mostly from the shared accounts, on every day, since not every engineer has the current password at hand; a single failure is the most common, and each longer run (up to four in a row) is rarer than the one before, so a few runs of three or four failures occur even on quiet days. Personal accounts seldom mistype. Consecutive failures stay below a lockout threshold of 5 (the switch allows 1 to 5). An ordinary session changes something only now and then, usually a port shutdown and re-enable, sometimes a speed change on a server port (1G; the link drops and half the time comes back at 1G), a logging file clear or removal of the auxiliary syslog receiver. Changed state is restored within the session or, if the session ends first, by whichever administrator logs in next: speed back to 10G, Up, receiver re-added.
- **Change days.** About three days in ten carry planned work. On such a day most shared-account sessions are change sessions: the shared password has just been rotated, so the login often starts with mistyped passwords, and the session sets a server port to 1G, clears the logging file and removes the auxiliary receiver, usually in that order, before the changes are restored. On other days such sessions are rare.

Typical daily counts without episodes:

| Day | Share of days | Logins | Failed logins | 3+ failures of one account within 1 h | Speed changes | File clears | Receiver removals |
|---|---:|---:|---:|---:|---:|---:|---:|
| Change day | about 3 in 10 | 182 | 26 | 4.7 | 37 | 15 | 9 |
| Other day | about 7 in 10 | 185 | 12 | 2.2 | 9 | 1.7 | 1.1 |

Rates, durations and operation mix are synthetic workload choices, not measured Eltex production frequencies.

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the generator emits only the background above, which never holds the complete chain; every step still occurs there on its own and in partial sequences, mostly in change sessions.

Sequence, one episode:

1. Three `AAA-W-REJECT` for one shared account and source, seconds apart.
2. `AAA-I-CONNECT` for the same user and source.
3. `LINK-N-PortConfRecover` sets a server port to 1G; `LINK-W-Down` for that port follows within seconds, then `MAC_CHANGED Removed` for its addresses.
4. `SYSLOG-N-CLEARLOGGINGFILE` clears the local logging file.
5. `SYSLOG-N-NOSYSLOGSERVER` removes the auxiliary receiver, then the session disconnects. If another administrator removed the receiver while the episode ran, the episode administrator first re-adds it (`SYSLOG-N-NEWSYSLOGSERVER`), then removes it.
6. Restoration follows the same rules as ordinary changes: the port is set back to 10G (Up and relearning follow) and the receiver re-added either within the same session, sometimes before the file clear, or by the next administrator to log in, usually minutes to about two hours later.

Linking fields: `user.name` and `source.ip` for steps 1-2, `interface.name` for step 3, `observer.name` and time for the actorless configuration lines. The native configuration messages carry no user, so attribution to the preceding login is temporal only. An episode spans about two to fifteen minutes; its gaps follow the same distributions as background typing and operations.

Actors and targets: the episode account normally alternates between the two shared accounts, and its port is a server port up at 10G, different from the previous episode's and, when possible, one the same account changed in the previous three days. The time from the account's previous logout to the episode login follows that account's ordinary absence. An episode is one extra session: no ordinary login, failure or change of any administrator is removed or moved because of it.

Recurrence: the first episode starts within the first `anomaly_interval_hours` or 24 hours, whichever is shorter (default interval 24, minimum 6). Each later episode starts one interval after the previous start, within a window a quarter of the interval wide but at most 6 hours, centred on that time (default: 21 to 27 hours after the previous start). If no shared account or server port is free within the window, that episode is skipped and not made up later. Start times fall at any hour of the day, like administrator activity.

An episode usually starts when no speed change happened on the switch in the previous hour and none is under way, so its receiver removal mostly follows its own port change only; late in its window it starts regardless.

Detection idea: within one hour, a run of three or more failed logins by one account followed by success, then on the same switch a port speed change, link loss and MAC removal on that port, a logging file clear and removal of a syslog destination. Each step alone, and every shorter part of the sequence, is ordinary administration here. The background never removes the receiver when that would complete the whole sequence within the hour; the removal is left out and nothing else changes.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Description |
|---|---|---|
| `switch_name` | `mes-access-01` | Switch name in `observer.name` and `observer.hostname` |
| `switch_ip` | `10.40.0.11` | Switch address; destination of administrator logins |
| `syslog_server_ip` | `10.40.0.12` | Auxiliary syslog receiver removed and re-added; the collector receiving this stream is a second destination that is never changed |
| `anomaly_mode` | `true` | Include periodic anomaly episodes; `false` gives background only |
| `anomaly_interval_hours` | `24` | Hours between episode starts; 6 to 8760, smaller values fail validation |

Accounts and endpoints come from `samples/admins.json` (user, source IP, `shared` for accounts used by several engineers, `period` in seconds for automation accounts, 0 for people; every account logs in over HTTPS) and `samples/endpoints.json` (MAC, VLAN, port, role `access` or `server`). Episodes need at least two shared accounts and two `server` ports.

### Output Parameters

The shipped output writes `output/events.json` and needs no credentials. To send events elsewhere, replace the output and pass values through top-level placeholders, for example:

```yaml
output:
  - opensearch:
      hosts:
        - ${params.opensearch_host}
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: eltex-mes
```

A collector that expects the native syslog body should read `event.original`.

## Usage

Live mode:

```bash
eventum generate --path generators/network-eltex-mes/generator.yml --id mes --live-mode true
```

Batch generation: `patterns/switch.yml` runs from today's midnight without an end. Set `start` and `end` of its `oscillator` to a finite range (for example `start: "2026-09-01T00:00:00Z"` and `end: "2026-09-08T00:00:00Z"`), then run:

```bash
eventum generate --path generators/network-eltex-mes/generator.yml --id mes --live-mode false --keep-order true
```

To change the volume, scale `ratio` in `patterns/switch.yml` and the number of access endpoints in `samples/endpoints.json` by the same factor, so MAC aging keeps pace with the message rate.

## Performance

About 2,200 to 4,800 events per second on one core, depending on machine load: a 14-day default run (about 300,000 events) takes 1 to 2.5 minutes of CPU time.

## Sample Output

An episode's first failed login, from a default run:

```json
{"@timestamp": "2026-09-02T21:18:31.319+00:00", "destination": {"ip": "10.40.0.11"}, "ecs": {"version": "8.17.0"}, "eltex": {"mes": {"component": "AAA", "details": {"connection": {"auth_method": "local user table", "type": "https"}}, "mnemonic": "REJECT", "severity_code": "W"}}, "event": {"action": "login_rejected", "category": ["authentication"], "dataset": "eltex.mes.syslog", "kind": "event", "module": "eltex", "original": "AAA-W-REJECT: New https connection for user noc-duty, source 10.40.1.12 destination 10.40.0.11, local user table REJECTED.", "outcome": "failure", "type": ["start", "denied"]}, "log": {"level": "warning"}, "message": "AAA-W-REJECT: New https connection for user noc-duty, source 10.40.1.12 destination 10.40.0.11, local user table REJECTED.", "observer": {"hostname": "mes-access-01", "ip": ["10.40.0.11"], "model": "MES5324", "name": "mes-access-01", "product": "MES", "type": "switch", "vendor": "Eltex"}, "source": {"ip": "10.40.1.12"}, "user": {"name": "noc-duty"}}
```

## Limitations

- The catalog carries no firmware version and shows message bodies only. No syslog priority, timestamp, hostname or transport framing is emitted; `@timestamp` is the synthetic event time. `observer.model`, the inventory and the parsed `eltex.mes.details` fields are normalization, not source fields.
- The catalog gives a complete example of `Removed` only; the learning form uses the parameter value `learnt` from the catalog table, so its exact capitalization in a live record is unconfirmed. The catalog labels `Up` Informational while its example uses `LINK-W-Up`; the example is followed.
- All logins are HTTPS; console, Telnet and SSH sessions are not modeled (the catalog has no `AAA-I-CONNECT` form for SSH). The link drop after a speed change, the flush of MAC notifications on Down and aging-driven removals are modeled behavior, not documented event timing.
- Messages the switch writes within milliseconds of each other appear seconds apart: a speed change is followed by its Down after a median of 3.0 s, and the MAC removals after a Down of an access port take a median of 3.3 minutes for about 49 addresses.
- Configuration lines (speed, file clear, receiver) name no user; which session made them is not in the source.
- Configuration work clusters on change days, which are frequent (about three in ten) and carry most speed changes, file clears and receiver removals and about twice the daily rate of mistyped-password runs; about 8% of login attempts fail (about 12% on change days, about 6% on other days).
- With `anomaly_mode: true` each episode adds its own records, so counts of the chain parts (runs of three failures followed by success, speed change - link loss - file clear - receiver removal sequences) are about one per episode higher than in background-only data.
- The switch has no daily cycle; administrators and episodes are active at any hour.
- No live capture, exact-build trace or maintained Elastic integration for Eltex MES was available for comparison.

## References

- [MES23xx/MES33xx/MES35xx/MES5324 syslog message catalog](https://eltex.ru/storage/upload_center/files/46/MES23xx_MES33xx_MES35xx_MES5324_Log_reference.pdf)
- [MES series operation manual 4.0.27.3](https://eltex.ru/storage/upload_center/files/60/MES_Series_user_manual_4.0.27.3.pdf) - password lockout after 1-5 consecutive failures, SFP+ 1G/10G, `logging host`, MAC aging 300 s
- [MES2324 downloads](https://eltex.ru/download/mes2324/)
