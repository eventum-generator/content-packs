# Eltex MES Switch Syslog

Generates syslog messages of one Eltex MES5324 access switch as ECS JSON: HTTPS administrator logins, interface speed and link changes, MAC table notifications and logging configuration changes. The native message body is kept verbatim in `event.original` and `message`, in the forms of the official [MES23xx/MES33xx/MES35xx/MES5324 syslog message catalog](https://eltex.ru/storage/upload_center/files/46/MES23xx_MES33xx_MES35xx_MES5324_Log_reference.pdf). Eltex ESR router logs are a separate stream.

## Event Types

Measured on a 156-hour default capture (`anomaly_mode: true`, 8,015 events). All classes occur in both modes.

| Native class | `event.action` | Share | Category |
|---|---|---:|---|
| `BRG_MACNTFY-I-MAC_CHANGED` (`Removed`) | `mac_removed` | 41.7% | network |
| `BRG_MACNTFY-I-MAC_CHANGED` (`learnt`) | `mac_learned` | 41.7% | network |
| `LINK-W-Down` | `interface_down` | 2.6% | network |
| `LINK-W-Up` | `interface_up` | 2.6% | network |
| `AAA-I-CONNECT` | `login_accepted` | 2.4% | authentication |
| `AAA-I-DISCONNECT` | `session_terminated` | 2.4% | authentication |
| `AAA-W-REJECT` | `login_rejected` | 2.0% | authentication |
| `LINK-N-PortConfRecover` | `interface_speed_changed` | 1.8% | configuration, network |
| `SYSLOG-N-CLEARLOGGINGFILE` | `logging_file_cleared` | 1.4% | configuration |
| `SYSLOG-N-NOSYSLOGSERVER` | `syslog_server_deleted` | 0.8% | configuration |
| `SYSLOG-N-NEWSYSLOGSERVER` | `syslog_server_added` | 0.8% | configuration |

The switch has eight ports: four access uplinks (`te1/0/1`-`te1/0/4`, twelve MAC addresses each) and four dual-rate 1G/10G server ports (`te1/0/5`-`te1/0/8`, three MAC addresses each, configured for 10G). Every endpoint, port and administrator follows its own random schedule; there is no fixed period, rotation or global wave.

- **MAC table.** Each MAC address is learnt and later removed (aging) after lognormal present and absent times. A Down removes every present address of that port one by one within seconds; after Up the addresses are learnt again.
- **Links.** Ports flap on their own (Down, then Up after seconds to minutes).
- **Administrators.** Six administrators (`samples/admins.json`) log in over HTTPS with the local user table every few hours. About a third of logins start with one to four mistyped passwords a few seconds apart; some attempts are abandoned and retried later. Consecutive failures stay below the configured lockout threshold (1 to 5). A session holds zero to several operations tens of seconds apart: a speed change on a server port (1G; the link drops and half the time comes back at 1G), a port shutdown and re-enable, a logging file clear, or removal of the auxiliary syslog receiver. Changed state is restored within the session or, if the session ends first, by whichever administrator logs in next: speed back to 10G, Up, receiver re-added.

One input tick per second emits the earliest due event with its own millisecond timestamp, or nothing. Rates, durations and operation mix are synthetic workload choices, not measured Eltex production frequencies.

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the generator emits only the background above, which never holds the complete chain; every step still occurs there on its own and in partial sequences (about four runs of three or more failures by one administrator per day, followed by success, speed changes, port drops, file clears and receiver removals in ordinary sessions).

Sequence, one episode:

1. Three `AAA-W-REJECT` for one administrator and source, seconds apart.
2. `AAA-I-CONNECT` for the same user and source.
3. `LINK-N-PortConfRecover` sets a server port to 1G; `LINK-W-Down` for that port follows within seconds, then `MAC_CHANGED Removed` for its addresses.
4. `SYSLOG-N-CLEARLOGGINGFILE` clears the local logging file.
5. `SYSLOG-N-NOSYSLOGSERVER` removes the auxiliary receiver, then the session disconnects. If another administrator removed the receiver while the episode ran, the episode administrator first re-adds it (`SYSLOG-N-NEWSYSLOGSERVER`), as any administrator repairs it, then removes it.
6. Restoration follows the ordinary repair path: the next administrator to log in sets the port back to 10G (Up and relearning follow) and re-adds the receiver. Measured from about 7 minutes to about 2 hours after the episode in the final captures (earlier captures up to about 7.5 hours); the delay depends on the next administrator login.

Linking fields: `user.name` and `source.ip` for steps 1-2, `interface.name` for step 3, `observer.name` and time for the actorless configuration lines. The native configuration messages carry no user, so attribution to the preceding login is temporal only. Measured episode spans: about 1 to 7 minutes. All gaps are drawn from the same distributions as background typing and operations.

Recurrence: the first episode starts within the first `anomaly_interval_hours` or 24 hours of generation, whichever is shorter (default interval 24, minimum 6). Each later episode is due one interval after the previous actual start and starts within a window centred on that due time, a quarter of the interval wide but at most 6 hours (default: 21 to 27 hours after the previous start); every start falls inside its window. A start time is drawn uniformly in the window; from then on, each free administrator (idle, own next login more than an hour away, not the previous episode's) opens the episode at a rate proportional to the ordinary absence density at the time since its last logout, divided by the chance of its next ordinary login being more than an hour away. That rate rises over the window's last hour, and on the window's last second one of the free administrators is picked with the same weights; if none is free, the previous episode's administrator may be used, and if that is not possible either, the start waits for the first free administrator (never observed in the measured captures). If no port meets the conditions, any up port is used. The time from an administrator's logout to an episode login therefore follows the ordinary absence distribution. The background has no daily cycle, so start times are uniform over the day. Episodes that did not start are not replayed afterwards. Each episode also picks a server port that is up at 10G with a present MAC, different from the previous episode's. The episode administrator's own schedule resumes unchanged, so the episode suspends or shifts no background activity; other administrators keep working, including receiver removals, during the episode. Measured on 156-hour captures: 7 episodes at 24 hours (start gaps 26.6, 26.1, 25.1, 25.4, 22.8 and 22.8 hours), 13 per capture at 12 hours (10.6-13.4 hours). Over 72 episodes the time from the administrator's logout to the episode login matched ordinary absences (median 2.8 hours against 3.1).

Detection idea: within one hour, a run of three or more failed logins by one account followed by success, then on the same switch a port speed change, link loss and MAC removal on that port, a logging file clear and removal of a syslog destination. Each step alone, and any shorter prefix, is ordinary administration here. The only background adjustment acts on the final step: an ordinary receiver removal that would complete the whole sequence, with the first failed login at most one hour earlier, is not performed, and nothing else changes. The check stays active after an episode completes: its own sequence keeps blocking ordinary removals until its one-hour window ends, so no ordinary removal completes it a second time.

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

Administrators and endpoints come from `samples/admins.json` (user, source IP) and `samples/endpoints.json` (MAC, VLAN, port, role `access` or `server`). The generator needs at least two administrators and two `server` ports for episode rotation.

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

Batch mode, as fast as possible (the cron input runs until stopped unless `start` and `end` are set on it):

```bash
eventum generate --path generators/network-eltex-mes/generator.yml --id mes --live-mode false
```

## Sample Output

An episode's first failed login, copied from the final default capture (line 217):

```json
{"@timestamp": "2026-09-20T02:12:41.653+00:00", "destination": {"ip": "10.40.0.11"}, "ecs": {"version": "8.17.0"}, "eltex": {"mes": {"component": "AAA", "details": {"connection": {"auth_method": "local user table", "type": "https"}}, "mnemonic": "REJECT", "severity_code": "W"}}, "event": {"action": "login_rejected", "category": ["authentication"], "dataset": "eltex.mes.syslog", "kind": "event", "module": "eltex", "original": "AAA-W-REJECT: New https connection for user i.petrov, source 10.40.1.31 destination 10.40.0.11, local user table REJECTED.", "outcome": "failure", "type": ["start", "denied"]}, "log": {"level": "warning"}, "message": "AAA-W-REJECT: New https connection for user i.petrov, source 10.40.1.31 destination 10.40.0.11, local user table REJECTED.", "observer": {"hostname": "mes-access-01", "ip": ["10.40.0.11"], "model": "MES5324", "name": "mes-access-01", "product": "MES", "type": "switch", "vendor": "Eltex"}, "source": {"ip": "10.40.1.31"}, "user": {"name": "i.petrov"}}
```

## Limitations

- The catalog carries no firmware version and shows message bodies only. No syslog priority, timestamp, hostname or transport framing is emitted; `@timestamp` is the synthetic event time. `observer.model`, the inventory and the parsed `eltex.mes.details` fields are normalization, not source fields.
- The catalog gives a complete example of `Removed` only; the learning form uses the parameter value `learnt` from the catalog table, so its exact capitalization in a live record is unconfirmed. The catalog labels `Up` Informational while its example uses `LINK-W-Up`; the example is followed.
- Only HTTPS logins are modeled. The link drop after a speed change, the flush of MAC notifications on Down and aging-driven removals are modeled behavior, not documented event timing.
- Configuration lines (speed, file clear, receiver) name no user; which session made them is not in the source.
- No live capture, exact-build trace or maintained Elastic integration for Eltex MES was available for comparison.

## References

- [MES23xx/MES33xx/MES35xx/MES5324 syslog message catalog](https://eltex.ru/storage/upload_center/files/46/MES23xx_MES33xx_MES35xx_MES5324_Log_reference.pdf)
- [MES series operation manual 4.0.27.3](https://eltex.ru/storage/upload_center/files/60/MES_Series_user_manual_4.0.27.3.pdf) - password lockout after 1-5 consecutive failures, SFP+ 1G/10G, `logging host`, MAC aging 300 s
- [MES2324 downloads](https://eltex.ru/download/mes2324/)
