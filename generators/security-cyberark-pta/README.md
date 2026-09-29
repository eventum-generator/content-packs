# CyberArk Privileged Threat Analytics CEF

Synthetic CyberArk Privileged Threat Analytics (PTA) security events as PTA sends them to a SIEM over syslog in CEF, for SIEM parsing and correlation testing. Each line is the ECS JSON document that the Elastic `cyberark_pta` integration builds from one CEF record; the CEF record itself is in `event.original`.

The generator models one PTA server that watches one Vault: 120 Vault users, 163 privileged accounts on target machines, and 97 administrator workstations and jump hosts that connect to those machines.

## Event types

| CEF class | Native alert | Severity | Share | Category |
| --- | --- | --- | --- | --- |
| `23` | Privileged access to the Vault during irregular hours | 2 | 60.3% | Vault access |
| `1` | Suspected credentials theft | 8 | 27.5% | Credential use outside the Vault |
| `26` | Active dormant Vault user | 5 | 12.2% | Vault access |

Shares are for 14 days of the default configuration: about 490 alerts on a weekday and 405 on a weekend day. Every alert is a PTA detection, so even the background is a stream of alerts, not benign activity.

## Volume and timing

Hours are UTC.

- Irregular-hours alerts peak in the evening (about 26 an hour at 20:00 on weekdays and 32 at weekends, over 15 an hour 18:00-22:00), with a smaller early-morning peak (about 14 an hour at 06:00) and 3-4 an hour after midnight. In office hours about 11 an hour come from users whose usual hours differ. On Saturdays and Sundays about 8 an hour more arrive between 08:00 and 22:00.
- Credential-theft and dormant-user alerts follow the working day on weekdays: about 10-13 theft alerts and 4-6 dormant-user alerts an hour between 08:00 and 18:00, about 1 an hour or fewer at night, and 3-5 theft alerts an hour through the weekend day.
- Activity is uneven across actors. Fourteen on-call administrators raise about 40% of the irregular-hours alerts (about 7-8 a day each) and about 64% of the dormant-user alerts; six administrator workstations whose owners connect with known passwords raise about 22% of the theft alerts (4-5 a day each). Other users raise about ten alerts a week at the median, and most other workstations a few.

Incidents vary in shape: single alerts; repeats by the same actor minutes later (an irregular-hours access repeated on the same or another account, a workstation reusing the account); and every two-alert part of the anomaly chain - a dormant user that then accesses the same account at an irregular hour a few minutes later (in the evening or at night), an irregular-hours access followed by a credential-theft alert on that account 5-60 minutes later, and a dormant-user alert followed by credential theft.

## Anomaly Chain

With `anomaly_mode: true` (the default), an episode is a three-alert sequence on one privileged account:

1. `26` Active dormant Vault user - Vault user V (`suser=<name>(Vault user)`) resurfaces on account A (`duser`, `dhost`, `dst`).
2. `23` Privileged access to the Vault during irregular hours - the same V on the same A, usually 1-9 minutes later and occasionally up to about 18; sometimes repeated.
3. `1` Suspected credentials theft - a single alert from a workstation or jump host (`suser`, `shost`, `src`) that normally uses A, typically 3-70 minutes after the last irregular-hours alert.

Linking fields: `destinationUserName` (`duser`) across all three alerts; `sourceUserName` (`suser`) between the first two. An episode usually spans under an hour; the detection window below is four hours.

Recurrence: `anomaly_interval_hours` (default 24, minimum 6) sets the spacing of episode starts. The first episode starts within the first `min(interval, 24 h)` of the data, at an hour drawn with the curve of background dormant-then-irregular incidents (evenings, nights and weekend afternoons). Each next episode is due one interval after the previous episode's start and starts within a window of `w = min(interval / 4, 6 h)` around the due time, weighted by the square of that curve plus a small floor, so any hour stays possible. Consecutive starts are therefore about interval ± w/2 apart: 21-27 h at the default 24 h, with starts between about 18:00 and 23:00, and 7-9 h at 8 h. Missed intervals are not caught up.

Variation: V, A and the workstation are drawn by their background frequency among the combinations that ordinary alerts carry often: in any four days of background, V raises several dormant-user alerts and about ten or more alerts on A, and the workstation about ten or more theft alerts on A. Every user, account, workstation, user-account pair and workstation-account pair of an episode therefore also occurs in ordinary alerts. Neither V nor A repeats between consecutive episodes. EventIDs, links and timings are drawn fresh for every alert.

Detection idea: per `duser`, raise when a dormant-user alert and an irregular-hours alert by the same Vault user are followed within four hours by a credential-theft alert on that account. Each alert on its own, and each pair of them, is ordinary here.

With `anomaly_mode: false`, the data holds only background: the same alerts, actors, volumes and partial sequences, without the complete three-alert sequence. The full sequence is also kept out of the background in anomaly mode: a background credential-theft alert that would complete it - within four hours of the dormant-user alert that opens it, the same window as the detection idea - names another account that the same workstation normally uses and that would not complete the sequence; when the workstation uses no such account, the alert is absent (about 1.5-3% of theft alerts). Its time and workstation stay, and a theft alert on that account more than four hours after the dormant-user alert is raised as usual.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Description |
| --- | --- | --- |
| `anomaly_mode` | `true` | Add recurring anomaly episodes to the background |
| `anomaly_interval_hours` | `24` | Hours between episode starts; at least 6 |
| `pta_version` | `12.0` | Version in the CEF header, `cef.device.version` and `observer.version` |
| `pvwa_host` | `pvwa.corp.example.test` | PVWA host in the PTA event link (`cs3`) |

Users, accounts and workstations come from three files under `samples/`:

- `vault_users.csv` - `user`, `weight` (relative alert activity; the on-call tier has 9) and `accounts` (the privileged accounts the user normally accesses, space-separated).
- `accounts.csv` - `account`, `host` and `ip` of each privileged account.
- `sources.csv` - `user` (`login@host`), `host`, `ip`, `weight` (relative theft-alert activity; the six busiest workstations have 6) and `accounts` (the accounts the workstation normally connects to).

Episodes use only frequent user-account-workstation combinations; if edited files leave none, the most frequent ones are used.

### Output Parameters

The shipped `generator.yml` writes JSON Lines to `output/events.json` and defines no top-level `params` or `secrets`. To deliver elsewhere, replace the `file` output and pass its settings as placeholders, for example:

```yaml
output:
  - opensearch:
      hosts:
        - ${params.opensearch_host}
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: cyberark-pta
```

For a CEF or syslog collector, forward `event.original` as the message body.

## Usage

Run from the content-packs repository root. Live generation at the configured rate:

```bash
eventum generate --path generators/security-cyberark-pta/generator.yml --id pta --live-mode true
```

Batch generation: set `start` and `end` of the `oscillator` in all twelve `patterns/*.yml` files to the same range, with `start` at 00:00 UTC on a Monday so that the hour bands and the weekday bands stay in place (for example `start: "2026-09-14T00:00:00Z"` and `end: "2026-09-28T00:00:00Z"`), then run:

```bash
eventum generate --path generators/security-cyberark-pta/generator.yml --id pta --live-mode false --keep-order true
```

The first episode starts within the first day, so use at least two days to see two episodes at the default interval. For background only, set `anomaly_mode: false`.

The volume and its curve are the sum of the pattern files: `irregular-*` (irregular-hours activity: a round-the-clock floor, the evening and early-morning peaks, Saturday and Sunday daytime) and `office-*` (office-hours activity: a floor, 07:00-19:00 every day, and 08:00-18:00 Monday to Friday). To change the volume, scale the `ratio` of every file by the same factor; episode actors are chosen for the shipped volume, and episode start hours follow the shipped curve.

Performance: about 1,200 alerts per second in batch mode (14 days, 6,500 alerts, 5.5 s on one core).

## Sample output event

The second alert of an episode (step 2, class 23), copied byte for byte from a default run:

```json
{"@timestamp": "2026-09-15T19:14:08Z", "cef": {"device": {"event_class_id": "23", "product": "PTA", "vendor": "CyberArk", "version": "12.0"}, "extensions": {"destinationAddress": "10.20.30.37", "destinationHostName": "srv-app-02.corp.example.test", "destinationUserName": "administrator@srv-app-02.corp.example.test", "deviceCustomDate1": "1789499648000", "deviceCustomDate1Label": "DetectionDate", "deviceCustomString1": "None", "deviceCustomString1Label": "ExtraData", "deviceCustomString2": "6aa9990050dae0b42a456337", "deviceCustomString2Label": "EventID", "deviceCustomString3": "https://pvwa.corp.example.test:443/PasswordVault/v10/pta/events/6aa9990050dae0b42a456337", "deviceCustomString3Label": "PTALink", "deviceCustomString4": "None", "deviceCustomString4Label": "ExternalLink", "sourceHostName": "None", "sourceUserName": "i.tarasov(Vault user)"}, "name": "Privileged access to the Vault during irregular hours", "severity": "2", "version": "0"}, "cyberark_pta": {"log": {"event_type": "23"}}, "destination": {"domain": "srv-app-02.corp.example.test", "ip": "10.20.30.37", "user": {"domain": "srv-app-02.corp.example.test", "email": "administrator@srv-app-02.corp.example.test", "name": "administrator"}}, "ecs": {"version": "8.11.0"}, "event": {"code": "23", "dataset": "cyberark_pta.events", "id": "6aa9990050dae0b42a456337", "original": "CEF:0|CyberArk|PTA|12.0|23|Privileged access to the Vault during irregular hours|2|suser=i.tarasov(Vault user) shost=None src=None duser=administrator@srv-app-02.corp.example.test dhost=srv-app-02.corp.example.test dst=10.20.30.37 cs1Label=ExtraData cs1=None cs2Label=EventID cs2=6aa9990050dae0b42a456337 deviceCustomDate1Label=DetectionDate deviceCustomDate1=1789499648000 cs3Label=PTALink cs3=https://pvwa.corp.example.test:443/PasswordVault/v10/pta/events/6aa9990050dae0b42a456337 cs4Label=ExternalLink cs4=None", "reason": "Privileged access to the Vault during irregular hours", "reference": "https://pvwa.corp.example.test:443/PasswordVault/v10/pta/events/6aa9990050dae0b42a456337", "severity": 2, "url": "None"}, "observer": {"product": "PTA", "vendor": "CyberArk", "version": "12.0"}, "related": {"user": ["i.tarasov(Vault user)", "administrator", "administrator@srv-app-02.corp.example.test"]}, "source": {"domain": "None", "user": {"name": "i.tarasov(Vault user)"}}}
```

## Format and coverage

The CEF layout follows two real PTA exports: an Elastic integration fixture from PTA 11.4 (`Active dormant Vault user`, class 26, severity 5) and a Secureworks Taegis sample from PTA 12.0 (`Privileged access to the Vault during irregular hours`, class 23, severity 2). Both carry the same 16 extension keys in the same order - `suser shost src duser dhost dst cs1Label cs1 cs2Label cs2 deviceCustomDate1Label deviceCustomDate1 cs3Label cs3 cs4Label cs4` - with the labels `ExtraData`, `EventID`, `DetectionDate`, `PTALink`, `ExternalLink`, `shost=None` for Vault-user alerts (with `src=None` in the 12.0 sample and a source address in the 11.4 fixture), `cs1=None`, `cs4=None` (`None.` in the 11.4 fixture), a detection date in epoch milliseconds on a whole second, and a link `https://<pvwa>:443/PasswordVault/v10/pta/events/<EventID>`. In both, the EventID is a MongoDB ObjectId whose first four bytes are the detection second; the generator builds it the same way (detection second, a per-run random part, a counter that advances by random steps).

`Suspected credentials theft` (class 1, severity 8, `suser=<user>@<shost>` with a source IP) comes from the Elastic integration's PTA 12.6 example. That example uses the spellings `detectionDate` and `PTAlink` and a link of the form `https://<ip>/incidents/<id>`; it matches CyberArk's documentation example rather than a captured record. The generator uses the spellings and link form of the two real exports for all three classes.

The JSON document follows the Elastic integration's parsed output: `cef.*` with long extension names, `event.code`, `event.id`, `event.reason`, `event.reference`, `event.url`, `event.severity`, `source.*` and `destination.*` with the user split at `@`, `related.user`, `observer.*` and `cyberark_pta.log.event_type`. Collector fields (`agent`, `data_stream`, `input`, `log`, `tags`, `event.ingested`) are omitted.

## Limitations

- Three PTA detections are modeled - the ones with a published raw record. PTA reports many more (unmanaged privileged access, suspicious password changes, risky sessions and others), whose CEF class IDs are not available from a public source.
- `@timestamp` equals the detection time, on a whole second without milliseconds, where the Elastic pipeline writes `.000`. `cef.extensions.deviceCustomDate1` stays in epoch milliseconds, as in the CEF record, where the Elastic pipeline converts it to an ISO date. When `src=None`, `sourceAddress` and `source.ip` are left out; no public fixture shows how the pipeline parses that value.
- The meaning of `duser`, `dhost` and `dst` in Vault-user alerts is taken as the privileged account and its machine. The public samples are anonymized and do not settle it.
- Rates, hour-of-day and weekday curves, repeat frequencies and the actor pools are synthetic. The busiest Vault users raise dormant-user alerts up to about three times a day, far more often than a real dormancy period would allow, so that every episode user also has ordinary dormant-user alerts.
- A dormant-user alert and the irregular-hours alert of the same return are usually 1-9 minutes apart (occasionally up to about 18), and repeated alerts of one actor are rarely less than a minute and a half apart (median about 6 minutes); PTA may raise alerts of one Vault login within seconds.
- Severities are fixed per class as in the samples. PTA risk scoring, alert aggregation, `ExtraData` content and external links are not modeled.
- The syslog header (RFC 3164 or 5424) and TCP/UDP transport are not modeled; the default output is JSON Lines.

## References

- [Elastic CyberArk PTA integration](https://www.elastic.co/docs/reference/integrations/cyberark_pta) - ECS mapping and sample event.
- [Elastic integration test fixtures](https://github.com/elastic/integrations/tree/main/packages/cyberark_pta) - raw PTA 11.4 and 12.6 CEF records and parsed output.
- [Secureworks Taegis CyberArk integration](https://docs.taegis.secureworks.com/integration/connectNetwork/cyberark_connect/) - raw PTA 12.0 syslog sample and `syslog_outbound` settings.
- [Google SecOps CyberArk PTA parser](https://docs.cloud.google.com/chronicle/docs/ingestion/default-parsers/cyberark-pta) - `syslog_outbound` CEF forwarding steps.

CyberArk's own PTA pages (CEF-based format definition, detection catalog, syslog forwarding) returned 404 when this pack was revised, so none of the format above rests on them.
