# CyberArk Privileged Threat Analytics CEF

Synthetic CyberArk Privileged Threat Analytics (PTA) security events as PTA sends them to a SIEM over syslog in CEF, for SIEM parsing and correlation testing. Each line is the ECS JSON document that the Elastic `cyberark_pta` integration builds from one CEF record; the CEF record itself is in `event.original`.

The generator models one PTA server that watches one Vault: 41 Vault users, 55 privileged accounts on target machines, and 32 administrator workstations and jump hosts that connect to those machines.

## Event types

| CEF class | Native alert | Severity | Share | Category |
| --- | --- | --- | --- | --- |
| `23` | Privileged access to the Vault during irregular hours | 2 | 54.5% | Vault access |
| `1` | Suspected credentials theft | 8 | 35.7% | Credential use outside the Vault |
| `26` | Active dormant Vault user | 5 | 9.7% | Vault access |

Shares are measured over six days of the default configuration (220 alerts per day; 191-213 per day across five background-only runs). Every alert is a PTA detection, so even the background is a stream of alerts, not benign activity.

Every Vault user and every workstation raises alerts on its own schedule: independent lognormal gaps weighted per actor, thinned by an hour-of-day profile. Irregular-hours alerts fall mostly at night and at weekends; lone dormant-user alerts mostly in working hours; credential-theft alerts across the day with a daytime lean. Background incidents include single alerts, repeats by the same actor within minutes, and every two-step part of the anomaly chain: a dormant user that then accesses the same account at an irregular hour, an irregular-hours access followed by a credential-theft alert on that account, and a dormant-user alert followed by credential theft.

## Anomaly Chain

With `anomaly_mode: true` (the default), an episode is a three-alert sequence on one privileged account:

1. `26` Active dormant Vault user - Vault user V (`suser=<name>(Vault user)`) resurfaces on account A (`duser`, `dhost`, `dst`).
2. `23` Privileged access to the Vault during irregular hours - the same V on the same A, a minute or two later; sometimes repeated.
3. `1` Suspected credentials theft - a workstation or jump host (`suser`, `shost`, `src`) that normally uses A connects to A with credentials not taken from the Vault, typically 10-30 minutes later.

Linking fields: `destinationUserName` (`duser`) across all three alerts; `sourceUserName` (`suser`) between the first two. An episode usually spans under half an hour and at most a few hours; the detection window below is four hours.

Recurrence: episodes recur on source time; `anomaly_interval_hours` (default 24, minimum 6) is the time from one episode's actual start to the next due time. The first episode is due one hour after the run starts. A random delay of up to `min(1 h, interval / 8)` is added to every due time, and the start is then drawn from a window of at most `min(interval / 4, 6 h)` after it, weighted by the hour-of-day profile of background dormant-then-irregular incidents (mostly nights and weekends, with a small floor so any hour is possible). Consecutive starts are therefore between one interval and interval + `min(1 h, interval / 8)` + `min(interval / 4, 6 h)` apart: measured 24.4-28.9 h at the default 24 h (6 episodes in six days) and 8.4-10.7 h at 8 h (15 episodes). Missed intervals are not caught up.

Variation: V and A are drawn from a recent background irregular-hours alert of a user who also has background dormant-user alerts, and the workstation from recent background credential-theft alerts on A, so episode actors follow background frequencies and every user, account, workstation, user-account pair and workstation-account pair of an episode also occurs in ordinary alerts. Neither V nor A repeats between consecutive episodes. EventIDs, links and timings are drawn fresh for every alert.

Detection idea: per `duser`, raise when a dormant-user alert and an irregular-hours alert by the same Vault user are followed within four hours by a credential-theft alert on that account. Each alert on its own, and each pair of them, is ordinary here.

With `anomaly_mode: false`, the generator produces only background: the same alerts, actors and partial sequences, without the complete three-alert sequence. The full sequence is also kept out of the background in anomaly mode: a background credential-theft alert that would complete it within six hours moves to another workstation and account.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Description |
| --- | --- | --- |
| `anomaly_mode` | `true` | Add recurring anomaly episodes to the background |
| `anomaly_interval_hours` | `24` | Hours between episode starts; at least 6 |
| `pta_version` | `12.0` | Version in the CEF header, `cef.device.version` and `observer.version` |
| `pvwa_host` | `pvwa.corp.example.test` | PVWA host in the PTA event link (`cs3`) |

Users, accounts and workstations come from `samples/vault_users.csv`, `samples/accounts.csv` and `samples/sources.csv`; the `accounts` columns list which accounts a Vault user or workstation normally uses.

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

Run from the content-packs repository root:

```bash
eventum generate --path generators/security-cyberark-pta/generator.yml --id pta --live-mode false
eventum generate --path generators/security-cyberark-pta/generator.yml --id pta --live-mode true
```

The input ticks once per second; a tick emits the next due alert or nothing. For a bounded batch run, add `start` and `end` to the `cron` input. For background only, set `anomaly_mode: false`.

## Sample output event

The second alert of an episode (step 2, class 23), copied byte for byte from a default run:

```json
{"@timestamp": "2026-09-15T06:08:03Z", "cef": {"device": {"event_class_id": "23", "product": "PTA", "vendor": "CyberArk", "version": "12.0"}, "extensions": {"destinationAddress": "10.20.30.150", "destinationHostName": "lnx-web-03.corp.example.test", "destinationUserName": "root@lnx-web-03.corp.example.test", "deviceCustomDate1": "1789452483000", "deviceCustomDate1Label": "DetectionDate", "deviceCustomString1": "None", "deviceCustomString1Label": "ExtraData", "deviceCustomString2": "6aa8e0c3e581fd0f83f81038", "deviceCustomString2Label": "EventID", "deviceCustomString3": "https://pvwa.corp.example.test:443/PasswordVault/v10/pta/events/6aa8e0c3e581fd0f83f81038", "deviceCustomString3Label": "PTALink", "deviceCustomString4": "None", "deviceCustomString4Label": "ExternalLink", "sourceHostName": "None", "sourceUserName": "b.golubev(Vault user)"}, "name": "Privileged access to the Vault during irregular hours", "severity": "2", "version": "0"}, "cyberark_pta": {"log": {"event_type": "23"}}, "destination": {"domain": "lnx-web-03.corp.example.test", "ip": "10.20.30.150", "user": {"domain": "lnx-web-03.corp.example.test", "email": "root@lnx-web-03.corp.example.test", "name": "root"}}, "ecs": {"version": "8.11.0"}, "event": {"code": "23", "dataset": "cyberark_pta.events", "id": "6aa8e0c3e581fd0f83f81038", "original": "CEF:0|CyberArk|PTA|12.0|23|Privileged access to the Vault during irregular hours|2|suser=b.golubev(Vault user) shost=None src=None duser=root@lnx-web-03.corp.example.test dhost=lnx-web-03.corp.example.test dst=10.20.30.150 cs1Label=ExtraData cs1=None cs2Label=EventID cs2=6aa8e0c3e581fd0f83f81038 deviceCustomDate1Label=DetectionDate deviceCustomDate1=1789452483000 cs3Label=PTALink cs3=https://pvwa.corp.example.test:443/PasswordVault/v10/pta/events/6aa8e0c3e581fd0f83f81038 cs4Label=ExternalLink cs4=None", "reason": "Privileged access to the Vault during irregular hours", "reference": "https://pvwa.corp.example.test:443/PasswordVault/v10/pta/events/6aa8e0c3e581fd0f83f81038", "severity": 2, "url": "None"}, "observer": {"product": "PTA", "vendor": "CyberArk", "version": "12.0"}, "related": {"user": ["b.golubev(Vault user)", "root", "root@lnx-web-03.corp.example.test"]}, "source": {"domain": "None", "user": {"name": "b.golubev(Vault user)"}}}
```

## Format and coverage

The CEF layout follows two real PTA exports: an Elastic integration fixture from PTA 11.4 (`Active dormant Vault user`, class 26, severity 5) and a Secureworks Taegis sample from PTA 12.0 (`Privileged access to the Vault during irregular hours`, class 23, severity 2). Both carry the same 16 extension keys in the same order - `suser shost src duser dhost dst cs1Label cs1 cs2Label cs2 deviceCustomDate1Label deviceCustomDate1 cs3Label cs3 cs4Label cs4` - with the labels `ExtraData`, `EventID`, `DetectionDate`, `PTALink`, `ExternalLink`, `shost=None src=None` for Vault-user alerts, `cs1=None`, `cs4=None`, a detection date in epoch milliseconds on a whole second, and a link `https://<pvwa>:443/PasswordVault/v10/pta/events/<EventID>`. In both, the EventID is a MongoDB ObjectId whose first four bytes are the detection second; the generator builds it the same way (detection second, a per-run random part, a counter that advances by random steps).

`Suspected credentials theft` (class 1, severity 8, `suser=<user>@<shost>` with a source IP) comes from the Elastic integration's PTA 12.6 example. That example uses the spellings `detectionDate` and `PTAlink` and a link of the form `https://<ip>/incidents/<id>`; it matches CyberArk's documentation example rather than a captured record. The generator uses the spellings and link form of the two real exports for all three classes.

The JSON document follows the Elastic integration's parsed output: `cef.*` with long extension names, `event.code`, `event.id`, `event.reason`, `event.reference`, `event.url`, `event.severity`, `source.*` and `destination.*` with the user split at `@`, `related.user`, `observer.*` and `cyberark_pta.log.event_type`. Collector fields (`agent`, `data_stream`, `input`, `log`, `tags`, `event.ingested`) are omitted.

## Limitations

- Three PTA detections are modeled - the ones with a published raw record. PTA reports many more (unmanaged privileged access, suspicious password changes, risky sessions and others), whose CEF class IDs are not available from a public source.
- `@timestamp` equals the detection time. `cef.extensions.deviceCustomDate1` stays in epoch milliseconds, as in the CEF record, where the Elastic pipeline converts it to an ISO date. When `src=None`, `sourceAddress` and `source.ip` are left out; no public fixture shows how the pipeline parses that value.
- The meaning of `duser`, `dhost` and `dst` in Vault-user alerts is taken as the privileged account and its machine. The public samples are anonymized and do not settle it.
- Rates, hour-of-day profiles, repeat frequencies and the actor pools are synthetic. Dormant-user alerts recur for the same user more often than a real dormancy period would allow, so that every episode actor also appears in ordinary alerts.
- Severities are fixed per class as in the samples. PTA risk scoring, alert aggregation, `ExtraData` content and external links are not modeled.
- The syslog header (RFC 3164 or 5424) and TCP/UDP transport are not modeled; the default output is JSON Lines.

## References

- [Elastic CyberArk PTA integration](https://www.elastic.co/docs/reference/integrations/cyberark_pta) - ECS mapping and sample event.
- [Elastic integration test fixtures](https://github.com/elastic/integrations/tree/main/packages/cyberark_pta) - raw PTA 11.4 and 12.6 CEF records and parsed output.
- [Secureworks Taegis CyberArk integration](https://docs.taegis.secureworks.com/integration/connectNetwork/cyberark_connect/) - raw PTA 12.0 syslog sample and `syslog_outbound` settings.
- [Google SecOps CyberArk PTA parser](https://docs.cloud.google.com/chronicle/docs/ingestion/default-parsers/cyberark-pta) - `syslog_outbound` CEF forwarding steps.

CyberArk's own PTA pages (CEF-based format definition, detection catalog, syslog forwarding) returned 404 when this pack was revised, so none of the format above rests on them.
