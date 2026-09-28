# Delinea Secret Server CEF

Generates the `SECRET - VIEW` audit records that one Delinea Secret Server 11.3 instance (formerly Thycotic) sends to a syslog/CEF collector, as ECS JSON, for training SIEM content on privileged credential access. `event.original` holds the syslog line in the layout of the complete 11.3.000001 record in the Elastic Thycotic Secret Server integration; the surrounding JSON mirrors the document that integration produces from it. The CEF header keeps the historical `Thycotic Software` vendor name used by this version.

## Event Types

Every record is native event `SECRET - VIEW` (CEF class `10004`, ECS `iam` / `info`). Shares by folder (`cs3`), measured on the final default capture (108 h, `anomaly_mode: true`, 10,968 records):

| Folder (`cs3`) | Viewed by | Share | Category |
|---|---|---:|---|
| `Applications` | DevOps, DBAs, administrators, automation accounts | 27.27% (2991) | IAM |
| Personal folders (one per person, named after the person) | the folder owner | 21.84% (2395) | IAM |
| `Network Devices` | network engineers, administrators | 18.46% (2025) | IAM |
| `Service Desk` | service desk, administrators | 12.79% (1403) | IAM |
| `Tier 0 - Infrastructure` | administrators, occasionally network engineers | 12.16% (1334) | IAM |
| `Databases` | DBAs, DevOps, administrators | 7.48% (820) | IAM |

Users, secret names, folder names, IDs and rates are an assumed mid-size organisation, not measured production data. Every user, source address, secret and folder the chain uses occurs in ordinary background in both modes. No field labels an episode.

## Background Model

Each one-second tick emits at most one record: the earliest due view, otherwise nothing. People start sessions as one merged Poisson stream (0.009 per second, scaled by an office-hours factor: 07:00-17:00 UTC 1.80, 17:00-21:00 0.79, night 0.28); each session picks a person by a fixed random per-user weight (log-normal), so users act independently and some open secrets far more often than others. Automation accounts add a flat stream (0.002 per second, any hour). The organisation itself (30 accounts with fixed IDs and one workstation address each, 5 shared folders with 33 secrets, one personal folder per person, per-user activity and per-secret popularity) comes from a fixed seed, so every run models the same instance and only behaviour is random.

- **Ordinary sessions**: 1-6 views, gaps log-normal (median 40 s); each view re-opens the previous secret (30%) or picks a folder by role (administrators, DBAs, network engineers, service desk, DevOps) and a secret by a fixed random popularity weight.
- **Infrastructure work** (25% of administrator sessions): 2-9 views, gaps log-normal (median 35 s), 85% of them Tier 0 secrets, 25% re-opens. These sessions put several distinct Tier 0 secrets by one administrator into a few minutes.
- **Automation** (`svc.ansible`, `svc.jenkins`): 1-6 application secrets seconds apart.

The syslog header carries the send time: a log-normal delay (median 3 s) after the event time `rt`, as in the Elastic fixture, where the header is 9 s later than `rt`.

In six 108 h `anomaly_mode: false` captures, counting from each Tier 0 view of a user, the fourth distinct Tier 0 secret came 20-25, 25-30, 30-35 and 35-40 minutes later 115, 155, 173 and 153 times, and the fifth distinct one 30-35, 35-40 and 40-45 minutes later 94, 77 and 118 times; no user reached five within 30 minutes by event time (`rt`, `thycotic_ss.event.time`); counted by syslog send time (`@timestamp`), send delay pulls 3 spans of 1803-1809 s under 30 minutes across the six captures.

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the generator emits the background only and the complete chain never occurs.

Sequence, all by one administrator U from U's usual workstation address: `SECRET - VIEW` of five distinct secrets in folder `Tier 0 - Infrastructure` within 30 minutes, with occasional re-opens of an already viewed one in between (25% after each view).

Linking fields: `suser` / `suid` and `src` in all steps; `cs3` is `Tier 0 - Infrastructure` and `fileId` differs across the five views.

Recurrence: episodes recur every `anomaly_interval_hours` of source time (default 24, minimum 2). The first start is drawn within the first min(interval, 24 h) of generation, with clock-hour slots weighted by the background office-hours factor, so its hour follows the background rather than the moment generation started. Each later episode is due one interval after the previous episode's actual start; its start is drawn in a window of w = min(interval / 4, 6 h) centred on the due time, with clock-hour slots weighted by the office-hours factor squared plus a small floor, so the phase stays in busy hours instead of drifting. Starts are therefore interval ± w/2 apart (24 h ± 3 h by default), and a late episode never causes catch-up. At intervals of 8 h or less the episodes necessarily cover the whole clock, night included. The episode may overlap the administrator's own infrastructure work; then Tier 0 views of that work within the 30 minutes count toward the five, and the pattern completes at an earlier episode view. The detected start is then up to 30 minutes before the episode's first view. The administrator viewed Tier 0 secrets in the 30 minutes before the first of the five distinct views in 10 of 18 detected patterns, and before the first of four distinct views in 249 of 446 four-secret occurrences in the six `anomaly_mode: false` captures. In the final captures the default interval gave 5 detected patterns starting at 00:09, 01:28, 22:39, 20:03 and 19:22 UTC (gaps 21.2-25.3 h): the first start fell at night, and the window moves the phase toward busy hours by at most 3 h per episode. An 8 h interval gave 13 patterns at every time of day (gaps 7.1-9.3 h). Patterns spanned 1.3-27.7 minutes; 9-15% of background Tier 0 views fall into 21:00-07:00 UTC.

Variation: the administrator differs from the previous episode's and is picked by the same per-user weights as the background, so active administrators are episode actors more often; the five secrets are a fresh random draw and the first one differs from the previous episode's first; gaps follow the infrastructure-session law. Viewing a secret changes no state, so there is nothing to restore.

Detection idea: one account viewing five or more distinct Tier 0 credentials within half an hour (credential harvesting from the vault). Each fragment occurs in background: repeated Tier 0 views by the same administrator within minutes, two to four distinct Tier 0 secrets within 30 minutes, five distinct ones over slightly more than 30 minutes, and the same user|secret pairs (4-5 of each episode's five occur in the background of the same capture). Only the complete pattern is kept out of the background: in six 108 h `anomaly_mode: false` captures no user viewed five distinct Tier 0 secrets within 30 minutes. The generator counts, per user, the distinct Tier 0 secrets viewed in the last 30 minutes (a sliding window). An ordinary view that would be the fifth re-opens one of the four instead, at the same time. The fifth distinct secret of an episode completes the pattern and starts the count afresh; the episode's remaining views then count as ordinary ones.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
|---|---|---|
| `anomaly_mode` | `true` | Add periodic episodes to the background |
| `anomaly_interval_hours` | `24` | Episode interval in source hours, 2-8760 |
| `server_host` | `SECRET-SRV-01` | Syslog hostname, `host.name` and `observer.hostname` |
| `device_version` | `11.3.000001` | Version in the CEF header; the layout is validated for this version only |
| `domain` | `contoso` | Domain prefix in personal admin account and breakglass secret names |

### Output Parameters

The shipped config writes `output/events.json` with the `json` formatter and needs no `${params.*}` or `${secrets.*}`. To send events elsewhere, replace the `output` section and put destination settings behind top-level placeholders, for example:

```yaml
output:
  - opensearch:
      hosts:
        - ${params.opensearch_host}
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: thycotic-ss-logs
```

A collector that parses Secret Server syslog/CEF needs `event.original` rather than the surrounding JSON.

## Usage

Live mode:

```bash
eventum generate --path generators/identity-delinea-secret-server/generator.yml --id delinea-ss --live-mode true
```

Batch mode needs a bounded input: add `start` and `end` to the `cron` input, then run:

```bash
eventum generate --path generators/identity-delinea-secret-server/generator.yml --id delinea-ss --live-mode false
```

## Limitations

- Only `SECRET - VIEW` is generated. It is the one Secret Server 11.3 event class with a complete published raw record; the Delinea event list names the other classes (check-out, launch, password displayed, login) but their 11.3 message and extension layout is not published, and the only other raw fixture (`PASSWORD_DISPLAYED`) is from 11.7 with a different message wording.
- The day in the syslog header is space-padded as in RFC 3164 and the day in `rt` is zero-padded; the fixture (day 10) cannot confirm either. `rt` uses the legacy "Syslog" DateTime format (`Jun 23 2022 11:22:33`); the ISO option of newer versions is not modelled. Clocks are UTC with second resolution.
- The ECS envelope follows the integration's expected document and `sample_event.json`; agent, data stream and ingest fields added by Elastic Agent are omitted, and `cef.*` is omitted as the pipeline removes it by default.
- One record per second at most; rates, roles and folder contents are training assumptions.

## Sample Output

The view that completes the second episode, copied byte for byte from the final default capture (line 2395; the other views of the pattern are lines 2381, 2389, 2392, 2393 and 2394):

```json
{"@timestamp": "2026-09-27T01:32:25.000Z", "ecs": {"version": "8.11.0"}, "event": {"action": "view", "category": ["iam"], "code": "10004", "dataset": "thycotic_ss.logs", "kind": "event", "original": "Sep 27 01:32:25 SECRET-SRV-01 CEF:0|Thycotic Software|Secret Server|11.3.000001|10004|SECRET - VIEW|2|msg=[[SecretServer]] Event: [Secret] Action: [View] By User: D.Lee Item Name: SCCM Network Access Account (Item Id: 2670) Container Name: Tier 0 - Infrastructure (Container Id: 162)  suid=709 suser=D.Lee cs4=David Lee cs4Label=suser Display Name src=10.20.5.41 rt=Sep 27 2026 01:32:19 fname=SCCM Network Access Account fileType=Secret fileId=2670 cs3Label=Folder cs3=Tier 0 - Infrastructure", "provider": "secret", "type": ["info"]}, "host": {"name": "SECRET-SRV-01"}, "message": "[[SecretServer]] Event: [Secret] Action: [View] By User: D.Lee Item Name: SCCM Network Access Account (Item Id: 2670) Container Name: Tier 0 - Infrastructure (Container Id: 162)", "observer": {"hostname": "SECRET-SRV-01", "product": "Secret Server", "vendor": "Thycotic Software", "version": "11.3.000001"}, "related": {"hosts": ["SECRET-SRV-01"], "ip": ["10.20.5.41"], "user": ["D.Lee"]}, "source": {"ip": "10.20.5.41"}, "thycotic_ss": {"event": {"secret": {"folder": "Tier 0 - Infrastructure", "id": "2670", "name": "SCCM Network Access Account"}, "time": "2026-09-27T01:32:19.000Z"}}, "user": {"full_name": "David Lee", "id": "709", "name": "D.Lee"}}
```

## References

- [Elastic Thycotic Secret Server integration](https://www.elastic.co/docs/reference/integrations/thycotic_ss): tested versions, fields; pipeline test fixture with the complete 11.3.000001 `SECRET - VIEW` line.
- [Delinea: Syslog Event List](https://docs.delinea.com/online-help/secret-server/alerts-events/logs/syslog-event-list/index.htm): `SECRET` / `VIEW`, action ID 10004.
- [Delinea: Secret Server Reported Events](https://docs.delinea.com/online-help/integrations/splunk/splunk-integration-secret-server/ssvr-reported-events.htm): CEF field meanings; `SECRET - VIEW` uses `cs3` and `cs4` only.
- [Delinea: Secure Syslog and CEF Logging](https://docs.delinea.com/online-help/secret-server/alerts-events/logs/secure-syslog-cef/index.htm): time zone and DateTime format options.
