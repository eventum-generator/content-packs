# Delinea Secret Server CEF

Generates the `SECRET - VIEW` audit records that one Delinea Secret Server 11.3 instance (formerly Thycotic) sends to a syslog/CEF collector, as ECS JSON, for training SIEM content on privileged credential access. `event.original` holds the syslog line in the layout of the complete 11.3.000001 record in the Elastic Thycotic Secret Server integration; the surrounding JSON mirrors the document that integration produces from it. The CEF header keeps the historical `Thycotic Software` vendor name used by this version.

## Event Types

Every record is native event `SECRET - VIEW` (CEF class `10004`, ECS `iam` / `info`). Approximate shares by folder (`cs3`):

| Folder (`cs3`) | Viewed by | Share | Category |
|---|---|---:|---|
| `Service Desk` | service desk, administrators | 32% | IAM |
| Personal folders (one per person, named after the person) | the folder owner | 25% | IAM |
| `Applications` | DevOps, automation accounts, DBAs, administrators | 22% | IAM |
| `Databases` | DBAs, DevOps, administrators, backup automation | 8% | IAM |
| `Network Devices` | network engineers, administrators, configuration backup automation | 8% | IAM |
| `Tier 0 - Infrastructure` | administrators, occasionally network engineers | 5% | IAM |

By account: service desk 42%, DevOps 24%, network engineers 11%, administrators 9%, DBAs 9%, automation accounts 5%.

Users, secret names, folder names, IDs and rates are an assumed large organisation, not measured production data. Every user, source address, secret and folder the chain uses occurs in ordinary activity in both modes. No field labels an episode.

## Volume and Activity

About 12,700 views per day by 240 people and 4 automation accounts, each with a fixed ID and one workstation or server address.

- **People** (about 12,000 per day) follow UTC office hours: about 0.25 views/s 07:00-17:00, 0.11/s 17:00-21:00 and 0.04/s at night, with ±3% day-to-day variation. Each session belongs to one person, chosen by a fixed per-person activity weight (0.4-2.5 times the average), so some people open secrets far more often than others; fewer people are active at night because fewer sessions start then.
- **Ordinary sessions**: 1-6 views, a gap of about 40 s (log-normal) between views; each view re-opens the previous secret (30%) or picks a folder by role (administrators, DBAs, network engineers, service desk, DevOps) and a secret by its fixed popularity.
- **Infrastructure work** (25% of administrator sessions): 2-9 views about 35 s apart, 85% of them Tier 0 secrets, 25% re-opens. These sessions put several distinct Tier 0 secrets by one administrator into a few minutes. An administrator views about 20-25 Tier 0 secrets per day on average; a day without any is rare.
- **Automation** (about 660 per day, any hour, on fixed schedules): `svc.jenkins` 2 application secrets every 10 minutes, `svc.zabbix` its monitoring API credential every 5 minutes, `svc.ansible` 3 application secrets at minute 05 of every hour and 6 network device credentials at 01:30, `svc.backup` 3 database credentials at 22:00. Each run fetches its secrets in the same order within one second.

The syslog header carries the send time: a log-normal delay (median 3 s) after the event time `rt`, as in the Elastic fixture, where the header is 9 s later than `rt`.

Outside episodes no user views five distinct Tier 0 secrets within 30 minutes of event time (`rt`, `thycotic_ss.event.time`): when a user viewed four distinct ones in the last 30 minutes, a further Tier 0 view re-opens the latest of them (about 30-50 such views per day). Four distinct Tier 0 secrets by one administrator within 30 minutes occur about 30-40 times per day.

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the generator emits ordinary activity only and the complete chain never occurs.

Sequence, all by one administrator U from U's usual workstation address: `SECRET - VIEW` of five distinct secrets in folder `Tier 0 - Infrastructure` within 30 minutes. The first four come within seconds to about 29 minutes (median about 5 minutes, within 10 minutes in about 70% of episodes, as in ordinary runs of four distinct Tier 0 secrets), with occasional re-opens of the second to fourth (25% after each of them); the fifth follows alone 25-28 minutes after the first, or up to 30 minutes after it when the first four took longer. The first secret is not viewed again in the episode.

Linking fields: `suser` / `suid` and `src` in all steps; `cs3` is `Tier 0 - Infrastructure` and `fileId` differs across the five views.

Recurrence: episodes recur every `anomaly_interval_hours` of source time (default 24, minimum 2). The first start falls within the first min(interval, 24 h) of generation. Each later episode is due one interval after the previous episode's actual start and starts within w = min(interval / 4, 6 h) centred on the due time. Both are weighted by the square of the people volume of the hour plus a small floor, so starts land in busy hours rather than at the moment generation started. Starts are interval ± w/2 apart (24 h ± 3 h by default), and a late episode never causes catch-up. At the default interval about 90% of first starts fall between 07:00 and 17:00 UTC, 7% between 17:00 and 21:00 and 3% at night; later starts stay within 3 hours of the previous start's clock time under the same weighting, so most episodes start between 07:00 and 17:00 UTC and the rest in the early morning, in the evening or, rarely, at night. At intervals of 8 h or less the episodes cover the whole clock, night included.

Variation: the administrator differs from the previous episode's and is picked by the same activity weights as ordinary sessions. The time before the first view looks like the time before ordinary runs of four distinct Tier 0 secrets in the same hours: in about a quarter of episodes by day and a fifth at night U viewed other Tier 0 secrets shortly before (a few seconds to 30 minutes, median under 3 minutes), and those secrets are among the second to fourth of the episode; in about 30% U had already viewed the first secret once shortly before (median about a minute); a little over half begin without any Tier 0 view by U in the previous 30 minutes. The other secrets are drawn by the same popularity as ordinary views; the first one and the set of five differ from the previous episode's. Once the first view is more than 30 minutes old, U re-opens none to six of the other four (29% none), as infrastructure work goes on past its fourth distinct secret. In the 30 minutes after the fifth distinct view, U views no Tier 0 secret after about 23% of episodes, as after ordinary runs of four distinct ones in the same hours. The episode's views come on top of U's ordinary sessions, which keep their times. When those sessions add other Tier 0 secrets within the 30 minutes, the pattern completes at an earlier episode view and the detected start can be up to 30 minutes before the episode's first view.

Detection idea: one account viewing five or more distinct Tier 0 credentials within half an hour (credential harvesting from the vault). Each fragment occurs in ordinary activity: repeated Tier 0 views by the same administrator within minutes, two to four distinct Tier 0 secrets within 30 minutes, five distinct ones over slightly more than 30 minutes, and every administrator with the same address.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
|---|---|---|
| `anomaly_mode` | `true` | Add periodic episodes to ordinary activity |
| `anomaly_interval_hours` | `24` | Episode interval in source hours, 2-8760 |
| `server_host` | `SECRET-SRV-01` | Syslog hostname, `host.name` and `observer.hostname` |
| `device_version` | `11.3.000001` | Version in the CEF header; the layout is validated for this version only |
| `domain` | `contoso` | Domain prefix in personal admin account and breakglass secret names |

### Organisation

The modelled organisation lives in `samples/`:

- `users.csv`: accounts (`username`, `display_name`, `role`, `user_id`, `ip`, activity `weight`, personal secret and folder IDs). Roles are `admin`, `dba`, `network`, `helpdesk`, `devops` and `svc` (automation); episodes pick `admin` accounts.
- `secrets.csv`: secrets per folder with IDs and `popularity`; `{domain}` in a name is replaced by the `domain` parameter. The chain needs at least five `Tier 0 - Infrastructure` secrets.
- `jobs.csv`: the secrets each automation job fetches, in order. A job name is the tag of its `cron` input in `generator.yml`, whose `count` is the number of rows of that job.

People volume and its hour curve are set in `patterns/*.yml` (`multiplier.ratio` is views per day).

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

Batch mode needs a finite window: set `oscillator.start` and `oscillator.end` in each file under `patterns/` (start at midnight UTC, so the office hours stay in place) and add the same `start` and `end` to every `cron` input, then run:

```bash
eventum generate --path generators/identity-delinea-secret-server/generator.yml --id delinea-ss --live-mode false
```

Performance: about 6,000 events per second in batch mode (14 days, 177,000 events, in 29 s).

## Limitations

- Only `SECRET - VIEW` is generated. It is the one Secret Server 11.3 event class with a complete published raw record; the Delinea event list names the other classes (check-out, launch, password displayed, login) but their 11.3 message and extension layout is not published, and the only other raw fixture (`PASSWORD_DISPLAYED`) is from 11.7 with a different message wording.
- The day in the syslog header is space-padded as in RFC 3164 and the day in `rt` is zero-padded; the fixture (day 10) cannot confirm either. `rt` uses the legacy "Syslog" DateTime format (`Jun 23 2022 11:22:33`); the ISO option of newer versions is not modelled. Clocks are UTC with second resolution.
- The ECS envelope follows the integration's expected document and `sample_event.json`; agent, data stream and ingest fields added by Elastic Agent are omitted, and `cef.*` is omitted as the pipeline removes it by default.
- Views of one person are seconds to minutes apart (median about 50 s between consecutive views of one session), wider at night when the instance is quiet. Rates, roles, folder contents, schedules and the office-hours curve are training assumptions; weekends are not modelled.
- With `anomaly_mode: true` each episode adds its own 5-15 Tier 0 views, so an episode day holds that many more Tier 0 views by administrators. From the fifth distinct view until the first of the five is 30 minutes old (usually 2-5 minutes), the administrator opens no Tier 0 secret; ordinary views in that time go to the administrator's other folders.
- An episode's run of Tier 0 views holds fewer of the administrator's own personal-folder views than an ordinary run of four or more distinct Tier 0 secrets (about 0.3 against 0.7 per run).

## Sample Output

The view that completes the second episode, copied byte for byte from a default output started at 2026-09-26 00:00 UTC; the same user viewed the four other distinct Tier 0 secrets of the pattern at 14:30:08-14:31:11 UTC, the first of them twice, the first view 26 minutes 58 seconds earlier:

```json
{"@timestamp": "2026-09-27T14:57:14.000Z", "ecs": {"version": "8.11.0"}, "event": {"action": "view", "category": ["iam"], "code": "10004", "dataset": "thycotic_ss.logs", "kind": "event", "original": "Sep 27 14:57:14 SECRET-SRV-01 CEF:0|Thycotic Software|Secret Server|11.3.000001|10004|SECRET - VIEW|2|msg=[[SecretServer]] Event: [Secret] Action: [View] By User: M.Mccarthy Item Name: ESXi root - esx-cl01 (Item Id: 5781) Container Name: Tier 0 - Infrastructure (Container Id: 162)  suid=2926 suser=M.Mccarthy cs4=Michael Mccarthy cs4Label=suser Display Name src=10.20.5.145 rt=Sep 27 2026 14:57:06 fname=ESXi root - esx-cl01 fileType=Secret fileId=5781 cs3Label=Folder cs3=Tier 0 - Infrastructure", "provider": "secret", "type": ["info"]}, "host": {"name": "SECRET-SRV-01"}, "message": "[[SecretServer]] Event: [Secret] Action: [View] By User: M.Mccarthy Item Name: ESXi root - esx-cl01 (Item Id: 5781) Container Name: Tier 0 - Infrastructure (Container Id: 162)", "observer": {"hostname": "SECRET-SRV-01", "product": "Secret Server", "vendor": "Thycotic Software", "version": "11.3.000001"}, "related": {"hosts": ["SECRET-SRV-01"], "ip": ["10.20.5.145"], "user": ["M.Mccarthy"]}, "source": {"ip": "10.20.5.145"}, "thycotic_ss": {"event": {"secret": {"folder": "Tier 0 - Infrastructure", "id": "5781", "name": "ESXi root - esx-cl01"}, "time": "2026-09-27T14:57:06.000Z"}}, "user": {"full_name": "Michael Mccarthy", "id": "2926", "name": "M.Mccarthy"}}
```

## References

- [Elastic Thycotic Secret Server integration](https://www.elastic.co/docs/reference/integrations/thycotic_ss): tested versions, fields; pipeline test fixture with the complete 11.3.000001 `SECRET - VIEW` line.
- [Delinea: Syslog Event List](https://docs.delinea.com/online-help/secret-server/alerts-events/logs/syslog-event-list/index.htm): `SECRET` / `VIEW`, action ID 10004.
- [Delinea: Secret Server Reported Events](https://docs.delinea.com/online-help/integrations/splunk/splunk-integration-secret-server/ssvr-reported-events.htm): CEF field meanings; `SECRET - VIEW` uses `cs3` and `cs4` only.
- [Delinea: Secure Syslog and CEF Logging](https://docs.delinea.com/online-help/secret-server/alerts-events/logs/secure-syslog-cef/index.htm): time zone and DateTime format options.
