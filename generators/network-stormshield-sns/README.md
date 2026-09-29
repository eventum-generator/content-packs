# Stormshield SNS audit logs

Stormshield Network Security (SNS v4) audit records of one firewall that separates office workstations from a server segment: IPS alarm 85 ("Interactive connection detected") from the `l_alarm` log and closed-connection records from the `l_connection` log. Eventum emits ECS JSON and keeps the native WELF key-value body, as the firewall forwards it over syslog, in `event.original`.

## Event types covered

Shares are typical of default output (anomaly mode on).

| Log | Record | `event.action` | Share | ECS category |
| --- | --- | --- | --- | --- |
| `l_connection` | HTTPS connection closed (`proto=https`, port 443) | `connection_closed` | 65.0% | network |
| `l_connection` | HTTP connection closed (`proto=http`, port 80) | `connection_closed` | 13.2% | network |
| `l_connection` | SSH connection closed (`proto=ssh`, port 22) | `connection_closed` | 9.3% | network |
| `l_alarm` | Alarm 85, interactive SSH connection detected (`action=pass`) | `interactive_connection_detected` | 7.4% | network, intrusion_detection |
| `l_connection` | NTP exchange with the firewall (`ipproto=udp`, port 123) | `connection_closed` | 5.1% | network |

### Volume and actors

About 6,000 records a day (+/- 3% from day to day), following an office day in UTC: about 440 records an hour from 08:00 to 18:00, 200 an hour from 18:00 to 22:00 and 80 an hour at night. Every source is a person's workstation, so all traffic follows this curve. Rates and actors are modelled, not measured SNS volumes:

- **Admin workstations** (`10.10.5.11` and up, host objects `adm_ws01`...) run SSH work tasks, weighted per workstation (the busiest does up to four times the work of the quietest). A task opens one to six sessions to servers from the workstation's own set of 6-11 servers, each session starting up to 15 minutes after the previous one; about 20% of sessions are scp-style transfers whose received volume is log-normal around 60 MB, so transfers of 100 MiB and more occur in ordinary traffic (about 20 a day).
- An interactive session produces alarm 85 at its start and an `l_connection` record when it closes (`startime` = session start, `time` = close, `duration`, `sent`, `rcvd`). A transfer session produces the connection record only.
- **Office workstations** (`10.10.1.20` and up, no host object) and admin workstations reach internal web servers over HTTPS and HTTP and synchronise time with the firewall.

## Anomaly Chain

One admin workstation opens interactive SSH sessions to three different servers and then pulls a bulk transfer of 100 MiB (104,857,600 bytes) or more over SSH:

| Step | Record | Condition |
| --- | --- | --- |
| 1 | `l_alarm`, `alarmid=85` | source S to server A |
| 2 | `l_alarm`, `alarmid=85` | source S to server B, B different from A |
| 3 | `l_alarm`, `alarmid=85` | source S to server C, C different from A and B |
| 4 | `l_connection`, `proto=ssh` | source S, `rcvd` (`destination.bytes`) >= 104857600 |

- **Linking fields:** `source.ip` (`src`), `destination.ip` (`dst`), `network.protocol`, `destination.bytes` (`rcvd`), time. The whole sequence spans at most one hour; spans are usually about 2-20 minutes and occasionally longer.
- **Recurrence:** one episode per `anomaly_interval_hours` of source time (default 24, minimum 2). The first episode starts within min(interval, 24 h) of the first record, at an hour drawn from the day curve. Each next episode is due one interval after the previous actual start and starts within +/- w/2 of that time, w = min(interval / 4, 6 h), favouring busy hours, so episodes stay in office hours and never drift; missed intervals are not caught up.
- **Variation:** the workstation is drawn with the ordinary per-workstation weights among the admin workstations that do at least 0.8 of an average share of admin work, and differs from the previous episode; the servers are drawn with the workstation's own weights among the servers it reaches at least about ten times in four days. Every workstation/server pair of an episode therefore also occurs in ordinary traffic of any few days, and every such workstation also makes ordinary transfers of 100 MiB and more. Session gaps, durations and volumes come from the ordinary distributions.
- **Records:** an episode has its own records (three alarms, three SSH connection records and one bulk transfer), which take the place of a few ordinary new connections so the hourly volume is the same in both modes; the workstation's ordinary work goes on alongside.
- **Background overlap:** alarm 85 to three or more different servers within an hour (about 50 a day), transfers of 100 MiB and more, and transfers after sessions to two servers all occur in ordinary traffic in both modes. Only the complete order is reserved: an ordinary transfer of 100 MiB or more that closes within an hour after the same source's alarms for three different servers carries a smaller volume instead.
- **Detection idea:** per source, count distinct servers with alarm 85 in a sliding hour and flag an SSH connection record with a large `rcvd` that follows a fan-out to three or more servers - an operator touching many servers and then copying data out.
- **Modes:** `anomaly_mode` defaults to `true`. With `false` the generator produces only the background described above, without the complete sequence.

The records show SSH sessions permitted by the filter policy; they do not prove authentication, lateral movement or data theft.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`.

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Add the anomaly episodes to the background. |
| `anomaly_interval_hours` | `24` | Source-time interval between episode starts (2-8760). |
| `firewall_name` | `sns-fw-01` | Firewall name written to `fw` and `observer.name`. |
| `admin_count` | `12` | Admin workstations (4-60), `10.10.5.11` upwards. The total admin work stays the same, so more workstations each do less. |
| `user_count` | `40` | Office workstations (10-200), `10.10.1.20` upwards. |

### Volume

The daily volume and its hour curve live in `patterns/`: `floor.yml` (all day), `daytime.yml` (08:00-22:00) and `office.yml` (08:00-18:00) each add `multiplier.ratio` records a day over their hours (UTC). Scale all three ratios together to change the volume without changing the mix of record types.

### Output Parameters

The shipped `generator.yml` writes to a local file and needs no overrides. To send events to a backend, replace the `file` output and take destination settings from top-level `${params.*}` / `${secrets.*}` placeholders, for example:

```yaml
output:
  - opensearch:
      hosts:
        - ${params.opensearch_host}
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: stormshield-sns
```

## Usage

From the content-packs repository:

```bash
# Live mode: records at wall-clock time
eventum generate --path generators/network-stormshield-sns/generator.yml --id stormshield --live-mode true

# Batch mode
eventum generate --path generators/network-stormshield-sns/generator.yml --id stormshield --live-mode false
```

Output: `generators/network-stormshield-sns/output/events.json`. Extract `event.original` when a collector expects the native key-value line. The pattern files start today at 00:00 and never end; for a finite batch window set `oscillator.start` to a midnight (for example `"2026-09-01T00:00:00Z"`) and `oscillator.end` in all three files under `patterns/`.

Performance: about 2,000 records per second in batch mode (14 days, 84,500 records, in 41 s).

## Sample output

The final step of an episode (bulk SSH transfer after alarms for three different servers), copied byte for byte from the default anomaly-mode capture:

```json
{"@timestamp": "2026-09-02T16:46:59+00:00", "destination": {"bytes": 363275464, "domain": "srv_app02", "ip": "10.20.0.12", "port": 22}, "ecs": {"version": "8.17.0"}, "event": {"action": "connection_closed", "category": ["network"], "dataset": "stormshield.sns", "duration": 11168025732, "end": "2026-09-02T16:46:59+00:00", "kind": "event", "original": "id=firewall time=\"2026-09-02 16:46:59\" fw=\"sns-fw-01\" tz=+0000 startime=\"2026-09-02 16:46:48\" pri=5 confid=01 slotlevel=2 ruleid=5 srcif=\"Ethernet1\" srcifname=\"in\" ipproto=tcp proto=ssh src=10.10.5.13 srcport=14255 srcportname=ephemeral_fw srcname=adm_ws03 dst=10.20.0.12 dstport=22 dstportname=ssh dstname=srv_app02 modsrc=10.10.5.13 modsrcport=14255 origdst=10.20.0.12 origdstport=22 ipv=4 sent=9533853 rcvd=363275464 duration=11.16 action=pass logtype=\"connection\"", "start": "2026-09-02T16:46:48+00:00", "type": ["connection", "end", "allowed"]}, "network": {"bytes": 372809317, "protocol": "ssh", "transport": "tcp", "type": "ipv4"}, "observer": {"ingress": {"interface": {"id": "Ethernet1", "name": "in"}}, "name": "sns-fw-01", "product": "SNS", "type": "firewall", "vendor": "Stormshield"}, "related": {"hosts": ["adm_ws03", "srv_app02"], "ip": ["10.10.5.13", "10.20.0.12"]}, "rule": {"id": "5"}, "source": {"bytes": 9533853, "ip": "10.10.5.13", "port": 14255}, "stormshield": {"sns": {"action": "pass", "confid": "01", "logtype": "connection", "priority": 5, "slotlevel": 2}}}
```

## Limitations

- Two log families only: `l_alarm` (alarm 85) and `l_connection`. Filter, authentication, web, VPN and system logs, other alarms and blocked traffic are out of scope.
- The vendor publishes one complete raw alarm line (alarm 85); the `l_connection` layout follows the field reference and lab syslog captures from the Elastic integration test fixtures. `logtype="..."` is the family field of the syslog export and is not part of the on-disk WELF files. No syslog header is added.
- That alarm 85 is raised for interactive sessions and not for scp-style transfers is a modelling assumption; the documentation does not describe the trigger.
- No address translation is modelled (`modsrc`/`origdst` equal `src`/`dst`); `tz=+0000`, local time equals UTC.
- Records that fall due together are written one after another over the following seconds, so an admin session can be logged a few seconds late (median about 30 s and occasionally several minutes at night) and its `duration` includes that wait.
- Host names, addresses, rule numbers, rates and volumes are synthetic. SNS 5.x is not claimed.
- An ordinary SSH transfer of 100 MiB or more that would complete the chain (about 13 a day) carries a smaller volume but keeps its original duration, so these transfers show a low throughput.
- With `anomaly_mode: true` each episode adds its own records, so alarm 85, SSH connection records and transfers of 100 MiB or more are each a few per episode higher than with `false`.

## References

- [Stormshield SNS v4: Understanding audit logs (WELF layout, alarm 85 example)](https://documentation.stormshield.eu/SNS/v4/en/Content/Description_of_Audit_logs/Understand_log_files.htm)
- [Stormshield SNS v4: audit log fields (A-Z pages)](https://documentation.stormshield.eu/SNS/v4/en/Content/Description_of_Audit_logs/Fields-S.htm)
- [Stormshield SNS v4: specific fields (fw, time, startime, tz)](https://documentation.stormshield.eu/SNS/v4/en/Content/Description_of_Audit_logs/Specific-Fields.htm)
- [Stormshield SNS v4 CLI: CONFIG SECURITYINSPECTION CONFIG ALARM LIST](https://documentation.stormshield.eu/SNS/v4/en/Content/CLI_Serverd_Commands_reference_Guide_v4/Commands/serverd/CONFIG.SECURITYINSPECTION.CONFIG.ALARM.LIST.htm)
- [Elastic integration: Stormshield SNS](https://www.elastic.co/docs/reference/integrations/stormshield)
