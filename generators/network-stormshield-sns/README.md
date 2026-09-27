# Stormshield SNS audit logs

Stormshield Network Security (SNS v4) audit records of one firewall that separates office workstations from a server segment: IPS alarm 85 ("Interactive connection detected") from the `l_alarm` log and closed-connection records from the `l_connection` log. Eventum emits ECS JSON and keeps the native WELF key-value body, as the firewall forwards it over syslog, in `event.original`.

## Event types covered

Shares measured on a 78-hour default capture (anomaly mode on, 18,760 records).

| Log | Record | `event.action` | Share | ECS category |
| --- | --- | --- | --- | --- |
| `l_connection` | HTTPS connection closed (`proto=https`, port 443) | `connection_closed` | 51.5% | network |
| `l_connection` | SSH connection closed (`proto=ssh`, port 22) | `connection_closed` | 17.7% | network |
| `l_alarm` | Alarm 85, interactive SSH connection detected (`action=pass`) | `interactive_connection_detected` | 16.3% | network, intrusion_detection |
| `l_connection` | HTTP connection closed (`proto=http`, port 80) | `connection_closed` | 10.5% | network |
| `l_connection` | NTP exchange with the firewall (`ipproto=udp`, port 123) | `connection_closed` | 4.0% | network |

Traffic is modelled as independent random processes, not measured SNS rates:

- **Admin workstations** (`10.10.5.11` and up, host objects `adm_ws01`...) run SSH work tasks as a merged random stream, busier in office hours and weighted per workstation. A task opens one to six sessions, spaced by random gaps, to servers from the workstation's own set of 6-11 servers; about 8% of sessions are scp-style transfers whose received volume is log-normal around 60 MB, so transfers of 100 MB and more occur in ordinary traffic.
- An interactive session produces alarm 85 at its start and an `l_connection` record when it closes (`startime` = session start, `time` = close, `duration`, `sent`, `rcvd`). A transfer session produces the connection record only.
- **Office workstations** (`10.10.1.20` and up, no host object) and admin workstations reach internal web servers over HTTPS and HTTP and synchronise time with the firewall.

## Anomaly Chain

One admin workstation opens interactive SSH sessions to three different servers and then pulls a bulk transfer of 100 MB or more over SSH:

| Step | Record | Condition |
| --- | --- | --- |
| 1 | `l_alarm`, `alarmid=85` | source S to server A |
| 2 | `l_alarm`, `alarmid=85` | source S to server B, B different from A |
| 3 | `l_alarm`, `alarmid=85` | source S to server C, C different from A and B |
| 4 | `l_connection`, `proto=ssh` | source S, `rcvd` (`destination.bytes`) >= 104857600 |

- **Linking fields:** `source.ip` (`src`), `destination.ip` (`dst`), `network.protocol`, `destination.bytes` (`rcvd`), time. The whole sequence spans at most one hour; measured spans are 6-15 minutes with the default interval and 2-14 minutes with a 6-hour interval.
- **Recurrence:** one episode per `anomaly_interval_hours` of source time (default 24, minimum 2). When an episode is due, it starts after a random delay that follows the same day curve as admin work (mean about 18 minutes in office hours, 40 minutes in the evening, 2 hours at night). The next episode is due one interval after the actual start; missed intervals are not caught up.
- **Variation:** the workstation is drawn with the same per-workstation weights as ordinary admin work and differs from the previous episode; servers are drawn from that workstation's own server set with its own weights, so every workstation/server pair of an episode also occurs in ordinary traffic. Session gaps, durations and volumes come from the ordinary distributions.
- **Background overlap:** alarm 85 to three or more different servers within an hour, transfers of 100 MB and more, and transfers after sessions to two servers all occur in ordinary traffic in both modes. Only the complete order is reserved: an ordinary transfer of 100 MB or more that closes within about 67 minutes after the same source's alarms for three different servers carries a smaller volume instead.
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
| `admin_count` | `12` | Admin workstations (4-60), `10.10.5.11` upwards. |
| `user_count` | `40` | Office workstations (10-200), `10.10.1.20` upwards. |

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
# Live mode, one tick per second
eventum generate --path generators/network-stormshield-sns/generator.yml --id stormshield --live-mode true

# Batch mode over the cron window
eventum generate --path generators/network-stormshield-sns/generator.yml --id stormshield --live-mode false
```

Output: `generators/network-stormshield-sns/output/events.json`. Extract `event.original` when a collector expects the native key-value line. A batch run needs `start` and `end` on the `cron` input to bound the window.

## Sample output

The final step of an episode (bulk SSH transfer after alarms for three different servers), copied from the default anomaly-mode capture:

```json
{"@timestamp": "2026-09-27T04:51:09+00:00", "destination": {"bytes": 200593679, "domain": "srv_k8s03", "ip": "10.20.0.93", "port": 22}, "ecs": {"version": "8.17.0"}, "event": {"action": "connection_closed", "category": ["network"], "dataset": "stormshield.sns", "duration": 3267236206, "end": "2026-09-27T04:51:09+00:00", "kind": "event", "original": "id=firewall time=\"2026-09-27 04:51:09\" fw=\"sns-fw-01\" tz=+0000 startime=\"2026-09-27 04:51:05\" pri=5 confid=01 slotlevel=2 ruleid=5 srcif=\"Ethernet1\" srcifname=\"in\" ipproto=tcp proto=ssh src=10.10.5.21 srcport=34939 srcportname=ephemeral_fw srcname=adm_ws11 dst=10.20.0.93 dstport=22 dstportname=ssh dstname=srv_k8s03 modsrc=10.10.5.21 modsrcport=34939 origdst=10.20.0.93 origdstport=22 ipv=4 sent=5780117 rcvd=200593679 duration=3.27 action=pass logtype=\"connection\"", "start": "2026-09-27T04:51:05+00:00", "type": ["connection", "end", "allowed"]}, "network": {"bytes": 206373796, "protocol": "ssh", "transport": "tcp", "type": "ipv4"}, "observer": {"ingress": {"interface": {"id": "Ethernet1", "name": "in"}}, "name": "sns-fw-01", "product": "SNS", "type": "firewall", "vendor": "Stormshield"}, "related": {"hosts": ["adm_ws11", "srv_k8s03"], "ip": ["10.10.5.21", "10.20.0.93"]}, "rule": {"id": "5"}, "source": {"bytes": 5780117, "ip": "10.10.5.21", "port": 34939}, "stormshield": {"sns": {"action": "pass", "confid": "01", "logtype": "connection", "priority": 5, "slotlevel": 2}}}
```

## Limitations

- Two log families only: `l_alarm` (alarm 85) and `l_connection`. Filter, authentication, web, VPN and system logs, other alarms and blocked traffic are out of scope.
- The vendor publishes one complete raw alarm line (alarm 85); the `l_connection` layout follows the field reference and lab syslog captures from the Elastic integration test fixtures. `logtype="..."` is the family field of the syslog export and is not part of the on-disk WELF files. No syslog header is added.
- That alarm 85 is raised for interactive sessions and not for scp-style transfers is a modelling assumption; the documentation does not describe the trigger.
- No address translation is modelled (`modsrc`/`origdst` equal `src`/`dst`); `tz=+0000`, local time equals UTC. At most one record per second.
- Host names, addresses, rule numbers, rates and volumes are synthetic. SNS 5.x is not claimed.
- An ordinary SSH transfer of 100 MB or more that would complete the chain carries a smaller volume but keeps its original duration, so these rare transfers show a low throughput. Gaps between the sessions of one episode are capped at 15 minutes, while ordinary admin gaps are not.

## References

- [Stormshield SNS v4: Understanding audit logs (WELF layout, alarm 85 example)](https://documentation.stormshield.eu/SNS/v4/en/Content/Description_of_Audit_logs/Understand_log_files.htm)
- [Stormshield SNS v4: audit log fields (A-Z pages)](https://documentation.stormshield.eu/SNS/v4/en/Content/Description_of_Audit_logs/Fields-S.htm)
- [Stormshield SNS v4: specific fields (fw, time, startime, tz)](https://documentation.stormshield.eu/SNS/v4/en/Content/Description_of_Audit_logs/Specific-Fields.htm)
- [Stormshield SNS v4 CLI: CONFIG SECURITYINSPECTION CONFIG ALARM LIST](https://documentation.stormshield.eu/SNS/v4/en/Content/CLI_Serverd_Commands_reference_Guide_v4/Commands/serverd/CONFIG.SECURITYINSPECTION.CONFIG.ALARM.LIST.htm)
- [Elastic integration: Stormshield SNS](https://www.elastic.co/docs/reference/integrations/stormshield)
