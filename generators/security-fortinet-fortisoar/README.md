# Fortinet FortiSOAR Alert Deletion Audit

Generates FortiSOAR 7.x audit records for deleted alerts, as FortiSOAR forwards them to a syslog server in CEF, for SOC teams and SIEM engineers who monitor who removes alerts from their SOAR platform. Each record is ECS JSON with the forwarded syslog line in `event.original`.

Eight analysts delete alerts from the FortiSOAR grid independently of each other. Each analyst starts work sessions at random times, more often during the day (peak around 12:30 UTC) and with a busier or quieter activity level per day. A session is a few deletions, one to a few alerts at a time, seconds to many minutes apart, and no analyst makes more than eight ordinary deletions from one address within two minutes. One delete of several selected alerts writes one record per alert, milliseconds apart. An analyst works from the office address or, for some sessions, from a remote-access address.

## Event Types

Shares measured on the final 10-day default-configuration capture (`anomaly_mode: true`, 2446 records).

| CEF event class | Operation | Share | Category |
| --- | --- | ---: | --- |
| `Alert Deleted` | Delete an alert record | 100% | configuration / deletion |

The pack covers one audit class: Fortinet publishes a complete forwarded line only for `Alert Deleted`. Other record types and operations (create, update, link, login) are not generated.

## Anomaly Chain

A mass deletion: one analyst, from one address, deletes at least nine alerts within two minutes.

1. The chain starts on an ordinary work session of analyst A.
2. On top of that session's own deletions, A deletes 10-15 more alerts in quick successive deletes (one to a few alerts each, 2-40 s apart), all within about 100 seconds.

The records share `user.name`, `user.id` and `source.ip`; every record deletes a different alert (`fortinet.fortisoar.alert_id`). Deleted alerts are not restored: FortiSOAR audits restores from the recycle bin, but Fortinet publishes no forwarded format for them.

**Recurrence.** One chain is due per `anomaly_interval_hours` (default 24, minimum 6) of source time. The first becomes due at a random point within the first interval; each next one is due one interval after the actual start of the previous chain. After it is due, a random delay of up to `min(interval / 4, 6 h)` passes, weighted by the daytime shape of the sessions with a small night floor, so every hour stays possible; the chain then starts on the next session of an analyst other than the previous chain's. Missed chains are not caught up. Measured gaps: 24.1-31.4 h at the default 24 h (8 chains over 10 days), 12.5-15.6 h at 12 h (17 chains over 10 days). Because the delay window is short, chain hours follow the daytime curve only loosely: at a fixed interval the start drifts around the clock, and night chains are more common than night deletions in the background.

**Variation.** The analyst is whoever starts the next session, so analysts are weighted like the background, except that the same analyst never gets two chains in a row. The address is that session's address (office or remote access). Deletion count, spacing and alerts are drawn per chain.

**Background.** Both modes contain everything the chain uses: every analyst and analyst/address pair, deletes of several alerts at once, quick successive deletes, and up to eight deletions by one analyst within two minutes (five or more in most captures). Ordinary work stays below the chain by pacing, not by changing actors: an analyst who has made eight ordinary deletions from one address in the last two minutes pauses: the rest of that delete moves later by an ordinary gap between deletes (actor, address and alerts unchanged), and later deletes of the session keep their times unless they too would be the ninth. Sessions are small enough that this pause is rarely needed. Measured on seven 10-day off captures: sessions (one analyst and address, deletions at most 10 minutes apart) peak at 1, 2, 3, 4, 5, 6, 7 and 8 deletions within two minutes in about 180, 155, 110, 65, 30, 15, 6 and 5 sessions per capture, none at 9; nine within 132 seconds occurs 0-4 times and within 180 seconds 1-8 times per capture. No deletion is attributed to an analyst other than the one whose session planned it.

**Detection idea.** Count `Alert Deleted` records per `suser` and `src`: nine or more within 120 seconds.

`anomaly_mode: true` is the default. With `false` the generator emits only the realistic background, with no complete chain.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`.

| Name | Default | Description |
| --- | --- | --- |
| `anomaly_mode` | `true` | Emit the anomaly chain on top of the background. |
| `anomaly_interval_hours` | `24` | Source-time interval between chain due times; range `6`-`8760`. |
| `sessions_per_day` | `60` | Average number of analyst work sessions per day, all analysts together (`2`-`2000`). |
| `alerts_per_day` | `900` | Rate at which alert IDs grow; deletions pick recent alerts below the current ID (`50`-`1000000`). |
| `device_name` | `fsrprimary` | Syslog hostname of the FortiSOAR node. |
| `device_id` | `FSRVMPTM20000061` | `devid`, the FortiSOAR serial number from the license. |
| `device_version` | `7.0.0` | CEF device version, as in Fortinet's sample. |
| `virtual_domain` | `enterprise` | `vd`: `enterprise`, `master` or `tenant`. |

Analysts, their user UUIDs, office and remote-access addresses and activity weights are in `samples/analysts.json`.

### Output Parameters

The shipped file output needs no parameters. To send events elsewhere, replace `output.file` with another output plugin and put destination values in `${params.*}` (hosts, ports) and `${secrets.*}` (credentials) placeholders, supplied at run time. A CEF or syslog collector needs the value of `event.original`, not the enclosing ECS JSON.

## Usage

```bash
eventum generate --path generators/security-fortinet-fortisoar/generator.yml --id fortisoar --live-mode true
```

For a batch run, add `start` and `end` to the `cron` input and run with `--live-mode false`:

```bash
eventum generate --path generators/security-fortinet-fortisoar/generator.yml --id fortisoar --live-mode false
```

Output: `output/events.json`, one JSON event per line.

## Sample Output

The first record of an anomaly chain (Marco Bellini, office address) from the final default-configuration capture, line 941:

```json
{"@timestamp": "2026-03-06T09:23:32.085+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "alert_deleted", "category": ["configuration"], "code": "Alert Deleted", "created": "2026-03-06T09:23:32.106044+00:00", "dataset": "fortinet.fortisoar.audit", "kind": "event", "original": "2026-03-06T09:23:32.106044+00:00 fsrprimary fortisoar-audit-log: CEF:0|Fortinet Inc|FortiSOAR|7.0.0|Alert Deleted|Alert Deleted|1|devid=\"FSRVMPTM20000061\" vd=\"enterprise\" level=\"warning\" type=\"Audit Log\" msg=\"Alert [150926] Deleted \" src=\"10.30.4.37\" suid=\"9446b38d-318b-4647-a109-e15432fa9365\" suser=\"Marco Bellini\" end=1772789012085 playbookName=\"\" playbookId=\"\" eventTimeStr=\"06 Mar 2026 09:23:32.085\"", "severity": 1, "type": ["deletion"]}, "fortinet": {"fortisoar": {"alert_id": 150926, "device_id": "FSRVMPTM20000061", "log_type": "Audit Log", "operation": "Delete", "record_type": "Alert", "virtual_domain": "enterprise"}}, "log": {"level": "warning", "logger": "fortisoar-audit-log"}, "observer": {"hostname": "fsrprimary", "product": "FortiSOAR", "serial_number": "FSRVMPTM20000061", "vendor": "Fortinet", "version": "7.0.0"}, "related": {"ip": ["10.30.4.37"], "user": ["Marco Bellini"]}, "source": {"ip": "10.30.4.37"}, "user": {"id": "9446b38d-318b-4647-a109-e15432fa9365", "name": "Marco Bellini"}}
```

## Limitations

- Fortinet publishes one complete forwarded audit line, for `Alert Deleted` (identical in the 7.2.0 and 7.6.5 administration guides). The record keeps its CEF header and all twelve extension keys in the sample's order. The number in `msg="Alert [<n>] Deleted "` is treated as the alert ID; the guide calls this part the record title, and the sample does not show which one it is.
- `playbookName` and `playbookId` stay empty: deletions by playbooks are not modelled, since the sample does not show how FortiSOAR fills them.
- The syslog header time is the forwarding time, a fraction of a second after the audit time in `end`/`eventTimeStr`; the sample shows a larger difference that the guide does not explain. Times are UTC. Only the Basic audit detail level is modelled; Fortinet publishes no Detailed sample.
- The input ticks every 2 seconds and each tick emits at most one record. Record times come from the planned deletion times, so in live mode a multi-alert delete is written a few seconds after its timestamps.
- Rates, weights, delays and analyst names are synthetic lab settings.

## References

- [FortiSOAR 7.2.0 Administration Guide: System configuration, Log Forwarding and Audit Log](https://docs.fortinet.com/document/fortisoar/7.2.0/administration-guide/304946)
- [FortiSOAR 7.6.5 Administration Guide: Audit Log](https://docs.fortinet.com/document/fortisoar/7.6.5/administration-guide/34876/audit-log)
- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782) (lists a Syslog-CEF normalizer for FortiSOAR; compatibility with this stream is untested)
