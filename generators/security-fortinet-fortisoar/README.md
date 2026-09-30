# Fortinet FortiSOAR Alert Deletion Audit

Generates FortiSOAR 7.x audit records for deleted alerts, as FortiSOAR forwards them to a syslog server in CEF, for SOC teams and SIEM engineers who monitor who removes alerts from their SOAR platform. Each record is ECS JSON with the forwarded syslog line in `event.original`.

Sixty-four analysts of a large, round-the-clock SOC delete alerts from the FortiSOAR grid independently of each other, in work sessions that are more frequent during the day. A session is a few deletions, one to a few alerts at a time, seconds to many minutes apart, and no analyst makes more than eight ordinary deletions from one address within two minutes. One delete of several selected alerts writes one record per alert, milliseconds apart. An analyst works from the office address or, for some sessions, from a remote-access address.

## Event Types

| CEF event class | Operation | Share | Category |
| --- | --- | ---: | --- |
| `Alert Deleted` | Delete an alert record | 100% | configuration / deletion |

The pack covers one audit class: Fortinet publishes a complete forwarded line only for `Alert Deleted`. Other record types and operations (create, update, link, login) are not generated.

## Volume and Timing

About 2,940 deletions a day (2,720-3,130 on individual days), UTC:

| UTC hours | Deletions per hour |
| --- | ---: |
| 00:00-06:00 | about 60 |
| 06:00-09:00 | 88, 126, 167 |
| 09:00-16:00 | about 215-220 |
| 16:00-19:00 | 165, 124, 85 |
| 19:00-24:00 | about 60 |

- Analysts: each makes between 0.6% and 3.7% of the deletions (Priya Raman is the busiest); each is busier on some days and quieter on others.
- Addresses: 85% of sessions come from the analyst's office address, 15% from the analyst's remote-access address; a session keeps its address.
- Deletes: 71% select one alert, 22% two, 5% three, the rest four or more. Records of one delete are about 0.2 seconds apart (0.46 s at the 90th percentile); the selected alerts sit close together in the grid, recent ones below the current alert ID.
- Deletes of one session follow each other after 4 seconds to 25 minutes (about two minutes typically).
- No alert is deleted twice.

## Anomaly Chain

A mass deletion: one analyst, from one address, deletes nine alerts within two minutes.

1. The chain starts on an ordinary work session of analyst A.
2. On top of that session's own deletions, A deletes more alerts in quick successive deletes (one to a few alerts each, 2-40 s apart), until A has deleted nine alerts from that address within 120 seconds. The session's own deletions in those two minutes count toward the nine.
3. A then continues the session at the ordinary pace.

The records share `user.name`, `user.id` and `source.ip`; every record deletes a different alert (`fortinet.fortisoar.alert_id`). Deleted alerts are not restored: FortiSOAR audits restores from the recycle bin, but Fortinet publishes no forwarded format for them.

**Recurrence.** One chain is due per `anomaly_interval_hours` (default 24, minimum 6) of source time. The first chain starts within the first `min(interval, 24 h)`, at an hour drawn from the daily curve of deletions. Each next chain is due one interval after the actual start of the previous one and starts within `min(interval / 8, 3 h)` before or after that due time, at an hour weighted by the square of the daily curve with a small floor, so every hour stays possible. Missed chains are not caught up. At the default interval the gaps between chains are about 21-27 hours; at 12 hours they are about 10.5-13.5 hours.

**Variation.** The analyst is drawn with the same weights as ordinary sessions, except that the same analyst never gets two chains in a row. The address is the office address or, for the ten most active analysts (each at least 2.4% of the deletions), the remote-access address, with the same odds as their ordinary sessions. Deletion sizes, spacing and alerts are drawn per chain.

**Background.** Both modes contain everything the chain uses: every analyst and every analyst/address pair a chain can use, deletes of several alerts at once, quick successive deletes, and bursts of up to eight deletions by one analyst from one address within two minutes. Across all analysts, about five sessions a day reach eight deletions within two minutes, eight reach seven and eighteen reach six; none reaches nine. After eight deletions from one address within two minutes, an analyst's next deletion comes after an ordinary gap between deletes.

**Detection idea.** Count `Alert Deleted` records per `suser` and `src`: nine or more within 120 seconds.

`anomaly_mode: true` is the default. With `false` the generator emits only the realistic background, with no complete chain.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`.

| Name | Default | Description |
| --- | --- | --- |
| `anomaly_mode` | `true` | Emit the anomaly chain on top of the background. |
| `anomaly_interval_hours` | `24` | Source-time interval between chain due times; range `6`-`8760`. |
| `alerts_per_day` | `10800` | Rate at which alert IDs grow; deletions pick recent alerts below the current ID (`50`-`1000000`). |
| `device_name` | `fsrprimary` | Syslog hostname of the FortiSOAR node. |
| `device_id` | `FSRVMPTM20000061` | `devid`, the FortiSOAR serial number from the license. |
| `device_version` | `7.0.0` | CEF device version, as in Fortinet's sample. |
| `virtual_domain` | `enterprise` | `vd`: `enterprise`, `master` or `tenant`. |

Analysts, their user UUIDs, office and remote-access addresses and activity weights are in `samples/analysts.json`.

### Output Parameters

The shipped file output needs no parameters. To send events elsewhere, replace `output.file` with another output plugin and put destination values in `${params.*}` (hosts, ports) and `${secrets.*}` (credentials) placeholders, supplied at run time. A CEF or syslog collector needs the value of `event.original`, not the enclosing ECS JSON.

## Usage

Live generation at the configured volume:

```bash
eventum generate --path generators/security-fortinet-fortisoar/generator.yml --id fortisoar --live-mode true
```

Batch generation: set `start` and `end` of the `oscillator` in all five `patterns/*.yml` files to the same range, with `start` at 00:00 UTC so the hour bands stay in place (for example `start: "2026-03-02T00:00:00Z"` and `end: "2026-03-06T00:00:00Z"`), then run:

```bash
eventum generate --path generators/security-fortinet-fortisoar/generator.yml --id fortisoar --live-mode false --keep-order true
```

Output: `output/events.json`, one JSON event per line.

The hour curve is the sum of five `time_patterns` files under `patterns/`: `around-the-clock` (00-24 UTC) and the day bands `day-06-19`, `day-07-18`, `day-08-17` and `day-09-16`. To change the volume, scale the `ratio` of every pattern file and `alerts_per_day` by the same factor; a higher volume makes every analyst proportionally busier, so add analysts to `samples/analysts.json` for a larger team. Chain start hours follow the shipped curve even if you reshape the pattern files.

In live mode a record is written at or after its own time, never before it. Several records of one delete or of a quick run of deletes are written one after another, so at the shipped volume records reach the output typically about a minute after their time and rarely more than a quarter of an hour after it; a lower volume lengthens the delay.

Performance: about 1,200 events per second in batch mode on one core.

## Sample Output

The ninth deletion of an anomaly chain (Nadia Benali, office address) from a default run:

```json
{"@timestamp": "2026-03-02T06:17:57.292+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "alert_deleted", "category": ["configuration"], "code": "Alert Deleted", "created": "2026-03-02T06:17:57.488412+00:00", "dataset": "fortinet.fortisoar.audit", "kind": "event", "original": "2026-03-02T06:17:57.488412+00:00 fsrprimary fortisoar-audit-log: CEF:0|Fortinet Inc|FortiSOAR|7.0.0|Alert Deleted|Alert Deleted|1|devid=\"FSRVMPTM20000061\" vd=\"enterprise\" level=\"warning\" type=\"Audit Log\" msg=\"Alert [223758] Deleted \" src=\"10.30.2.190\" suid=\"5494f6a2-d621-4d4d-8e2d-786696290a61\" suser=\"Nadia Benali\" end=1772432277292 playbookName=\"\" playbookId=\"\" eventTimeStr=\"02 Mar 2026 06:17:57.292\"", "severity": 1, "type": ["deletion"]}, "fortinet": {"fortisoar": {"alert_id": 223758, "device_id": "FSRVMPTM20000061", "log_type": "Audit Log", "operation": "Delete", "record_type": "Alert", "virtual_domain": "enterprise"}}, "log": {"level": "warning", "logger": "fortisoar-audit-log"}, "observer": {"hostname": "fsrprimary", "product": "FortiSOAR", "serial_number": "FSRVMPTM20000061", "vendor": "Fortinet", "version": "7.0.0"}, "related": {"ip": ["10.30.2.190"], "user": ["Nadia Benali"]}, "source": {"ip": "10.30.2.190"}, "user": {"id": "5494f6a2-d621-4d4d-8e2d-786696290a61", "name": "Nadia Benali"}}
```

## Limitations

- Fortinet publishes one complete forwarded audit line, for `Alert Deleted` (identical in the 7.2.0 and 7.6.5 administration guides). The record keeps its CEF header and all twelve extension keys in the sample's order. The number in `msg="Alert [<n>] Deleted "` is treated as the alert ID; the guide calls this part the record title, and the sample does not show which one it is.
- `playbookName` and `playbookId` stay empty: deletions by playbooks are not modelled, since the sample does not show how FortiSOAR fills them.
- The syslog header time is the forwarding time, a fraction of a second after the audit time in `end`/`eventTimeStr`; the sample shows a larger difference that the guide does not explain. Times are UTC. Only the Basic audit detail level is modelled; Fortinet publishes no Detailed sample.
- Weekends look like weekdays: the volume follows the same daily curve every day.
- A chain is exactly nine deletions within two minutes; a real mass deletion may go on longer.
- Chains start mostly during the working day: nearly all between 06:00 and 18:00 UTC, against about 74% of ordinary deletions.
- With `anomaly_mode: true` the daily volume stays the same, so a chain's few extra deletions replace ordinary ones: in the hour after a chain the other analysts delete about 5% fewer alerts than usual (about as many as the chain itself); later hours are unchanged.
- Rates, weights, delays and analyst names are synthetic lab settings.

## References

- [FortiSOAR 7.2.0 Administration Guide: System configuration, Log Forwarding and Audit Log](https://docs.fortinet.com/document/fortisoar/7.2.0/administration-guide/304946)
- [FortiSOAR 7.6.5 Administration Guide: Audit Log](https://docs.fortinet.com/document/fortisoar/7.6.5/administration-guide/34876/audit-log)
- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782) (lists a Syslog-CEF normalizer for FortiSOAR; compatibility with this stream is untested)
