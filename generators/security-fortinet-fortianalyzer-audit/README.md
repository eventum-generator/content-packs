# Fortinet FortiAnalyzer Incident Audit

Generates FortiAnalyzer 7.2.4 local application event (`type=appevent subtype=incident`) records for SOC teams and SIEM engineers who need incident-management audit trails. Each record is ECS JSON with the FortiAnalyzer key-value line in `event.original`. This is FortiAnalyzer's own incident audit log, not FortiGate traffic forwarded through it.

Incidents arrive at a rate that peaks in the afternoon (UTC). About 62% are raised by playbooks (`user=system`), the rest by one of eight analysts. Each incident gets its own random lifecycle: evidence attachments, analyst work sessions of one to several operations seconds to minutes apart, occasional attachment removal, and deletion of about one incident in five, from minutes to days after creation.

## Event Types

Shares measured on the final 10-day default-configuration capture (`anomaly_mode: true`, 1754 records).

| Fortinet message | Message ID | Share | Category |
| --- | --- | ---: | --- |
| `Incident_Update` | `100002` | 32.6% | configuration / change |
| `Incident_Attachment_Add` | `100005` | 31.9% | configuration / change |
| `New_Incident_Create` | `100001` | 21.4% | configuration / creation |
| `Incident_Attachment_Delete` | `100006` | 8.7% | configuration / change |
| `Incident_Delete` | `100003` | 5.4% | configuration / deletion |

All five IDs are the Information-level `APPEVENT` / `INCIDENT` messages of the Fortinet 7.2.4 log reference. The error variants (`110001`-`110006`) and `Incident_Attachment_Update` (`100004`) are not generated.

## Anomaly Chain

One analyst raises an incident and attaches evidence; another analyst removes the evidence and deletes the incident:

1. `New_Incident_Create` by analyst C. Playbook-raised incidents (`user=system`) are outside the chain: an analyst removing evidence from and deleting a playbook incident is the ordinary way to close a false positive.
2. `Incident_Attachment_Add` by C, with the same delay as ordinary first attachments.
3. Some minutes later analyst D (D is not C) opens the incident: optionally an `Incident_Update`, then `Incident_Attachment_Delete` of that attachment.
4. `Incident_Delete` by D seconds to minutes later.

The records share `fortinet.fortianalyzer.incident_id`; steps 2 and 3 share `fortinet.fortianalyzer.attachment`; steps 3 and 4 share `user.name`. `source.ip` is D's current address; like every analyst, D keeps one address (office or remote access) for minutes to hours before possibly switching, so steps 3 and 4 usually, but not always, share it. The whole chain completes within 100 minutes of creation. Deletion is final: FortiAnalyzer logs no restore of a deleted incident, so nothing is restored.

**Recurrence.** One chain per `anomaly_interval_hours` (default 24, minimum 6) of source time. The first becomes due between 0.3 and 1.0 intervals after the start; each next one is due one interval after the actual start of the previous chain. After it is due, a random delay of up to `min(1 h, interval / 8)` passes, and the chain starts on the next incident an analyst raises through the ordinary arrival process, so its hour of day and creator follow the analyst-raised background. Missed chains are not caught up.

**Variation.** C is the analyst who raises that incident; D is drawn by the analysts' ordinary activity weights, never C and never the previous chain's D. The incident, attachment, severity and all delays are drawn per chain.

**Background.** Every action, actor, severity and actor/address pair of the chain also occurs in ordinary traffic in both modes: incidents deleted within minutes, attachments removed by an analyst other than the creator, removal followed by deletion by the same analyst, and handovers where one analyst removes the evidence and a colleague deletes the incident minutes later. A deletion is done by the assignee (the creator on an analyst-raised incident) in 60% of cases, otherwise by a colleague; the removal before it is usually the deleter's own, but when a colleague deletes an analyst-raised incident the evidence was mostly removed by the creator (50%) or a third analyst (35%). Playbook incidents keep their natural lifecycle. On analyst-raised incidents only the final step is guarded: if the first analyst other than the creator to remove an attachment would also delete the incident within two hours, that deletion keeps its time but is redrawn by the ordinary deleter rule until it is someone else. The removal and all other operations stay. As a result, a non-creator who removed evidence and then deletes the analyst-raised incident never does so within two hours in the background, and rarely after two hours.

**Detection idea.** Join by incident ID: creation by an analyst C (not `system`), an attachment added, an attachment removed by D different from C, and deletion by D within two hours.

`anomaly_mode: true` is the default. With `false` the generator emits only the realistic background, with no complete chain.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`.

| Name | Default | Description |
| --- | --- | --- |
| `anomaly_mode` | `true` | Emit the anomaly chain on top of the background. |
| `anomaly_interval_hours` | `24` | Source-time interval between chain starts; minimum `6`. |
| `incidents_per_day` | `36` | Average number of incidents raised per day. |
| `analyzer_serial` | `FAZ-VMTM26001234` | `devid` of the FortiAnalyzer unit. |
| `analyzer_name` | `faz-soc-01` | `devname` of the FortiAnalyzer unit. |
| `adom` | `root` | `vd` and `adom` values. |

Analysts, their workstation and remote-access addresses and activity weights are in `samples/analysts.json`.

### Output Parameters

The shipped file output needs no parameters. To send events elsewhere, replace `output.file` with another output plugin and put destination values in `${params.*}` (hosts, ports) and `${secrets.*}` (credentials) placeholders, supplied at run time.

## Usage

```bash
eventum generate --path generators/security-fortinet-fortianalyzer-audit/generator.yml --id faz-audit --live-mode true
```

For a batch run, add `start` and `end` to the `cron` input and run with `--live-mode false`:

```bash
eventum generate --path generators/security-fortinet-fortianalyzer-audit/generator.yml --id faz-audit --live-mode false
```

Output: `output/events.json`, one JSON event per line.

## Sample Output

An `Incident_Attachment_Delete` record from the final default-configuration capture (anomaly chain step 3), line 38:

```json
{"@timestamp": "2026-09-01T11:17:55+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "Incident_Attachment_Delete", "category": ["configuration"], "code": "100006", "dataset": "fortinet.fortianalyzer.appevent", "kind": "event", "original": "id=7680524551845518376 itime=2026-09-01 11:17:55 euid=1 epid=1 dsteuid=1 dstepid=1 vd=root logid=100006 type=appevent subtype=incident level=information date=2026-09-01 time=11:17:55 user=gpetrov user_from=GUI(10.20.6.8) desc=Incident_Attachment_Delete msg=Attachment deleted from incident IN00000621 incident_id=IN00000621 incident_severity=critical attachment=202609011000050736 adom=root devid=FAZ-VMTM26001234 devname=faz-soc-01 dtime=2026-09-01 11:17:55 itime_t=1788261475", "outcome": "success", "type": ["change"]}, "fortinet": {"fortianalyzer": {"adom": "root", "attachment": "202609011000050736", "desc": "Incident_Attachment_Delete", "incident_id": "IN00000621", "incident_severity": "critical", "level": "information", "logid": "100006", "subtype": "incident", "type": "appevent", "user_from": "GUI(10.20.6.8)"}}, "observer": {"name": "faz-soc-01", "product": "FortiAnalyzer", "serial_number": "FAZ-VMTM26001234", "type": "siem", "vendor": "Fortinet"}, "related": {"ip": ["10.20.6.8"], "user": ["gpetrov"]}, "source": {"ip": "10.20.6.8"}, "user": {"name": "gpetrov"}}
```

## Limitations

- Fortinet publishes the `INCIDENT` field catalog and message IDs but no complete raw incident record. The raw line copies the header and trailer layout of the one complete 7.2.4 application log example (a `playbook` record): `id` carries `itime_t` in its upper 32 bits, `dtime` equals `itime`, and `euid`/`epid`/`dsteuid`/`dstepid` keep the example's value `1`. Which incident fields each message carries, the `msg` text, the `desc` value (the catalog message name is used), the `IN` plus eight digits incident ID, lowercase severities and event-ID-style attachment values are assumptions.
- `user_from=GUI(<address>)` for analysts follows FortiManager/FortiAnalyzer event logs in Elastic's test fixtures; `system` follows the application log example.
- Dates and times are UTC; the `tz` field is not emitted. No Syslog header, CEF form or collector envelope is generated, so compatibility with a specific FortiAnalyzer collector or a CEF normalizer (for example KUMA's FortiAnalyzer CEF profile) is unverified.
- Incident status, category, assignment and notes are not modelled; updates change only the severity, sometimes.
- Rates, weights, delays and analyst names are synthetic lab settings.

## References

- [Fortinet 7.2.4 Log Reference PDF](https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/1582da54-5713-11ee-8e6d-fa163e15d75b/FortiManager_%26_FortiAnalyzer_7.2.4_Log_Reference.pdf)
- [Fortinet 7.2.4 APPEVENT fields and INCIDENT messages](https://docs.fortinet.com/document/fortimanager/7.2.4/log-message-reference/100001/appevent)
- [Fortinet 7.2.4 FortiAnalyzer application log message example](https://docs.fortinet.com/document/fortimanager/7.2.4/log-message-reference/395380/fortianalyzer-application-log-message-example)
- [FortiAnalyzer 7.2.4 raising an incident](https://docs.fortinet.com/document/fortianalyzer/7.2.4/administration-guide/347975/raising-an-incident)
- [Elastic Fortinet FortiManager/FortiAnalyzer integration](https://github.com/elastic/integrations/tree/main/packages/fortinet_fortimanager) (no incident fixture)
