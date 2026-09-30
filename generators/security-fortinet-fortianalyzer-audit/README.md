# Fortinet FortiAnalyzer Incident Audit

Generates FortiAnalyzer 7.2.4 local application event (`type=appevent subtype=incident`) records for SOC teams and SIEM engineers who need incident-management audit trails. Each record is ECS JSON with the FortiAnalyzer key-value line in `event.original`. This is FortiAnalyzer's own incident audit log, not FortiGate traffic forwarded through it.

The modelled SOC has twelve analysts and raises about 340 incidents a day: about 225 by playbooks (`user=system`) and 115 by analysts. Each incident has its own lifecycle: evidence attachments, analyst work sessions of one to several operations, occasional attachment removal, and deletion of about one incident in five, from minutes to days after creation.

## Volume and Timing

About 2,050 records a day. Playbooks raise incidents and attach evidence round the clock, with a peak around 13:00 UTC. Analysts work a day shift from 07:00 to 19:00 UTC with core hours 09:00-17:00 and a small night shift; work left at the end of the day continues the next morning.

| Hours (UTC) | Records per hour |
| --- | ---: |
| 00:00-07:00, 19:00-24:00 | about 26 |
| 07:00-09:00, 17:00-19:00 | about 100 |
| 09:00-17:00 | 150-190 |

An analyst's consecutive operations on one incident are typically 30 seconds to 12 minutes apart (median about 1.5 minutes). Playbook evidence follows its incident within seconds to minutes. About two in five deletions come within an hour of creation, the rest hours to days later. Each analyst works from the office address or the remote-access address and keeps one of them for minutes to hours.

## Event Types

Approximate shares with the default configuration.

| Fortinet message | Message ID | Share | Category |
| --- | --- | ---: | --- |
| `Incident_Update` | `100002` | 47.7% | configuration / change |
| `Incident_Attachment_Add` | `100005` | 25.5% | configuration / change |
| `New_Incident_Create` | `100001` | 17.6% | configuration / creation |
| `Incident_Attachment_Delete` | `100006` | 6.1% | configuration / change |
| `Incident_Delete` | `100003` | 3.1% | configuration / deletion |

All five IDs are the Information-level `APPEVENT` / `INCIDENT` messages of the Fortinet 7.2.4 log reference. The error variants (`110001`-`110006`) and `Incident_Attachment_Update` (`100004`) are not generated.

## Anomaly Chain

One analyst raises an incident and attaches evidence; another analyst removes the evidence and deletes the incident:

1. `New_Incident_Create` by analyst C. Playbook-raised incidents (`user=system`) are outside the chain: an analyst removing evidence from and deleting a playbook incident is the ordinary way to close a false positive.
2. `Incident_Attachment_Add` by C, with the same delay as ordinary first attachments.
3. Minutes later analyst D (D is not C) opens the incident: optionally an `Incident_Update`, then `Incident_Attachment_Delete` of that attachment.
4. `Incident_Delete` by D seconds to minutes later.

The records share `fortinet.fortianalyzer.incident_id`; steps 2 and 3 share `fortinet.fortianalyzer.attachment`; steps 3 and 4 share `user.name`. `source.ip` is D's current address, so steps 3 and 4 usually, but not always, share it. The whole chain completes within two hours of creation, usually within 90 minutes. Deletion is final: FortiAnalyzer logs no restore of a deleted incident, so nothing is restored.

**Recurrence.** One chain per `anomaly_interval_hours` (default 24, minimum 6). The first starts within `min(interval, 24 h)` of the start of the data. Each next one starts one interval after the actual start of the previous one, give or take half of a window that is a quarter of the interval and at most 6 hours: 21-27 hours apart at the default 24 hours, 7-9 hours at 8 hours, 5.25-6.75 hours at 6 hours. Within that window working hours are strongly preferred; night starts occur mainly at short intervals, where the window itself falls at night. Chains are never skipped.

**Variation.** C is one of the four busiest analysts, drawn by activity; D is another of them, drawn by activity and never the previous chain's D. The incident, attachment, severity and all delays are drawn per chain.

**Background.** Every action, analyst and analyst/address pair of the chain also occurs in ordinary traffic in both modes: incidents deleted within minutes, attachments removed by an analyst other than the creator, removal followed by deletion by the same analyst, handovers where one analyst removes the evidence and a colleague deletes the incident minutes later, and the chain's analysts working on each other's incidents. A deletion is done by the assignee (the creator on an analyst-raised incident) in 60% of cases, otherwise by a colleague; the removal before it is usually the deleter's own, but when a colleague deletes an analyst-raised incident the evidence was mostly removed by the creator (50%) or a third analyst (35%). In ordinary traffic an analyst other than the creator who removed evidence from an analyst-raised incident never also deletes it within two hours of creation; in those rare cases the deletion is done by someone else at the same moment.

**Detection idea.** Join by incident ID: creation by an analyst C (not `system`), an attachment added, an attachment removed by D different from C, and deletion by D within two hours.

`anomaly_mode: true` is the default. With `false` the generator emits only the realistic background, with no complete chain.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`.

| Name | Default | Description |
| --- | --- | --- |
| `anomaly_mode` | `true` | Emit the anomaly chain on top of the background. |
| `anomaly_interval_hours` | `24` | Interval between chain starts; range `6`-`8760`. |
| `analyzer_serial` | `FAZ-VMTM26001234` | `devid` of the FortiAnalyzer unit. |
| `analyzer_name` | `faz-soc-01` | `devname` of the FortiAnalyzer unit. |
| `adom` | `root` | `vd` and `adom` values. |

Analysts, their office and remote-access addresses and activity weights are in `samples/analysts.json`. The chain uses the four analysts with the highest weights.

### Output Parameters

The shipped file output needs no parameters. To send events elsewhere, replace `output.file` with another output plugin and put destination values in `${params.*}` (hosts, ports) and `${secrets.*}` (credentials) placeholders, supplied at run time.

## Usage

```bash
eventum generate --path generators/security-fortinet-fortianalyzer-audit/generator.yml --id faz-audit --live-mode true
```

The three inputs read the files under `patterns/`: `playbook-*.yml` for playbook-raised incidents and their evidence, `raise-*.yml` for incidents raised by analysts, `work-*.yml` for analyst work. Every input timestamp is one record, so `multiplier.ratio` in these files sets the daily volume; scale all of them by the same factor to keep the mix. The files run from `2026-01-01` with `end: never`. For a batch run, set `start` in every file to midnight UTC of the first day and `end` to the end of the window, then run with `--live-mode false`:

```bash
eventum generate --path generators/security-fortinet-fortianalyzer-audit/generator.yml --id faz-audit --live-mode false
```

Output: `output/events.json`, one JSON event per line.

Performance: about 1,000 events/s in batch mode (14 days, 28,700 records, in 29 s).

## Sample Output

An `Incident_Attachment_Delete` record (anomaly chain step 3):

```json
{"@timestamp": "2026-09-14T09:40:17+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "Incident_Attachment_Delete", "category": ["configuration"], "code": "100006", "dataset": "fortinet.fortianalyzer.appevent", "kind": "event", "original": "id=7685323499194656677 itime=2026-09-14 09:40:17 euid=1 epid=1 dsteuid=1 dstepid=1 vd=root logid=100006 type=appevent subtype=incident level=information date=2026-09-14 time=09:40:17 user=amartin user_from=GUI(10.20.4.21) desc=Incident_Attachment_Delete msg=Attachment deleted from incident IN00000943 incident_id=IN00000943 incident_severity=high attachment=202609141000026412 adom=root devid=FAZ-VMTM26001234 devname=faz-soc-01 dtime=2026-09-14 09:40:17 itime_t=1789378817", "outcome": "success", "type": ["change"]}, "fortinet": {"fortianalyzer": {"adom": "root", "attachment": "202609141000026412", "desc": "Incident_Attachment_Delete", "incident_id": "IN00000943", "incident_severity": "high", "level": "information", "logid": "100006", "subtype": "incident", "type": "appevent", "user_from": "GUI(10.20.4.21)"}}, "observer": {"name": "faz-soc-01", "product": "FortiAnalyzer", "serial_number": "FAZ-VMTM26001234", "type": "siem", "vendor": "Fortinet"}, "related": {"ip": ["10.20.4.21"], "user": ["amartin"]}, "source": {"ip": "10.20.4.21"}, "user": {"name": "amartin"}}
```

## Limitations

- Fortinet publishes the `INCIDENT` field catalog and message IDs but no complete raw incident record. The raw line copies the header and trailer layout of the one complete 7.2.4 application log example (a `playbook` record): `id` carries `itime_t` in its upper 32 bits, `dtime` equals `itime`, and `euid`/`epid`/`dsteuid`/`dstepid` keep the example's value `1`. Which incident fields each message carries, the `msg` text, the `desc` value (the catalog message name is used), the `IN` plus eight digits incident ID, lowercase severities and event-ID-style attachment values are assumptions.
- `user_from=GUI(<address>)` for analysts follows FortiManager/FortiAnalyzer event logs in Elastic's test fixtures; `system` follows the application log example.
- Dates and times are UTC; the `tz` field is not emitted. No Syslog header, CEF form or collector envelope is generated, so compatibility with a specific FortiAnalyzer collector or a CEF normalizer (for example KUMA's FortiAnalyzer CEF profile) is unverified.
- Incident status, category, assignment and notes are not modelled; updates change only the severity, sometimes.
- Weekends and holidays look like weekdays.
- With `anomaly_mode: true` each chain adds one analyst-raised incident whose evidence a colleague removes and which that colleague deletes within two hours, so counts of those parts are about one per chain higher than with `false`.
- Rates, weights, delays and analyst names are synthetic lab settings.

## References

- [Fortinet 7.2.4 Log Reference PDF](https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/1582da54-5713-11ee-8e6d-fa163e15d75b/FortiManager_%26_FortiAnalyzer_7.2.4_Log_Reference.pdf)
- [Fortinet 7.2.4 APPEVENT fields and INCIDENT messages](https://docs.fortinet.com/document/fortimanager/7.2.4/log-message-reference/100001/appevent)
- [Fortinet 7.2.4 FortiAnalyzer application log message example](https://docs.fortinet.com/document/fortimanager/7.2.4/log-message-reference/395380/fortianalyzer-application-log-message-example)
- [FortiAnalyzer 7.2.4 raising an incident](https://docs.fortinet.com/document/fortianalyzer/7.2.4/administration-guide/347975/raising-an-incident)
- [Elastic Fortinet FortiManager/FortiAnalyzer integration](https://github.com/elastic/integrations/tree/main/packages/fortinet_fortimanager) (no incident fixture)
