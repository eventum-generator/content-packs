# Dr.Web Enterprise Security Suite Administrator Notifications

Collector-normalized ECS JSON for a selected Dr.Web ESS 13.0.1 administrator-notification profile. It represents published notification variables, not native CEF, syslog, JSON, or a captured delivery payload.

## Source Profile

One Server receives reports from 48 existing connected Windows stations in their configured primary group. One administrator notification profile selects all seven classes below. Threat, scan-statistics and Application Control reporting are enabled. Epidemic handling, grouped Preventive reports and multiple-block summaries are disabled so the selected individual reports are retained. Neighbor-server forwarding is outside the profile.

Application Control uses a real deny rule for untrusted executable launch attempts, without test mode. A block prevents launch; a user who retries the launch produces another block of the same copy. PowerShell is a separate permitted interpreter whose attempted HOSTS modification uses Preventive protection Ask mode and configured user-interaction rights. The local user may allow this protected-object action. This neither reverses an executable block nor establishes execution of the blocked object.

Selected manual Scanner runs use configured Move to quarantine. An infected targeted run covers one newly introduced copy plus known-clean companions. Its detection report states one completed move, which removes the original file, and the run's completion follows with Infected/Moved/VirusActivity all 1. Clean targeted runs report these counters as 0. Other response counters are 0 in this selected subset. One Scanner run per station is in progress at a time. Office documents occur in Scanner scope; process-launch blocks select only executable `.exe`/`.scr` files.

Natural dated filenames distinguish new copies of the same synthetic binary; the embedded time is when the copy appeared, before its first report. Each station retains at most four modeled quarantined copies. An explicitly configured **external administrator task completes quarantine deletion 72 hours after receipt**. Deletion is supported by the vendor API, but this schedule/completion is an environment assumption, not a Dr.Web default or an emitted notification. Fresh entries are never removed to make space; a workflow that would quarantine on a full station picks another station.

Station agents reconnect after network interruptions, so connection notifications repeat for one station within minutes: a failed authorization is often retried, and a reconnect can collide with the station's still-registered session. Update failures are retried by the agent as well.

`@timestamp` is normalized UTC Server receipt. Threat/scan/update `MSG.ServerTime` is that documented receipt GMT, not station occurrence time. Block/Preventive `MSG.StationTime` is 1-24 seconds earlier (station occurrence plus delivery delay, under a synchronized station-clock assumption). Speed is KB/s. `file.path`/`file.name` repeat the blocked `MSG.Path` or detected `MSG.ObjectName` as collector ECS enrichment. No native event, session, scan or episode ID is invented.

## Event Types

The single `spin` dispatcher selects workflows and seven schema-specific body templates. There are nine physical Jinja files including the dispatcher and shared envelope macro. All seven notification classes occur ordinarily in both modes. Shares are measured in the final 194-hour default captures (3568 background-mode and 3669 anomaly-mode records).

| Action | Notification | Share off / on | Category |
|---|---|---:|---|
| `scan-completed` | Scan statistics | 39.0% / 38.2% | malware |
| `application-control-blocked` | Application Control blocked the process | 18.2% / 18.6% | process |
| `station-authorization-failed` | Station authorization failed | 11.7% / 12.2% | authentication |
| `preventive-protection-allowed` | Report of Preventive protection | 10.3% / 9.6% | process |
| `security-threat-detected` | Security threat detected | 7.8% / 7.4% | malware |
| `station-update-error` | Critical error of station update | 7.0% / 6.3% | package |
| `station-id-duplicate` | Station already logged in | 6.1% / 7.7% | authentication |

Ordinary activity mixes independent workflows: clean scans, launch blocks with retries, infected scans (detection then completion), user-allowed HOSTS edits, update failures with retries, connection failures (retried, sometimes followed by a session collision) and standalone collisions. Stations are chosen at random with unequal activity weights drawn per run; there is no rotation or schedule. About 20 times a day an ordinary workflow reproduces a contiguous part of the anomaly chain, mostly one of its two five-step parts, on one station with the chain's own timing (for example block, allowed HOSTS edit, detection of the blocked copy, scan completion and an authorization failure, without the collision). A guard keeps background from completing the full chain by coincidence. When an ordinary part starts with a block and reaches the detection of that copy, it starts only on a station with no connection notification already scheduled. For 96 minutes after its last block of that copy (longer than the 95-minute detection window), no new connection-failure or collision workflow starts on that station. The guard has a residual effect, identical in both modes: after such an ordinary four-step prefix, a collision never follows on that station within the window, whereas without the guard about two coincidental chains per eight days would occur.

## Anomaly Chain

`anomaly_mode: true` is the default; `false` produces only background. The first episode becomes eligible `anomaly_interval_hours` (default 24) after the start of generation and starts at a random moment after that, on average about 7 minutes later. The next episode becomes eligible one interval after the previous actual start, so start delays accumulate and episode clock times drift later: default episodes started 24.02-24.32 hours apart and drifted from 00:01 to 01:03 UTC over eight days. There are no catch-up bursts. The supported interval is 6 to 8760 finite hours.

An episode picks a station at random, independent of its current load, among stations that are not running a Scanner job, have a free quarantine slot, are not under the guard described above and were not among the three previous episode stations. It picks an executable different from the previous episode's.

1. Application Control prevents launch of a new executable copy (the user may retry, as in ordinary traffic).
2. 1-20 minutes later, the same station/user allows a separate PowerShell HOSTS modification.
3. 2-25 minutes later, a manually launched Scanner detects that exact blocked-file copy and moves it to quarantine.
4. 0.5-12 minutes later, the corresponding scan completes with one infected/moved object.
5. 1-20 minutes later, a connection attempt claiming the same registered station UUID fails credentials (and may be retried).
6. 0.3-10 minutes later, another attempt collides with that station's existing connected identity.

Measured spans were 21-42 minutes (default), 31-54 minutes (12-hour interval) and 22-53 minutes (6-hour interval). Other stations' notifications interleave with the episode. The step gaps, retries and every step type are the same as in ordinary traffic. Only the complete ordered sequence on one station within 95 minutes, with the blocked path equal to the detected path, is specific to episodes; background cannot produce it because of the guard. The Server registration ID in the duplicate report is `MSG.Server`. These are related training correlations, not proof that malware executed, changed HOSTS, cloned an Agent or corrected a password. Authorization hooks describe duplicate checking after valid ID/password checking, but this notification pair does not identify the attempting peer or prove it was the same process. Inventory IP/hostname context on those reports denotes the registered asset, not an observed request source.

Detection idea: per station, block of file F, then an allowed protected-object operation, then detection and quarantine of F with its completion, then a failed authorization and a duplicate-ID collision for the same station UUID, all within about 1.5 hours. Any shorter part of this sequence also occurs in ordinary traffic.

## Field Coverage and Evidence Limits

| Notification | Selected class-specific MSG variables | Published class-specific MSG variables |
|---|---:|---:|
| Application Control block | 9 | 11 |
| Preventive user allow | 9 | 12 |
| Security threat | 8 | 8 |
| Scan statistics | 15 | 15 |
| Update error | 2 | 2 |
| Authorization failure | 3 | 3 |
| Duplicate station identity | 3 | 3 |
| Total | 49 | 54 |

This is **49/54 (90.7%) variable-name coverage**, not native-byte or realism certification. Direct-executable blocks omit conditional script Target/TargetSHA256. User-allowed protected access omits administrator-initiated AdminName, unauthorized-code ShellGuardType and automatic-denial Total. Neighbor `GEN.ServerRecvLink*`/`GEN.ServerOriginator*`, common catalog/environment fields and all other notification classes are outside this denominator and selected single-server profile.

The vendor publishes editable text templates and variable meanings, not a fixed serialization. Notification names, English action/type labels, message text, severity, ECS outcomes, `file.*` enrichment and inventory enrichment are collector choices. The shown Action/HipsType/IsShellGuard strings are descriptive normalized values, not proved installed-build enum bytes. Normal Security threat detected has no published SHA256 variable, so its join to an application block uses station/path. SHA256 appears only in the Application Control message. Threat names use published Dr.Web labels, while filenames, hashes and their association with those labels are entirely synthetic, not genuine malware fixtures. A named threat does not prove its behavior occurred.

Synthetic timing limits: the input ticks every 10 seconds and each tick carries at most one notification at a whole-second receipt time; the rate (427-479 notifications per day in the final captures) has no daily cycle; the workflow mix, retry probabilities, gaps, scan counter/speed distributions and delivery delays are selected training assumptions. Primary sources give no rates. Ordinary chain parts are deliberately frequent so that no part of the chain identifies an episode; as a result, the detection rate (about 35 per day) and the duplicate-ID collision rate (about 27 per day) far exceed a typical 48-station fleet and are set by this separability design, not by any source.

No complete native delivery capture, maintained Elastic sample or live SIEM-parser round trip was established in the bounded search. **BLOCKED_RAW_EVIDENCE** remains. No claim extends to another product version or complete ESS telemetry.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`.

| Parameter | Default | Meaning |
|---|---|---|
| `anomaly_mode` | `true` | Mix recurring episodes with ordinary activity; `false` emits ordinary activity only |
| `anomaly_interval_hours` | `24` | Finite interval from 6 to 8760 hours, measured from the previous actual episode start |
| `server_name` | `drweb-srv-01.example.test` | Registered Server hostname |
| `server_id` | `9f0ca284-b95a-4cc8-8338-f253a30ab001` | Server registration UUID in duplicate-station reports |
| `server_ip` | `10.20.0.10` | Collector inventory context for the Server |
| `server_version` | `13.0.1` | Metadata for the documented profile; changing it does not establish other-version fidelity |
| `station_group` | `Workstations` | Configured primary-group inventory label |
| `ecs_version` | `8.17.0` | ECS normalization version |

### Output Parameters

The shipped file output writes `output/events.json` and requires no top-level `${params}` or secrets. To deliver to a SIEM, replace the output plugin and put its connection values in `${params.*}` placeholders and credentials in `${secrets.*}` placeholders, resolved at runtime from the Eventum keyring.

## Usage

From the content-packs checkout, live mode:

```bash
eventum generate --path generators/security-drweb-ess/generator.yml --id drweb --live-mode true
```

For a finite sample, copy `generator.yml` to `generator.finite.yml` beside it and set `input[0].cron.start: "2026-09-26T00:00:00+00:00"` and `end: "2026-09-28T02:00:00+00:00"`. At the default interval this covers two episodes. Run:

```bash
eventum generate --path generators/security-drweb-ess/generator.finite.yml --id drweb --live-mode false --keep-order true
```

## Validation

| Finite input | Records | Complete episodes | Episode intervals (h) | Maximum quarantine per station |
|---|---:|---:|---|---:|
| Default, 24 h interval, 194 h, anomaly | 3669 | 8 | 24.02-24.32 | 4 |
| Default, 24 h interval, 194 h, background | 3568 | 0 | - | 4 |
| Custom profile, 12 h interval, 98 h, anomaly | 1842 | 8 | 12.01-12.14 | 4 |
| Custom profile, 12 h interval, 98 h, background | 1739 | 0 | - | 4 |
| Minimum 6 h interval, 98 h, anomaly | 1956 | 15 | 6.01-6.46 | 4 |
| Minimum 6 h interval, 98 h, background | 1866 | 0 | - | 4 |

All runs exited 0 with complete JSON output to the configured end and no log output. None of the 25 background-mode and 8 anomaly-mode captures generated for this version contains a chain produced by background (background mode has zero chains; anomaly-mode chains are exactly the scheduled episodes, one per interval). Checks covered the seven exact selected field sets, UTC receipt/occurrence clocks, strictly increasing receipt times, registered identity roles, new-file/quarantine/run counters and bounds, recurrence (first start after one interval, later starts at least one interval and at most three hours late, rotating stations and executables), zero complete chains in background mode, ordinary coverage of every class, all 48 stations, four executable hashes, six threat labels and every contiguous chain part. The custom profile changed Server UUID/name/IP, quoted Unicode group, ECS version and input timezone.

Background decisions were compared between modes against six further independent background captures per profile: class volumes, same-station repeats within 1-60 minutes, bursts, retry shares, inter-class transitions, chain-part counts, station gaps, scan run durations, copy ages, station delays and scan counters, including their lowest quantiles and extremes; neither mode shows a feature the other lacks. Ordinary rows of an episode's station within two hours of the episode are compared with that station's own rate: 102 observed against 119.6 expected over 8 anomaly-mode captures (ratio 0.85). The shortfall (z = -1.6, not significant) comes from the eligibility filters above, which skip stations that are under the guard, running a Scanner job or holding a full quarantine. Mutations are rejected: a chain step moved to another station, infected statistics without detection, re-quarantine of a removed copy, a different UUID in the final collision, a complete chain in background mode, a collision appended to an ordinary five-step part, background suspended around episodes, background without short same-station repeats, a fixed station rotation, a fixed cadence, a constant station delay, incrementing PIDs and duplicated captures.

## Sample Output

Actual default-mode episode block, copied from the finite capture:

```json
{
  "@timestamp": "2026-09-27T00:01:14+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "kind": "event",
    "module": "drweb",
    "dataset": "drweb.ess",
    "action": "application-control-blocked",
    "category": [
      "process"
    ],
    "type": [
      "denied"
    ],
    "outcome": "success",
    "severity": 5
  },
  "message": "Application Control prevented launch of C:\\Users\\Public\\Downloads\\updater_20260926_234019.exe on WS-HR-07.",
  "observer": {
    "vendor": "Doctor Web",
    "product": "Enterprise Security Suite",
    "version": "13.0.1",
    "hostname": "drweb-srv-01.example.test",
    "ip": [
      "10.20.0.10"
    ]
  },
  "host": {
    "id": "10a56af1-2be3-4381-927f-4d7b1e02c023",
    "name": "WS-HR-07",
    "hostname": "WS-HR-07",
    "ip": [
      "10.20.11.107"
    ]
  },
  "user": {
    "name": "user23"
  },
  "file": {
    "path": "C:\\Users\\Public\\Downloads\\updater_20260926_234019.exe",
    "name": "updater_20260926_234019.exe"
  },
  "related": {
    "hosts": [
      "WS-HR-07"
    ],
    "ip": [
      "10.20.11.107"
    ],
    "user": [
      "user23"
    ],
    "hash": [
      "775d486ec80d5cd7b615d573ac891579e3a2b518373804134121855cdd5d4ee8"
    ]
  },
  "drweb": {
    "ess": {
      "notification": "Application Control blocked the process",
      "station": {
        "id": "10a56af1-2be3-4381-927f-4d7b1e02c023",
        "name": "WS-HR-07",
        "ip": "10.20.11.107",
        "primary_group": "Workstations"
      },
      "variables": {
        "MSG.AppCtlAction": 5,
        "MSG.AppCtlType": 1,
        "MSG.Path": "C:\\Users\\Public\\Downloads\\updater_20260926_234019.exe",
        "MSG.Profile": "Default deny executables",
        "MSG.Rule": "Block untrusted application",
        "MSG.SHA256": "775d486ec80d5cd7b615d573ac891579e3a2b518373804134121855cdd5d4ee8",
        "MSG.StationTime": "2026-09-27T00:01:00+00:00",
        "MSG.TestMode": 0,
        "MSG.User": "user23"
      }
    }
  }
}
```

## References

- [ESS 13.0.1 notification-variable catalog](https://cdn-download.drweb.com/pub/drweb/esuite/13.0.1/documentation/html/en/appendices/app_notifications_templates.htm): all seven types and variable meanings.
- [Notification configuration](https://cdn-download.drweb.com/pub/drweb/esuite/13.0.1/documentation/html/en/admin_manual/notifications_configure.htm) and [Server statistics](https://cdn-download.drweb.com/pub/drweb/esuite/13.0.1/documentation/html/en/admin_manual/server_setup_statistic.htm): selected collection/profile assumptions.
- [Preventive protection](https://cdn-download.drweb.com/pub/drweb/esuite/13.0.1/documentation/html/ru/user_manual_agent/preventive_behavior.html): Ask mode and protected-object modification.
- [Scanner actions](https://cdn-download.drweb.com/pub/drweb/esuite/13.0.1/documentation/html/en/admin_manual/scanner_setup_actions.htm): Move to quarantine removes the original file.
- [Station hooks](https://cdn-download.drweb.com/pub/drweb/esuite/13.0.1/documentation/html/en/appendices/app_hooks_stations.htm): authorization phases and scan counters.
- [Quarantine deletion API](https://cdn-download.drweb.com/pub/drweb/esuite/13.0.1/documentation/html/en/web-api/quarantine_delete.htm): deletion capability, not proof of the selected 72-hour task.
- [Dr.Web virus labels](https://news.drweb.com/show/?i=14493): Office downloader/adware names. [Downloader](https://vms.drweb.co.jp/virus/?i=9678667), [injection Trojan](https://vms.drweb.fr/virus/?i=9481305) and [Tool.KMS.7](https://st.drweb.com/static/new-www/news/2020/DrWeb_review_may_2020.pdf) establish names, not synthetic artifact bytes.
