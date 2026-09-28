# Dr.Web Enterprise Security Suite Administrator Notifications

Collector-normalized ECS JSON for a selected Dr.Web ESS 13.0.1 administrator-notification profile. It represents published notification variables, not native CEF, syslog, JSON, or a captured delivery payload.

## Source Profile

One Server receives reports from 960 existing connected Windows stations in their configured primary group. One administrator notification profile selects all seven classes below. Threat, scan-statistics and Application Control reporting are enabled. Epidemic handling, grouped Preventive reports and multiple-block summaries are disabled so the selected individual reports are retained. Neighbor-server forwarding is outside the profile.

Application Control uses a real deny rule for untrusted executable launch attempts, without test mode. A block prevents launch; a user who retries the launch produces another block of the same copy. PowerShell is a separate permitted interpreter whose attempted HOSTS modification uses Preventive protection Ask mode and configured user-interaction rights. The local user may allow this protected-object action. This neither reverses an executable block nor establishes execution of the blocked object.

Selected manual Scanner runs use configured Move to quarantine. An infected targeted run covers one newly introduced copy plus known-clean companions. Its detection report states one completed move, which removes the original file, and the run's completion follows with Infected/Moved/VirusActivity all 1. Clean targeted runs report these counters as 0. Other response counters are 0 in this selected subset. One Scanner run per station is in progress at a time. Office documents occur in Scanner scope; process-launch blocks select only executable `.exe`/`.scr` files.

Natural dated filenames distinguish new copies of the same synthetic binary; the embedded time is when the copy appeared, before its first report. Each station retains at most four modeled quarantined copies. An explicitly configured **external administrator task completes quarantine deletion 72 hours after receipt**. Deletion is supported by the vendor API, but this schedule/completion is an environment assumption, not a Dr.Web default or an emitted notification. Fresh entries are never removed to make space; a workflow that would quarantine on a full station picks another station.

Station agents reconnect after network interruptions, so connection notifications repeat for one station within minutes: a failed authorization is often retried, and a reconnect can collide with the station's still-registered session. Update failures are retried by the agent as well.

`@timestamp` is normalized UTC Server receipt. Threat/scan/update `MSG.ServerTime` is that documented receipt GMT, not station occurrence time. Block/Preventive `MSG.StationTime` is 1-24 seconds earlier (station occurrence plus delivery delay, under a synchronized station-clock assumption). Speed is KB/s. `file.path`/`file.name` repeat the blocked `MSG.Path` or detected `MSG.ObjectName` as collector ECS enrichment. No native event, session, scan or episode ID is invented.

## Event Types

The single `spin` dispatcher selects workflows and seven schema-specific body templates. There are nine physical Jinja files including the dispatcher and shared envelope macro. All seven notification classes occur ordinarily in both modes. Shares are measured in the final 156-hour default captures (59,206 background-mode and 59,271 anomaly-mode records).

| Action | Notification | Share off / on | Category |
|---|---|---:|---|
| `scan-completed` | Scan statistics | 38.3% / 38.2% | malware |
| `application-control-blocked` | Application Control blocked the process | 19.0% / 19.4% | process |
| `station-authorization-failed` | Station authorization failed | 13.2% / 12.8% | authentication |
| `preventive-protection-allowed` | Report of Preventive protection | 9.5% / 9.8% | process |
| `security-threat-detected` | Security threat detected | 7.5% / 7.5% | malware |
| `station-id-duplicate` | Station already logged in | 7.1% / 6.9% | authentication |
| `station-update-error` | Critical error of station update | 5.4% / 5.5% | package |

Ordinary activity mixes independent workflows: clean scans, launch blocks with retries, infected scans (detection then completion), user-allowed HOSTS edits, update failures with retries, connection failures (retried, sometimes followed by a session collision) and standalone collisions. Stations are chosen at random with unequal activity weights drawn per run (lognormal), so each station reports about ten notifications a day on average; there is no rotation or schedule. About 400 times a day an ordinary workflow reproduces a contiguous part of the anomaly chain on one station with the chain's own timing, each of the two five-step parts about 140 times a day (for example block, allowed HOSTS edit, detection of the blocked copy, scan completion and an authorization failure, without the collision). A guard keeps background from completing the full chain by coincidence, and it acts only on the chain's last step: an ordinary duplicate-ID collision that would complete the chain on its station (block of a copy, allowed HOSTS edit, detection of that copy, infected scan completion and an authorization failure, the block at most 95 minutes earlier) is not reported, and its input timestamp carries the next notification instead. This happened 25-26 times in 156 hours (about 4 a day, 0.04% of notifications). Nothing else on the station changes: connection failures, other collisions and every other workflow start and run as usual. The check stays active after an episode completes: its own sequence keeps blocking such collisions on that station until its 95-minute window ends, so neither an ordinary collision nor a retry of the episode's own collision completes it a second time.

## Input Design

The input sets the rate: `patterns/notifications.yml` (`time_patterns`) produces 380 timestamps an hour, spread uniformly within each hour, each hour's count varying by up to 10%, around the clock (about 9,100 a day). Every timestamp becomes exactly one notification at that time (whole seconds); nothing is dropped. The fleet size (960 stations) follows from this rate at about ten notifications per station per day.

The template is a dispatcher. Notifications whose time follows from a workflow - later steps of a workflow, launch/reconnect/update retries and episode steps - wait in a queue with a due time. At each timestamp the earliest due queued notification is emitted; if none is due, a due episode starts; otherwise a new ordinary workflow starts on a station drawn by activity weight and its first notification is emitted. A queued notification therefore appears at the first timestamp after it is due that no earlier-due notification takes: in the measured runs 10 s after its due time in median, 32 s at the 90th percentile, at most about 2 minutes. A detection due while another Scanner run on its station is still open waits 30 s and goes back to the queue; a launch retry of a copy that has since been quarantined is skipped. In both cases the timestamp carries the next notification.

**Episode timestamps.** Episode steps are queued like the steps of ordinary workflows and take over input timestamps that would otherwise have started a new ordinary workflow. The input produces the same number of timestamps in both modes; the six to eight notifications of an episode (its steps plus retries) take the place of that many ordinary workflow starts, out of about 5,900 a day, and no queued background notification is paused, shifted or re-phased.

## Anomaly Chain

`anomaly_mode: true` is the default; `false` produces only background. The first episode starts at a uniformly random moment within the first `anomaly_interval_hours` or 24 hours of generation, whichever is shorter. Each later episode is due one interval after the previous actual start and starts at a uniformly random moment in a window centred on that due time, a quarter of the interval wide but at most 6 hours (default: 21 to 27 hours after the previous start); it takes over the first input timestamp from then on at which no queued notification is due (0.5-32 seconds later in the measured runs). The background has no daily cycle, so start times are uniform over the day. There are no catch-up bursts. The supported interval is 6 to 8760 finite hours.

An episode picks a station with the same activity weights as ordinary workflows, among stations that are not running a Scanner job, have a free quarantine slot, are not in the middle of an ordinary chain part whose detection of the blocked copy has been reported or is scheduled (the episode's collision would otherwise complete that older part instead of its own) and were not among the three previous episode stations. It picks an executable different from the previous episode's.

1. Application Control prevents launch of a new executable copy (the user may retry, as in ordinary traffic).
2. 1-20 minutes later, the same station/user allows a separate PowerShell HOSTS modification.
3. 2-25 minutes later, a manually launched Scanner detects that exact blocked-file copy and moves it to quarantine.
4. 0.5-12 minutes later, the corresponding scan completes with one infected/moved object.
5. 1-20 minutes later, a connection attempt claiming the same registered station UUID fails credentials (and may be retried).
6. 0.3-10 minutes later, another attempt collides with that station's existing connected identity.

Measured spans were 32-56 minutes (default) and 24-53 minutes (12-hour interval). Other stations' notifications interleave with the episode. The step gaps, retries and every step type are the same as in ordinary traffic. Only the complete ordered sequence on one station within 95 minutes, with the blocked path equal to the detected path, is specific to episodes; background cannot produce it because of the guard. The Server registration ID in the duplicate report is `MSG.Server`. These are related training correlations, not proof that malware executed, changed HOSTS, cloned an Agent or corrected a password. Authorization hooks describe duplicate checking after valid ID/password checking, but this notification pair does not identify the attempting peer or prove it was the same process. Inventory IP/hostname context on those reports denotes the registered asset, not an observed request source.

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

Synthetic timing limits: the rate (about 9,100 notifications per day for 960 stations) has no daily cycle; receipt times are whole seconds, so one second can carry several notifications of the fleet. Notifications queued for the same moment come out on consecutive input timestamps, about 10 seconds apart on average: a queued notification appears 10 s after its due time in median, 32 s at the 90th percentile and at most about 2 minutes later, so the shortest launch retries (due 3-15 s after the block) arrive later than the configured gap. The workflow mix, retry probabilities, gaps, scan counter/speed distributions and delivery delays are selected training assumptions. Primary sources give no rates. Ordinary chain parts are deliberately frequent so that no part of the chain identifies an episode; as a result, the detection rate (about 690 per day, 0.7 per station) and the duplicate-ID collision rate (about 640 per day) far exceed a typical fleet and are set by this separability design, not by any source.

Episode stations are chosen among stations the scheduler can use at that moment (no scan running, quarantine below its cap, no unfinished ordinary chain part), which slightly favours quieter stations: across 63 episodes in six anomaly-mode captures, ordinary rows of the episode station within two hours of the episode were 112 against 130.8 expected from that station's own rate (0.86; per capture z -3.3 to 0.4, one capture at -3.3). In the two hours before an episode the ratio was 0.87 (49 against 56.5), while ordinary block-to-detection prefixes in the same captures show 0.86-1.09. No single capture separates episode stations by activity alone.

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

### Input

`patterns/notifications.yml` sets the rate: `multiplier.ratio` (default `380`) notifications per hour for the whole fleet, `randomizer.deviation` (default `0.1`) the hour-to-hour variation. Per-station rates follow from the ratio divided by the 960 stations in `samples/stations.csv`.

### Output Parameters

The shipped file output writes `output/events.json` and requires no top-level `${params}` or secrets. To deliver to a SIEM, replace the output plugin and put its connection values in `${params.*}` placeholders and credentials in `${secrets.*}` placeholders, resolved at runtime from the Eventum keyring.

## Usage

From the content-packs checkout, live mode:

```bash
eventum generate --path generators/security-drweb-ess/generator.yml --id drweb --live-mode true
```

The pattern starts at midnight (UTC) of the current day and never ends. For a finite sample, copy the generator directory, set `start: "2026-09-26T00:00:00Z"` and `end: "+52h"` in the copy's `patterns/notifications.yml`, and run it in batch mode. At the default interval 52 hours cover one or, usually, two episodes:

```bash
eventum generate --path <copy>/generator.yml --id drweb --live-mode false --keep-order true
```

## Validation

| Finite input | Records | Complete episodes | Episode intervals (h) | Maximum quarantine per station |
|---|---:|---:|---|---:|
| Default, 24 h interval, 156 h, anomaly (two runs) | 59,271 / 59,309 | 6 / 6 | 21.27-26.85 | 4 |
| Default, 24 h interval, 156 h, background (six runs) | 58,756-59,653 | 0 | - | 4 |
| 12 h interval, 156 h, anomaly (four runs) | 59,098-59,491 | 12 / 13 / 13 / 13 | 10.59-13.49 | 4 |
| 12 h interval, 156 h, background | 59,260 | 0 | - | 4 |

All runs exited 0 with complete JSON output to the configured end and no log output. None of the seven background-mode captures contains a complete chain, and the anomaly-mode chains are exactly the scheduled episodes, also when every candidate binding is kept and completions reset nothing (6, 6, 12, 13, 13 and 13 chains). Checks covered the seven exact selected field sets, UTC receipt/occurrence clocks, non-decreasing receipt times, registered identity roles, new-file/quarantine/run counters and bounds, recurrence (first start within min(interval, 24 h), later starts within the centred window, rotating stations and executables), zero complete chains in background mode, ordinary coverage of every class, all 960 stations, four executable hashes, six threat labels and every contiguous chain part.

Background decisions were compared between modes against five further independent background captures: class volumes, same-station repeats within 1-60 minutes, bursts, retry shares, inter-class transitions, chain-part counts, station gaps, scan run durations, copy ages, station delays and scan counters, including their lowest quantiles and extremes; neither mode shows a feature the other lacks. Counts of every step pair of the chain on one station within 95 minutes, of every contiguous chain part, of failure bursts and of each class stay within the run-to-run variation of background-mode captures, and every step pair occurs thousands of times in every background-mode capture. Around a background chain prefix (block through authorization failure on one station, 6,309 prefixes in seven captures), authorization failures of that station decay smoothly from the prefix's own retries into the background rate across the 95-minute boundary (0.10 and 0.06 per prefix-hour in the last two 16-minute bins inside, 0.04-0.06 outside), and collisions on other stations stay at about 25.8 per prefix-hour on both sides. Collisions on the prefix's own station are 0 inside the window (the guard) and 0.02-0.03 per prefix-hour after it.

## Performance

Measured on one core: a 14-day default run writes 127,552 notifications in 43 s (about 2,950 per second); 6 hours take 1.8 s including start-up. A replay of the pattern's own timestamps gives exactly one notification per timestamp (2,244 of 2,244 in 6 hours, 128,108 of 128,108 in 14 days).

## Sample Output

Actual default-mode episode block, copied from the final default anomaly-mode capture (row 7000), pretty-printed:

```json
{
  "@timestamp": "2026-09-26T18:41:25+00:00",
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
  "message": "Application Control prevented launch of C:\\Users\\Public\\Downloads\\invoice.pdf_20260926_183718.exe on WS-IT-112.",
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
    "id": "10a56af1-2be3-4381-927f-4d7b1e02c912",
    "name": "WS-IT-112",
    "hostname": "WS-IT-112",
    "ip": [
      "10.20.15.132"
    ]
  },
  "user": {
    "name": "m.makarov"
  },
  "file": {
    "path": "C:\\Users\\Public\\Downloads\\invoice.pdf_20260926_183718.exe",
    "name": "invoice.pdf_20260926_183718.exe"
  },
  "related": {
    "hosts": [
      "WS-IT-112"
    ],
    "ip": [
      "10.20.15.132"
    ],
    "user": [
      "m.makarov"
    ],
    "hash": [
      "57a04e9de7e32d301ddbf6b93359a45f1c17f24e8a45b5e4d79ed28533e3b221"
    ]
  },
  "drweb": {
    "ess": {
      "notification": "Application Control blocked the process",
      "station": {
        "id": "10a56af1-2be3-4381-927f-4d7b1e02c912",
        "name": "WS-IT-112",
        "ip": "10.20.15.132",
        "primary_group": "Workstations"
      },
      "variables": {
        "MSG.AppCtlAction": 5,
        "MSG.AppCtlType": 1,
        "MSG.Path": "C:\\Users\\Public\\Downloads\\invoice.pdf_20260926_183718.exe",
        "MSG.Profile": "Default deny executables",
        "MSG.Rule": "Block untrusted application",
        "MSG.SHA256": "57a04e9de7e32d301ddbf6b93359a45f1c17f24e8a45b5e4d79ed28533e3b221",
        "MSG.StationTime": "2026-09-26T18:41:12+00:00",
        "MSG.TestMode": 0,
        "MSG.User": "m.makarov"
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
