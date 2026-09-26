# Dr.Web Enterprise Security Suite Administrator Notifications

Collector-normalized ECS JSON for a selected Dr.Web ESS 13.0.1 administrator-notification profile. It represents published notification variables, not native CEF, syslog, JSON, or a captured delivery payload.

## Source Profile

One Server receives reports from 48 existing connected Windows stations in their configured primary group. One administrator notification profile selects all seven classes below. Threat, scan-statistics and Application Control reporting are enabled. Epidemic handling, grouped Preventive reports and multiple-block summaries are disabled so the selected individual reports are retained. Neighbor-server forwarding is outside the profile.

Application Control uses a real deny rule for untrusted executable launch attempts, without test mode. A block prevents launch. PowerShell is a separate permitted interpreter whose attempted HOSTS modification uses Preventive protection Ask mode and configured user-interaction rights. The local user may allow this protected-object action. This neither reverses the executable block nor establishes execution of that blocked object.

Selected manual Scanner runs use configured Move to quarantine. An infected targeted run covers one newly introduced copy plus known-clean companions. Its notification reports one completed move, which removes the original file. The next notification is that run's completion, with Infected/Moved/VirusActivity all 1. Clean targeted runs cover known-clean objects and have these counters 0. Other response counters are 0 in this selected subset. Office documents occur in Scanner scope; process-launch blocks select only executable `.exe`/`.scr` files.

Natural dated filenames distinguish new copies of the same synthetic binary. Each station retains at most four modeled quarantined copies. An explicitly configured **external administrator task completes quarantine deletion 72 hours after receipt**. Deletion is supported by the vendor API, but this schedule/completion is an environment assumption, not a Dr.Web default or an emitted notification. Fresh entries are never removed to make space. An ordinary incoming infected-copy workflow is deferred if its station is full, and a clean run is selected instead. A due episode chooses another eligible station or waits. Source state consists of 48 bounded station records, one queue of at most six notifications, rotating cursors and scalar clocks/PIDs. Short PowerShell exit and external cleanup are outside the selected output. A finite batch can end with one moved object awaiting its scan-completion notification ten minutes later.

The source sends **one notification every ten minutes, 144 per day**. Workflows, rates, scan counters/speed distributions, inventory and receipt delays are selected training assumptions. `@timestamp` is normalized UTC Server receipt. Threat/scan/update `MSG.ServerTime` is that documented receipt GMT, not station occurrence time. Block/Preventive `MSG.StationTime` is respectively two/three seconds earlier, under a synchronized station-clock assumption. Speed is KB/s. No native event, session, scan or episode ID is invented.

## Event Types

The single `spin` dispatcher selects workflows and seven schema-specific body templates. There are nine physical Jinja files including the dispatcher and shared envelope macro. All seven notification classes occur ordinarily in both modes.

| Action | Notification | Ordinary selection | Category |
|---|---|---|---|
| `scan-completed` | Scan statistics | Clean scan weight 48; completion after infected scan | malware |
| `application-control-blocked` | Application Control blocked the process | Weight 18 | process |
| `security-threat-detected` | Security threat detected | Infected scan weight 15, then completion | malware |
| `preventive-protection-allowed` | Report of Preventive protection | Weight 8 | process |
| `station-update-error` | Critical error of station update | Weight 6 | package |
| `station-authorization-failed` | Station authorization failed | Connection-noise workflow weight 5 | authentication |
| `station-id-duplicate` | Station already logged in | Second unrelated identity in that workflow | authentication |

Weights describe synthetic workflow choices, not production percentages or individual-record shares. Ordinary selection rotates the same 48 station actors independently of episode selection. Both modes retain the same executable hashes, threat labels, filename families, PowerShell/HOSTS activity and connection-notification classes. Normal infected scans remain causally paired with their own completion. Ordinary connection-noise pairs concern distinct station IDs.

## Anomaly Chain

`anomaly_mode: true` is the default. The first episode becomes eligible after `anomaly_interval_hours`, default 24 hours. Subsequent eligibility is measured from the actual first block, after the current ordinary workflow completes. There are no catch-up bursts. The supported interval is 6 to 8760 finite hours. Episodes rotate stations and newly introduced file-copy paths.

1. Application Control prevents launch of a new executable copy.
2. Ten minutes later, the same station/user allows a separate PowerShell HOSTS modification.
3. Ten minutes later, a manually launched Scanner detects that exact blocked-file copy and moves it to quarantine.
4. Ten minutes later, the corresponding scan completes with one infected/moved object and one threat.
5. Ten minutes later, a connection attempt claiming the same registered station UUID fails credentials.
6. Ten minutes later, another attempt collides with that station's existing connected identity.

Six notifications span 50 minutes. The first four span 30 minutes and join by station/user/time, with exact block/detection path equality. The last pair spans ten minutes and joins by `MSG.ID`. The Server registration ID in the duplicate report is `MSG.Server`. These are two related training correlations, not proof that malware executed, changed HOSTS, cloned an Agent, or corrected a password. Authorization hooks describe duplicate checking after valid ID/password checking, but this notification pair does not identify the attempting peer or prove it was the same process. The existing registered Agent remains connected. Inventory IP/hostname context on those reports denotes the registered asset, not an observed request source.

`anomaly_mode: false` retains ordinary activity without either complete same-station four-event sequence or adjacent same-ID connection pair. Detection ideas include block followed by a separate allowed protected-object operation and matched quarantine/completion, and repeated connection attempts for one existing station UUID. An external quarantine cleanup is not evidence used for these detections.

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

The vendor publishes editable text templates and variable meanings, not a fixed serialization. Notification names, English action/type labels, message text, severity, ECS outcomes and inventory enrichment are collector choices. The shown Action/HipsType/IsShellGuard strings are descriptive normalized values, not proved installed-build enum bytes. Normal Security threat detected has no published SHA256 variable, so its join to an application block uses station/path. SHA256 appears only in the Application Control message. Threat names use published Dr.Web labels, while filenames, hashes and their association with those labels are entirely synthetic, not genuine malware fixtures. A named threat does not prove its behavior occurred.

No complete native delivery capture, maintained Elastic sample or live SIEM-parser round trip was established in the bounded search. **BLOCKED_RAW_EVIDENCE** remains. The selected normalized variables and behavior are validated independently of raw transport. No claim extends to another product version or complete ESS telemetry.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`.

| Parameter | Default | Meaning |
|---|---|---|
| `anomaly_mode` | `true` | Mix recurring episodes with ordinary activity; false emits ordinary activity |
| `anomaly_interval_hours` | `24` | Finite interval from 6 to 8760 hours, measured between actual starts |
| `server_name` | `drweb-srv-01.example.test` | Registered Server hostname |
| `server_id` | `9f0ca284-b95a-4cc8-8338-f253a30ab001` | Server registration UUID in duplicate-station reports |
| `server_ip` | `10.20.0.10` | Collector inventory context for the Server |
| `server_version` | `13.0.1` | Metadata for the documented profile; changing it does not establish other-version fidelity |
| `station_group` | `Workstations` | Configured primary-group inventory label |
| `ecs_version` | `8.17.0` | ECS normalization version |

### Output Parameters

The shipped file output writes `output/events.json` and requires no top-level `${params}` or secrets. Configure an output plugin and its `${params.*}`/`${secrets.*}` overrides when delivering to a SIEM.

## Usage

From the content-packs checkout:

```bash
uv run --project ../eventum eventum generate --path generators/security-drweb-ess/generator.yml --id drweb --live-mode true --keep-order true
```

For a finite sample, copy `generator.yml` to `generator.finite.yml` beside it and set `input[0].cron.start: "2026-09-26T00:00:00+00:00"` and `end: "2026-09-28T01:30:00+00:00"`. This covers two complete default episodes when eligible, with room for pending ordinary notifications. Run:

```bash
flock -x /tmp/eventum-generator-heavy.lock uv run --project ../eventum eventum generate --path generators/security-drweb-ess/generator.finite.yml --id drweb --live-mode false --keep-order true
```

## Validation

| Finite input | Rows | Complete episodes | Maximum quarantine per station |
|---|---:|---:|---:|
| Default on, 76h20 | 459 | 3 | 4 |
| Default off, 76h20 | 459 | 0 | 3 |
| Custom on, 12h interval, 76h20 | 459 | 6 | 4 |
| Custom off, 76h20 | 459 | 0 | 4 |
| Stress on, 6h interval, 100h20 | 603 | 16 | 4 |

All five runs exited 0 with nonempty JSON and no error-log output. Checks covered seven exact selected field sets, UTC receipt/occurrence clocks, ten-minute spacing, registered identity roles, new-file/quarantine/run counters, bounds and ordinary coverage of all 48 stations, four executable hashes and six threat labels. The custom profile changed Server UUID/name/IP, quoted Unicode group/ECS version and input timezone. Its off capture ends in one valid pending scan tail; no invisible completion is inserted.

Four native-consistent mutations are rejected: station mismatch within the four-event sequence, infected statistics without its detection, re-quarantine of a removed file copy and a different UUID in the final collision attempt. A separately generated actual original `102d2da` trace had 459 records at valid ten-minute spacing, only one four-event chain and one same-ID pair, 13 unmatched infected completions and five repeated same-station/file quarantine reports. Historical short timeouts are not used as final validation.

## Sample Output

Actual default-on episode block, copied from the finite capture:

```json
{
  "@timestamp": "2026-09-27T00:00:00+00:00",
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
  "message": "Application Control prevented launch of C:\\Users\\Public\\Downloads\\invoice.pdf_20260927_000000.exe on WS-FIN-01.",
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
    "id": "10a56af1-2be3-4381-927f-4d7b1e02c001",
    "name": "WS-FIN-01",
    "hostname": "WS-FIN-01",
    "ip": [
      "10.20.10.21"
    ]
  },
  "user": {
    "name": "a.petrov"
  },
  "related": {
    "hosts": [
      "WS-FIN-01"
    ],
    "ip": [
      "10.20.10.21"
    ],
    "user": [
      "a.petrov"
    ],
    "hash": [
      "57a04e9de7e32d301ddbf6b93359a45f1c17f24e8a45b5e4d79ed28533e3b221"
    ]
  },
  "drweb": {
    "ess": {
      "notification": "Application Control blocked the process",
      "station": {
        "id": "10a56af1-2be3-4381-927f-4d7b1e02c001",
        "name": "WS-FIN-01",
        "ip": "10.20.10.21",
        "primary_group": "Workstations"
      },
      "variables": {
        "MSG.AppCtlAction": 5,
        "MSG.AppCtlType": 1,
        "MSG.Path": "C:\\Users\\Public\\Downloads\\invoice.pdf_20260927_000000.exe",
        "MSG.Profile": "Default deny executables",
        "MSG.Rule": "Block untrusted application",
        "MSG.SHA256": "57a04e9de7e32d301ddbf6b93359a45f1c17f24e8a45b5e4d79ed28533e3b221",
        "MSG.StationTime": "2026-09-26T23:59:58+00:00",
        "MSG.TestMode": 0,
        "MSG.User": "a.petrov"
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
