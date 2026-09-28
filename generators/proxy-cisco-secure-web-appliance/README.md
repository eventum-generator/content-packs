# Cisco Secure Web Appliance access log

Synthetic standard (Squid-style) access log entries from one Cisco Secure Web Appliance (formerly WSA) running AsyncOS 15.2, for SIEM and proxy-analytics testing. Forty office clients browse, download software from mirrors, and hit URL-category and web-reputation blocks. Each record carries the native line in `event.original` and an inferred ECS mapping (no Elastic integration exists for this source).

## Event Types

Shares measured on a 156-hour default capture (`anomaly_mode: true`, 193,767 entries). Background volume follows each client's own working hours: a start between 04:00 and 11:00 UTC and a length of 7 to 10.5 hours, shifted by a random amount each day (standard deviation about 35 minutes), with about one day in ten off; client activity weights are skewed but bounded.

| Result / ACL decision | Share | Category | Meaning |
| --- | ---: | --- | --- |
| `TCP_MISS/200` `DEFAULT_CASE` (pages, assets, POST) | 57.8% | web | Fetched from the origin server |
| `TCP_HIT/200` | 9.1% | web | Served from disk cache |
| `TCP_IMS_HIT/304` | 9.0% | web | If-Modified-Since answered from cache |
| `TCP_DENIED/403` `BLOCK_WEBCAT` | 6.8% | web | Blocked URL category (games, gambling, streaming, filter avoidance, file sharing) |
| `TCP_MEM_HIT/200` | 6.1% | web | Served from memory cache |
| `TCP_REFRESH_HIT/200` | 4.9% | web | Revalidated cached object |
| `TCP_CLIENT_REFRESH_MISS/200` | 2.7% | web | Client sent `Pragma: no-cache` |
| `TCP_MISS/200` (about 5% `TCP_CLIENT_REFRESH_MISS/200`) software download with AMP file name and SHA-256 | 2.4% | web, file | Package fetched from an allowed mirror |
| `NONE/503`, `NONE/504` | 0.9% | web | Upstream DNS failure or gateway timeout |
| `TCP_DENIED/403` `BLOCK_WBRS` | 0.4% | web | Low web-reputation score |

## Anomaly Chain

**Sequence.** One client is denied a software package on a blocked file-sharing site two or more times (`TCP_DENIED/403`, `BLOCK_WEBCAT`, category `IW_osb`, `IW_free` or `IW_fts`), then downloads the same URL path from an allowed mirror (`TCP_MISS/200`, or `TCP_CLIENT_REFRESH_MISS/200` in about 5% of downloads, category `IW_infr`, `IW_comp` or `IW_swup`) with the file name and SHA-256 in the AMP verdict fields.

**Linking fields.** `source.ip`, `url.path` (same package path on both hosts), differing `url.domain`; the download adds `file.name` and `file.hash.sha256`.

**Recurrence.** The first episode starts within the first `anomaly_interval_hours` (at most 24 h) of generation, at a time of day drawn from the overall background hour curve (the combined working hours of all clients). Each later episode is due `anomaly_interval_hours` after the actual start of the previous one (default 24, minimum 1) and starts within a window centred on that due time, a quarter of the interval wide (at most 6 hours), favouring busier hours. A 156-hour default capture has 6 episodes, the first after 20.8 h, with gaps of 21.2-26.9 h and starts between 16:00 and 21:00 UTC; a 156-hour run at 6 hours has 26 episodes with gaps of 5.3-6.6 h. The first start follows the overall hour curve, which keeps some weight in the evening, and each later start is only pulled towards busier hours within its own window, so an evening start can repeat for several days. Denials are spaced like ordinary retries (median about 25 s), and the download follows the last denial after a median of about 3 minutes (at most 20 minutes).

**Variation.** Each episode picks a different client and a different package than the previous one, a random blocked sharing site and a random mirror, and 2 or more denials.

**Background.** Every element also occurs in ordinary traffic of both modes: all clients, sharing sites, mirrors and packages; repeated denials of the same package by one client within minutes; a single denial followed by the same package from a mirror; denials followed by a different package; and plain mirror downloads. A guard acts on the final step only: a background download of a path that would complete the chain with any earlier rows (two or more denials of that path by the same client in the preceding 30 minutes, and the download from another domain) is not logged; denials and every other download stay as generated. In six 156-hour background captures (12,162 cases of two denials of one path by one client), a download of that path by the same client follows at 0.12-0.21 per hour between 30 and 60 minutes after the first denial, with no gap beyond the 30-minute window; downloads of that path by other clients (3.6-4.1 per hour) and other traffic of the same client keep a smooth rate across the window boundary.

**Detection idea.** Per client and URL path: two or more `BLOCK_WEBCAT` denials, then an allowed 200 response for the same path from a different domain within 30 minutes (policy bypass through a mirror). Confirm with the SHA-256 against endpoint telemetry.

`event.template.params.anomaly_mode` defaults to `true`. Set it to `false` for background traffic only, without the complete sequence.

## Parameters

### Event Parameters

Set in `event.template.params` of `generator.yml`.

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Add periodic anomaly episodes to background |
| `anomaly_interval_hours` | `24` | Source time between episodes, 1 to 8760 |
| `host_name` | `swa-01.example.test` | Appliance hostname |
| `client_prefix` | `10.20.40.` | Client subnet prefix |
| `client_first` | `11` | First client host number |
| `client_count` | `40` | Number of clients (at least 4) |
| `access_policies` | `[Staff, Engineering]` | Two Access Policy group names in the ACL decision tag |
| `identity_policy` | `Corp_Identity` | Identification Profile name in the ACL decision tag |
| `sites` | 10 allowed sites | Browsed domains with URL category abbreviation and pages |
| `blocked_sites` | 4 sites | Domains blocked by URL category |
| `sharing_sites` | 3 sites | Blocked file-sharing domains used for package downloads |
| `mirrors` | 3 sites | Allowed download mirrors |
| `low_reputation_domains` | 3 domains | Domains blocked by web reputation |
| `packages` | 10 paths | Software package paths hosted on sharing sites and mirrors |
| `assets` | 8 paths | Embedded page objects |

### Output Parameters

The shipped configuration writes `output/events.json` with no connection parameters or secrets. To send events to a SIEM, replace the file output in a local copy and reference `${params.siem_host}` and `${secrets.siem_token}` as the selected output plugin requires.

## Usage

```bash
eventum generate --path generators/proxy-cisco-secure-web-appliance/generator.yml --id swa --live-mode false
eventum generate --path generators/proxy-cisco-secure-web-appliance/generator.yml --id swa --live-mode true
```

## Sample Output

The final download of an episode, copied from the default `anomaly_mode: true` capture:

```json
{"@timestamp": "2026-09-01T20:51:30.327+00:00", "cisco": {"swa": {"acl_decision_tag": "DEFAULT_CASE_12-Staff-Corp_Identity-DefaultGroup-NONE-NONE-DefaultRouting", "elapsed_ms": 3035, "hierarchy": "DIRECT/updates.example.org", "mime_type": "application/x-dosexec", "policy_group": "Staff", "result_code": "TCP_MISS", "scan_verdict": "\u003c\"IW_swup\",6.2,-,\"-\",-,-,-,-,\"-\",-,-,-,\"-\",-,-,\"-\",\"-\",-,-,\"IW_swup\",-,\"-\",\"-\",\"-\",\"Unknown\",\"Unknown\",\"-\",\"-\",28591.29,0,-,\"-\",\"-\",0,\"-\",-,0,\"archiver-23.01-x64.exe\",\"0278b9322c7eba677f9d82dd2979c292d8efdca93c855c1b58303247c216fb10\"\u003e", "url_category": "IW_swup", "wbrs_score": "6.2"}}, "destination": {"domain": "updates.example.org"}, "ecs": {"version": "8.17.0"}, "event": {"action": "tcp_miss", "category": ["web", "network"], "dataset": "cisco_swa.access", "duration": 3035000000, "kind": "event", "original": "1788295890.327 3035 10.20.40.11 TCP_MISS/200 10846821 GET http://updates.example.org/pub/archiver/archiver-23.01-x64.exe - DIRECT/updates.example.org application/x-dosexec DEFAULT_CASE_12-Staff-Corp_Identity-DefaultGroup-NONE-NONE-DefaultRouting \u003c\"IW_swup\",6.2,-,\"-\",-,-,-,-,\"-\",-,-,-,\"-\",-,-,\"-\",\"-\",-,-,\"IW_swup\",-,\"-\",\"-\",\"-\",\"Unknown\",\"Unknown\",\"-\",\"-\",28591.29,0,-,\"-\",\"-\",0,\"-\",-,0,\"archiver-23.01-x64.exe\",\"0278b9322c7eba677f9d82dd2979c292d8efdca93c855c1b58303247c216fb10\"\u003e -", "outcome": "success", "type": ["allowed", "connection"]}, "file": {"hash": {"sha256": "0278b9322c7eba677f9d82dd2979c292d8efdca93c855c1b58303247c216fb10"}, "name": "archiver-23.01-x64.exe"}, "host": {"name": "swa-01.example.test"}, "http": {"request": {"method": "GET"}, "response": {"bytes": 10846821, "mime_type": "application/x-dosexec", "status_code": 200}}, "network": {"protocol": "http"}, "observer": {"hostname": "swa-01.example.test", "product": "Secure Web Appliance", "type": "proxy", "vendor": "Cisco"}, "related": {"hash": ["0278b9322c7eba677f9d82dd2979c292d8efdca93c855c1b58303247c216fb10"], "hosts": ["updates.example.org"], "ip": ["10.20.40.11"]}, "source": {"ip": "10.20.40.11"}, "url": {"domain": "updates.example.org", "full": "http://updates.example.org/pub/archiver/archiver-23.01-x64.exe", "original": "http://updates.example.org/pub/archiver/archiver-23.01-x64.exe", "path": "/pub/archiver/archiver-23.01-x64.exe", "scheme": "http"}}
```

## Limitations

- The native line follows the AsyncOS 15.2 standard access log: `%t %e %a %w/%h %s %1r %2r %A %H/%d %c %D-<policy groups> <%Xr> <suspect user agent>`. The verdict holds positions 1-39 of Cisco's scanning-verdict table (URL category through AMP SHA-256); the archive-scan, Web Tap and YouTube positions 40-44 are omitted. Cisco's own full-entry example has a different verdict length, so the exact count may differ by release and enabled features.
- The episode client is picked uniformly, while background clients follow per-client weights and working hours; episode start times follow the overall hour curve, so an episode by a client outside its own working hours stands out more.
- URL categories are written quoted (`"IW_comp"`) as the guide states for AsyncOS 11.8 and later; the guide's example lines still show them unquoted.
- The ACL decision tag uses the six policy-group components the guide describes (Access Policy, Identity, Outbound Malware Scanning, Data Security, External DLP, Routing); the example line's extra trailing `-NONE` is not reproduced.
- No complete raw capture of a clean AsyncOS 15.2 transaction was available. Webroot, McAfee, Sophos, DLP and AVC positions are hyphens or `"Unknown"` as in the guide's examples; values for WBRS scores, bandwidth and AMP verdicts are synthetic within the documented value ranges.
- Only plain HTTP `GET`/`POST` through an explicit proxy is modeled: no HTTPS `CONNECT` tunnels, decryption decisions, authenticated usernames (`%A` is always `-`), W3C logs or syslog wrapping.
- Traffic shares and timings are synthetic, not measured appliance data.

## References

- [Cisco Secure Web Appliance AsyncOS 15.2 User Guide: Monitoring and Troubleshooting (access log fields, result codes, ACL decision tags, scanning verdict entries)](https://www.cisco.com/c/en/us/td/docs/security/wsa/wsa-15-2/user-guide/swa-userguide-15-2/m-monitoring-troubleshooting.html)
- [AsyncOS 15.2 User Guide: Access Control (URL category abbreviations)](https://www.cisco.com/c/en/us/td/docs/security/wsa/wsa-15-2/user-guide/swa-userguide-15-2/m-access-control.html)
- [AsyncOS 15.2 User Guide: Network Security (blocked-request access log example)](https://www.cisco.com/c/en/us/td/docs/security/wsa/wsa-15-2/user-guide/swa-userguide-15-2/m-network-security.html)
- No Elastic integration exists for Cisco Secure Web Appliance; the ECS mapping is inferred.
