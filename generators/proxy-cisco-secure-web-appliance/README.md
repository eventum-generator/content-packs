# Cisco Secure Web Appliance access log

Synthetic standard (Squid-style) access log entries from one Cisco Secure Web Appliance (formerly WSA) running AsyncOS 15.2, for SIEM and proxy-analytics testing. Forty office clients browse, download software from mirrors, and hit URL-category and web-reputation blocks. Each record carries the native line in `event.original` and an inferred ECS mapping (no Elastic integration exists for this source).

## Event Types

The appliance logs about 29,200 entries a day (varying by about 3% from day to day) on a working-day curve in UTC:

| Hours (UTC) | Entries per hour |
| --- | ---: |
| 22:00-05:00 | 350 |
| 05:00-06:00, 19:00-22:00 | 750 |
| 06:00-08:00, 17:00-19:00 | 1,250 |
| 08:00-09:00, 15:00-17:00 | 1,750 |
| 09:00-15:00 | 2,250 |

Each client keeps its own working hours: a start between 04:00 and 11:00 UTC and a length of 7 to 10.5 hours, shifted by a random amount each day (standard deviation about 35 minutes), with about one day in ten off. Outside its working hours a client stays at about an eighth of its daytime activity, and at 45% in the four hours after. Client activity weights are skewed but bounded (the busiest client carries about 8% of the entries); the same clients are the busy ones on every run for a given subnet.

Shares over four days with `anomaly_mode: true` (116,778 entries):

| Result / ACL decision | Share | Category | Meaning |
| --- | ---: | --- | --- |
| `TCP_MISS/200` `DEFAULT_CASE` (pages, assets, POST) | 57.7% | web | Fetched from the origin server |
| `TCP_HIT/200` | 9.1% | web | Served from disk cache |
| `TCP_IMS_HIT/304` | 9.0% | web | If-Modified-Since answered from cache |
| `TCP_DENIED/403` `BLOCK_WEBCAT` | 6.7% | web | Blocked URL category (games, gambling, streaming, filter avoidance, file sharing) |
| `TCP_MEM_HIT/200` | 5.9% | web | Served from memory cache |
| `TCP_REFRESH_HIT/200` | 5.0% | web | Revalidated cached object |
| `TCP_CLIENT_REFRESH_MISS/200` | 2.7% | web | Client sent `Pragma: no-cache` |
| `TCP_MISS/200` (about 5% `TCP_CLIENT_REFRESH_MISS/200`) software download with AMP file name and SHA-256 | 2.5% | web, file | Package fetched from an allowed mirror |
| `NONE/503`, `NONE/504` | 0.9% | web | Upstream DNS failure or gateway timeout |
| `TCP_DENIED/403` `BLOCK_WBRS` | 0.4% | web | Low web-reputation score |

## Anomaly Chain

**Sequence.** One client is denied a software package on a blocked file-sharing site two or more times (`TCP_DENIED/403`, `BLOCK_WEBCAT`, category `IW_osb`, `IW_free` or `IW_fts`), then downloads the same URL path from an allowed mirror (`TCP_MISS/200`, or `TCP_CLIENT_REFRESH_MISS/200` in about 5% of downloads, category `IW_infr`, `IW_comp` or `IW_swup`) with the file name and SHA-256 in the AMP verdict fields.

**Linking fields.** `source.ip`, `url.path` (same package path on both hosts), differing `url.domain`; the download adds `file.name` and `file.hash.sha256`.

**Recurrence.** The first episode starts within the first `anomaly_interval_hours` (at most 24 h) of generation, at a time of day drawn from the hour curve above. Each later episode is due `anomaly_interval_hours` after the actual start of the previous one (default 24, minimum 1) and starts within a window centred on that due time, a quarter of the interval wide (at most 6 hours), favouring busier hours. At the default interval consecutive episodes start 21 to 27 hours apart; at 6 hours, 5.25 to 6.75 hours apart. The first start follows the overall hour curve, which keeps some weight in the evening, and each later start is only pulled towards busier hours within its own window, so an evening start can repeat for several days. Denials are spaced like ordinary retries (median about 25 s, all within 15 minutes), and the download follows the last denial after a median of about 3 minutes, at most 25 minutes after the first denial. The episode's requests are part of the appliance's hourly volume; the client's ordinary browsing continues around them.

**Variation.** The episode client is one of the eight most active clients, drawn by activity weight and its working hours at the start time like ordinary traffic, and differs from the previous episode's client; the package differs from the previous one; the blocked sharing site and the mirror are random, with 2 or more denials.

**Background.** Every element also occurs in ordinary traffic of both modes: all clients, sharing sites, mirrors and packages, and every episode client with every package; repeated denials of the same package by one client within minutes; a single denial followed by the same package from a mirror; denials followed by a different package; and plain mirror downloads. In ordinary traffic a client who was denied a package twice or more in the preceding 30 minutes does not download that same package; it fetches a different package from the mirror instead.

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

The files in `patterns/` set the hourly volume. They start at 00:00 of the current day and have no end, which suits live mode; for a finite batch run set `start` and `end` in each of them (for example `start: "2026-09-01T00:00:00Z"`, `end: "2026-09-05T00:00:00Z"`), keeping the start at midnight so the hour bands stay in place.

Performance: about 2,900 entries per second in batch mode (14 days, 409,474 entries, in 143 s).

## Sample Output

The final download of an episode with the default `anomaly_mode: true`:

```json
{"@timestamp": "2026-09-01T12:31:57.557+00:00", "cisco": {"swa": {"acl_decision_tag": "DEFAULT_CASE_11-Staff-Corp_Identity-DefaultGroup-NONE-NONE-DefaultRouting", "elapsed_ms": 1381, "hierarchy": "DIRECT/updates.example.org", "mime_type": "application/zip", "policy_group": "Staff", "result_code": "TCP_MISS", "scan_verdict": "\u003c\"IW_swup\",4.7,-,\"-\",-,-,-,-,\"-\",-,-,-,\"-\",-,-,\"-\",\"-\",-,-,\"IW_swup\",-,\"-\",\"-\",\"-\",\"Unknown\",\"Unknown\",\"-\",\"-\",54062.07,0,-,\"-\",\"-\",0,\"-\",-,0,\"netscan-3.5.zip\",\"5cf61ec035254ada6e53e0ec3b2c5c418646181bff880556d85f1dcb81ee0dfb\"\u003e", "url_category": "IW_swup", "wbrs_score": "4.7"}}, "destination": {"domain": "updates.example.org"}, "ecs": {"version": "8.17.0"}, "event": {"action": "tcp_miss", "category": ["web", "network"], "dataset": "cisco_swa.access", "duration": 1381000000, "kind": "event", "original": "1788265917.557 1381 10.20.40.17 TCP_MISS/200 9332465 GET http://updates.example.org/pub/netscan/netscan-3.5.zip - DIRECT/updates.example.org application/zip DEFAULT_CASE_11-Staff-Corp_Identity-DefaultGroup-NONE-NONE-DefaultRouting \u003c\"IW_swup\",4.7,-,\"-\",-,-,-,-,\"-\",-,-,-,\"-\",-,-,\"-\",\"-\",-,-,\"IW_swup\",-,\"-\",\"-\",\"-\",\"Unknown\",\"Unknown\",\"-\",\"-\",54062.07,0,-,\"-\",\"-\",0,\"-\",-,0,\"netscan-3.5.zip\",\"5cf61ec035254ada6e53e0ec3b2c5c418646181bff880556d85f1dcb81ee0dfb\"\u003e -", "outcome": "success", "type": ["allowed", "connection"]}, "file": {"hash": {"sha256": "5cf61ec035254ada6e53e0ec3b2c5c418646181bff880556d85f1dcb81ee0dfb"}, "name": "netscan-3.5.zip"}, "host": {"name": "swa-01.example.test"}, "http": {"request": {"method": "GET"}, "response": {"bytes": 9332465, "mime_type": "application/zip", "status_code": 200}}, "network": {"protocol": "http"}, "observer": {"hostname": "swa-01.example.test", "product": "Secure Web Appliance", "type": "proxy", "vendor": "Cisco"}, "related": {"hash": ["5cf61ec035254ada6e53e0ec3b2c5c418646181bff880556d85f1dcb81ee0dfb"], "hosts": ["updates.example.org"], "ip": ["10.20.40.17"]}, "source": {"ip": "10.20.40.17"}, "url": {"domain": "updates.example.org", "full": "http://updates.example.org/pub/netscan/netscan-3.5.zip", "original": "http://updates.example.org/pub/netscan/netscan-3.5.zip", "path": "/pub/netscan/netscan-3.5.zip", "scheme": "http"}}
```

## Limitations

- The native line follows the AsyncOS 15.2 standard access log: `%t %e %a %w/%h %s %1r %2r %A %H/%d %c %D-<policy groups> <%Xr> <suspect user agent>`. The verdict holds positions 1-39 of Cisco's scanning-verdict table (URL category through AMP SHA-256); the archive-scan, Web Tap and YouTube positions 40-44 are omitted. Cisco's own full-entry example has a different verdict length, so the exact count may differ by release and enabled features.
- Requests of one page view are spread over consecutive entries: embedded objects follow their page after a median of 1.6 s in office hours (90th percentile 5.5 s) and 7.5 s at night (90th percentile 26 s), where a real browser fetches them within about a second.
- Every day has the same working-day curve; there is no weekend dip.
- With `anomaly_mode: true` each episode adds its own denials and download, so repeated denials of one package by one client are about one per episode more frequent than without it.
- URL categories are written quoted (`"IW_comp"`) as the guide states for AsyncOS 11.8 and later; the guide's example lines still show them unquoted.
- The ACL decision tag uses the six policy-group components the guide describes (Access Policy, Identity, Outbound Malware Scanning, Data Security, External DLP, Routing); the example line's extra trailing `-NONE` is not reproduced.
- No complete raw AsyncOS 15.2 log line of a clean transaction was available as a reference. Webroot, McAfee, Sophos, DLP and AVC positions are hyphens or `"Unknown"` as in the guide's examples; values for WBRS scores, bandwidth and AMP verdicts are synthetic within the documented value ranges.
- Only plain HTTP `GET`/`POST` through an explicit proxy is modeled: no HTTPS `CONNECT` tunnels, decryption decisions, authenticated usernames (`%A` is always `-`), W3C logs or syslog wrapping.
- Traffic shares and timings are synthetic, not measured appliance data.

## References

- [Cisco Secure Web Appliance AsyncOS 15.2 User Guide: Monitoring and Troubleshooting (access log fields, result codes, ACL decision tags, scanning verdict entries)](https://www.cisco.com/c/en/us/td/docs/security/wsa/wsa-15-2/user-guide/swa-userguide-15-2/m-monitoring-troubleshooting.html)
- [AsyncOS 15.2 User Guide: Access Control (URL category abbreviations)](https://www.cisco.com/c/en/us/td/docs/security/wsa/wsa-15-2/user-guide/swa-userguide-15-2/m-access-control.html)
- [AsyncOS 15.2 User Guide: Network Security (blocked-request access log example)](https://www.cisco.com/c/en/us/td/docs/security/wsa/wsa-15-2/user-guide/swa-userguide-15-2/m-network-security.html)
- No Elastic integration exists for Cisco Secure Web Appliance; the ECS mapping is inferred.
