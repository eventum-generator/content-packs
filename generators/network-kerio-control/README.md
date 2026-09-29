# Kerio Control Filter Log

Generates the URL content-rule records that one Kerio Control firewall writes to its Filter log, as ECS JSON, for training SIEM content on web-filter telemetry. `event.original` holds the Filter log line in the layout documented by GFI; the surrounding JSON maps its fields to ECS. The firewall serves one office user segment and logs the content rules that have **Log the traffic** enabled.

## Event Types

Shares over four days of default output (`anomaly_mode: true`, 20,000 records).

| Rule (`rule.name`) | Filter log action | Method | Share | Category |
|---|---|---|---:|---|
| `Deny social networks` | `DENY URL` | GET | 38.19% (7638) | Web |
| `Allow automatic updates and MS Windows activation` | `ALLOW URL` | GET | 27.59% (5518) | Web |
| `Deny anonymizers` | `DENY URL` | GET | 14.29% (2859) | Web |
| `Log executable downloads` | `ALLOW URL` | GET | 9.32% (1864) | Web |
| `Deny file sharing` | `DENY URL` | GET | 8.01% (1601) | Web |
| `Deny file sharing` | `DENY URL` | POST | 2.60% (520) | Web |

Rule names and the set of logged rules are an assumed office configuration: the automatic-updates rule is the one GFI names in its documentation, the others are typical deny rules plus an allow rule on executable file names. Every user, anonymizer host, tunnel-client host and rule used by the chain occurs in ordinary background in both modes. No field labels an episode.

## Volume and Timing

About 5,000 records per day from 32 users, one client address each.

| UTC hours | Users' browsing (records/s) | Automatic updates (records/s) |
|---|---:|---:|
| 00-07, 20-24 | 0.003 | 0.016 |
| 07-08, 17-20 | 0.033 | 0.016 |
| 08-17 | 0.093 | 0.016 |

Users browse on a working-day curve: 08:00-17:00 carries about 85% of their records, the shoulder hours about 12%, the night about 3%. The computers fetch updates and activation checks round the clock, attributed to the user of the computer. Daily volume varies by about 3%. Consecutive records are about 6 s apart in office hours (median), 14 s in the shoulder hours and about 40 s at night.

Each user has a fixed propensity (log-normal, bounded to a factor of about 5 between the quietest and the busiest user), so some users hit blocked sites far more often than others, yet every user appears every day. The first quarter of the users in `samples/users.csv` (at least two; with the default 32 users: jsmith, mbrown, akowalski, dlee, epetrova, fgarcia, hmuller, ikhan) carry the highest propensities and take remote-access and tunnel clients regularly; the others do so rarely. What a user does:

- **Social networks** (43% of browsing actions): 1-6 denied requests, gaps log-normal (median 25 s), host kept or switched at random.
- **Anonymizers** (22%): 1-4 denied requests to web proxies, gaps log-normal (median 45 s), often on different proxies. After 22% of these bursts the user downloads an installer about five minutes later; 65% of those come from a tunnel-client host for the first-quarter users, 25% for the others.
- **File sharing** (18%): 1-3 denied requests, 25% of them upload POSTs.
- **Executable downloads** (17%): 1-2 installers, from a tunnel-client host in 45% of the downloads of the first-quarter users and 5% of the others.
- **Updates** (automatic): 1-4 allowed update or activation requests to one host.

Over four days the background holds about 1,800-2,100 pairs of denials on two different anonymizers by one user within an hour, 160-225 tunnel-client downloads and 95-130 tunnel-client downloads within an hour of an anonymizer denial. Each first-quarter user downloads about 9-35 tunnel clients in four days, each other user 0-8.

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the generator emits the background only and the complete chain never occurs.

Sequence, all for one user U at one client address:

1. `DENY URL 'Deny anonymizers'` for anonymizer host A.
2. `DENY URL 'Deny anonymizers'` for another anonymizer host B (in 40% of episodes one more anonymizer denial follows).
3. `ALLOW URL 'Log executable downloads'` of an installer from a tunnel-client host T (`tunnel_hosts`).

Linking fields: `user.name` and `source.ip` in all steps; `url.domain` differs between steps 1 and 2 and belongs to `tunnel_hosts` in step 3. The steps span a few minutes to about half an hour, always within one hour.

Recurrence: the first episode starts within the first `anomaly_interval_hours` of the output (at most 24 h), at an hour drawn from the users' browsing curve. Each later episode starts within a window around one interval after the previous start (window width a quarter of the interval, at most 6 h), favouring busy browsing hours, so at the default 24 h most episodes fall in office hours and their hour drifts from day to day. The next interval counts from the actual start, so a late episode never causes catch-up. `anomaly_interval_hours` defaults to 24 (minimum 2).

Variation: the user differs from the previous episode's, the first anonymizer and the tunnel-client host too; episode users are drawn from the first quarter of the users, weighted by the same per-user propensity as ordinary proxy use. Gaps between denials follow the background burst law and the download follows after a log-normal delay (median 7 min). The episode's records are part of the day's volume; the user's own browsing continues unchanged around them. With `anomaly_mode: true` each episode adds its own records, so counts of the chain parts (anonymizer denials on two hosts, tunnel-client downloads) are about one per episode higher. The Filter log records no state that the chain changes, so there is nothing to restore.

Detection idea: after the web filter blocks a user on two different anonymizers, the same user downloads a tunneling or remote-access client within an hour (filter evasion). Each fragment occurs in background: repeated anonymizer denials, denials on several proxies, tunnel-client downloads and tunnel-client downloads after a single proxy denial. Only the complete sequence is kept out of the background: an ordinary download by a user blocked on two different anonymizers within the last hour comes from an ordinary software host instead of a tunnel-client host.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
|---|---|---|
| `anomaly_mode` | `true` | Add periodic episodes to the background |
| `anomaly_interval_hours` | `24` | Episode interval in source hours, 2-8760 |
| `firewall_host` | `kerio-fw-01.example.test` | `observer.hostname` |
| `client_prefix` | `10.10.20.` | Client addresses are this prefix plus a host number |
| `client_first` | `11` | First client host number |
| `user_count` | `32` | Number of users, one address each, taken in order from `samples/users.csv`; the first quarter (at least two) are the busiest (4-40; `client_first + user_count` at most 255) |
| `anonymizer_hosts` | 4 hosts under `.example` | Hosts denied by `Deny anonymizers` (at least 3) |
| `tunnel_hosts` | 3 hosts under `.example` | Tunnel and remote-access client download hosts (at least 2) |

### Output Parameters

The shipped config writes `output/events.json` with the `json` formatter and needs no `${params.*}` or `${secrets.*}`. To send events elsewhere, replace the `output` section and put destination settings behind top-level placeholders, for example:

```yaml
output:
  - opensearch:
      hosts:
        - ${params.opensearch_host}
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: kerio-control-filter
```

A collector that parses Filter log lines needs `event.original` rather than the surrounding JSON.

## Usage

Live mode:

```bash
eventum generate --path generators/network-kerio-control/generator.yml --id kerio-control --live-mode true
```

Batch mode needs a bounded time window: in each file under `patterns/` set `oscillator.start` to a midnight (UTC) and `oscillator.end` to the end of the window, then run:

```bash
eventum generate --path generators/network-kerio-control/generator.yml --id kerio-control --live-mode false
```

The files under `patterns/` hold the volume and the hour curve: scale `multiplier.ratio` in all of them to change the volume, or move the `spreader` bounds to change the office hours. The episode placement follows the shipped curve. The user names are in `samples/users.csv`, the ordinary update, software, social-network and file-sharing hosts in `samples/hosts.csv`.

Performance: about 2,900 records/s (14 days, 70,000 records, in 24 s).

## Limitations

- GFI documents the URL-rule line with one raw example (`ALLOW`) and names `DENY` as the other action; `DENY` lines use the same layout. Only HTTP URLs are generated: the log format of HTTPS matches, FTP rules, the `Drop` action and hosts with no logged-in user (the user name is then omitted) is not documented in enough detail.
- Packet-rule records of the Filter log (template-defined format) and the other Kerio Control logs (Http, Web, Security, Connection) are out of scope.
- The firewall clock is UTC; the raw line carries second resolution, as documented. No syslog framing is produced.
- Rule names, rates, host lists and user behavior are training assumptions, not measured production volume. Every day has the same working-day curve; there is no weekend dip.
- Requests of one burst are at least a few seconds apart, and at night about a minute apart, rather than the sub-second spacing of a page load.
- No Elastic integration exists for this source, so the ECS mapping is an assumption; `kerio_control.filter.*` keeps the rule type and action token.

## Sample Output

The download that completes the first episode of a default four-day run (line 4569; the anonymizer denials are lines 4552 and 4556):

```json
{"@timestamp": "2026-09-01T18:55:36+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "ALLOW", "category": ["web", "network"], "dataset": "kerio_control.filter", "kind": "event", "original": "[01/Sep/2026 18:55:36] ALLOW URL \u0027Log executable downloads\u0027 10.10.20.12 mbrown HTTP GET http://download.socksclient.example/socksclient/10.3/socksclient-setup.exe", "type": ["access", "allowed"]}, "http": {"request": {"method": "GET"}}, "kerio_control": {"filter": {"action": "ALLOW", "rule_type": "URL"}}, "observer": {"hostname": "kerio-fw-01.example.test", "product": "Kerio Control", "type": "firewall", "vendor": "GFI"}, "related": {"hosts": ["download.socksclient.example"], "ip": ["10.10.20.12"], "user": ["mbrown"]}, "rule": {"name": "Log executable downloads"}, "source": {"ip": "10.10.20.12"}, "url": {"domain": "download.socksclient.example", "full": "http://download.socksclient.example/socksclient/10.3/socksclient-setup.exe", "path": "/socksclient/10.3/socksclient-setup.exe", "scheme": "http"}, "user": {"name": "mbrown"}}
```

## References

- [Kerio Control: Using the Filter log](https://manuals.gfi.com/en/kerio/control/content/logs/using-the-filter-log-1454.html): URL-rule line layout and example.
- [Kerio Control: Filter logs (GFI support)](https://support.keriocontrol.gfi.com/en-us/article/118924-filter-logs-in-kerio-control): the same format with a one-line example.
- [Kerio Control: Configuring the Content Filter](https://manuals.gfi.com/en/kerio/control/content/content-filtering/configuring-the-content-filter-1513.html): content rules, actions and the **Log the traffic** option.
- [Elastic ECS field reference](https://www.elastic.co/docs/reference/ecs/ecs-field-reference)
