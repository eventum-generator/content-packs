# Kerio Control Filter Log

Generates the URL content-rule records that one Kerio Control firewall writes to its Filter log, as ECS JSON, for training SIEM content on web-filter telemetry. `event.original` holds the Filter log line in the layout documented by GFI; the surrounding JSON maps its fields to ECS. The firewall serves one office user segment and logs the content rules that have **Log the traffic** enabled.

## Event Types

Shares measured on the final default capture (78 h, `anomaly_mode: true`, 13,738 records).

| Rule (`rule.name`) | Filter log action | Method | Share | Category |
|---|---|---|---:|---|
| `Deny social networks` | `DENY URL` | GET | 38.06% (5229) | Web |
| `Allow automatic updates and MS Windows activation` | `ALLOW URL` | GET | 28.05% (3853) | Web |
| `Deny anonymizers` | `DENY URL` | GET | 13.98% (1921) | Web |
| `Log executable downloads` | `ALLOW URL` | GET | 9.04% (1242) | Web |
| `Deny file sharing` | `DENY URL` | GET | 8.23% (1131) | Web |
| `Deny file sharing` | `DENY URL` | POST | 2.64% (362) | Web |

Rule names and the set of logged rules are an assumed office configuration: the automatic-updates rule is the one GFI names in its documentation, the others are typical deny rules plus an allow rule on executable file names. Every user, anonymizer host, tunnel-client host and rule used by the chain occurs in ordinary background in both modes. No field labels an episode.

## Background Model

Each one-second tick emits at most one record: the earliest due request, otherwise nothing. New activity arrives as one merged Poisson stream (0.03 per second, scaled by an office-hours factor: 07:00-17:00 UTC 1.58, 17:00-21:00 0.84, night 0.32); each arrival picks a user by a fixed random per-user weight (log-normal), so users act independently and some hit blocked sites far more often than others.

- **Social networks** (31% of arrivals): 1-6 denied requests, gaps log-normal (median 25 s), host kept or switched at random.
- **Updates** (28%): 1-4 allowed update or activation requests to one host, seconds apart.
- **Anonymizers** (16%): 1-4 denied requests to web proxies, gaps log-normal (median 45 s), often on different proxies. After 22% of these bursts the user downloads an installer about five minutes later; 35% of those come from a tunnel-client host.
- **File sharing** (13%): 1-3 denied requests, 25% of them upload POSTs.
- **Executable downloads** (12%): 1-2 installers; 14% from a tunnel-client host.

Over 78 h an `anomaly_mode: false` capture holds 1,030-1,220 pairs of denials on two different anonymizers by one user within an hour, 120-150 tunnel-client downloads and 55-85 tunnel-client downloads within an hour of an anonymizer denial.

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the generator emits the background only and the complete chain never occurs.

Sequence, all for one user U at one client address:

1. `DENY URL 'Deny anonymizers'` for anonymizer host A.
2. `DENY URL 'Deny anonymizers'` for another anonymizer host B (in 40% of episodes one more anonymizer denial follows).
3. `ALLOW URL 'Log executable downloads'` of an installer from a tunnel-client host T (`tunnel_hosts`).

Linking fields: `user.name` and `source.ip` in all steps; `url.domain` differs between steps 1 and 2 and belongs to `tunnel_hosts` in step 3.

Recurrence: an episode becomes due every `anomaly_interval_hours` of source time (default 24, minimum 2), first one interval after generation starts. It starts after a random delay (exponential, mean 20 min). The next due time counts from the actual start, so a late episode never causes catch-up. Episodes in the final captures spanned 7-17 minutes at the default interval and 4-55 minutes at 6 h.

Variation: the user differs from the previous episode's, the first anonymizer and the tunnel-client host too; gaps between denials follow the background burst law and the download follows after a log-normal delay (median 7 min). The episode start ignores the day/night load curve, so night episodes stand out more against the lower night background; the episode user is picked uniformly, so rarely active users are over-represented as chain actors. The Filter log records no state that the chain changes, so there is nothing to restore.

Detection idea: after the web filter blocks a user on two different anonymizers, the same user downloads a tunneling or remote-access client within an hour (filter evasion). Each fragment occurs in background: repeated anonymizer denials, denials on several proxies, tunnel-client downloads and tunnel-client downloads after a single proxy denial. Only the complete sequence is kept out of the background: an ordinary tunnel-client download by a user with denials on two different anonymizers in the last 4,000 s comes from an ordinary software host instead.

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
| `user_count` | `32` | Number of users, one address each (4-40; `client_first + user_count` at most 255) |
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

Batch mode needs a bounded input: add `start` and `end` to the `cron` input, then run:

```bash
eventum generate --path generators/network-kerio-control/generator.yml --id kerio-control --live-mode false
```

## Limitations

- GFI documents the URL-rule line with one raw example (`ALLOW`) and names `DENY` as the other action; `DENY` lines use the same layout. Only HTTP URLs are generated: the log format of HTTPS matches, FTP rules, the `Drop` action and hosts with no logged-in user (the user name is then omitted) is not documented in enough detail.
- Packet-rule records of the Filter log (template-defined format) and the other Kerio Control logs (Http, Web, Security, Connection) are out of scope.
- The firewall clock is UTC; the raw line carries second resolution, as documented. No syslog framing is produced.
- Rule names, rates, host lists and user behavior are training assumptions, not measured production volume. One record per second at most. No Elastic integration exists for this source, so the ECS mapping is an assumption; `kerio_control.filter.*` keeps the rule type and action token.

## Sample Output

The download that completes the first episode, copied byte for byte from the final default capture (line 4507; the anonymizer denials are lines 4479, 4480 and 4487):

```json
{"@timestamp": "2026-09-27T00:19:27+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "ALLOW", "category": ["web", "network"], "dataset": "kerio_control.filter", "kind": "event", "original": "[27/Sep/2026 00:19:27] ALLOW URL \u0027Log executable downloads\u0027 10.10.20.11 jsmith HTTP GET http://dl.remotedesk.example/remotedesk/15.7/remotedesk-x64.msi", "type": ["access", "allowed"]}, "http": {"request": {"method": "GET"}}, "kerio_control": {"filter": {"action": "ALLOW", "rule_type": "URL"}}, "observer": {"hostname": "kerio-fw-01.example.test", "product": "Kerio Control", "type": "firewall", "vendor": "GFI"}, "related": {"hosts": ["dl.remotedesk.example"], "ip": ["10.10.20.11"], "user": ["jsmith"]}, "rule": {"name": "Log executable downloads"}, "source": {"ip": "10.10.20.11"}, "url": {"domain": "dl.remotedesk.example", "full": "http://dl.remotedesk.example/remotedesk/15.7/remotedesk-x64.msi", "path": "/remotedesk/15.7/remotedesk-x64.msi", "scheme": "http"}, "user": {"name": "jsmith"}}
```

## References

- [Kerio Control: Using the Filter log](https://manuals.gfi.com/en/kerio/control/content/logs/using-the-filter-log-1454.html): URL-rule line layout and example.
- [Kerio Control: Filter logs (GFI support)](https://support.keriocontrol.gfi.com/en-us/article/118924-filter-logs-in-kerio-control): the same format with a one-line example.
- [Kerio Control: Configuring the Content Filter](https://manuals.gfi.com/en/kerio/control/content/content-filtering/configuring-the-content-filter-1513.html): content rules, actions and the **Log the traffic** option.
- [Elastic ECS field reference](https://www.elastic.co/docs/reference/ecs/ecs-field-reference)
