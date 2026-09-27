# SonicWall TZ Web Traffic and Content Filtering Logs

Generates the LAN-to-WAN web traffic records of one SonicWall TZ firewall (SonicOS 6.5.4) as ECS JSON, for training SIEM content on perimeter firewall and web filtering telemetry. `event.original` holds the native line in SonicOS's default key-value Syslog format, and the ECS fields follow the Elastic `sonicwall_firewall` integration. The source is one firewall between a LAN (`X0`, 10.20.30.0/24) and the internet (`X1`) with the Content Filtering Service (CFS) blocking the `Gambling` category.

## Event Types

Shares measured on the final default capture (130 h, `anomaly_mode: true`, 71359 records).

| `m` | Record | Share | `event.category` |
|---|---|---:|---|
| `537` | Connection Closed, HTTPS | 68.18% | network |
| `97` | Website accessed (HTTP, URL data), `Information Technology/Computers` | 7.95% | - (no `event.category` for m=97) |
| `97` | Website accessed (HTTP, URL data), `Not Rated` | 6.78% | - (no `event.category` for m=97) |
| `97` | Website accessed (HTTP, URL data), `Search Engines and Portals` | 6.41% | - (no `event.category` for m=97) |
| `97` | Website accessed (HTTP, URL data), `Business and Economy` | 5.20% | - (no `event.category` for m=97) |
| `537` | Connection Closed, HTTP without request | 3.05% | network |
| `14` | CFS Web site access denied, `Gambling` | 2.43% | network |

SonicOS logs every closed connection once: m=97 when CFS saw URL data (plain HTTP), m=537 otherwise (HTTPS, or HTTP closed before a request). m=97 carries the CFS category of the site; m=14 is the CFS denial. Every client, host, path and record type used by the chain occurs in ordinary background in both modes. No field labels an episode.

## Background Model

Each one-second tick emits at most one record: the earliest due record of a queue, otherwise nothing. Activity arrives as independent Poisson streams with an office-hours factor (08:00-18:00 UTC 1.64, 07:00-08:00 and 18:00-21:00 0.92, 21:00-23:00 0.51, night 0.21); each arrival picks its client by a fixed random per-client weight, so clients act independently.

- **Browsing sessions** (0.02 per second x factor): a client opens log-normally many connections (median 6), log-normal gaps (median 4 s). 70% are HTTPS (m=537) to 60 internet servers of skewed popularity, 27% plain HTTP with URL data (m=97) to sites in four CFS categories (Search Engines and Portals, Information Technology/Computers, Business and Economy, Not Rated), 3% HTTP connections closed without a request (m=537).
- **Blocked-site attempts** (0.0014 per second x factor): a client with a gambling interest (per-client weight, log-normal) opens one of six gambling sites, picked by the client's own site preference, and is denied 1-6 times (reloads and other pages; gaps log-normal, median 12 s; 60% repeat the previous path). In 30% of attempts the user then tries a Not Rated host a little later (log-normal, median 90 s), half of the time with a path copied from the denied pages.

Source ports advance per client by 1-3 through the ephemeral range, as on a desktop OS. Byte and packet counters and `cdur` are log-normal. `n` (`event.sequence`) is the per-message-ID count that SonicOS documents ("number of times event occurs"); it advances by 1-4 because the same message IDs are also counted for traffic this generator does not model (other zones, UDP, inbound).

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the generator emits the background only and the complete chain never occurs.

Sequence, for one LAN client C (`source.ip`), one gambling host H and one Not Rated host U:

1. m=14 `Web site access denied`, `Category="Gambling"`, C to H, path P (`url.path`).
2. m=14 C to H again (any path).
3. m=14 C to H again; 3-6 denials in total.
4. m=97 `Category="Not Rated"`, C to U, the same path P, a few minutes later (log-normal, median 90 s).

Linking fields: `source.ip` in all steps, `url.domain` (H) in steps 1-3, `url.path` (P) in steps 1 and 4, `url.domain` U different from H. The whole chain spans less than 30 minutes (measured spans 179 s, 87 s, 123 s, 198 s, 109 s).

Recurrence: an episode becomes due every `anomaly_interval_hours` of source time (default 24, minimum 2), first one interval after generation starts. Its start is then drawn within min(interval / 4, 6 h) after the due time, with the background hour-of-day factor as density, so it falls into busy hours when the window reaches them and any hour stays possible. The next due time counts from the actual start, so a late episode never causes catch-up. In the final default capture (130 h) 5 episodes started 26.65, 28.37, 25.56, 24.16 h after the previous one (start hours UTC 01, 03, 08, 09, 09); a custom 8 h capture (120 h) had 13 episodes 8.04-9.97 h apart (start hours 09, 18, 03, 11, 20, 06, 14, 23, 08, 16, 01, 11, 19), each by a different client than the one before.

Variation: client and gambling host are taken from one of the last 60 background blocked-site attempts, excluding the previous episode's client, so they follow the background weights and the pair already occurs in background; the unrated host is one the client visited in background. Paths, denial count, gaps and delay come from the background law for blocked-site attempts. The chain changes no firewall state.

Detection idea: a client denied by CFS three or more times for one site, then fetching the same path from an uncategorized host within 30 minutes: a mirror or proxy used to evade the web filter. Every fragment occurs in background: per day of the final captures (on / off), 54.9 / 52.3 times a client reached a third denial of one site within 10 minutes, 95.1 / 107.7 Not Rated visits followed a denial of the same client within 30 minutes, and 21.8 / 15.0 of them reused a denied path. Only the complete sequence is kept out of the background: an ordinary Not Rated visit keeps its time, client and host, but takes another path when its path is that of a denial followed by at least two more denials of the same site by that client within the last 30 minutes.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
|---|---|---|
| `anomaly_mode` | `true` | Add periodic episodes to the background |
| `anomaly_interval_hours` | `24` | Episode interval in source hours, 2-8760 |
| `firewall_wan_ip` | `192.0.2.10` | Firewall WAN address: `fw=` and the Syslog header host |
| `firewall_serial` | `02DEADBEEF01` | Synthetic serial (`sn=`, 12 characters; use hex digits); also the firewall MAC in m=14 `dstMac` |
| `upstream_mac` | `02:00:5e:00:53:01` | MAC of the upstream router, `dstMac` of forwarded traffic |
| `client_prefix` | `10.20.30.` | Client addresses are this prefix plus a host number |
| `client_first` | `20` | First client host number |
| `client_count` | `40` | Number of LAN clients (at least 8; `client_first + client_count` at most 255) |

### Output Parameters

The shipped config writes `output/events.json` with the `json` formatter and needs no `${params.*}` or `${secrets.*}`. To send events elsewhere, replace the `output` section, for example:

```yaml
output:
  - opensearch:
      hosts: ["${params.opensearch_url}"]
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: sonicwall-tz
```

A collector that parses the native format needs `event.original` rather than the surrounding JSON.

## Usage

Live mode:

```bash
eventum generate --path generators/network-sonicwall-tz/generator.yml --id sonicwall --live-mode true
```

Batch mode needs a bounded input: add `start` and `end` to the `cron` input, then run:

```bash
eventum generate --path generators/network-sonicwall-tz/generator.yml --id sonicwall --live-mode false
```

## Limitations

- The native lines copy the field sets and order of the SonicOS 6.5.4 guide's default Syslog examples: m=97 and m=14 (Content Filtering examples) and both m=537 shapes (Connection Closed examples, with and without `srcMac`, `rcvd` and `rpkt`). `app=11` for HTTPS m=537 comes from a real capture in the Elastic integration's test data; the guide itself shows only HTTP. The CFS codes and names (11 Gambling, 64 Not Rated, 29, 27, 15) are the ones in those sources.
- Content filtering records are HTTP only: HTTPS appears only as m=537, as without DPI-SSL. Not generated: m=98 Connection Opened, NAT fields, zones, users (`usr`, `sess`), `gcat`, `referer`, IPv6, ArcSight CEF format, and the other SonicOS message IDs.
- The Syslog header carries the firewall WAN address and the same UTC clock as `time=` plus 0-1 s receipt delay; the device time zone is UTC. The vendor examples also show a relay in another time zone, which is not modeled.
- The guide covers SonicOS 6.5.4 on TZ and other appliances; it is not a TZ-specific capture, and SonicOS 7 lines (with `gcat`, zones, `appName`) differ.
- Rates, sizes, durations and address pools are training assumptions, not measured production values. There is no weekday cycle.
- Episodes recur on a schedule, so they cannot follow the background hour-of-day mix exactly: when the whole start window lies in night hours the episode starts at night. Background blocked-site attempts fall 23:00-07:00 UTC about 9% of the time; in the final captures 2 of 5 default episodes (the first two, whose windows after a midnight capture start were entirely night) and 4 of 13 custom 8 h episodes started in those hours. Daytime windows put the start into busy hours.
- The ECS document follows the Elastic pipeline output for these message IDs (`event.code`, `event.sequence`, `rule.id`, `url.*`, `sonicwall.firewall.*`); like that pipeline, m=97 records have no `event.action` or `event.category`.

## Sample Output

The m=97 step of the first episode in the final default capture (line 13541), byte-exact:

```json
{"@timestamp": "2026-09-27T01:16:12+00:00", "destination": {"bytes": 4402, "ip": "203.0.113.81", "mac": "02-00-5E-00-53-01", "port": 80}, "ecs": {"version": "8.17.0"}, "event": {"code": "97", "dataset": "sonicwall_firewall.log", "kind": "event", "original": "Sep 27 01:16:12 192.0.2.10 id=firewall sn=02DEADBEEF01 time=\"2026-09-27 01:16:12\" fw=192.0.2.10 pri=6 c=1024 m=97 app=48 n=1885362 src=10.20.30.21:64639:X0 dst=203.0.113.81:80:X1 srcMac=02:da:6e:73:9e:2a dstMac=02:00:5e:00:53:01 proto=tcp/http op=1 sent=1341 rcvd=4402 dpi=0 dstname=203.0.113.81 arg=/casino/lobby code=64 Category=\"Not Rated\" note=\"Policy: CFS Default Policy, Info: 6148 \" rule=\"9 (LAN-\u003eWAN)\" fw_action=\"NA\"", "sequence": 1885362, "severity": 6}, "http": {"request": {"method": "GET"}}, "log": {"level": "info"}, "message": "Policy: CFS Default Policy, Info: 6148 ", "network": {"bytes": 5743, "protocol": "http", "transport": "tcp"}, "observer": {"egress": {"interface": {"name": "X1"}}, "ingress": {"interface": {"name": "X0"}}, "ip": ["192.0.2.10"], "name": "firewall", "product": "SonicOS", "serial_number": "02DEADBEEF01", "type": "firewall", "vendor": "SonicWall"}, "related": {"ip": ["10.20.30.21", "203.0.113.81", "192.0.2.10"]}, "rule": {"id": "9 (LAN-\u003eWAN)"}, "sonicwall": {"firewall": {"Category": "Not Rated", "app": "48", "code": "64", "dpi": "false"}}, "source": {"bytes": 1341, "ip": "10.20.30.21", "mac": "02-DA-6E-73-9E-2A", "port": 64639}, "url": {"domain": "203.0.113.81", "full": "http://203.0.113.81/casino/lobby", "path": "/casino/lobby", "scheme": "http"}}
```

## References

- [SonicOS 6.5.4 Log Events Reference Guide](https://www.sonicwall.com/techdocs/pdf/sonicos-6-5-4-log-events-reference-guide.pdf): Traffic Report Syslogs (m=97 and m=537), Syslog tag descriptions, Examples of Standard Syslog Messages.
- [Elastic integration: SonicWall Firewall](https://github.com/elastic/integrations/tree/main/packages/sonicwall_firewall): ingest pipeline and test fixtures.
- [Elastic ECS field reference](https://www.elastic.co/docs/reference/ecs/ecs-field-reference)
