# SonicWall TZ Web Traffic and Content Filtering Logs

Generates the LAN-to-WAN web traffic records of one SonicWall TZ firewall (SonicOS 6.5.4) as ECS JSON, for training SIEM content on perimeter firewall and web filtering telemetry. `event.original` holds the native line in SonicOS's default key-value Syslog format, and the ECS fields follow the Elastic `sonicwall_firewall` integration. The source is one firewall between a LAN (`X0`, 10.20.30.0/24) and the internet (`X1`) with the Content Filtering Service (CFS) blocking the `Gambling` category.

## Event Types

Shares over several days of default output (about 12,500 records a day).

| `m` | Record | Share | `event.category` |
|---|---|---:|---|
| `537` | Connection Closed, HTTPS | 68.2% | network |
| `97` | Website accessed (HTTP, URL data), `Information Technology/Computers` | 8.0% | - (no `event.category` for m=97) |
| `97` | Website accessed (HTTP, URL data), `Not Rated` | 6.9% | - (no `event.category` for m=97) |
| `97` | Website accessed (HTTP, URL data), `Search Engines and Portals` | 6.5% | - (no `event.category` for m=97) |
| `97` | Website accessed (HTTP, URL data), `Business and Economy` | 5.2% | - (no `event.category` for m=97) |
| `537` | Connection Closed, HTTP without request | 2.9% | network |
| `14` | CFS Web site access denied, `Gambling` | 2.3% | network |

SonicOS logs every closed connection once: m=97 when CFS saw URL data (plain HTTP), m=537 otherwise (HTTPS, or HTTP closed before a request). m=97 carries the CFS category of the site; m=14 is the CFS denial. Every client, host, path and record type used by the chain occurs in ordinary background in both modes. No field labels an episode.

## Volume and Clients

About 12,500 records a day on a working-day curve (UTC): 113 an hour at night (23:00-07:00), 507 at 07:00-08:00 and 18:00-21:00, 901 in office hours (08:00-18:00), 282 at 21:00-23:00, with the daily volume varying by about 3%. The clients present follow the same curve: all 40 in office hours, about 24 in the early morning and evening hours, 13 late in the evening and 8 at night (machines left running, late workers). The same parameters always describe the same office: client MAC addresses, how busy each client is, who works late, users' favourite sites and the popularity of internet servers.

- **Browsing sessions** (93% of client activities): a client opens log-normally many connections (median 6, at most 40), a few seconds apart. 70% are HTTPS (m=537) to 60 internet servers of skewed popularity, 27% plain HTTP with URL data (m=97) to sites in four CFS categories (Search Engines and Portals, Information Technology/Computers, Business and Economy, Not Rated), 3% HTTP connections closed without a request (m=537). Clients differ in how much they browse (bounded per-client weights).
- **Blocked-site attempts** (7% of client activities): a client opens one of six gambling sites and is denied 1-6 times (one denial more common than two, two than three; reloads and other pages; 60% repeat the previous path). A fifth of the users try gambling sites often, mostly one favourite site; the rest rarely. In 30% of attempts the user then tries a Not Rated host a little later (log-normal, median 90 s, at most 20 minutes), half of the time with a path copied from the denied pages.

Source ports advance per client by 1-3 through the ephemeral range, as on a desktop OS. Byte and packet counters and `cdur` are log-normal. `n` (`event.sequence`) is the per-message-ID count that SonicOS documents ("number of times event occurs"); it advances by 1-4 because the same message IDs are also counted for traffic this generator does not model (other zones, UDP, inbound).

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the generator emits the background only and the complete chain never occurs.

Sequence, for one LAN client C (`source.ip`), one gambling host H and one Not Rated host U:

1. m=14 `Web site access denied`, `Category="Gambling"`, C to H, path P (`url.path`, `/` or `/login`).
2. m=14 C to H again (any path).
3. m=14 C to H again; 3-6 denials in total.
4. m=97 `Category="Not Rated"`, C to U, the same path P, a few minutes later (log-normal, median 90 s).

Linking fields: `source.ip` in all steps, `url.domain` (H) in steps 1-3, `url.path` (P) in steps 1 and 4, `url.domain` U different from H. The whole chain spans less than 30 minutes: typically 1 to 9 minutes (median about 2.5 minutes), rarely up to about 20 minutes.

Recurrence: the first episode starts within min(`anomaly_interval_hours`, 24 h) of the start of the data, its time following the hour-of-day volume. Each later episode starts within a window of min(interval / 4, 6 h) centred on the previous start plus the interval, busy hours strongly preferred (weight: squared hourly volume plus a small floor), so with the default 24 h interval episodes start at a similar, usually busy, hour every day. The next interval counts from the actual start; there is no catch-up. Consecutive episodes use different clients.

Variation: client and gambling host are one of the frequent client/site pairs of the users who often try gambling sites, among the clients present at that hour (two of these clients are present at every hour); the Not Rated host is one the client visits often. Each such pair and host occurs many times a day in ordinary background. Paths, denial count, gaps and delay come from the background law for blocked-site attempts, conditioned on at least three denials and on the copied first path; that path is one that ordinary Not Rated browsing also requests (`/` or `/login`), so each host and path of the last step also occur together in background. The chain changes no firewall state.

Detection idea: a client denied by CFS three or more times for one site, then fetching the same path from an uncategorized host within 30 minutes: a mirror or proxy used to evade the web filter. Every fragment occurs in background every day: repeated denials of one site, Not Rated visits shortly after denials, and Not Rated visits that reuse a denied path. Only the complete sequence is absent from the background: an ordinary Not Rated visit never carries the path of a denial that the same client followed with at least two more denials of that site within the preceding 30 minutes.

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

### Sample Files

`samples/sites.csv` lists the web sites by CFS category (`category`, `domain`, `ip`); categories are `gambling` (blocked), `search`, `it`, `business` and `unrated`, each with at least one site. Edit it to use other host names or addresses.

### Volume

The record rate and its hour-of-day curve are set by the four files in `patterns/` (records per day in `multiplier.ratio`, the hours each band covers in `spreader.parameters` as fractions of the day).

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

Batch mode: set `start` and `end` of the `oscillator` in all four `patterns/*.yml` files to the same range, with `start` at 00:00 UTC so the hour bands stay in place (for example `start: "2026-09-01T00:00:00Z"` and `end: "2026-09-05T00:00:00Z"`), then run:

```bash
eventum generate --path generators/network-sonicwall-tz/generator.yml --id sonicwall --live-mode false --keep-order true
```

Performance: about 2,000 records per second in batch mode on one core.

## Limitations

- The native lines copy the field sets and order of the SonicOS 6.5.4 guide's default Syslog examples: m=97 and m=14 (Content Filtering examples) and both m=537 shapes (Connection Closed examples, with and without `srcMac`, `rcvd` and `rpkt`). `app=11` for HTTPS m=537 comes from a real capture in the Elastic integration's test data; the guide itself shows only HTTP. The CFS codes and names (11 Gambling, 64 Not Rated, 29, 27, 15) are the ones in those sources.
- Content filtering records are HTTP only: HTTPS appears only as m=537, as without DPI-SSL. Not generated: m=98 Connection Opened, NAT fields, zones, users (`usr`, `sess`), `gcat`, `referer`, IPv6, ArcSight CEF format, and the other SonicOS message IDs.
- The Syslog header carries the firewall WAN address and the same UTC clock as `time=` plus 0-1 s receipt delay; the device time zone is UTC. The vendor examples also show a relay in another time zone, which is not modeled.
- The guide covers SonicOS 6.5.4 on TZ and other appliances; it is not a TZ-specific capture, and SonicOS 7 lines (with `gcat`, zones, `appName`) differ.
- Rates, sizes, durations and address pools are training assumptions, not measured production values. There is no weekday cycle.
- Records of one moment are spread over consecutive seconds: connections of one browsing session are a few seconds apart in office hours and up to about half a minute apart at night, and repeated CFS denials of one attempt are a median 20 s apart (90th percentile 90 s) instead of the sub-second bursts of a real browser.
- With `anomaly_mode: true` each episode adds its own records, so counts of the chain parts (denials of one site by one client, Not Rated visits after denials) are about one episode's worth higher than without episodes.
- Episodes recur on a schedule, so they cannot follow the background hour-of-day mix exactly: with intervals that are not a multiple of 24 h the start hour moves around the clock and some episodes start at night, when about 6-7% of blocked-site attempts occur; with the default 24 h interval episodes stay near busy hours.
- The ECS document follows the Elastic pipeline output for these message IDs (`event.code`, `event.sequence`, `rule.id`, `url.*`, `sonicwall.firewall.*`); like that pipeline, m=97 records have no `event.action` or `event.category`.

## Sample Output

The m=97 step of an episode with `anomaly_mode: true`, byte-exact:

```json
{"@timestamp": "2026-09-01T10:00:57+00:00", "destination": {"bytes": 789, "ip": "203.0.113.61", "mac": "02-00-5E-00-53-01", "port": 80}, "ecs": {"version": "8.17.0"}, "event": {"code": "97", "dataset": "sonicwall_firewall.log", "kind": "event", "original": "Sep  1 10:00:57 192.0.2.10 id=firewall sn=02DEADBEEF01 time=\"2026-09-01 10:00:57\" fw=192.0.2.10 pri=6 c=1024 m=97 app=48 n=2309112 src=10.20.30.48:54396:X0 dst=203.0.113.61:80:X1 srcMac=02:23:8d:54:1c:50 dstMac=02:00:5e:00:53:01 proto=tcp/http op=1 sent=456 rcvd=789 dpi=0 dstname=static-host.example arg=/ code=64 Category=\"Not Rated\" note=\"Policy: CFS Default Policy, Info: 6148 \" rule=\"9 (LAN-\u003eWAN)\" fw_action=\"NA\"", "sequence": 2309112, "severity": 6}, "http": {"request": {"method": "GET"}}, "log": {"level": "info"}, "message": "Policy: CFS Default Policy, Info: 6148 ", "network": {"bytes": 1245, "protocol": "http", "transport": "tcp"}, "observer": {"egress": {"interface": {"name": "X1"}}, "ingress": {"interface": {"name": "X0"}}, "ip": ["192.0.2.10"], "name": "firewall", "product": "SonicOS", "serial_number": "02DEADBEEF01", "type": "firewall", "vendor": "SonicWall"}, "related": {"ip": ["10.20.30.48", "203.0.113.61", "192.0.2.10"]}, "rule": {"id": "9 (LAN-\u003eWAN)"}, "sonicwall": {"firewall": {"Category": "Not Rated", "app": "48", "code": "64", "dpi": "false"}}, "source": {"bytes": 456, "ip": "10.20.30.48", "mac": "02-23-8D-54-1C-50", "port": 54396}, "url": {"domain": "static-host.example", "full": "http://static-host.example/", "path": "/", "scheme": "http"}}
```

## References

- [SonicOS 6.5.4 Log Events Reference Guide](https://www.sonicwall.com/techdocs/pdf/sonicos-6-5-4-log-events-reference-guide.pdf): Traffic Report Syslogs (m=97 and m=537), Syslog tag descriptions, Examples of Standard Syslog Messages.
- [Elastic integration: SonicWall Firewall](https://github.com/elastic/integrations/tree/main/packages/sonicwall_firewall): ingest pipeline and test fixtures.
- [Elastic ECS field reference](https://www.elastic.co/docs/reference/ecs/ecs-field-reference)
