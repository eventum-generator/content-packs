# FreeRADIUS 3.2.10 Linelog Generator

Produces ECS JSON from the **file `linelog` output** of one FreeRADIUS 3.2.10 server that authenticates 802.1X wireless clients of one controller: `Accepted user` and `Rejected user` lines, and accounting `Connect` (Start) and `Disconnect` (Stop) lines. Background-only and anomaly modes are supported; `anomaly_mode: true` is the default. The file line is kept verbatim in `event.original` and `message`, without a syslog header. `@timestamp`, `host.name` and `radius.client_shortname` are collector enrichment: the configured lines carry no clock and no server or client name.

## Required FreeRADIUS profile

These lines require explicit `linelog` configuration. Built-in `log.auth` is `no` in the tagged 3.2.10 `radiusd.conf`, and the default `linelog` authentication messages carry only the user name. Add this named instance to `mods-available/linelog` and enable the file through `mods-enabled/linelog`:

```text
linelog auth_siemaudit {
    filename = ${logdir}/linelog
    permissions = 0600
    format = ""
    reference = "messages.%{%{reply:Packet-Type}:-default}"
    messages {
        Access-Accept = "Accepted user: [%{User-Name}] (cli %{Calling-Station-Id} port %{NAS-Port})"
        Access-Reject = "Rejected user: [%{User-Name}] (cli %{Calling-Station-Id} port %{NAS-Port})"
    }
}
```

Keep the tagged `linelog log_accounting` instance (`filename = ${logdir}/linelog-accounting`, `reference = "Accounting-Request.%{%{Acct-Status-Type}:-unknown}"`) with its Start and Stop formats:

```text
Start = "Connect: [%{User-Name}] (did %{Called-Station-Id} cli %{Calling-Station-Id} port %{NAS-Port} ip %{Framed-IP-Address})"
Stop = "Disconnect: [%{User-Name}] (did %{Called-Station-Id} cli %{Calling-Station-Id} port %{NAS-Port} ip %{Framed-IP-Address}) %{Acct-Session-Time} seconds"
```

Call `auth_siemaudit` in the active virtual server's `post-auth` section and inside its `Post-Auth-Type REJECT` subsection, and `log_accounting` in its `accounting` section (for the tagged default site, `sites-available/default` enabled through `sites-enabled/default`). This is a placement sketch inside the existing sections, not a replacement site file:

```text
post-auth {
    auth_siemaudit
    Post-Auth-Type REJECT {
        auth_siemaudit
    }
}
accounting {
    log_accounting
}
```

Authentication and accounting go to **two files**; a collector reads both and parses the formats above. `Called-Station-Id` and `Calling-Station-Id` use the RFC 3580 form: upper-case MAC octets separated by `-`, and `:SSID` after the access-point MAC. Interim-Update, Accounting-On/Off and Access-Challenge lines are not generated.

## Event Types

Shares over seven days with `anomaly_mode: true` (194,582 lines):

| Action | Native line | Share | ECS category |
| --- | --- | ---: | --- |
| `accept` | `Accepted user: ...` | 31.8% | `authentication` |
| `connect` | `Connect: ...` (Accounting Start) | 31.2% | `session` |
| `disconnect` | `Disconnect: ... N seconds` (Accounting Stop) | 31.2% | `session` |
| `reject` | `Rejected user: ...` | 5.7% | `authentication` |

The site has 726 users with 1,000 client devices (`samples/clients.json`; 274 users carry a laptop and a phone) and 30 access points of one SSID (`samples/access_points.json`). Each device has its own activity level (within a factor of four of the others) and one to three preferred neighbouring access points.

Volume is about 27,800 lines a day and follows a fixed hour-of-day curve in UTC: 0.06 lines/s from 00:00 to 05:00, rising through 06:00-08:00 to 0.6 lines/s from 08:00 to 16:00, then tapering hour by hour to 0.08 lines/s at 23:00. The daily total varies by about 2%. Up to about 690 sessions are open at the same time in office hours.

Each authentication attempt belongs to one device:

- 93.5% succeed at once: `Accepted user`, then the accounting Start a few seconds later (median 3 s).
- 5% start with one to eight mistyped passwords a few seconds apart, each extra reject half as likely as the previous count; 15% of these users give up, the rest are accepted.
- 1.5% come from a device with a stale saved password, rejected 2 to 14 times about every 20 minutes (fewer retries more likely) until it is updated and accepted.
- 1.5% of accepts have no accounting Start (the client does not complete the association).

Sessions last a lognormal time (10th/50th/90th percentile about 12 minutes, 36 minutes and 1.8 hours, at most about 12 hours); `Acct-Session-Time` in the Stop equals the actual Start-to-Stop time. The framed IP is the device's fixed lease; `NAS-Port` is the association ID (RFC 3580), new for each attempt. A device has at most one attempt or session at a time. All rates are synthetic, not measured FreeRADIUS statistics. The log starts with no open sessions, and sessions still open at the end of a finite run have no Stop.

## Anomaly Chain

Password guessing that succeeds from a device's usual station, then a network session:

1. Five to eight `Rejected user` lines for one user and calling station, seconds apart and all within about six minutes.
2. `Accepted user` for the same user and station.
3. `Connect` (Accounting Start) for that user, station and NAS port, a few seconds later, with the device's framed IP and one of its access points.
4. `Disconnect` (Accounting Stop) after an ordinary session length; `Acct-Session-Time` is the real elapsed time.

Linking fields: `user.name` + `source.mac` (`Calling-Station-Id`), `radius.nas_port` across the accept and accounting lines, and the Start/Stop pair on the station. The selected formats carry no `Acct-Session-Id`, so a session is the Start/Stop pair of one station.

Recurrence: with `anomaly_mode: true` (the default) the first episode starts within `min(anomaly_interval_hours, 24 h)` of the first line, at an hour drawn from the volume curve. Each next episode is due `anomaly_interval_hours` after the actual start of the previous one and starts inside a window of `w = min(interval / 4, 6 h)` centred on that due time, weighted by the squared volume curve plus a small floor, so start hours do not drift far and missed intervals are never caught up. Consecutive starts are `interval ± w/2` apart (24 ± 3 h by default). An episode that first falls at night keeps the next ones near that hour and moves towards office hours by about an hour a day; with a short interval (8 h) some episodes fall at night as well.

Each episode uses a device chosen with the ordinary activity levels among devices that have no attempt or session open, never the previous episode's user. Its reject count comes from the tail (five to eight) of the mistyped-password law above; its reject gaps, port, access point and session length are drawn like ordinary ones. The episode's lines are interleaved with ordinary traffic (the daily line count is the same in both modes, so they stand in for a few ordinary attempts), and the device's own sessions before and after it are unchanged.

Everything the chain uses also occurs in ordinary traffic of both modes: every user and station pair, every station and access point pair, runs of five to eight rejects seconds apart followed by an accept, and sessions of the same length distribution. Only the complete chain is absent from ordinary traffic: an accept that follows five or more rejects of its user and station within ten minutes (about 25 a day) is never followed by an accounting Start in that window.

Detection idea: at least five `Rejected user` lines for the same user and calling station within ten minutes, followed by `Accepted user` and an accounting Start for that pair; alert on the Start and follow the session to its Stop.

With `anomaly_mode: false`, only ordinary traffic is generated.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Emit recurring episodes; `false` gives background only |
| `anomaly_interval_hours` | `24` | Hours from one episode start to the next due time; 2 to 720 (a value outside fails the render) |
| `radius_host` | `radius-01` | `host.name` enrichment |
| `nas_client` | `wlc-01` | `radius.client_shortname` enrichment (the controller's `clients.conf` short name) |
| `ssid` | `corp-wifi` | SSID appended to the access-point MAC in `Called-Station-Id` |

Users, devices and leases are in `samples/clients.json`, access-point MACs in `samples/access_points.json`. Keep station MACs and IPs unique when editing them.

### Output Parameters

The shipped output writes `output/events.json` and uses no `${params.*}` or `${secrets.*}` placeholders. To send events elsewhere, replace the `output` block and pass values through placeholders, for example an `opensearch` output with `hosts: ["${params.opensearch_host}"]` and `password: ${secrets.opensearch_password}`, with the secret stored in the Eventum keyring.

## Usage

Live generation at the configured rate, until stopped:

```bash
eventum generate --path generators/identity-freeradius/generator.yml --id freeradius --live-mode true
```

Batch generation: set `start` and `end` of the `oscillator` in every `patterns/*.yml` file to the same range, with `start` at 00:00 UTC so the hour curve stays in place (for example `start: "2026-09-01T00:00:00Z"` and `end: "2026-09-08T00:00:00Z"`), then run:

```bash
eventum generate --path generators/identity-freeradius/generator.yml --id freeradius --live-mode false --keep-order true
```

The hour curve is the sum of the ten `time_patterns` files under `patterns/`, each adding a flat rate over one UTC hour range. To change the volume, scale the `ratio` of every pattern file by the same factor. Episode start hours follow the shipped curve even if you reshape the pattern files.

Performance: about 3,000 lines per second in batch mode on one core.

## Limitations

- No raw output from a running FreeRADIUS 3.2.10 server was available. The accounting lines follow the tagged `log_accounting` formats verbatim; the authentication lines follow the custom `auth_siemaudit` instance above, built with tagged `linelog` syntax but not exercised on a daemon. Compatibility with syslog-oriented FreeRADIUS parsers is not claimed.
- One RADIUS server, one controller and one SSID; no roaming within a session, no Interim-Update, no NAS reboots.
- The hour curve is in UTC and repeats every day, with no weekday cycle.
- Lines of one attempt are seconds apart rather than milliseconds: the accounting Start follows its accept after a median 3 s, and at night after up to about three minutes.
- An accept that follows five or more rejects of its user and station within ten minutes is never followed by an accounting Start in ordinary traffic, while other accepts miss their Start only 1.5% of the time. A detector with a lower threshold or a longer window also matches ordinary near misses.
- With `anomaly_mode: true` each episode adds its own lines, so counts of the chain parts (runs of five or more rejects, such runs followed by an accept) are about one per episode higher than in ordinary traffic: about seven more a week at the default interval, on top of roughly 175 runs of five or more rejects a week.

## Sample output

Accounting Start that completes an episode of a default run (`anomaly_mode: true`):

```json
{"@timestamp": "2026-09-04T08:18:12.849+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "connect", "category": ["session"], "dataset": "freeradius.linelog", "kind": "event", "module": "freeradius", "original": "Connect: [matvey.titov] (did 06-1B-2C-41-2F-95:corp-wifi cli 02-4C-1A-7E-8C-C3 port 224 ip 10.50.7.129)", "outcome": "success", "type": ["start"]}, "host": {"name": "radius-01"}, "message": "Connect: [matvey.titov] (did 06-1B-2C-41-2F-95:corp-wifi cli 02-4C-1A-7E-8C-C3 port 224 ip 10.50.7.129)", "radius": {"acct_status_type": "Start", "called_station_id": "06-1B-2C-41-2F-95:corp-wifi", "calling_station_id": "02-4C-1A-7E-8C-C3", "client_shortname": "wlc-01", "framed_ip_address": "10.50.7.129", "nas_port": 224}, "service": {"name": "radiusd"}, "source": {"ip": "10.50.7.129", "mac": "02-4C-1A-7E-8C-C3"}, "user": {"name": "matvey.titov"}}
```

## References

- [FreeRADIUS 3.2.10 `mods-available/linelog`](https://github.com/FreeRADIUS/freeradius-server/blob/release_3_2_10/raddb/mods-available/linelog)
- [FreeRADIUS 3.2.10 `sites-available/default`](https://github.com/FreeRADIUS/freeradius-server/blob/release_3_2_10/raddb/sites-available/default)
- [FreeRADIUS 3.2.10 `radiusd.conf.in`](https://github.com/FreeRADIUS/freeradius-server/blob/release_3_2_10/raddb/radiusd.conf.in)
- [RFC 3580: IEEE 802.1X RADIUS Usage Guidelines](https://www.rfc-editor.org/rfc/rfc3580)
- The ECS layout is inferred; no vendor-published ECS mapping for these lines was used.
