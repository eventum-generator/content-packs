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

Measured in the final default-on 120-hour capture (6,007 lines, starting 2026-09-21 00:00 UTC):

| Action | Native line | Share | ECS category |
| --- | --- | ---: | --- |
| `accept` | `Accepted user: ...` | 29.4% | `authentication` |
| `connect` | `Connect: ...` (Accounting Start) | 29.4% | `session` |
| `disconnect` | `Disconnect: ... N seconds` (Accounting Stop) | 29.3% | `session` |
| `reject` | `Rejected user: ...` | 11.8% | `authentication` |

The site has 36 users and 50 client devices (`samples/clients.json`; 14 users carry a laptop and a phone) and six access points of one SSID (`samples/access_points.json`). Each device is an independent random process with its own activity weight and preferred access points: an idle gap (lognormal, thinned by an office-hours curve in UTC), one authentication attempt, an accounting Start 0-3 seconds after the accept, and a Stop after a lognormal session (median about 35 minutes). `Acct-Session-Time` equals the actual Start-to-Stop time; the framed IP is the device's fixed lease; `NAS-Port` is the association ID (RFC 3580), new for each attempt. About 12% of attempts start with one to eight mistyped passwords a few seconds apart, each extra reject half as likely as the previous count, and 15% of them give up; about 2% come from a device with a stale saved password that is rejected 2 to 14 times, every few tens of minutes, until it is updated. All rates are synthetic, not measured FreeRADIUS statistics. Each one-second tick emits at most one line; a tick with nothing due is silent. The log starts with no open sessions, and sessions still open at the end of a finite run have no Stop.

## Anomaly Chain

Password guessing that succeeds from a device's usual station, then a network session:

1. Five to eight `Rejected user` lines for one user and calling station, seconds apart.
2. `Accepted user` for the same user and station.
3. `Connect` (Accounting Start) for that user, station and NAS port, 0-3 seconds later, with the device's framed IP and one of its access points.
4. `Disconnect` (Accounting Stop) after an ordinary session length; `Acct-Session-Time` is the real elapsed time.

Linking fields: `user.name` + `source.mac` (`Calling-Station-Id`), `radius.nas_port` across the accept and accounting lines, and the Start/Stop pair on the station. The selected formats carry no `Acct-Session-Id`, so a session is the Start/Stop pair of one station.

Recurrence: with `anomaly_mode: true` (the default) the first episode starts within `min(anomaly_interval_hours, 24 h)` of the first event, at an hour drawn from the background office-hours curve. Each next episode is due `anomaly_interval_hours` after the actual start of the previous one and starts inside a window of `w = min(interval / 4, 6 h)` centred on that due time, weighted by the squared office-hours curve plus a small floor, so start hours do not drift and missed intervals are never caught up. Consecutive starts are therefore `interval ± w/2` apart (24 ± 3 h by default). With a short interval the window is narrow (2 h at 8 h) and some due times fall at night, so a share of episodes then starts outside office hours. Each episode picks a device with the background activity weights among devices that are idle and whose own next attempt comes after the episode ends, never the previous episode's user. Its reject count is drawn from the tail (five to eight) of the same mistyped-password law as background bursts; its reject gaps, port, access point and session length are drawn like background. The device's own traffic is neither suspended nor moved.

Everything the chain uses also occurs in ordinary traffic of both modes: every user|station pair, the same access points, reject bursts seconds apart, runs of five to eight rejects, four rejects followed by an accept and a Start, and sessions of the same length distribution. Only the complete ordered chain is absent from background: an ordinary attempt whose Start would complete five rejects of its user and station within ten minutes ends silently, as a user who gives up: after its last reject, or before its accept when it has no reject of its own. No line is added or changed, so reject-run lengths keep the burst law. In five background-only 120-hour captures, bursts of rejects seconds apart had lengths 4/5/6/7/8 = 86/40/21/7/1; 86-88% of two- to four-reject bursts ended in an accept, and no burst of five or more did. No Start came within 600 seconds of its fifth-last reject; the shortest such spans were 638, 662 and 709 seconds, with 4 between 600 and 900 seconds and 8 between 900 and 1,200 over 600 hours.

Detection idea: at least five `Rejected user` lines for the same user and calling station within ten minutes, followed by `Accepted user` and an accounting Start for that pair; alert on the Start and follow the session to its Stop.

With `anomaly_mode: false`, only background is generated.

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

Live mode, one line per second at most, until stopped:

```bash
eventum generate --path generators/identity-freeradius/generator.yml --id freeradius --live-mode true
```

Batch mode: add `start` and `end` to `input[0].cron` in a copy of `generator.yml`, then:

```bash
eventum generate --path generator.yml --id freeradius --live-mode false --keep-order true
```

## Limitations

- No raw output from a running FreeRADIUS 3.2.10 server was available. The accounting lines follow the tagged `log_accounting` formats verbatim; the authentication lines follow the custom `auth_siemaudit` instance above, built with tagged `linelog` syntax but not exercised on a daemon. Compatibility with syslog-oriented FreeRADIUS parsers is not claimed.
- One RADIUS server, one controller and one SSID; no roaming within a session, no Interim-Update, no NAS reboots.
- Office hours are in UTC, with no weekday cycle.
- In background, five or more rejects of one user and station within ten minutes are never followed by an accept and Start within that window; this is the chain itself. A detector with a lower threshold or a longer window also matches background near misses.

## Sample output

Chain Start of the first episode of the final default-on capture, copied unchanged:

```json
{"@timestamp": "2026-09-21T19:56:53.334+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "connect", "category": ["session"], "dataset": "freeradius.linelog", "kind": "event", "module": "freeradius", "original": "Connect: [ekaterina.romanova] (did 06-1B-2C-41-10-A2:corp-wifi cli 02-4C-1A-EE-32-EA port 117 ip 10.50.1.223)", "outcome": "success", "type": ["start"]}, "host": {"name": "radius-01"}, "message": "Connect: [ekaterina.romanova] (did 06-1B-2C-41-10-A2:corp-wifi cli 02-4C-1A-EE-32-EA port 117 ip 10.50.1.223)", "radius": {"acct_status_type": "Start", "called_station_id": "06-1B-2C-41-10-A2:corp-wifi", "calling_station_id": "02-4C-1A-EE-32-EA", "client_shortname": "wlc-01", "framed_ip_address": "10.50.1.223", "nas_port": 117}, "service": {"name": "radiusd"}, "source": {"ip": "10.50.1.223", "mac": "02-4C-1A-EE-32-EA"}, "user": {"name": "ekaterina.romanova"}}
```

## References

- [FreeRADIUS 3.2.10 `mods-available/linelog`](https://github.com/FreeRADIUS/freeradius-server/blob/release_3_2_10/raddb/mods-available/linelog)
- [FreeRADIUS 3.2.10 `sites-available/default`](https://github.com/FreeRADIUS/freeradius-server/blob/release_3_2_10/raddb/sites-available/default)
- [FreeRADIUS 3.2.10 `radiusd.conf.in`](https://github.com/FreeRADIUS/freeradius-server/blob/release_3_2_10/raddb/radiusd.conf.in)
- [RFC 3580: IEEE 802.1X RADIUS Usage Guidelines](https://www.rfc-editor.org/rfc/rfc3580)
- The ECS layout is inferred; no vendor-published ECS mapping for these lines was used.
