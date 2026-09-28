# Progress Kemp LoadMaster ESP CEF

Edge Security Pack (ESP) user logs of a Progress Kemp LoadMaster in Common Event Format, for one virtual service that pre-authenticates a webmail portal. Each output line is ECS JSON with the vendor CEF body in `event.original` and the parsed header and extension under `kemp.loadmaster`. The pack is for SIEM teams that test CEF parsing, ESP authentication monitoring and correlation of failed ESP logons with later access.

## Event Types

Shares measured on the final default capture (156 h, `anomaly_mode: true`, 26,430 events). The `anomaly_mode: false` capture of the same window differs by less than 0.9 percentage points per class.

| CEF class ID | Name | `event.action` | Share | ECS category |
| --- | --- | --- | --- | --- |
| `14` | Request | `request` | 48.1% | `web` |
| `2` | SSL accept | `ssl-accept` | 13.3% | `network` |
| `4` | Connected | `connected` | 11.0% | `network` |
| `15` | Attempt | `attempt` | 6.7% | `web` |
| `100` | User AAA | `user-aaa` | 5.0% | `authentication` |
| `8` | Logged on | `logged-on` | 5.0% | `authentication`, `session` |
| `6` | Logged off | `logged-off` | 2.8% | `authentication`, `session` |
| `102` | User session kill | `user-session-kill` | 2.8% | `session` |
| `101` | User session timeout | `user-session-timeout` | 2.2% | `session` |
| `9` | Access Denied | `access-denied` | 2.2% | `authentication` |
| `3` | Connection timed out | `connection-timed-out` | 0.7% | `network` |
| `5` | Connection failed | `connection-failed` | 0.2% | `network` |

Names, severities, extension keys and key order follow the vendor examples for each class ID. The rates are a synthetic workload, not measured LoadMaster traffic.

## Background Model

Forty users (`samples/users.csv`) start portal sessions as independent random processes, about five per user per day, with the highest activity from 07:00 to 17:00 UTC, a middle level from 17:00 to 21:00 and a low night level. A session is a TLS accept and an unauthenticated `Attempt` for `/owa/`, zero to five `Access Denied` records (about 6% of sessions have three or more, and 15% of sessions with a failure end without a logon), then `User AAA`, `Logged on` and `Connected` to a real server. Requests follow with log-normal gaps; about 5% of them open an Exchange control panel path under `/ecp/`. New client connections add `SSL accept` and `Connected`, rarely after a `Connection failed`. A session ends with `Logged off` plus `User session kill`, or with `User session timeout` after the idle time. Users connect from their office address or, in 30% of sessions, from a random external address. Anonymous clients add TLS accepts that time out or send one `Attempt`.

Every record is emitted at the one-second tick it is due; records that fall on the same second leave one per tick, so a few are delayed by a second or two.

## Anomaly Chain

A user fails the ESP logon repeatedly and then logs on and opens the Exchange control panel:

1. `Access Denied` (class 9) three to five times for user U from address I, seconds apart.
2. `User AAA` (100) with `result=0:Success` and `Logged on` (8) for U from I.
3. `Request` (14) for one to three `/ecp/` paths by U from I, among the first requests of the session.
4. The session ends like any other: `Logged off` (6) and `User session kill` (102), or `User session timeout` (101).

Linking fields: `user.name`, `source.ip` (CEF `user`, `srcip`), the same virtual service `vs`, and `@timestamp`. The measured episodes lasted 3.0 to 27.5 minutes from the first denial to the session end.

Recurrence: the first episode starts within the first `anomaly_interval_hours` (at most 24 h) of generation, at a time drawn from the background activity curve, so it does not sit at a fixed offset from the generation start. Each next episode is due `anomaly_interval_hours` after the actual start of the previous one and starts in a window of a quarter of the interval (at most 6 h) centred on the due time, weighted by the square of the activity curve plus a small floor, so most episodes fall in office hours; missed episodes are not caught up. The chain user is drawn at random among users without an open session, never the previous episode's user; the address comes from that user's normal choice (office or external). The default interval is 24 h; the minimum is 6 h. In the final 156 h captures the default configuration produced 6 episodes, 23.3-26.1 h apart, and a 12 h interval produced 12, 11.7-13.4 h apart. The window is narrower than the night: after a first episode at night (in the default capture at 21:00 UTC), later ones can stay at night for several days, as they did there (20:00-03:00 UTC).

Variation: the number of denials, the user, the address, the `/ecp/` paths and the rest of the session change between episodes.

Nothing in the chain is unique to it: every user, address type, class ID and `/ecp/` path also occurs in background, including logons that follow three or more denials from the same address (61 to 81 per 156-hour background capture) and `/ecp/` requests by every user (40 of 40 per capture). Only the full sequence is kept out of background: an ordinary `/ecp/` request that would complete the chain (three denials, then a logon, from the request's address, the first denial at most 30 minutes earlier) becomes a request for an `/owa/` path, at the same time. The guard uses the chain window exactly, so an `/ecp/` request more than 30 minutes after the first denial is left as is.

Detection idea: for one user and source address, three or more `Access Denied` records followed within 30 minutes by `Logged on` and a `Request` for `/ecp/`. The logs show portal behavior; they do not show whether the account was compromised.

`anomaly_mode: true` is the default. With `anomaly_mode: false` the generator emits the same background without episodes.

## Parameters

### Event Parameters

| Parameter | Default | Description |
| --- | --- | --- |
| `device_name` | `lm-edge-01` | LoadMaster host name in `observer.hostname` |
| `virtual_ip` | `10.42.20.15` | ESP virtual service address (`vs`, `destination.ip`) |
| `virtual_port` | `443` | Virtual service port |
| `portal_host` | `mail.example.test` | Host in request URLs |
| `real_servers` | `[172.20.0.21, 172.20.0.22, 172.20.0.23]` | Real servers in `Connected` and `Connection failed` |
| `real_server_port` | `443` | Real server port |
| `user_domain` | `example.test` | `domain` of `User AAA` |
| `sso_domain` | `EXAMPLE-ESP` | ESP SSO domain in session timeout and kill records |
| `aaa_server` | `10.42.30.10` | Authentication server in `User AAA` |
| `aaa_protocol` | `LDAP Unencrypted` | Authentication protocol in `User AAA` |
| `sessions_per_user_day` | `6` | Mean session starts per user per day before office-hours thinning (about 5 are realized) |
| `session_idle_seconds` | `900` | Idle time before `User session timeout` |
| `probes_per_day` | `80` | Anonymous client connections per day |
| `anomaly_mode` | `true` | Include anomaly episodes; `false` emits background only |
| `anomaly_interval_hours` | `24` | Hours between episodes, from the actual start of the previous one (6 to 8760) |

Users and their office addresses are in `samples/users.csv`.

### Output Parameters

The shipped config writes `output/events.json` with the `json` formatter and needs no `${params.*}` or `${secrets.*}`. To send events elsewhere, replace the `output` section, for example:

```yaml
output:
  - opensearch:
      hosts: ["${params.opensearch_url}"]
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: kemp-loadmaster-esp
```

## Usage

Live mode:

```bash
eventum generate --path generators/network-kemp-loadmaster/generator.yml --id kemp-loadmaster --live-mode true
```

Batch mode needs a bounded input: add `start` and `end` to the `cron` input, then run:

```bash
eventum generate --path generators/network-kemp-loadmaster/generator.yml --id kemp-loadmaster --live-mode false
```

## Limitations

- The vendor documents the CEF body per class ID but no raw syslog line for the L7 ESP classes, so `event.original` holds the CEF body only. The documented syslog framing (`<time> <host> ssomgr: CEF:...`) exists only for classes 100-104.
- The CEF header table states Device Version `0`, while every vendor example carries `1.0`; the pack follows the examples.
- Failure result strings of `User AAA` are not documented, so `User AAA` is emitted only for successful logons, and a failed logon produces `Access Denied` alone. Access Blocked, Access Locked, Access Disabled, Password Expired, User interaction, WAF, SMTP, Kill all sessions and Flush SSO cache are not modelled. The User Logs page also says a session is deleted on invalid credentials; the pack emits no 101/102 session records after denials.
- CEF logging requires firmware 7.2.50 or later; session records 101 and 102 follow the 7.2.53 behavior. No firmware version is claimed beyond that.
- Timestamps have one-second resolution, and at most one record is emitted per second.
- Office hours are fixed to UTC.

## Sample Output

The first `/ecp/` request of the first episode, copied byte for byte from the final default capture (line 3474):

```json
{"@timestamp": "2026-09-26T21:10:49+00:00", "destination": {"ip": "10.42.20.15", "port": 443}, "ecs": {"version": "8.17.0"}, "event": {"action": "request", "category": ["web"], "code": "14", "dataset": "kemp_loadmaster.esp", "kind": "event", "module": "kemp_loadmaster", "original": "CEF:0|Kemp|LM|1.0|14|Request|1|vs=10.42.20.15:443 event=Request srcip=10.60.11.68 srcport=61824 method=GET url=https://mail.example.test/ecp/Security/AdminRoles.slab user=e.lindqvist@example.test useragent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0", "severity": 1, "type": ["access"]}, "http": {"request": {"method": "GET"}}, "kemp": {"loadmaster": {"cef": {"device_event_class_id": "14", "device_product": "LM", "device_vendor": "Kemp", "device_version": "1.0", "name": "Request", "severity": 1, "version": 0}, "extension": {"event": "Request", "method": "GET", "srcip": "10.60.11.68", "srcport": "61824", "url": "https://mail.example.test/ecp/Security/AdminRoles.slab", "user": "e.lindqvist@example.test", "useragent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0", "vs": "10.42.20.15:443"}}}, "observer": {"hostname": "lm-edge-01", "product": "LoadMaster", "type": "load-balancer", "vendor": "Progress Kemp"}, "related": {"ip": ["10.60.11.68", "10.42.20.15"], "user": ["e.lindqvist@example.test"]}, "source": {"ip": "10.60.11.68", "port": 61824}, "url": {"domain": "mail.example.test", "full": "https://mail.example.test/ecp/Security/AdminRoles.slab", "path": "/ecp/Security/AdminRoles.slab", "scheme": "https"}, "user": {"name": "e.lindqvist@example.test"}, "user_agent": {"original": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0"}}
```

## References

- [Progress Kemp: CEF Extension (examples per class ID)](https://docs.progress.com/bundle/loadmaster-technical-note-common-event-format-cef-logs-ga/page/CEF-Extension.html)
- [Progress Kemp: CEF Header (class ID, name, severity)](https://docs.progress.com/bundle/loadmaster-technical-note-common-event-format-cef-logs-ga/page/CEF-Header.html)
- [Progress Kemp: Common Event Format (CEF) Logs](https://docs.progress.com/bundle/loadmaster-technical-note-common-event-format-cef-logs-ga/page/Common-Event-Format-CEF-Logs.html)
- [Progress Kemp: ESP User Logs](https://docs.progress.com/bundle/loadmaster-technical-note-esp-logs-ltsf/page/User-Logs.html)
- No Elastic integration exists for Kemp LoadMaster ESP logs.
