# Progress Kemp LoadMaster ESP CEF

Edge Security Pack (ESP) user logs of a Progress Kemp LoadMaster in Common Event Format, for one virtual service that pre-authenticates a webmail portal. Each output line is ECS JSON with the vendor CEF body in `event.original` and the parsed header and extension under `kemp.loadmaster`. The pack is for SIEM teams that test CEF parsing, ESP authentication monitoring and correlation of failed ESP logons with later access.

## Event Types

Shares over four days with `anomaly_mode: true` (about 160,000 records); with `anomaly_mode: false` every share differs by less than 0.5 percentage points.

| CEF class ID | Name | `event.action` | Share | ECS category |
| --- | --- | --- | --- | --- |
| `14` | Request | `request` | 51.7% | `web` |
| `2` | SSL accept | `ssl-accept` | 12.0% | `network` |
| `4` | Connected | `connected` | 11.4% | `network` |
| `15` | Attempt | `attempt` | 5.6% | `web` |
| `100` | User AAA | `user-aaa` | 5.2% | `authentication` |
| `8` | Logged on | `logged-on` | 5.2% | `authentication`, `session` |
| `6` | Logged off | `logged-off` | 2.9% | `authentication`, `session` |
| `102` | User session kill | `user-session-kill` | 2.9% | `session` |
| `101` | User session timeout | `user-session-timeout` | 2.3% | `session` |
| `9` | Access Denied | `access-denied` | 0.4% | `authentication` |
| `3` | Connection timed out | `connection-timed-out` | 0.2% | `network` |
| `5` | Connection failed | `connection-failed` | 0.2% | `network` |

Names, severities, extension keys and key order follow the vendor examples for each class ID. The rates are a synthetic workload, not measured LoadMaster traffic.

## Traffic Model

The virtual service logs about 40,000 records a day (+/- 3% from day to day) on a working-day curve in UTC: about 0.2 records per second from 21:00 to 03:00, rising from about 03:00, a peak of about 0.87 per second between 10:00 and 12:00, and a decline through the afternoon and evening.

The portal has 400 users (`samples/users.csv`), each with a fixed activity level: the most active users open about four times as many sessions as the least active ones, and a user averages about five sessions a day. Sessions follow the day curve, so about 40 distinct users are active in a night hour and about 170 in the 11:00 hour.

A session is a TLS accept and an unauthenticated `Attempt` for `/owa/`, then `User AAA`, `Logged on` and `Connected` to a real server. About 4% of logons follow one or more `Access Denied` records (fewer sessions have more denials: under 1% have three or more), and 15% of sessions with a denial end without a logon, so about 6% of logon attempts fail. Requests follow with log-normal gaps; about 5% of them open an Exchange control panel path under `/ecp/`. New client connections add `SSL accept` and `Connected`, rarely after a `Connection failed`. A session ends with `Logged off` plus `User session kill`, or with `User session timeout` after the idle time. A user connects from their office address or, in 30% of sessions, from a random external address. Anonymous clients add about 240 TLS accepts a day around the clock that time out or send one `Attempt`.

## Anomaly Chain

A user fails the ESP logon repeatedly and then logs on and opens the Exchange control panel:

1. `Access Denied` (class 9) three to five times for user U from address I, seconds apart.
2. `User AAA` (100) with `result=0:Success` and `Logged on` (8) for U from I.
3. One `Request` (14) for an `/ecp/` path by U from I, among the first three requests of the session.
4. The session continues and ends like any other: `Logged off` (6) and `User session kill` (102), or `User session timeout` (101).

Linking fields: `user.name`, `source.ip` (CEF `user`, `srcip`), the same virtual service `vs`, and `@timestamp`. The `/ecp/` request follows the first denial by 20 seconds to about 4 minutes. The chain user is one of the more active half of the users, logging on from their office address; the number of denials follows the same proportions as ordinary sessions with three or more denials.

Recurrence: the first episode starts within the first `anomaly_interval_hours` (at most 24 h) of generation, at a time drawn from the day curve, so it does not sit at a fixed offset from the generation start. Each next episode is due `anomaly_interval_hours` after the actual start of the previous one and starts in a window of a quarter of the interval (at most 6 h) centred on the due time, weighted by the square of the day curve plus a small floor, so episodes favour office hours; missed episodes are not caught up. The chain user is never the previous episode's user. The default interval is 24 h; the minimum is 6 h. At the default interval episodes start 21-27 h apart; at an 8 h interval about 7-9 h apart. The window is narrower than the night: after a first episode in the evening, later ones can stay in the evening for several days.

Variation: the number of denials, the user, the `/ecp/` path, its position among the first requests and the rest of the session change between episodes.

Nothing in the chain is unique to it: every user, office address, class ID and `/ecp/` path also occurs in ordinary traffic, including logons that follow three or more denials from the same address within 30 minutes (about 40 to 70 per four days) and `/ecp/` requests by almost every user. Only the full sequence is absent from ordinary traffic: when three denials and then a logon from one address precede a request of that user from that address, and the first of those denials is at most 30 minutes old, the request is for an `/owa/` path, with the method that path always uses (POST for `/owa/service.svc` and `/owa/ev.owa2`, GET otherwise). Later requests of the episode session inside that window follow the same rule. Each episode session carries its own denials and logon, so with `anomaly_mode: true` the count of logons after three or more denials is about one per episode higher; the total volume is the same in both modes.

Detection idea: for one user and source address, three or more `Access Denied` records followed within 30 minutes by `Logged on` and a `Request` for `/ecp/`. The logs show portal behavior; they do not show whether the account was compromised.

`anomaly_mode: true` is the default. With `anomaly_mode: false` the generator emits the same traffic without episodes.

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
| `session_idle_seconds` | `900` | Idle time before `User session timeout` |
| `probes_per_day` | `240` | Anonymous client connections per day |
| `anomaly_mode` | `true` | Include anomaly episodes; `false` emits ordinary traffic only |
| `anomaly_interval_hours` | `24` | Hours between episodes, from the actual start of the previous one (6 to 8760) |

Users and their office addresses are in `samples/users.csv`. The daily volume and its hour curve are set by `multiplier.ratio` and `spreader` in `patterns/floor.yml` (round-the-clock share) and `patterns/daytime.yml` (working-day share). Keep the user count in proportion to the volume, about one user per 100 records a day, so each user keeps a realistic number of sessions.

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

Batch mode needs a bounded time window: set `oscillator.start` and `oscillator.end` in both `patterns/floor.yml` and `patterns/daytime.yml` (start at 00:00 UTC so the day curve keeps its hours), for example `start: "2026-09-01T00:00:00Z"` and `end: "2026-09-05T00:00:00Z"`, then run:

```bash
eventum generate --path generators/network-kemp-loadmaster/generator.yml --id kemp-loadmaster --live-mode false
```

Performance: about 2,800 records per second (14 days, 558,000 records, in about 3.3 minutes of CPU time).

## Limitations

- The vendor documents the CEF body per class ID but no raw syslog line for the L7 ESP classes, so `event.original` holds the CEF body only. The documented syslog framing (`<time> <host> ssomgr: CEF:...`) exists only for classes 100-104.
- The CEF header table states Device Version `0`, while every vendor example carries `1.0`; the pack follows the examples.
- Failure result strings of `User AAA` are not documented, so `User AAA` is emitted only for successful logons, and a failed logon produces `Access Denied` alone. Access Blocked, Access Locked, Access Disabled, Password Expired, User interaction, WAF, SMTP, Kill all sessions and Flush SSO cache are not modelled. The User Logs page also says a session is deleted on invalid credentials; the pack emits no 101/102 session records after denials.
- CEF logging requires firmware 7.2.50 or later; session records 101 and 102 follow the 7.2.53 behavior. No firmware version is claimed beyond that.
- Records that a LoadMaster writes in the same instant (`User AAA` and `Logged on`, `Logged off` and `User session kill`, `SSL accept` and `Attempt`) are seconds apart: 2 s at the median, 7 s at the 90th percentile, up to about a minute at night.
- Timestamps have one-second resolution.
- Office hours are fixed to UTC, and there is no weekly cycle: weekends look like weekdays.

## Sample Output

The `/ecp/` request of an episode:

```json
{"@timestamp": "2026-09-01T18:34:30+00:00", "destination": {"ip": "10.42.20.15", "port": 443}, "ecs": {"version": "8.17.0"}, "event": {"action": "request", "category": ["web"], "code": "14", "dataset": "kemp_loadmaster.esp", "kind": "event", "module": "kemp_loadmaster", "original": "CEF:0|Kemp|LM|1.0|14|Request|1|vs=10.42.20.15:443 event=Request srcip=10.60.26.201 srcport=53479 method=GET url=https://mail.example.test/ecp/ user=d.kaur@example.test useragent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0", "severity": 1, "type": ["access"]}, "http": {"request": {"method": "GET"}}, "kemp": {"loadmaster": {"cef": {"device_event_class_id": "14", "device_product": "LM", "device_vendor": "Kemp", "device_version": "1.0", "name": "Request", "severity": 1, "version": 0}, "extension": {"event": "Request", "method": "GET", "srcip": "10.60.26.201", "srcport": "53479", "url": "https://mail.example.test/ecp/", "user": "d.kaur@example.test", "useragent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0", "vs": "10.42.20.15:443"}}}, "observer": {"hostname": "lm-edge-01", "product": "LoadMaster", "type": "load-balancer", "vendor": "Progress Kemp"}, "related": {"ip": ["10.60.26.201", "10.42.20.15"], "user": ["d.kaur@example.test"]}, "source": {"ip": "10.60.26.201", "port": 53479}, "url": {"domain": "mail.example.test", "full": "https://mail.example.test/ecp/", "path": "/ecp/", "scheme": "https"}, "user": {"name": "d.kaur@example.test"}, "user_agent": {"original": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0"}}
```

## References

- [Progress Kemp: CEF Extension (examples per class ID)](https://docs.progress.com/bundle/loadmaster-technical-note-common-event-format-cef-logs-ga/page/CEF-Extension.html)
- [Progress Kemp: CEF Header (class ID, name, severity)](https://docs.progress.com/bundle/loadmaster-technical-note-common-event-format-cef-logs-ga/page/CEF-Header.html)
- [Progress Kemp: Common Event Format (CEF) Logs](https://docs.progress.com/bundle/loadmaster-technical-note-common-event-format-cef-logs-ga/page/Common-Event-Format-CEF-Logs.html)
- [Progress Kemp: ESP User Logs](https://docs.progress.com/bundle/loadmaster-technical-note-esp-logs-ltsf/page/User-Logs.html)
- No Elastic integration exists for Kemp LoadMaster ESP logs.
