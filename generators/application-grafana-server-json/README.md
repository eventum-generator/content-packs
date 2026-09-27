# Grafana OSS JSON server log

Synthetic Grafana OSS 9.5.1 server log lines in the JSON log format, wrapped in ECS JSON, for testing detections of login abuse and service account token creation in Grafana.

The profile is a single Grafana instance with `[log] format = json` on the chosen output, `level = info` and `[server] router_logging = true`, so that successful requests are logged too. Nine browser users (four of them organization admins) run independent random sessions: the login page, form logins with occasional mistyped passwords, give-ups and brute-force lockouts, dashboard reads and data source queries, and logouts. Admins also list, create and delete service account tokens. Two service accounts call the API with bearer tokens around the clock.

## Event Types

Shares are measured on a 120-hour `anomaly_mode: true` capture (31,945 events, four episodes).

| Native line (`msg`, request) | Share | Category |
| --- | ---: | --- |
| `Request Completed`, `POST /api/ds/query` 200 | 43.04% | web |
| `Request Completed`, `GET /api/dashboards/uid/<uid>` 200 | 13.29% | web |
| `Request Completed`, `GET /api/annotations` 200 | 11.03% | web |
| `Request Completed`, `GET /api/search` 200 | 10.58% | web |
| `Request Completed`, `POST /api/frontend-metrics` 200 | 6.95% | web |
| `Request Completed`, `GET /api/user` 200 | 4.59% | web |
| `Request Completed`, `GET /` 200 | 3.74% | web |
| `Request Completed`, `GET /api/serviceaccounts/search` 200 | 1.38% | web |
| `Request Completed`, `GET /api/serviceaccounts/<id>/tokens` 200 | 1.08% | web |
| `Successful Login` (logger `http.server`) | 0.80% | authentication |
| `Request Completed`, `POST /login` 200 | 0.80% | web, authentication |
| `Request Completed`, `GET /login` 200 | 0.63% | web |
| `Invalid username or password` (logger `context`, level `error`) | 0.57% | authentication |
| `Request Completed`, `POST /login` 401 | 0.57% | web, authentication |
| `Request Completed`, `POST /api/serviceaccounts/<id>/tokens` 200 | 0.25% | web |
| `Request Completed`, `DELETE /api/serviceaccounts/<id>/tokens/<tokenId>` 200 | 0.24% | web |
| `Successful Logout` (logger `http.server`) | 0.24% | authentication |
| `Request Completed`, `GET /logout` 302 | 0.24% | web |

Rates, session lengths, durations and response sizes of data requests are synthetic; Grafana publishes no frequency data. `event.action` holds the native message in lowercase with hyphens.

## Anomaly Chain

From one admin workstation address, three or four `POST /login` requests fail (`Invalid username or password` followed by `Request Completed` with status 401), the next succeeds (`Successful Login` followed by `Request Completed` with status 200), and after zero to three ordinary requests that admin creates a token for a service account (`POST /api/serviceaccounts/<id>/tokens`, status 200). The session then continues like any other admin session until it ends. Later, an admin who is signed in at that moment deletes the token (`DELETE /api/serviceaccounts/<id>/tokens/<tokenId>`), which restores the previous token set.

- **Linking fields:** `grafana.log.remote_addr` (`source.ip`) on every step; `uname`/`userId` on the token request (login requests carry `userId` 0 and an empty `uname`, because Grafana logs them before the session exists); the email in `User` of `Successful Login`; the service account id in the request path.
- **Timing:** gaps between attempts and requests and the session length come from the same model as ordinary sessions; measured spans from the first failed login to the token creation were 37-166 seconds (default capture) and 56-212 seconds (9-hour capture).
- **Recurrence:** `anomaly_interval_hours` (default 24, minimum 6, maximum 8760). The first episode is due one interval after the generator starts. At each due time the episode starts after a random delay of up to `min(30 min, interval / 8)`, and waits for an idle admin whose own next login is more than an hour away and who has no failed login in the last 10 minutes. The next due time is one interval after the actual start; missed episodes are not replayed. Measured gaps: 24.02-24.28 h (default), 9.11-9.76 h (9-hour interval).
- **Variation:** each episode uses an admin and a service account different from the previous episode's. All four admins, their addresses and all four service accounts also appear in ordinary traffic.
- **Background overlap:** ordinary traffic in both modes contains one to six failed logins from the same address seconds to minutes apart (24-36 runs of three or more within 10 minutes per 120 hours), lockouts after five failures, logins that give up, three or more failures followed by a successful login, and token creations within ten minutes of a login. Only the full ordered sequence is kept out of the background: an ordinary token creation that would complete it within an hour is replaced by a read.
- **Detection idea:** per `source.ip`, three or more `POST /login` responses with status 401 followed by one with status 200 and a service account token creation within an hour. Sort by `@timestamp` first. The failed-login line does not name the attempted username, so failures of different accounts from one address look the same.

`anomaly_mode` defaults to `true`. With `anomaly_mode: false` the generator produces only the background described above, with no complete chain.

## Parameters

### Event Parameters

| Name | Default | Description |
| --- | --- | --- |
| `grafana_host` | `grafana-01` | `host.name` of the Grafana server |
| `root_url` | `https://grafana.example.test` | Scheme and host used in `referer` values |
| `anomaly_mode` | `true` | Add recurring anomaly chain episodes to the background |
| `anomaly_interval_hours` | `24` | Hours between episode due times (6-8760) |

### Output Parameters

The shipped config writes `output/events.json` and needs no connection parameters or secrets. To send events to a SIEM, replace the file output in a local copy and reference placeholders such as `${params.opensearch_host}` and `${secrets.opensearch_password}` in the chosen output plugin.

## Usage

```bash
eventum generate --path generators/application-grafana-server-json/generator.yml --id grafana --live-mode false
eventum generate --path generators/application-grafana-server-json/generator.yml --id grafana --live-mode true
```

Live mode emits one event at most per second. For a finite batch, add `start` and `end` to the `cron` input.

## Sample Output

The first failed login and the token creation of an episode, copied from the final `anomaly_mode: true` capture:

```json
{"@timestamp": "2026-09-21T00:04:39.860672+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "invalid-username-or-password", "category": ["authentication"], "dataset": "grafana.server", "kind": "event", "module": "grafana", "original": "{\"error\":\"invalid username or password\",\"level\":\"error\",\"logger\":\"context\",\"msg\":\"Invalid username or password\",\"orgId\":0,\"remote_addr\":\"10.40.2.21\",\"t\":\"2026-09-21T00:04:39.860672394Z\",\"traceID\":\"\",\"uname\":\"\",\"userId\":0}", "outcome": "failure", "reason": "invalid username or password", "type": ["info"]}, "grafana": {"log": {"error": "invalid username or password", "level": "error", "logger": "context", "msg": "Invalid username or password", "orgId": 0, "remote_addr": "10.40.2.21", "t": "2026-09-21T00:04:39.860672394Z", "traceID": "", "uname": "", "userId": 0}}, "host": {"name": "grafana-01"}, "log": {"level": "error", "logger": "context"}, "message": "Invalid username or password", "related": {"hosts": ["grafana-01"], "ip": ["10.40.2.21"]}, "service": {"name": "grafana", "type": "grafana", "version": "9.5.1"}, "source": {"ip": "10.40.2.21"}}
{"@timestamp": "2026-09-21T00:05:47.280460+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "request-completed", "category": ["web"], "dataset": "grafana.server", "duration": 9599001, "kind": "event", "module": "grafana", "original": "{\"duration\":\"9.599001ms\",\"handler\":\"/api/serviceaccounts/:serviceAccountId/tokens\",\"level\":\"info\",\"logger\":\"context\",\"method\":\"POST\",\"msg\":\"Request Completed\",\"orgId\":1,\"path\":\"/api/serviceaccounts/17/tokens\",\"referer\":\"https://grafana.example.test/org/serviceaccounts/17\",\"remote_addr\":\"10.40.2.21\",\"size\":90,\"status\":200,\"t\":\"2026-09-21T00:05:47.280460563Z\",\"time_ms\":9,\"uname\":\"akozlova\",\"userId\":3}", "outcome": "success", "type": ["creation"]}, "grafana": {"log": {"duration": "9.599001ms", "handler": "/api/serviceaccounts/:serviceAccountId/tokens", "level": "info", "logger": "context", "method": "POST", "msg": "Request Completed", "orgId": 1, "path": "/api/serviceaccounts/17/tokens", "referer": "https://grafana.example.test/org/serviceaccounts/17", "remote_addr": "10.40.2.21", "size": 90, "status": 200, "t": "2026-09-21T00:05:47.280460563Z", "time_ms": 9, "uname": "akozlova", "userId": 3}}, "host": {"name": "grafana-01"}, "http": {"request": {"method": "POST", "referrer": "https://grafana.example.test/org/serviceaccounts/17"}, "response": {"body": {"bytes": 90}, "status_code": 200}}, "log": {"level": "info", "logger": "context"}, "message": "Request Completed", "related": {"hosts": ["grafana-01"], "ip": ["10.40.2.21"], "user": ["akozlova"]}, "service": {"name": "grafana", "type": "grafana", "version": "9.5.1"}, "source": {"ip": "10.40.2.21"}, "url": {"path": "/api/serviceaccounts/17/tokens"}, "user": {"id": "3", "name": "akozlova"}}
```

## Coverage and Limits

- **Format.** `event.original` is the native line as the go-kit JSON logger of Grafana 9.5.1 writes it: compact JSON with keys sorted alphabetically; `t` is RFC 3339 with up to nine fractional digits (trailing zeros dropped), and every line carries `level`, `logger` and `msg`. Four real 9.5.0/9.5.1 lines in the Grafana issue below confirm the layout and the `Request Completed` field set; `grafana.log` repeats the parsed fields.
- **Field sources.** `Request Completed` fields follow `pkg/middleware/loggermw/logger.go`: `duration` is Go `time.Duration` text, `time_ms` its whole milliseconds, `handler` the registered route pattern (for example `/api/search/` for path `/api/search` and `/api/user/` for `/api/user`; these trailing-slash forms are inferred from the route registration, not from captured lines), `userId`/`orgId`/`uname` come from the request context. The failed-login line and its 55-byte response body follow `response.Error` in `pkg/api/response/response.go`; the lockout text and the five-attempts-in-five-minutes rule follow `pkg/login/auth.go` and the login attempt service. Login, logout and token-deletion body sizes are exact; data request sizes are synthetic.
- **Configuration.** Grafana defaults to text logs and `router_logging = false`; with router logging off, requests answered with 200 or 304 are not logged, and only the 302 and 401 request lines and the `Invalid username or password`, `Successful Login` and `Successful Logout` messages of this pack remain. Debug lines (for example `Got IP address from client address`) are not emitted at level `info`.
- **Not modeled.** Static files, `/api/health` probes, live websocket traffic, 304, 403, 404 and 5xx responses, expired-session and API-key authentication, LDAP/OAuth/JWT logins, alerting and provisioning logs, tracing (`traceID` stays empty), the `authnService` feature toggle, and daily activity patterns. The failed-login line has no username field; the pack cannot show which account was guessed. The clock is UTC (`Z`).
- **Timing.** The generator emits at most one event per one-second input tick; lines due close together are written on consecutive ticks but keep their own timestamps, so output order and timestamps stay consistent.
- **Mapping.** ECS fields repeat values from the native line only.

## References

- [Grafana issue 67582 with real 9.5.0/9.5.1 JSON server log lines](https://github.com/grafana/grafana/issues/67582)
- [Grafana v9.5.1 logger (`pkg/infra/log/log.go`)](https://github.com/grafana/grafana/blob/v9.5.1/pkg/infra/log/log.go)
- [Grafana v9.5.1 request logging middleware](https://github.com/grafana/grafana/blob/v9.5.1/pkg/middleware/loggermw/logger.go)
- [Grafana v9.5.1 login handlers (`pkg/api/login.go`)](https://github.com/grafana/grafana/blob/v9.5.1/pkg/api/login.go)
- [Grafana v9.5.1 service account token API](https://github.com/grafana/grafana/blob/v9.5.1/pkg/services/serviceaccounts/api/token.go)
- [Grafana v9.5.1 logging and router defaults (`conf/defaults.ini`)](https://github.com/grafana/grafana/blob/v9.5.1/conf/defaults.ini)
- [Grafana configuration: log and router_logging options](https://grafana.com/docs/grafana/v9.5/setup-grafana/configure-grafana/)
- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)
