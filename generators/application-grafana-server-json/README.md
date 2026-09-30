# Grafana OSS JSON server log

Synthetic Grafana OSS 9.5.1 server log lines in the JSON log format, wrapped in ECS JSON, for testing detections of login abuse and service account token creation in Grafana.

The profile is a single Grafana instance with `[log] format = json` on the chosen output, `level = info` and `[server] router_logging = true`, so that successful requests are logged too. Eighty browser users (four of them organization admins) sign in with the login form, open dashboards and run data source queries, occasionally mistype passwords, give up or hit the brute-force lockout, and sign out. Admins also list, create and delete service account tokens. Four service accounts call the HTTP API with bearer tokens around the clock.

## Event Types

Approximate shares of all lines with the default configuration over four days (about 32,000 lines a day).

| Native line (`msg`, request) | Share | Category |
| --- | ---: | --- |
| `Request Completed`, `POST /api/ds/query` 200 | 43.7% | web |
| `Request Completed`, `GET /api/dashboards/uid/<uid>` 200 | 13.2% | web |
| `Request Completed`, `GET /api/annotations` 200 | 11.6% | web |
| `Request Completed`, `GET /api/search` 200 | 10.2% | web |
| `Request Completed`, `POST /api/frontend-metrics` 200 | 7.5% | web |
| `Request Completed`, `GET /api/user` 200 | 4.9% | web |
| `Request Completed`, `GET /` 200 | 4.2% | web |
| `Successful Login` (logger `http.server`) | 1.23% | authentication |
| `Request Completed`, `POST /login` 200 | 1.23% | web, authentication |
| `Request Completed`, `GET /login` 200 | 0.85% | web |
| `Successful Logout` (logger `http.server`) | 0.36% | authentication |
| `Request Completed`, `GET /logout` 302 | 0.36% | web |
| `Request Completed`, `GET /api/serviceaccounts/search` 200 | 0.19% | web |
| `Invalid username or password` (logger `context`, level `error`) | 0.13% | authentication |
| `Request Completed`, `POST /login` 401 | 0.13% | web, authentication |
| `Request Completed`, `GET /api/serviceaccounts/<id>/tokens` 200 | 0.13% | web |
| `Request Completed`, `POST /api/serviceaccounts/<id>/tokens` 200 | 0.06% | web |
| `Request Completed`, `DELETE /api/serviceaccounts/<id>/tokens/<tokenId>` 200 | 0.06% | web |

About 9% of `POST /login` requests fail. Most users sign in at the first attempt; admins, whose long passwords are typed by hand, mistype them more often (about one login in six starts with one or more failures, against one in twenty-five for other users). Each extra failure in a row is rarer than the previous one; the sixth failure within five minutes gets the lockout text. `event.action` holds the native message in lowercase with hyphens.

## Volume and Timing

- **Browser users** follow a working-day curve in UTC: about 0.07 lines/s at night, rising from 05:00, above half of the peak between about 07:00 and 13:30 and peaking at about 0.95 lines/s near 10:40, back to the night level after 18:00. Sign-ins and the number of users active in an hour follow the same curve (about 15 distinct accounts an hour at night, about 70 at the peak).
- **Sessions:** a user session lasts about 40 minutes (median, up to eight hours) with a request every few seconds to several minutes; admins work in shorter sessions of about 15 minutes and sign in about 11 to 17 times a day. About 30% of sessions end with an explicit logout.
- **Service accounts** call the API at a flat 0.05 lines/s, day and night.
- **Tokens:** admins create about 15 service account tokens a day, mostly for the service account each admin looks after; every token is deleted later by an admin who is signed in at that time, usually within an hour (a token created late in the day may stay until the next morning).
- The two lines of one request (a handler line and its `Request Completed` line) are written microseconds apart, one right after the other.

## Anomaly Chain

From one admin workstation address, three or four `POST /login` requests fail (`Invalid username or password` followed by `Request Completed` with status 401), the next succeeds (`Successful Login` followed by `Request Completed` with status 200), and after zero to three ordinary requests that admin creates a token for the service account they look after (`POST /api/serviceaccounts/<id>/tokens`, status 200). The session then continues and ends like any other admin session. Later, an admin who is signed in at that moment deletes the token (`DELETE /api/serviceaccounts/<id>/tokens/<tokenId>`), on the same schedule as every other token.

- **Linking fields:** `grafana.log.remote_addr` (`source.ip`) on every step; `uname`/`userId` on the token request (login requests carry `userId` 0 and an empty `uname`, because Grafana logs them before the session exists); the email in `User` of `Successful Login`; the service account id in the request path.
- **Timing:** gaps between attempts and requests come from the same model as ordinary logins and sessions; the first failed login and the token creation are usually 1-5 minutes apart. An earlier failed login of the same address within the hour can extend the span.
- **Recurrence:** `anomaly_interval_hours` (default 24, minimum 6, maximum 8760). The first episode starts within `min(interval, 24 h)` of the start of the data, its hour drawn from the browser-user curve. Each later episode is due one interval after the previous one actually started and starts within a window of `min(interval / 4, 6 h)` centred on that due time, favouring busy hours (weighted by the squared curve plus a small floor), so episodes mostly fall in working hours. An episode waits for an admin who is signed out and has no failed login in the last 10 minutes; missed episodes are not replayed.
- **Variation:** consecutive episodes use different admins and therefore different service accounts. All four admins, their addresses and all four service accounts appear in ordinary traffic every day.
- **Background overlap:** ordinary traffic in both modes contains failed logins by every admin, runs of three or more failures from one address within 10 minutes (about 4-5 a day), lockouts (about one a day), three or more failures followed by a successful login (about 2 a day) and token creations within ten minutes of a login (about 6 a day). Only the full ordered sequence within an hour does not occur: an ordinary token creation that would complete it opens the service account's token list instead.
- **Detection idea:** per `source.ip`, three or more `POST /login` responses with status 401 followed by one with status 200 and a service account token creation within an hour. Sort by `@timestamp` first. The failed-login line does not name the attempted username, so failures of different accounts from one address look the same.

`anomaly_mode` defaults to `true`. With `anomaly_mode: false` the generator produces only the background described above, with no complete chain. With `anomaly_mode: true` each episode adds its own login failures, login and token creation (and the later deletion) on top of the background, so these counts are about one per episode higher.

## Parameters

### Event Parameters

| Name | Default | Description |
| --- | --- | --- |
| `grafana_host` | `grafana-01` | `host.name` of the Grafana server |
| `root_url` | `https://grafana.example.test` | Scheme and host used in `referer` values |
| `anomaly_mode` | `true` | Add recurring anomaly chain episodes to the background |
| `anomaly_interval_hours` | `24` | Hours between episode due times (6-8760) |

### Sample Files

- `samples/users.json` - browser users: `login`, `email`, `id`, workstation `ip`, `role` (`Admin` users manage tokens and are the episode actors), relative `activity`, and `primary_service_account` (the service account id an admin looks after; empty for other roles).
- `samples/service_accounts.json` - service accounts: `login`, `id`, `ip`, relative `activity`.
- `samples/dashboards.json` - dashboard `uid` and `slug` values.

### Output Parameters

The shipped config writes `output/events.json` and needs no connection parameters or secrets. To send events to a SIEM, replace the file output in a local copy and reference placeholders such as `${params.opensearch_host}` and `${secrets.opensearch_password}` in the chosen output plugin.

## Usage

```bash
eventum generate --path generators/application-grafana-server-json/generator.yml --id grafana --live-mode false
eventum generate --path generators/application-grafana-server-json/generator.yml --id grafana --live-mode true
```

The pattern files under `patterns/` set the rates and the hour curve and run without an end. For a finite batch, copy the generator and set `start` (a midnight UTC, so the daily curve keeps its hours) and `end` in every pattern file of the copy. To scale the volume, change `multiplier.ratio` in all pattern files by the same factor; scale the user list with it to keep per-user activity realistic.

Performance: about 1,700 lines/s in batch mode on one core.

## Sample Output

The first failed login and the token creation of an episode, copied from `anomaly_mode: true` output:

```json
{"@timestamp": "2026-09-01T12:45:46.243362+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "invalid-username-or-password", "category": ["authentication"], "dataset": "grafana.server", "kind": "event", "module": "grafana", "original": "{\"error\":\"invalid username or password\",\"level\":\"error\",\"logger\":\"context\",\"msg\":\"Invalid username or password\",\"orgId\":0,\"remote_addr\":\"10.40.2.21\",\"t\":\"2026-09-01T12:45:46.243362334Z\",\"traceID\":\"\",\"uname\":\"\",\"userId\":0}", "outcome": "failure", "reason": "invalid username or password", "type": ["info"]}, "grafana": {"log": {"error": "invalid username or password", "level": "error", "logger": "context", "msg": "Invalid username or password", "orgId": 0, "remote_addr": "10.40.2.21", "t": "2026-09-01T12:45:46.243362334Z", "traceID": "", "uname": "", "userId": 0}}, "host": {"name": "grafana-01"}, "log": {"level": "error", "logger": "context"}, "message": "Invalid username or password", "related": {"hosts": ["grafana-01"], "ip": ["10.40.2.21"]}, "service": {"name": "grafana", "type": "grafana", "version": "9.5.1"}, "source": {"ip": "10.40.2.21"}}
{"@timestamp": "2026-09-01T12:48:35.411114+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "request-completed", "category": ["web"], "dataset": "grafana.server", "duration": 11271685, "kind": "event", "module": "grafana", "original": "{\"duration\":\"11.271685ms\",\"handler\":\"/api/serviceaccounts/:serviceAccountId/tokens\",\"level\":\"info\",\"logger\":\"context\",\"method\":\"POST\",\"msg\":\"Request Completed\",\"orgId\":1,\"path\":\"/api/serviceaccounts/17/tokens\",\"referer\":\"https://grafana.example.test/org/serviceaccounts/17\",\"remote_addr\":\"10.40.2.21\",\"size\":89,\"status\":200,\"t\":\"2026-09-01T12:48:35.411114386Z\",\"time_ms\":11,\"uname\":\"akozlova\",\"userId\":3}", "outcome": "success", "type": ["creation"]}, "grafana": {"log": {"duration": "11.271685ms", "handler": "/api/serviceaccounts/:serviceAccountId/tokens", "level": "info", "logger": "context", "method": "POST", "msg": "Request Completed", "orgId": 1, "path": "/api/serviceaccounts/17/tokens", "referer": "https://grafana.example.test/org/serviceaccounts/17", "remote_addr": "10.40.2.21", "size": 89, "status": 200, "t": "2026-09-01T12:48:35.411114386Z", "time_ms": 11, "uname": "akozlova", "userId": 3}}, "host": {"name": "grafana-01"}, "http": {"request": {"method": "POST", "referrer": "https://grafana.example.test/org/serviceaccounts/17"}, "response": {"body": {"bytes": 89}, "status_code": 200}}, "log": {"level": "info", "logger": "context"}, "message": "Request Completed", "related": {"hosts": ["grafana-01"], "ip": ["10.40.2.21"], "user": ["akozlova"]}, "service": {"name": "grafana", "type": "grafana", "version": "9.5.1"}, "source": {"ip": "10.40.2.21"}, "url": {"path": "/api/serviceaccounts/17/tokens"}, "user": {"id": "3", "name": "akozlova"}}
```

## Coverage and Limits

- **Format.** `event.original` is the native line as the go-kit JSON logger of Grafana 9.5.1 writes it: compact JSON with keys sorted alphabetically; `t` is RFC 3339 with up to nine fractional digits (trailing zeros dropped), and every line carries `level`, `logger` and `msg`. Four real 9.5.0/9.5.1 lines in the Grafana issue below confirm the layout and the `Request Completed` field set; `grafana.log` repeats the parsed fields.
- **Field sources.** `Request Completed` fields follow `pkg/middleware/loggermw/logger.go`: `duration` is Go `time.Duration` text, `time_ms` its whole milliseconds, `handler` the registered route pattern (for example `/api/search/` for path `/api/search` and `/api/user/` for `/api/user`; these trailing-slash forms are inferred from the route registration, not from captured lines), `userId`/`orgId`/`uname` come from the request context. The failed-login line and its 55-byte response body follow `response.Error` in `pkg/api/response/response.go`; the lockout text and the five-attempts-in-five-minutes rule follow `pkg/login/auth.go` and the login attempt service. Login, logout and token-deletion body sizes are exact; data request sizes are synthetic.
- **Configuration.** Grafana defaults to text logs and `router_logging = false`; with router logging off, requests answered with 200 or 304 are not logged, and only the 302 and 401 request lines and the `Invalid username or password`, `Successful Login` and `Successful Logout` messages of this pack remain. Debug lines (for example `Got IP address from client address`) are not emitted at level `info`.
- **Rates.** Request mix, session lengths, sign-in frequency, failure rates, token activity, durations and response sizes of data requests are synthetic; Grafana publishes no frequency data. There is no weekly cycle: weekends look like weekdays.
- **Timing.** Requests of a session are spread seconds to minutes apart; the burst of panel queries a real dashboard load makes within one second is not reproduced.
- **Not modeled.** Static files, `/api/health` probes, live websocket traffic, 304, 403, 404 and 5xx responses, expired-session and API-key authentication, LDAP/OAuth/JWT logins, alerting and provisioning logs, and tracing (`traceID` stays empty). The failed-login line has no username field; the data cannot show which account was guessed. The clock is UTC (`Z`).
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
