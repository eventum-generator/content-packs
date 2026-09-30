# Solar webProxy SIEM log

Synthetic Solar webProxy 4.3.1 request messages in the vendor `siem-log` syslog format, for testing web-proxy detections. One filtering node in forward mode with TLS inspection serves 30 office users, about 20,000 messages a day; each message is also mapped to ECS. The pack models filtering decisions and traffic volumes, not administrator audit, `access-log` JSON, `cef-log` or `ip-translation-log` output.

## Event types

Shares of all messages, about 20,300 a day (each daily total within about 3%); shares over a four-day period fall within the ranges shown.

| Request | Share | ECS category | `event.action` / status |
| --- | ---: | --- | --- |
| Page and embedded-object GET to allowed sites | 84.5-85.3% | `web`, `network` | `http-allowed`; 200, 304, 302, 404 |
| Application polling GET (JSON endpoints of business applications) | 5.6-6.1% | `web`, `network` | `http-allowed`; 200, 304 |
| GET to a blocked entertainment site, with user retries | 3.5-4.0% | `web`, `network` | `http-denied`; 403, `flt-reason:URL(<host>)` |
| Small POST to a business application | 1.9-2.0% | `web`, `network` | `http-allowed`; 200, 201, 400 |
| POST upload to sanctioned cloud storage | 1.9-2.1% | `web`, `network` | `http-allowed`; 200 |
| GET download from cloud storage | 1.3-1.4% | `web`, `network` | `http-allowed`; 200 |
| POST upload to a blocked file-sharing site, occasionally retried | 0.2-0.3% | `web`, `network` | `http-denied`; 403, `flt-reason:URL(<host>)` |

**Volume and hours.** Message volume follows the office day in the node's local time (UTC+3): about 120 messages an hour at night, 265 at 07:00 and 19:00 local, 815 at 08:00 and 18:00, 1,365 at 09:00 and 17:00, and 2,000 an hour from 10:00 to 17:00, each daily total varying by about 3%. Every day has the same shape; there is no weekend dip.

**Users.** Each user has a fixed activity weight (the busiest carry 4-12% of all messages, the quietest about 0.4%) and fixed working hours: a start between 07:00 and 10:00 local and a length of 8 to 10 hours, shifted by a random amount each day (standard deviation about 35 minutes). On about one day in ten a user is absent; on about one day in three a user stays 0.5 to 3 hours late; on about one day in eight a workstation stays logged on overnight and keeps polling business applications. About 27 of the 30 users appear in each office hour and 4 to 11 at night. Blocked uploads number about 45-60 a day; about three quarters or more come from the six busiest users (4 to 10 a day each), each mostly to one habitual file-sharing site, and about one attempt in six is retried. A user refused twice on one site within 30 minutes usually makes no upload for the next 40 minutes to 2 hours. Blocked browsing, blocked uploads with retries, a single blocked upload followed by an upload to sanctioned storage, and repeated blocked uploads without any upload all occur in ordinary traffic in both modes. Background with `anomaly_mode: false` has the same mix within run-to-run variation.

## Anomaly Chain

**Sequence.** One user is denied two or more POST uploads to the same blocked file-sharing site (`flt-status:403`, `bytes-out:0`, `flt-reason:URL(<host>)`, retries a few seconds to minutes apart), then makes an allowed POST upload to a sanctioned cloud-storage host (`flt-status:200`, large `bytes-out`), usually within 10 minutes of the first denial and always within 25 minutes.

**Linking fields.** `acc-name` (`user.name`) and `acc-ip` (`source.ip`) tie the steps; `req-hostname` is the same for the denials and different for the upload; `req-time` (`@timestamp`) orders them.

**Recurrence.** The first episode starts within the first `anomaly_interval_hours` (at most 24 h) of generation, at a time of day drawn from the hour curve above. Each later episode is due `anomaly_interval_hours` after the actual start of the previous one (default 24, allowed 1-8760) and starts within a window centred on that due time, a quarter of the interval wide (at most 6 hours), favouring busier hours. With the default interval, episodes are 21 to 27 hours apart and mostly start between 08:00 and 14:00 UTC; when the first episode falls in the evening, later ones stay in the evening and night hours for several days. With a 6-hour interval, episodes are 5.25 to 6.75 hours apart, about 16 in four days.

**Variation.** Each episode uses a different user than the previous one, taken from the six most active users in proportion to their current activity, and that user's habitual file-sharing site, which differs from the previous episode's; the number of denials (two to five), the retry gaps, the storage target and the upload size vary. Every user, site, address, method and status in the chain also appears in ordinary traffic of both modes, including repeated denied uploads and uploads after a single denial. Outside episodes, no user makes an allowed upload to another host within 30 minutes of two or more denied uploads to one host.

**Detection idea.** Per `user.name`, alert when two or more `http-denied` POSTs to one host are followed within 30 minutes by an allowed POST upload to a different host. This flags possible circumvention of an upload block. The log does not show file contents, so it is a correlation, not proof that the same data was uploaded.

`anomaly_mode` defaults to `true`. With `false`, the generator produces only background traffic, which contains no complete chain.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Add recurring anomaly episodes; `false` produces background only |
| `anomaly_interval_hours` | `24` | Episode interval on source time, 1-8760 hours |
| `proxy_host` | `wp-01` | Host name in the syslog header |
| `syslog_utc_offset_hours` | `3` | Local time offset of the syslog header and of the users' working hours; `req-time` stays UTC. The hourly volume in `patterns/` is set in UTC for an office at UTC+3: when changing the offset, shift the band hours in those files by the same amount |
| `account_domain` | `CORP` | `acc-domain` value |
| `client_prefix` | `10.20.4.` | Prefix of user addresses |
| `client_first` | `21` | Last octet of the first user address; users get consecutive addresses (`client_first` plus the user count must stay at most 255) |
| `users` | 30 logins | `acc-name` values, at least 4 |
| `groups` | `Employees`, `Finance`, `Engineering`, `Sales` | `acc-groups` values, one per user, drawn at start with a skew toward the first |
| `decrypt_rule` | `https` | Name of the TLS inspection rule that leads `flt-rules` for HTTPS requests |
| `block_layer` | `Restricted` | Policy layer that blocks, written to `flt-policy` and `flt-rules` |
| `sites` | 8 sites | Allowed sites: host, address, `flt-categories` value, pages |
| `blocked_sites` | 3 sites | Blocked entertainment sites: host, address, category, blocking rule name, pages |
| `sharing_sites` | 3 sites | Blocked file-sharing sites: host, address, category, blocking rule name, upload path |
| `storage_sites` | 2 sites | Sanctioned cloud storage: host, address, category, upload path |

### Output Parameters

The shipped configuration writes `output/events.json` with no connection parameters or secrets. To send events to a SIEM, replace the file output in a local copy and reference `${params.siem_host}` and `${secrets.siem_token}` as the selected output plugin requires.

## Usage

Live generation:

```bash
eventum generate --path generators/proxy-solar-webproxy/generator.yml --id solar-webproxy --live-mode true
```

Batch generation of a fixed period: in each file under `patterns/`, set `start` to the first midnight of the period (for example `"2026-09-01T00:00:00Z"`) and `end` to its last moment instead of `never`, then run:

```bash
eventum generate --path generators/proxy-solar-webproxy/generator.yml --id solar-webproxy --live-mode false
```

The hourly volume is set by the five files in `patterns/` (`multiplier.ratio` is the number of messages per day in the band, `spreader` bounds are the band hours as fractions of the UTC day).

Performance: about 1,600 messages per second on one core (14 days, 282,338 messages, in about 3 minutes).

## Sample output

The final upload of an episode (the JSON formatter writes non-ASCII rule names as `\u` escapes):

```json
{"@timestamp": "2026-09-01T08:41:30.355+00:00", "destination": {"bytes": 649, "domain": "disk.fabrikam.test", "ip": "198.51.100.30", "port": 443}, "ecs": {"version": "8.17.0"}, "event": {"action": "http-allowed", "category": ["web", "network"], "duration": 9000000, "kind": "event", "original": "Sep 1 11:41:30 wp-01 java: [acc-domain:CORP] [acc-groups:Employees] [acc-ip:10.20.4.25] [acc-name:e.popova] [acc-port:59633] [bytes-in:649] [bytes-out:320919] [flt-categories:0] [flt-codes:11,0,0,0,0,0] [flt-policy:\u0417\u0430\u0432\u0435\u0440\u0448\u0435\u043d\u0438\u0435 \u043e\u0431\u0440\u0430\u0431\u043e\u0442\u043a\u0438 \u043f\u043e\u043b\u0438\u0442\u0438\u043a\u0438] [flt-rules:https,\u041f\u0435\u0440\u0435\u0445\u043e\u0434 \u043a \u0441\u043b\u043e\u044e Icap Request,\u041f\u0435\u0440\u0435\u0445\u043e\u0434 \u043a \u0441\u043b\u043e\u044e Filter req,\u041f\u0435\u0440\u0435\u0445\u043e\u0434 \u043a \u0441\u043b\u043e\u044e Icap Response,\u041f\u0435\u0440\u0435\u0445\u043e\u0434 \u043a \u0441\u043b\u043e\u044e Filter resps,\u041f\u0435\u0440\u0435\u0445\u043e\u0434 \u043a \u0441\u043b\u043e\u044e \u0417\u0430\u0432\u0435\u0440\u0448\u0435\u043d\u0438\u0435 \u043e\u0431\u0440\u0430\u0431\u043e\u0442\u043a\u0438 \u043f\u043e\u043b\u0438\u0442\u0438\u043a\u0438] [flt-status:200] [flt-time:9] [req-hostname:disk.fabrikam.test] [req-method:POST] [req-pathname:/api/v1/files/upload] [req-protocol:https] [req-query:] [req-referer:https://disk.fabrikam.test/] [req-time:2026-09-01T08:41:30.355Z] [req-user-agent:Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36] [res-datatype:application/json] [res-ip:198.51.100.30] [traf-mode:forward] [x-virus-id] [req-port:443] [flt-reason:]", "outcome": "success", "type": ["allowed", "connection"]}, "host": {"name": "wp-01"}, "http": {"request": {"bytes": 320919, "method": "POST", "referrer": "https://disk.fabrikam.test/"}, "response": {"bytes": 649, "mime_type": "application/json", "status_code": 200}}, "observer": {"hostname": "wp-01", "product": "Solar webProxy", "type": "proxy", "vendor": "Solar"}, "related": {"hosts": ["disk.fabrikam.test"], "ip": ["10.20.4.25", "198.51.100.30"], "user": ["e.popova"]}, "rule": {"name": "\u0417\u0430\u0432\u0435\u0440\u0448\u0435\u043d\u0438\u0435 \u043e\u0431\u0440\u0430\u0431\u043e\u0442\u043a\u0438 \u043f\u043e\u043b\u0438\u0442\u0438\u043a\u0438"}, "solar_webproxy": {"account_groups": "Employees", "filter_categories": "0", "filter_codes": "11,0,0,0,0,0", "filter_policy": "\u0417\u0430\u0432\u0435\u0440\u0448\u0435\u043d\u0438\u0435 \u043e\u0431\u0440\u0430\u0431\u043e\u0442\u043a\u0438 \u043f\u043e\u043b\u0438\u0442\u0438\u043a\u0438", "filter_reason": "", "filter_rules": "https,\u041f\u0435\u0440\u0435\u0445\u043e\u0434 \u043a \u0441\u043b\u043e\u044e Icap Request,\u041f\u0435\u0440\u0435\u0445\u043e\u0434 \u043a \u0441\u043b\u043e\u044e Filter req,\u041f\u0435\u0440\u0435\u0445\u043e\u0434 \u043a \u0441\u043b\u043e\u044e Icap Response,\u041f\u0435\u0440\u0435\u0445\u043e\u0434 \u043a \u0441\u043b\u043e\u044e Filter resps,\u041f\u0435\u0440\u0435\u0445\u043e\u0434 \u043a \u0441\u043b\u043e\u044e \u0417\u0430\u0432\u0435\u0440\u0448\u0435\u043d\u0438\u0435 \u043e\u0431\u0440\u0430\u0431\u043e\u0442\u043a\u0438 \u043f\u043e\u043b\u0438\u0442\u0438\u043a\u0438", "filter_status": 200, "filter_time_ms": 9, "request_time": "2026-09-01T08:41:30.355Z", "response_datatype": "application/json", "traffic_mode": "forward"}, "source": {"bytes": 320919, "ip": "10.20.4.25", "port": 59633}, "url": {"domain": "disk.fabrikam.test", "full": "https://disk.fabrikam.test/api/v1/files/upload", "path": "/api/v1/files/upload", "port": 443, "scheme": "https"}, "user": {"domain": "CORP", "group": {"name": "Employees"}, "name": "e.popova"}, "user_agent": {"original": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"}}
```

## Format and limitations

- `event.original` follows table 9.2 and the raw example of the 4.3.1 installation manual: a syslog-ng header (`<Mmm d HH:MM:SS> <host> java:`) and 27 bracketed fields in the example's order, including `acc-name` and the bare `[x-virus-id]` marker the example carries without a detection. Field meanings, including header plus body byte counts and `flt-codes` as one code per applied rule, come from appendix F.1.
- The header clock is local time (the vendor example is 3 hours ahead of its `req-time`) and is written when filtering ends, `flt-time` milliseconds after `req-time`. The day is not zero-padded, as in the example; the PDF text does not show whether syslog-ng pads it with a second space.
- `flt-codes` values are copied from the vendor examples (11 for the decryption rule, 0 for layer transitions, 2 for the blocking rule). The manual lists action names but not the numeric mapping, so other codes are not generated. `flt-categories` is `0` or one numeric category from the vendor example; the categorizer's full list is not published.
- A blocked request carries `bytes-in:0`, `bytes-out:0` and `res-datatype:application/skvt-unchecked`, as in the vendor example; whether a blocked POST reports its partial body is not documented.
- Only URL-list blocks are modelled. Antivirus, DLP, category, schedule and quota blocks, reverse-proxy mode and authentication failures are not generated.
- Host names use reserved test domains and documentation address ranges; users and groups are synthetic. Traffic ratios are scenario choices, since Solar does not publish them.
- Compatibility with third-party `siem-log` normalizers has not been tested.
- The allowed upload of an episode comes within 25 minutes of the first denial; an ordinary upload after a single denial has no such limit (about 1% of them come later).
- Requests are seconds apart rather than milliseconds: the embedded objects of a page follow it after a median of about 6 seconds in office hours and about 70 seconds at night, where a browser fetches them within a second.
- Volume and user presence follow the same daily curve every day, without weekends or holidays.
- With `anomaly_mode: true` each episode adds its own records, so counts of denied uploads and uploads to storage are a few records per episode higher than without episodes.

## References

- [Solar webProxy 4.3.1 installation and configuration manual](https://rt-solar.ru/products/solar_webproxy/doc/solar-webproxy-rukovodstvo-po-nastroyke-i-ustanovke-431-astra.pdf): table 9.2 `siem-log` fields and example; appendix F.1 `access-log` parameters
- [Solar webProxy documentation](https://rt-solar.ru/products/solar_webproxy/documents/)
- [Solar webProxy specifications](https://rt-solar.ru/products/solar_webproxy/specifications/): syslog export in `access-log`, `siem-log`, `cef-log` and `ip-translation-log` formats
