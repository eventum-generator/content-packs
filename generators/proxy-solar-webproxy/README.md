# Solar webProxy SIEM log

Synthetic Solar webProxy 4.3.1 request messages in the vendor `siem-log` syslog format, for testing web-proxy detections. One filtering node in forward mode with TLS inspection serves 30 office users; each message is also mapped to ECS. The pack models filtering decisions and traffic volumes, not administrator audit, `access-log` JSON, `cef-log` or `ip-translation-log` output.

## Event types

Shares measured on the final 156-hour default capture (121,473 messages, about 13 per minute, with a working-hours peak in the node's local time).

| Request | Share | ECS category | `event.action` / status |
| --- | ---: | --- | --- |
| Page and embedded-object GET to allowed sites | 87.42% | `web`, `network` | `http-allowed`; 200, 304, 302, 404 |
| GET to a blocked entertainment site, with user retries | 3.86% | `web`, `network` | `http-denied`; 403, `flt-reason:URL(<host>)` |
| POST upload to sanctioned cloud storage | 1.94% | `web`, `network` | `http-allowed`; 200 |
| Small POST to a business application | 2.16% | `web`, `network` | `http-allowed`; 200, 201, 400 |
| POST upload to a blocked file-sharing site, with user retries | 3.14% | `web`, `network` | `http-denied`; 403, `flt-reason:URL(<host>)` |
| GET download from cloud storage | 1.47% | `web`, `network` | `http-allowed`; 200 |

Each user acts as an independent random process with a skewed activity weight and its own working hours: a start between 06:00 and 11:30 local time and a length of 7 to 10.5 hours, shifted by a random amount each day (standard deviation about 35 minutes), with about one day in ten off. Blocked browsing, blocked uploads with retries, a single blocked upload followed by an upload to sanctioned storage, and repeated blocked uploads without any upload all occur in ordinary traffic in both modes. Background with `anomaly_mode: false` has the same mix within run-to-run variation.

## Anomaly Chain

**Sequence.** One user is denied two or more POST uploads to the same blocked file-sharing site (`flt-status:403`, `bytes-out:0`, `flt-reason:URL(<host>)`, retries a few seconds to minutes apart), then makes an allowed POST upload to a sanctioned cloud-storage host (`flt-status:200`, large `bytes-out`), usually within 10 minutes of the first denial.

**Linking fields.** `acc-name` (`user.name`) and `acc-ip` (`source.ip`) tie the steps; `req-hostname` is the same for the denials and different for the upload; `req-time` (`@timestamp`) orders them.

**Recurrence.** The first episode starts within the first `anomaly_interval_hours` (at most 24 h) of generation, at a time of day drawn from the combined working hours of all users. Each later episode is due `anomaly_interval_hours` after the actual start of the previous one (default 24, allowed 1-8760) and starts within a window centred on that due time, a quarter of the interval wide (at most 6 hours), favouring busier hours. A 156-hour default capture has 7 episodes, the first after 10.0 h, with gaps of 21.2-25.6 h and starts between 08:00 and 12:00 UTC (hours carrying 6.5-9.2% of the traffic each, against about 1% at night); a 156-hour run at 6 hours has 26 episodes with gaps of 5.3-6.8 h.

**Variation.** Each episode uses a different user and a different blocked file-sharing site from the previous one, a random number of denials (two to ten), random retry gaps, a random storage target and a lognormal upload size. Every user, site, address, method and status in the chain also appears in ordinary traffic of both modes, including repeated denied uploads and uploads after a denial. A guard acts on the final step only: an ordinary sanctioned upload that would complete the chain with any earlier messages (two or more denied uploads by the same user to one host in the preceding 30 minutes, then the upload to another host) is not logged; denials stay as generated. In six 156-hour background captures (8,169 pairs of denied uploads to one host), a sanctioned upload by the same user follows at 1.4-1.6 per hour between 30 and 60 minutes after the first denial, with no gap beyond the 30-minute window, and uploads by other users follow at 19-20 per hour both inside and outside it.

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
| `syslog_utc_offset_hours` | `3` | Local time offset of the syslog header and of the users' working hours; `req-time` stays UTC |
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

Batch generation of a fixed period (add `start` and `end` to the `cron` input first):

```bash
eventum generate --path generators/proxy-solar-webproxy/generator.yml --id solar-webproxy --live-mode false
```

Live generation:

```bash
eventum generate --path generators/proxy-solar-webproxy/generator.yml --id solar-webproxy --live-mode true
```

## Sample output

The final upload of the first episode, copied byte for byte from the final default capture (line 7496) (the JSON formatter writes non-ASCII rule names as `\u` escapes):

```json
{"@timestamp": "2026-09-01T09:59:50.535+00:00", "destination": {"bytes": 655, "domain": "disk.fabrikam.test", "ip": "198.51.100.30", "port": 443}, "ecs": {"version": "8.17.0"}, "event": {"action": "http-allowed", "category": ["web", "network"], "duration": 177000000, "kind": "event", "original": "Sep 1 12:59:50 wp-01 java: [acc-domain:CORP] [acc-groups:Employees] [acc-ip:10.20.4.47] [acc-name:x.kiseleva] [acc-port:49944] [bytes-in:655] [bytes-out:17223918] [flt-categories:0] [flt-codes:11,0,0,0,0,0] [flt-policy:\u0417\u0430\u0432\u0435\u0440\u0448\u0435\u043d\u0438\u0435 \u043e\u0431\u0440\u0430\u0431\u043e\u0442\u043a\u0438 \u043f\u043e\u043b\u0438\u0442\u0438\u043a\u0438] [flt-rules:https,\u041f\u0435\u0440\u0435\u0445\u043e\u0434 \u043a \u0441\u043b\u043e\u044e Icap Request,\u041f\u0435\u0440\u0435\u0445\u043e\u0434 \u043a \u0441\u043b\u043e\u044e Filter req,\u041f\u0435\u0440\u0435\u0445\u043e\u0434 \u043a \u0441\u043b\u043e\u044e Icap Response,\u041f\u0435\u0440\u0435\u0445\u043e\u0434 \u043a \u0441\u043b\u043e\u044e Filter resps,\u041f\u0435\u0440\u0435\u0445\u043e\u0434 \u043a \u0441\u043b\u043e\u044e \u0417\u0430\u0432\u0435\u0440\u0448\u0435\u043d\u0438\u0435 \u043e\u0431\u0440\u0430\u0431\u043e\u0442\u043a\u0438 \u043f\u043e\u043b\u0438\u0442\u0438\u043a\u0438] [flt-status:200] [flt-time:177] [req-hostname:disk.fabrikam.test] [req-method:POST] [req-pathname:/api/v1/files/upload] [req-protocol:https] [req-query:uploadType=resumable] [req-referer:https://disk.fabrikam.test/] [req-time:2026-09-01T09:59:50.535Z] [req-user-agent:Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36] [res-datatype:application/json] [res-ip:198.51.100.30] [traf-mode:forward] [x-virus-id] [req-port:443] [flt-reason:]", "outcome": "success", "type": ["allowed", "connection"]}, "host": {"name": "wp-01"}, "http": {"request": {"bytes": 17223918, "method": "POST", "referrer": "https://disk.fabrikam.test/"}, "response": {"bytes": 655, "mime_type": "application/json", "status_code": 200}}, "observer": {"hostname": "wp-01", "product": "Solar webProxy", "type": "proxy", "vendor": "Solar"}, "related": {"hosts": ["disk.fabrikam.test"], "ip": ["10.20.4.47", "198.51.100.30"], "user": ["x.kiseleva"]}, "rule": {"name": "\u0417\u0430\u0432\u0435\u0440\u0448\u0435\u043d\u0438\u0435 \u043e\u0431\u0440\u0430\u0431\u043e\u0442\u043a\u0438 \u043f\u043e\u043b\u0438\u0442\u0438\u043a\u0438"}, "solar_webproxy": {"account_groups": "Employees", "filter_categories": "0", "filter_codes": "11,0,0,0,0,0", "filter_policy": "\u0417\u0430\u0432\u0435\u0440\u0448\u0435\u043d\u0438\u0435 \u043e\u0431\u0440\u0430\u0431\u043e\u0442\u043a\u0438 \u043f\u043e\u043b\u0438\u0442\u0438\u043a\u0438", "filter_reason": "", "filter_rules": "https,\u041f\u0435\u0440\u0435\u0445\u043e\u0434 \u043a \u0441\u043b\u043e\u044e Icap Request,\u041f\u0435\u0440\u0435\u0445\u043e\u0434 \u043a \u0441\u043b\u043e\u044e Filter req,\u041f\u0435\u0440\u0435\u0445\u043e\u0434 \u043a \u0441\u043b\u043e\u044e Icap Response,\u041f\u0435\u0440\u0435\u0445\u043e\u0434 \u043a \u0441\u043b\u043e\u044e Filter resps,\u041f\u0435\u0440\u0435\u0445\u043e\u0434 \u043a \u0441\u043b\u043e\u044e \u0417\u0430\u0432\u0435\u0440\u0448\u0435\u043d\u0438\u0435 \u043e\u0431\u0440\u0430\u0431\u043e\u0442\u043a\u0438 \u043f\u043e\u043b\u0438\u0442\u0438\u043a\u0438", "filter_status": 200, "filter_time_ms": 177, "request_time": "2026-09-01T09:59:50.535Z", "response_datatype": "application/json", "traffic_mode": "forward"}, "source": {"bytes": 17223918, "ip": "10.20.4.47", "port": 49944}, "url": {"domain": "disk.fabrikam.test", "full": "https://disk.fabrikam.test/api/v1/files/upload?uploadType=resumable", "path": "/api/v1/files/upload", "port": 443, "query": "uploadType=resumable", "scheme": "https"}, "user": {"domain": "CORP", "group": {"name": "Employees"}, "name": "x.kiseleva"}, "user_agent": {"original": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"}}
```

## Format and limitations

- `event.original` follows table 9.2 and the raw example of the 4.3.1 installation manual: a syslog-ng header (`<Mmm d HH:MM:SS> <host> java:`) and 27 bracketed fields in the example's order, including `acc-name` and the bare `[x-virus-id]` marker the example carries without a detection. Field meanings, including header plus body byte counts and `flt-codes` as one code per applied rule, come from appendix F.1.
- The header clock is local time (the vendor example is 3 hours ahead of its `req-time`) and is written when filtering ends, `flt-time` milliseconds after `req-time`. The day is not zero-padded, as in the example; the PDF text does not show whether syslog-ng pads it with a second space.
- `flt-codes` values are copied from the vendor examples (11 for the decryption rule, 0 for layer transitions, 2 for the blocking rule). The manual lists action names but not the numeric mapping, so other codes are not generated. `flt-categories` is `0` or one numeric category from the vendor example; the categorizer's full list is not published.
- A blocked request carries `bytes-in:0`, `bytes-out:0` and `res-datatype:application/skvt-unchecked`, as in the vendor example; whether a blocked POST reports its partial body is not documented.
- Only URL-list blocks are modelled. Antivirus, DLP, category, schedule and quota blocks, reverse-proxy mode and authentication failures are not generated.
- Host names use reserved test domains and documentation address ranges; users and groups are synthetic. Traffic ratios are scenario choices, since Solar does not publish them.
- Compatibility with third-party `siem-log` normalizers has not been tested.
- The allowed upload of an episode follows its last denial within 20 minutes; ordinary uploads after denials have no such cap (about 1% of them come later).

## References

- [Solar webProxy 4.3.1 installation and configuration manual](https://rt-solar.ru/products/solar_webproxy/doc/solar-webproxy-rukovodstvo-po-nastroyke-i-ustanovke-431-astra.pdf): table 9.2 `siem-log` fields and example; appendix F.1 `access-log` parameters
- [Solar webProxy documentation](https://rt-solar.ru/products/solar_webproxy/documents/)
- [Solar webProxy specifications](https://rt-solar.ru/products/solar_webproxy/specifications/): syslog export in `access-log`, `siem-log`, `cef-log` and `ip-translation-log` formats
