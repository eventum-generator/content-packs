# Fortinet FortiADC 7.1 SLB HTTP traffic

Traffic logs of one FortiADC 7.1 HTTP virtual server (`traffic/slb_http`, log ID `0101008001`) that balances an internal web portal over three real servers. Each event is ECS JSON with the complete native key=value record in `event.original` and its fields under `fortinet.fortiadc`. For SOC analysts and detection engineers who need load-balancer access traffic with a recurring suspicious `/admin` access pattern.

## Event Types

| Log ID | Record | Share | ECS category |
| --- | --- | --- | --- |
| `0101008001` | `type=traffic subtype=slb_http`: one HTTP request through the virtual server, with client, virtual server, real server, request line and response code | 100% | `web` |

Shares over 96 hours with the default settings (anomaly_mode true, 20,354 records):

| Request | Share of records | Responses |
| --- | --- | --- |
| `/api/items` | 22.6% | 200 92%, 400 3%, 401 3%, 500 1%, 503 <1% |
| `/assets/app.js` | 12.7% | 200 80%, 304 18%, 404 2% |
| `/api/orders` | 11.5% | 200 93%, 400 2%, 401 2%, 500 2%, 503 1% |
| `/assets/app.css` | 10.8% | 200 80%, 304 18%, 404 2% |
| `/api/items/search` | 10.1% | 200 93%, 400 2%, 401 2%, 500 1%, 503 <1% |
| `/assets/logo.png` | 7.5% | 200 79%, 304 19%, 404 2% |
| `/` | 6.4% | 200 88%, 304 12% |
| `/admin` | 5.8% | 200 50%, 403 21%, 404 17%, 302 12% |
| `/login` | 4.8% | 200 57%, 302 43% |
| `/favicon.ico` | 3.2% | 200 68%, 404 32% |
| `/index.html` | 3.2% | 200 88%, 304 12% |
| `/logout` | 1.5% | 302 100% |

## Background Model

Sixty clients (`samples/clients.csv`: 48 office users and 8 administrators on browsers, 4 service scripts) send about 5,100 requests a day. Browser traffic follows a UTC working day: about 40 requests an hour at night (20:00-06:00), 120 an hour at 06:00-07:00 and 18:00-20:00, 250 an hour at 07:00-08:00 and 17:00-18:00 and 380 an hour at 08:00-17:00. The number of active browser clients follows the same curve: about 5 an hour at night, about 25 in office hours. The service scripts send about 400 requests a day, evenly around the clock. Daily totals vary by about 3%.

Every request belongs to a client session of a skewed number of requests (median 9, mean 15), and a client has one session open at a time. Requests of one session are a median 34 s apart in office hours and about 2 minutes apart at night, with a long tail. Each request opens a new connection with probability 0.6, and each connection is balanced to a random real server. Administrators spend about a quarter to a third of their requests on `/admin` and mostly get 200 (403, 404 and a 302 redirect about 12% each); office users and scripts request it rarely and mostly get 403 or 404. Every `/admin` request is followed by another `/admin` request with probability 0.3 (reload or retry), so repeated `/admin` answers with mixed codes from different real servers within minutes are ordinary traffic. `msg_id` is a device-wide 16-digit counter: records of other log types and virtual servers take the numbers in between, so consecutive records here differ by a random step.

## Anomaly Chain

An administrator's browser walks through the `/admin` answers of the pool until one real server serves the page:

1. `GET /admin` answered `404` by real server A.
2. A retry of `/admin` answered `403` by real server B (not A).
3. A retry of `/admin` answered `200` by real server C (neither A nor B).

The episode is one session of an administrator (the clients that open `/admin` regularly), drawn uniformly among those with no session open, never the previous episode's. It starts only when that administrator has no session open, so it neither interrupts nor delays the administrator's own sessions; the day's request count stays the same. The session looks like any administrator session containing `/admin` requests; one of its `/admin` runs is the chain, and the requests before and after it are ordinary. The three chain requests are consecutive, like any `/admin` retry run, and their gaps are drawn like any retry gap (median 25 s, at most 400 s), so the whole chain stays within 15 minutes.

Linking fields: `source.ip` (`src`), `url.path` (`http_url`), `fortinet.fortiadc.real_server`, `fortinet.fortiadc.policy`, `destination.ip` and `@timestamp`.

Recurrence: the first episode starts within the first `anomaly_interval_hours` (at most 24 h) of generation, at a time drawn from the browser hour curve, not at a fixed offset from the generation start. Each next episode is due `anomaly_interval_hours` after the actual start of the previous one and starts in a window of a quarter of the interval (at most 6 h) centred on the due time, weighted by the square of the browser hour curve plus a small floor. The chain sits at a random point of the episode session and starts within a minute or two of its drawn time in office hours, up to about 20 minutes off at night. Missed episodes are not caught up. The default interval is 24 h; the minimum is 6 h. At intervals of 8 h or less the episodes necessarily cover night hours too. With the defaults, chains start 21-27 h apart, mostly in office hours, and last about 20 s to a few minutes; with an 8 h interval they start about 7-9 h apart around the clock and last up to about 8 minutes.

Variation: the administrator, the order of real servers, the position of the run in the session, the gaps, an optional fourth `/admin` retry and the rest of the session change between episodes.

Nothing in the chain is unique to it: every chain client, its client-server pairs and `/admin` with each of the codes 404, 403 and 200 also occur in background, including `/admin` 404 followed by 403 and 403 followed by 200 for one client on different real servers within minutes (over 96 hours of background about 45 pairs of 404 then 403 on two servers within 15 minutes, and about 100 of 403 then 200). Only the full ordered sequence is kept out of background: an ordinary `/admin` request that would complete it (a 404 and then a 403 for the same client from two real servers other than the one now answering, the 404 at most 15 minutes earlier) gets another answer that client role receives for `/admin` (302, 403 or 404, in the role's proportions) at the same time, about three requests a day. The same rule applies after an episode, so an episode completes the sequence exactly once. A `200` more than 15 minutes after the first 404 is left as is.

Detection idea: per source address, `/admin` answered 404, 403 and 200 by three different real servers of one virtual server within 15 minutes. It points at a pool member whose access control differs from the others; the traffic log only records the HTTP result, not whether anyone authenticated or what the page exposed.

`anomaly_mode: true` is the default. With `anomaly_mode: false` the generator emits the same background without episodes.

## Parameters

### Event Parameters

| Parameter | Default | Description |
| --- | --- | --- |
| `device_name` | `fortiadc-01.example.test` | ECS `host.name` of the appliance |
| `virtual_server` | `vs_web` | Virtual server name (`policy`) |
| `virtual_ip` | `10.41.20.15` | Virtual server address (`dst`) |
| `virtual_port` | `80` | Virtual server port (`dst_port`) |
| `http_host` | `portal.example.test` | `Host` header of the requests (`http_host`) |
| `snat_ip` | `10.41.30.1` | Source NAT address toward the real servers (`trans_src`) |
| `real_servers` | `app01` `10.41.30.11`, `app02` `10.41.30.12`, `app03` `10.41.30.13`, port 80 | Pool members (`real_server`, `trans_dst`, `trans_dst_port`); the chain needs at least three |
| `anomaly_mode` | `true` | Include the anomaly chain; `false` emits background only |
| `anomaly_interval_hours` | `24` | Hours between episode starts, 6 to 8760 |

Clients are listed in `samples/clients.csv` (`ip`, `role` of `user`, `admin` or `service`, `agent`).

The request volume and the hour curve are set in `patterns/`: `users-floor.yml`, `users-day.yml`, `users-work.yml` and `users-office.yml` are stacked hour bands of browser requests (requests a day in `multiplier.ratio`, hours as fractions of the day in `spreader.parameters`), `services.yml` the requests of the service scripts. Scale the ratios to change the volume.

### Output Parameters

The default output writes JSON lines to `output/events.json` and needs no parameters. To deliver elsewhere, replace the `output` block with another output plugin and pass its endpoint and credentials as `${params.*}` / `${secrets.*}` placeholders, for example:

```yaml
output:
  - opensearch:
      hosts: ["${params.opensearch_url}"]
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: fortiadc-traffic
```

## Usage

```bash
# Live: requests at the rates above, in real time
eventum generate --path generators/network-fortinet-fortiadc/generator.yml --id fortiadc --live-mode true

# Batch: as fast as possible over a finite window (see below)
eventum generate --path generators/network-fortinet-fortiadc/generator.yml --id fortiadc --live-mode false
```

The files in `patterns/` start at midnight of the current day and never end. For a finite batch window, set `start` to a midnight and `end` in every file, for example `start: "2026-09-01T00:00:00Z"` and `end: "+96h"`; a start other than midnight shifts the hour curve.

Performance: about 1,600 events/s (14 days, 71,700 records, in 43 s of CPU time).

## Limitations

- One log type only: `traffic/slb_http` is the one traffic record with a complete raw example in the FortiADC 7.1 log reference. Event (admin, health check, configuration), WAF and other traffic sub-types are not generated.
- The 7.1 reference page is titled `0100008001`, but its example and the "Anatomy of a log message" example both carry `log_id=0101008001`; the pack follows the examples.
- One HTTP virtual server on port 80; no HTTPS virtual server, persistence, content routing or health-check effects on server choice.
- The unit of `duration` is not documented; it is a small skewed integer. `@timestamp`, `date` and `time` are UTC with one-second resolution; several records can share a second.
- Requests of one session are further apart at night than in office hours (median gap about 2 minutes versus 34 s): sessions share the hourly request rate, while a real user's click pace does not depend on the hour.
- Every day follows the same hour curve; weekends and holidays are not quieter.
- With `anomaly_mode: true` each episode adds one `/admin` run of 404, 403 and 200 to an administrator's traffic, so these administrator answers are about one per episode more frequent than with `anomaly_mode: false`.
- `user`, `usrgrp` and `auth_status` are `none` (no authentication policy on the virtual server), and `srccountry`/`dstcountry` are `Reserved` for private addresses, as in the vendor examples.
- The response mix, byte sizes and client behavior are synthetic workload settings, not measured FortiADC rates.
- The shipped file is an ECS JSON envelope; send `event.original` as the syslog payload to test a parser of native FortiADC logs. No syslog header is generated.

## Sample Output

An event from a 96-hour default run (the `200` step of an episode):

```json
{"@timestamp": "2026-09-01T16:43:15+00:00", "destination": {"ip": "10.41.20.15", "port": 80}, "ecs": {"version": "8.17.0"}, "event": {"action": "slb-http-response", "category": ["web"], "code": "0101008001", "dataset": "fortinet_fortiadc.log", "kind": "event", "original": "date=2026-09-01 time=16:43:15 log_id=0101008001 type=traffic subtype=slb_http pri=information vd=root msg_id=8892571232853858 duration=14 ibytes=637 obytes=3177 proto=6 service=http src=10.41.2.20 src_port=55066 dst=10.41.20.15 dst_port=80 trans_src=10.41.30.1 trans_src_port=22117 trans_dst=10.41.30.13 trans_dst_port=80 policy=vs_web action=none http_method=get http_host=portal.example.test http_agent=Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0 http_url=/admin http_qry=none http_referer=http://portal.example.test/ http_cookie=sessionid=bf3113a1f1fe9a1e3a124a9fbd1627bd http_retcode=200 user=none usrgrp=none auth_status=none srccountry=Reserved dstcountry=Reserved real_server=app03", "outcome": "success", "type": ["access"]}, "fortinet": {"fortiadc": {"action": "none", "auth_status": "none", "date": "2026-09-01", "dst": "10.41.20.15", "dst_port": 80, "dstcountry": "Reserved", "duration": 14, "http_agent": "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0", "http_cookie": "sessionid=bf3113a1f1fe9a1e3a124a9fbd1627bd", "http_host": "portal.example.test", "http_method": "get", "http_qry": "none", "http_referer": "http://portal.example.test/", "http_retcode": 200, "http_url": "/admin", "ibytes": 637, "log_id": "0101008001", "msg_id": 8892571232853858, "obytes": 3177, "policy": "vs_web", "pri": "information", "proto": 6, "real_server": "app03", "service": "http", "src": "10.41.2.20", "src_port": 55066, "srccountry": "Reserved", "subtype": "slb_http", "time": "16:43:15", "trans_dst": "10.41.30.13", "trans_dst_port": 80, "trans_src": "10.41.30.1", "trans_src_port": 22117, "type": "traffic", "user": "none", "usrgrp": "none", "vd": "root"}}, "host": {"name": "fortiadc-01.example.test"}, "http": {"request": {"method": "GET"}, "response": {"status_code": 200}}, "network": {"protocol": "http", "transport": "tcp"}, "related": {"ip": ["10.41.2.20", "10.41.20.15", "10.41.30.13"]}, "source": {"ip": "10.41.2.20", "port": 55066}, "url": {"path": "/admin"}, "user_agent": {"original": "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0"}}
```

## References

- [FortiADC 7.1.0 Log Reference: 0100008001 (traffic: SLB HTTP)](https://docs.fortinet.com/document/fortiadc/7.1.0/log-reference/173525/0100008001-traffic-slb-http)
- [FortiADC 7.1.0 Log Reference: Anatomy of a log message](https://docs.fortinet.com/document/fortiadc/7.1.0/log-reference/378226/anatomy-of-a-log-message)
- [FortiADC 7.1.0 Log Reference: Log ID schema](https://docs.fortinet.com/document/fortiadc/7.1.0/log-reference/62525/log-id-schema)
- The ECS fields are this pack's mapping of the native fields; Fortinet documents only the native record.
