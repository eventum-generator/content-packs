# Fortinet FortiADC 7.1 SLB HTTP traffic

Traffic logs of one FortiADC 7.1 HTTP virtual server (`traffic/slb_http`, log ID `0101008001`) that balances an internal web portal over three real servers. Each event is ECS JSON with the complete native key=value record in `event.original` and its fields under `fortinet.fortiadc`. For SOC analysts and detection engineers who need load-balancer access traffic with a recurring suspicious `/admin` access pattern.

## Event Types

| Log ID | Record | Share | ECS category |
| --- | --- | --- | --- |
| `0101008001` | `type=traffic subtype=slb_http`: one HTTP request through the virtual server, with client, virtual server, real server, request line and response code | 100% | `web` |

Measured in the final 96-hour default capture (anomaly_mode true):

| Request | Share of records | Responses |
| --- | --- | --- |
| `/api/items` | 22.4% | 200 93%, 400 3%, 401 2%, 500 2%, 503 <1% |
| `/assets/app.js` | 13.1% | 200 80%, 304 18%, 404 2% |
| `/api/orders` | 12.0% | 200 93%, 400 3%, 401 2%, 500 2%, 503 <1% |
| `/assets/app.css` | 11.4% | 200 80%, 304 18%, 404 2% |
| `/api/items/search` | 10.1% | 200 93%, 400 3%, 401 2%, 500 1%, 503 <1% |
| `/assets/logo.png` | 7.9% | 200 80%, 304 18%, 404 2% |
| `/` | 7.0% | 200 86%, 304 14% |
| `/login` | 4.7% | 200 53%, 302 47% |
| `/index.html` | 3.5% | 200 89%, 304 11% |
| `/favicon.ico` | 3.4% | 200 71%, 404 29% |
| `/admin` | 2.8% | 200 43%, 403 27%, 404 22%, 302 8% |
| `/logout` | 1.7% | 302 100% |


## Background Model

Sixty clients (`samples/clients.csv`: 48 office users and 8 administrators on browsers, 4 service scripts) start sessions as independent random processes, on average `sessions_per_client_day` per client, thinned by an hour-of-day activity curve (office hours UTC up to nine times the night rate). A session holds a skewed number of requests (median 9) with skewed gaps (median 5 s, long tail up to 15 min); each request opens a new connection with probability 0.6, and each connection is balanced to a random real server. Administrators request `/admin` often and mostly get 200; office users and scripts request it rarely and mostly get 403 or 404. Every `/admin` request is followed by another `/admin` request with probability 0.3 (reload or retry), so repeated `/admin` answers with mixed codes from different real servers within minutes are ordinary traffic. `msg_id` is a device-wide 16-digit counter: records of other log types and virtual servers take the numbers in between, so consecutive records here differ by a random step.

## Anomaly Chain

One client walks through the `/admin` answers of the pool until one real server serves the page:

1. `GET /admin` answered `404` by real server A.
2. A retry of `/admin` answered `403` by real server B (not A).
3. A retry of `/admin` answered `200` by real server C (neither A nor B).

The episode session is an ordinary session of that client drawn from the background model until it contains an `/admin` request; one of its `/admin` runs, chosen uniformly, becomes the chain, and the requests before and after it stay as drawn. The three chain requests are consecutive, like any `/admin` retry run, and their gaps are drawn like any retry gap (median 25 s, at most 400 s), so the whole chain stays within 15 minutes. In the final captures the chain head sat at session positions 0 to 65 (median 5 of 11 browser-session episodes; background `/admin` runs median 10 to 12), at a mean relative position of 0.40 (background 0.49).

Linking fields: `source.ip` (`src`), `url.path` (`http_url`), `fortinet.fortiadc.real_server`, `fortinet.fortiadc.policy`, `destination.ip` and `@timestamp`.

Recurrence: the first episode starts within the first `anomaly_interval_hours` (at most 24 h) of generation, at a time drawn from the activity curve, not at a fixed offset from the generation start. Each next episode is due `anomaly_interval_hours` after the actual start of the previous one and starts in a window of a quarter of the interval (at most 6 h) centred on the due time, weighted by the square of the activity curve plus a small floor; when no eligible client is idle at that second, the start waits for the next tick. Missed episodes are not caught up. The default interval is 24 h; the minimum is 6 h. At intervals of 8 h or less the episodes necessarily cover night hours too. In the final 96-hour default capture 4 chains started 22.4, 23.0 and 26.5 h apart, between 13:00 and 16:00 UTC, each spanning 69 to 113 s; a 12 h interval produced 8 chains 10.7 to 13.5 h apart, alternating between 06:00-08:00 and 18:00 UTC, spanning 18 to 484 s.

Variation: the client (drawn uniformly among idle clients, never the previous episode's), the order of real servers, the position of the run in the session, the gaps, an optional fourth `/admin` retry and the rest of the session change between episodes.

Nothing in the chain is unique to it: every chain client, its client-server pairs and `/admin` with each of the codes 404, 403 and 200 also occur in background, including `/admin` 404 followed by 403 and 403 followed by 200 for one client on different real servers within minutes (404 then 403 on two servers within 15 minutes: about 12 per 96-hour background capture). Only the full ordered sequence is kept out of background: an ordinary `/admin` request that would complete it (a 404 and then a 403 for the same client from two real servers other than the one now answering, the 404 at most 15 minutes earlier) is answered `403` instead of `200`, at the same time. The guard uses the chain window exactly, so a `200` more than 15 minutes after the first 404 is left as is.

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
| `sessions_per_client_day` | `6` | Mean sessions per client per day |
| `anomaly_mode` | `true` | Include the anomaly chain; `false` emits background only |
| `anomaly_interval_hours` | `24` | Hours between episode starts, 6 to 8760 |

Clients are listed in `samples/clients.csv` (`ip`, `role` of `user`, `admin` or `service`, `agent`).

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
# Live: one-second ticks in real time
eventum generate --path generators/network-fortinet-fortiadc/generator.yml --id fortiadc --live-mode true

# Batch: add start/end to the cron input, then generate as fast as possible
eventum generate --path generators/network-fortinet-fortiadc/generator.yml --id fortiadc --live-mode false
```

## Limitations

- One log type only: `traffic/slb_http` is the one traffic record with a complete raw example in the FortiADC 7.1 log reference. Event (admin, health check, configuration), WAF and other traffic sub-types are not generated.
- The 7.1 reference page is titled `0100008001`, but its example and the "Anatomy of a log message" example both carry `log_id=0101008001`; the pack follows the examples.
- One HTTP virtual server on port 80; no HTTPS virtual server, persistence, content routing or health-check effects on server choice.
- The unit of `duration` is not documented; it is a small skewed integer. `@timestamp`, `date` and `time` are UTC with one-second resolution, and at most one record is emitted per second.
- `user`, `usrgrp` and `auth_status` are `none` (no authentication policy on the virtual server), and `srccountry`/`dstcountry` are `Reserved` for private addresses, as in the vendor examples.
- The response mix, byte sizes and client behavior are synthetic workload settings, not measured FortiADC rates.
- The shipped file is an ECS JSON envelope; send `event.original` as the syslog payload to test a parser of native FortiADC logs. No syslog header is generated.

## Sample Output

An event from the final default capture (the `200` step of an episode):

```json
{"@timestamp": "2026-09-04T15:58:19+00:00", "destination": {"ip": "10.41.20.15", "port": 80}, "ecs": {"version": "8.17.0"}, "event": {"action": "slb-http-response", "category": ["web"], "code": "0101008001", "dataset": "fortinet_fortiadc.log", "kind": "event", "original": "date=2026-09-04 time=15:58:19 log_id=0101008001 type=traffic subtype=slb_http pri=information vd=root msg_id=8897080279353243 duration=3 ibytes=523 obytes=11489 proto=6 service=http src=10.41.1.141 src_port=65368 dst=10.41.20.15 dst_port=80 trans_src=10.41.30.1 trans_src_port=30673 trans_dst=10.41.30.11 trans_dst_port=80 policy=vs_web action=none http_method=get http_host=portal.example.test http_agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0 http_url=/admin http_qry=none http_referer=http://portal.example.test/ http_cookie=sessionid=d749f6ec5c322d52841438b2ea32543b http_retcode=200 user=none usrgrp=none auth_status=none srccountry=Reserved dstcountry=Reserved real_server=app01", "outcome": "success", "type": ["access"]}, "fortinet": {"fortiadc": {"action": "none", "auth_status": "none", "date": "2026-09-04", "dst": "10.41.20.15", "dst_port": 80, "dstcountry": "Reserved", "duration": 3, "http_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0", "http_cookie": "sessionid=d749f6ec5c322d52841438b2ea32543b", "http_host": "portal.example.test", "http_method": "get", "http_qry": "none", "http_referer": "http://portal.example.test/", "http_retcode": 200, "http_url": "/admin", "ibytes": 523, "log_id": "0101008001", "msg_id": 8897080279353243, "obytes": 11489, "policy": "vs_web", "pri": "information", "proto": 6, "real_server": "app01", "service": "http", "src": "10.41.1.141", "src_port": 65368, "srccountry": "Reserved", "subtype": "slb_http", "time": "15:58:19", "trans_dst": "10.41.30.11", "trans_dst_port": 80, "trans_src": "10.41.30.1", "trans_src_port": 30673, "type": "traffic", "user": "none", "usrgrp": "none", "vd": "root"}}, "host": {"name": "fortiadc-01.example.test"}, "http": {"request": {"method": "GET"}, "response": {"status_code": 200}}, "network": {"protocol": "http", "transport": "tcp"}, "related": {"ip": ["10.41.1.141", "10.41.20.15", "10.41.30.11"]}, "source": {"ip": "10.41.1.141", "port": 65368}, "url": {"path": "/admin"}, "user_agent": {"original": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0"}}

```

## References

- [FortiADC 7.1.0 Log Reference: 0100008001 (traffic: SLB HTTP)](https://docs.fortinet.com/document/fortiadc/7.1.0/log-reference/173525/0100008001-traffic-slb-http)
- [FortiADC 7.1.0 Log Reference: Anatomy of a log message](https://docs.fortinet.com/document/fortiadc/7.1.0/log-reference/378226/anatomy-of-a-log-message)
- [FortiADC 7.1.0 Log Reference: Log ID schema](https://docs.fortinet.com/document/fortiadc/7.1.0/log-reference/62525/log-id-schema)
- The ECS fields are this pack's mapping of the native fields; Fortinet documents only the native record.
