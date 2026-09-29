# F5 BIG-IP ASM / Advanced WAF request log (CEF)

Eventum content pack for the F5 BIG-IP Application Security Manager (Advanced WAF) request log sent to a remote logging profile in the ArcSight CEF format over syslog. It models one BIG-IP unit protecting four virtual servers and emits ECS JSON with the native syslog CEF line in `event.original`. The message layout follows the ASM 11.3.0 CEF examples in F5's External Monitoring Implementations guide.

## Events

| CEF class (`event.code`) | Name | `act` | Share (default) | ECS category |
| --- | --- | --- | --- | --- |
| `Successful Request` | Successful Request | passed | 92.4% | `web` |
| `Illegal HTTP status in response` | Illegal HTTP status in response | alerted | 2.2% | `web`, `intrusion_detection` |
| `200000098` | XSS script tag (Parameter) | blocked / alerted | 1.1% / 0.2% | `web`, `intrusion_detection` |
| `200002273` | SQL-INJ exec() | blocked / alerted | 1.1% / 0.2% | `web`, `intrusion_detection` |
| `Illegal URL` | Illegal URL | blocked / alerted | 0.8% / 0.1% | `web`, `intrusion_detection` |
| `Host header contains IP address` | HTTP protocol compliance failed | blocked / alerted | 0.8% / 0.1% | `web`, `intrusion_detection` |
| `200021069` | Automated client access "wget" | blocked / alerted | 0.5% / 0.1% | `web`, `intrusion_detection` |
| `Illegal query string length` | Illegal query string length | blocked / alerted | 0.5% / 0.1% | `web`, `intrusion_detection` |

About 15,000 requests a day (daily totals vary by about 3%). Ordinary traffic is a mix of independent visitors and automated attackers:

- Browsing (about 1,800 sessions a day): a client picked by a skewed per-client weight opens a session on one application and requests 1-60 URIs with lognormal gaps (median about 12 s in the afternoon). Backend status codes 403, 409 and 500 raise `Illegal HTTP status in response` (alerted). About 0.6% of dynamic requests trip a violation (blocked or alerted); a blocked client often retries the same URI within a minute or two, and the retry is blocked again or passes.
- Automated attack bursts (about 130 a day, evenly around the clock): a client attacks one to six URIs of an application with signature and violation payloads and probes for files that do not exist (`Illegal URL`). About a third of the attacked URIs also get one plain request, usually early in the sequence (position k among the payloads with weight 0.55^k).

Browsing volume follows a daily curve by UTC hour; attack traffic stays flat:

| UTC hours | Requests per hour (approx.) |
| --- | --- |
| 00-05 | 160-310, lowest at 03:00 |
| 06-09 | 440-820, rising |
| 10-17 | 870-1,030, peak at 13:00 |
| 18-23 | 790 falling to 340 |

Blocked requests carry `cn1=0`; passed and alerted requests carry the backend status. `externalId` (support ID) grows by random steps; `suid` is shared by the requests of one session or burst.

## Anomaly Chain

**Sequence.** One client sends requests to one URI of one virtual server that are blocked for three or four distinct violations (SQL injection, XSS, wget client, oversized query string, IP address in the Host header, in random order, with up to two repeats), then a plain request from the same client to the same URI passes with status 200. The request pattern reads as payload cycling until one request gets through.

**Linking fields.** `source.ip`, `destination.ip` (virtual server), `url.path`, distinct `event.code` values with `event.action: blocked`, then `event.action: passed`; `f5.asm.session_id` is shared inside the episode.

**Recurrence.** `anomaly_interval_hours` (default 24, minimum 2, maximum 8760). The first start falls within the first min(interval, 24 h), at a time drawn with the hour-of-day request volume. Each later start is drawn in a window centred on the due time (actual previous start + interval), width w = min(interval / 4, 6 h), weighted by the hour-of-day volume squared plus a small floor, so episodes mostly fall between 07:00 and 21:00 UTC; consecutive starts are therefore interval ± w/2 apart. There is no catch-up. At intervals of 8 h or less the window is narrow and the start phase necessarily drifts around the clock. An episode spans about 5-140 s.

**Variation.** Each episode takes a client and a virtual server URI with a query from the frequent combinations of ordinary browsing (a busy client on a popular URI, browsed together in several sessions a day on average and weighted by how often), so the client and the client-server-URI combination also occur in ordinary traffic; client and target differ from the previous episode. Violation codes are drawn with the background weights; gaps follow the same law as background attack bursts. Episodes do not change the hourly request volume, and the episode client's own browsing goes on as usual: the few episode requests take the place of requests of newly arriving visitors at that moment.

**Background overlap.** Ordinary traffic in both modes contains every chain feature: repeated blocks by one client within a minute (about 470 a day), blocked requests that complete three or more distinct violations by one client on one URI within 30 minutes (about 170 a day), and a passed request after one or two distinct blocks on that URI (about 8% and 5% of those blocks are followed within a minute by a pass on the same URI). After a block with two versus three or more distinct violations on the URI, the client's next request within a minute is another violation on that URI in about 60% versus 58% of cases and goes to another URI in about 14% versus 16%. Only the complete ordered chain never occurs in background: after three or more distinct blocks by one client on one URI, that client's later requests to the same URI within 30 minutes are violations again (blocked or alerted at the ordinary attack shares), never a pass. The same holds for the episode client after an episode.

**Detection idea.** Per `source.ip` + `destination.ip` + `url.path`: at least three distinct blocked violation codes followed by a passed request within 30 minutes. A passed request alone does not prove a bypass or data access; confirm with the application logs.

`anomaly_mode` defaults to `true`; `false` produces only background, with no complete chain.

## Parameters

### Event Parameters

Set in `event.template.params` of `generator.yml`.

| Parameter | Default | Meaning |
| --- | --- | --- |
| `anomaly_mode` | `true` | Add anomaly episodes; `false` emits background only |
| `anomaly_interval_hours` | `24` | Hours between episode starts (2-8760) |
| `device_hostname` | `bigip-waf-01.example.com` | Syslog host and CEF `dvchost` |
| `device_management_ip` | `10.60.0.5` | BIG-IP management address, CEF `dvc` |
| `device_version` | `11.3.0` | CEF Device Version |
| `virtual_servers` | 4 servers | Host name, address, port (80 or 443), ASM policy name, traffic weight and URI list (method, path, query template with `{n}` or `{q}`, weight) |
| `forceful_paths` | 8 paths | Non-existent paths probed by attack bursts |
| `search_terms` | 10 terms | Values for the `{q}` query placeholder |

### Samples

| File | Content |
| --- | --- |
| `samples/clients.json` | 360 client addresses in 198.51.100.0/24 and 192.0.2.0/24, each with a request weight (0.2-8), a browser user agent and a country code (`N/A` when unknown) |

### Output Parameters

The shipped `generator.yml` writes to `output/events.json` and needs no credentials. To send events to a SIEM, replace the `output` block and use top-level placeholders for the endpoint and credentials, for example `hosts: ["${params.opensearch_host}"]` and `password: ${secrets.opensearch_password}`, then pass them at run time.

## Usage

Live mode:

```bash
eventum generate --path generators/web-f5-advanced-waf/generator.yml --id web-f5-advanced-waf --live-mode true
```

Batch mode:

```bash
eventum generate --path generators/web-f5-advanced-waf/generator.yml --id web-f5-advanced-waf --live-mode false
```

The request volume and its daily curve are set in the three files under `patterns/` (`web-floor.yml`, `web-day.yml`, `scan.yml`); their days start at 04:00 UTC from 2026-01-01 and never end. For a finite batch run set `start` and `end` in all three files, keeping the start at 04:00 UTC so the daily curve stays in place, for example `start: "2026-09-01T04:00:00Z"` and `end: "2026-09-05T04:00:00Z"`. Scaling the `ratio` values changes the volume; episode start times keep following the shipped hourly curve.

Performance: about 1,100 events/s in batch mode (14 days, about 209,000 events, in about 3 minutes).

## Sample Output

A blocked request with anomaly_mode: true (second step of an episode):

```json
{"@timestamp": "2026-09-01T14:05:48+00:00", "destination": {"ip": "203.0.113.10", "port": 443}, "ecs": {"version": "8.17.0"}, "event": {"action": "blocked", "category": ["web", "intrusion_detection"], "code": "200000098", "dataset": "f5.asm", "kind": "alert", "original": "\u003c131\u003eSep  1 14:05:48 bigip-waf-01.example.com ASM:CEF:0|F5|ASM|11.3.0|200000098|XSS script tag (Parameter)|5|dvchost=bigip-waf-01.example.com dvc=10.60.0.5 cs1=shop-web cs1Label=policy_name cs2=/Common/shop-web cs2Label=http_class_name deviceCustomDate1=Jul 25 2026 20:32:05 deviceCustomDate1Label=policy_apply_date externalId=13504540882566727567 act=blocked cn1=0 cn1Label=response_code src=192.0.2.10 spt=49717 dst=203.0.113.10 dpt=443 requestMethod=GET app=HTTPS cs5=N/A cs5Label=x_forwarded_for_header_value rt=Sep 01 2026 14:05:48 deviceExternalId=0 cs4=Cross Site Scripting (XSS) cs4Label=attack_type cs6=US cs6Label=geo_location c6a1= c6a1Label=device_address c6a2= c6a2Label=source_address c6a3= c6a3Label=destination_address c6a4=N/A c6a4Label=ip_address_intelligence msg=N/A suid=45f4c6c0cf4461ac suser=N/A request=/products?page\\=%22%3E\u003cscript src\\=//cdn.example.net/x.js\u003e\u003c/script\u003e cs3Label=full_request cs3=GET /products?page\\=%22%3E\u003cscript src\\=//cdn.example.net/x.js\u003e\u003c/script\u003e HTTP/1.1\\r\\nHost: shop.example.com\\r\\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36\\r\\nAccept: text/html,application/xhtml+xml,application/xml;q\\=0.9,*/*;q\\=0.8\\r\\nAccept-Language: en-US,en;q\\=0.9\\r\\nAccept-Encoding: gzip, deflate, br\\r\\nConnection: keep-alive\\r\\n\\r\\n", "outcome": "failure", "severity": 5, "type": ["access", "denied"]}, "f5": {"asm": {"attack_type": "Cross Site Scripting (XSS)", "http_class_name": "/Common/shop-web", "policy_apply_date": "Jul 25 2026 20:32:05", "policy_name": "shop-web", "request_status": "blocked", "response_code": 0, "session_id": "45f4c6c0cf4461ac", "support_id": "13504540882566727567"}}, "http": {"request": {"method": "GET"}}, "network": {"protocol": "https"}, "observer": {"ip": ["10.60.0.5"], "name": "bigip-waf-01.example.com", "product": "ASM", "type": "waf", "vendor": "F5", "version": "11.3.0"}, "related": {"ip": ["192.0.2.10", "203.0.113.10"]}, "rule": {"id": "200000098", "name": "XSS script tag (Parameter)"}, "source": {"geo": {"country_iso_code": "US"}, "ip": "192.0.2.10", "port": 49717}, "url": {"original": "/products?page=%22%3E\u003cscript src=//cdn.example.net/x.js\u003e\u003c/script\u003e", "path": "/products", "query": "page=%22%3E\u003cscript src=//cdn.example.net/x.js\u003e\u003c/script\u003e"}, "user_agent": {"original": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"}}
```

## Limitations

- The layout is the ASM 11.3.0 CEF request message as published by F5 (Successful Request and signature examples). Headers for non-signature violations follow the 10.1.0 ArcSight guide example and third-party 11.6.1 and 15.1 raw logs; severities 5 and 2 and the syslog PRI mapping (`<131>` for severity 5, `<134>` otherwise) are inferred from those examples. Newer releases (14.x and later) add keys such as `violation_rating` and `microservice`, which are not modelled.
- One violation per request; multi-violation requests, `violation_details`, brute force, web scraping, DoS and bot defense messages, request bodies and XFF values are not modelled. `geo_location` is a synthetic country code per client.
- Signature IDs are limited to three documented ones (200002273, 200000098, 200021069). Rates, weights, sessions and payloads are synthetic; all times are UTC with whole-second resolution, as in `rt`.
- The syslog header time equals `rt` or is one second later, as in the vendor examples. The day is space-padded per RFC 3164.
- Requests of one session or attack burst are never closer together than the site-wide request spacing: at night (about 160 requests an hour at 03:00 UTC) consecutive requests of one client are typically about 20 s apart, against about 12 s in the afternoon, and automated payload sequences are slowed the same way.
- Every day has the same hourly curve; there is no weekly cycle. The client population is a fixed set of 360 addresses from two documentation ranges.
- With anomaly_mode: true each episode adds its own blocked requests, so counts of blocked sequences with three or more distinct violations by one client on one URI are about one per episode higher than with anomaly_mode: false.
- Episodes are weighted to busy hours more strongly than background (volume squared); the chain client is a frequent browsing client, whereas ordinary attack bursts come from any client with equal probability, so most client addresses trip a violation within a few days.
- SIEM parser compatibility (for example KUMA or Elastic CEF) has not been tested.

## References

- [F5 External Monitoring of BIG-IP Systems: Implementations - event messages and ASM CEF examples](https://techdocs.f5.com/en-us/bigip-15-0-0/external-monitoring-of-big-ip-systems-implementations/event-messages-and-attack-types.html)
- [F5 BIG-IP ASM: logging application security events](https://techdocs.f5.com/en-us/bigip-17-5-0/big-ip-asm-implementations/logging-application-security-events.html)
- [ArcSight F5 ASM Certified CEF Configuration Guide examples, as Graylog CEF test fixtures](https://github.com/Graylog2/graylog2-server/tree/master/graylog2-server/src/test/resources/fixtures)
- [Wazuh F5 BIG-IP ruleset tests with ASM 14.1.2 CEF logs](https://github.com/wazuh/wazuh/blob/master/ruleset/testing/tests/f5_big_ip.ini)
