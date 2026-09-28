# F5 BIG-IP ASM / Advanced WAF request log (CEF)

Eventum content pack for the F5 BIG-IP Application Security Manager (Advanced WAF) request log sent to a remote logging profile in the ArcSight CEF format over syslog. It models one BIG-IP unit protecting four virtual servers and emits ECS JSON with the native syslog CEF line in `event.original`. The message layout follows the ASM 11.3.0 CEF examples in F5's External Monitoring Implementations guide.

## Events

| CEF class (`event.code`) | Name | `act` | Share (126 h, default on) | ECS category |
| --- | --- | --- | --- | --- |
| `Successful Request` | Successful Request | passed | 89.3% | `web` |
| `Illegal HTTP status in response` | Illegal HTTP status in response | alerted | 2.0% | `web`, `intrusion_detection` |
| `200002273` | SQL-INJ exec() | blocked / alerted | 1.9% / 0.3% | `web`, `intrusion_detection` |
| `200000098` | XSS script tag (Parameter) | blocked / alerted | 1.8% / 0.3% | `web`, `intrusion_detection` |
| `Illegal URL` | Illegal URL | blocked / alerted | 1.2% / 0.1% | `web`, `intrusion_detection` |
| `Host header contains IP address` | HTTP protocol compliance failed | blocked / alerted | 1.0% / 0.2% | `web`, `intrusion_detection` |
| `200021069` | Automated client access "wget" | blocked / alerted | 0.9% / 0.1% | `web`, `intrusion_detection` |
| `Illegal query string length` | Illegal query string length | blocked / alerted | 0.8% / 0.1% | `web`, `intrusion_detection` |

About 33,000 events per 126 hours (6,300 per day) with the defaults (one event per second at most, diurnal load by UTC hour). Background is a mix of independent random processes:

- Browsing sessions: a client picked by a skewed per-client weight opens a session on one application and requests 1-60 URIs with lognormal gaps. Backend status codes 403, 409 and 500 raise `Illegal HTTP status in response` (alerted). About 0.6% of dynamic requests trip a violation (blocked or alerted); a blocked client often retries the same URI within a minute or two, and the retry is blocked again or passes.
- Automated attack bursts (about 1 per 15 minutes, mildly diurnal): a client attacks one to six URIs of an application with signature and violation payloads and probes for files that do not exist (`Illegal URL`). About a third of the attacked URIs also get one plain request, usually early in the sequence (position k among the payloads with weight 0.55^k).

Blocked requests carry `cn1=0`; passed and alerted requests carry the backend status. `externalId` (support ID) grows by random steps; `suid` is shared by the requests of one session or burst.

## Anomaly Chain

**Sequence.** One client sends requests to one URI of one virtual server that are blocked for three or four distinct violations (SQL injection, XSS, wget client, oversized query string, IP address in the Host header, in random order, with up to two repeats), then a plain request from the same client to the same URI passes with status 200. The request pattern reads as payload cycling until one request gets through.

**Linking fields.** `source.ip`, `destination.ip` (virtual server), `url.path`, distinct `event.code` values with `event.action: blocked`, then `event.action: passed`; `f5.asm.session_id` is shared inside the episode.

**Recurrence.** `anomaly_interval_hours` (default 24, minimum 2, maximum 8760). The first start falls within the first min(interval, 24 h) of the run, at a time drawn with the background hour-of-day load. Each later start is drawn in a window centred on the due time (actual previous start + interval), width w = min(interval / 4, 6 h), weighted by load squared plus a small floor, so episodes stay in busy hours; consecutive starts are therefore interval ± w/2 apart. There is no catch-up. At intervals of 8 h or less the window is narrow and the start phase necessarily drifts around the clock. Measured (126 h): default 5 chains with start gaps 23.0-26.8 h, starts 08-15 UTC; 12 h interval 11 chains, gaps 10.7-13.3 h. The measured start is the first matching blocked request, which may be an earlier background block of the same client on that URI.

**Variation.** Each episode takes its client, virtual server and URI from recent ordinary traffic, so the client and the client-server-URI combination also occur in background; client and target differ from the previous episode. Violation codes are drawn with the background weights; gaps follow the same law as background attack bursts. Measured spans of the matched chain: 25-79 s (default) and 12-51 s (12 h interval).

**Background overlap.** Ordinary traffic in both modes contains every chain feature: repeated blocks by one client within a minute (about 1,800 per 126 h), blocked requests that complete three or more distinct violations by one client on one URI within 30 minutes (about 600-670), and a passed request after one or two distinct blocks on that URI (about 8% and 6% of those blocks are followed within a minute by a pass on the same URI). After a block with two versus three or more distinct violations on the URI, the client's next request within a minute is another violation on that URI in about 61% versus 61% of cases and goes to another URI in about 15% versus 17%. Only the complete ordered chain is kept out of background. Because plain requests come early in an attack sequence, a pass right after three distinct blocks is already rare; when an ordinary passed request would still follow three or more distinct blocks by the same client on the same URI within 30 minutes, it keeps its URI and time and trips one of those violations again (blocked at the ordinary 88% attack share, otherwise alerted).

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
| `client_count` | `360` | Client addresses in 198.51.100.0/24 and 192.0.2.0/24 (50-480) |
| `virtual_servers` | 4 servers | Host name, address, port (80 or 443), ASM policy name, traffic weight and URI list (method, path, query template with `{n}` or `{q}`, weight) |
| `forceful_paths` | 8 paths | Non-existent paths probed by attack bursts |
| `search_terms` | 10 terms | Values for the `{q}` query placeholder |

### Output Parameters

The shipped `generator.yml` writes to `output/events.json` and needs no credentials. To send events to a SIEM, replace the `output` block and use top-level placeholders for the endpoint and credentials, for example `hosts: ["${params.opensearch_host}"]` and `password: ${secrets.opensearch_password}`, then pass them at run time.

## Usage

Live mode:

```bash
eventum generate --path generators/web-f5-advanced-waf/generator.yml --id web-f5-advanced-waf --live-mode true
```

Batch sample (add `start` and `end` to the `cron` input to bound the time range):

```bash
eventum generate --path generators/web-f5-advanced-waf/generator.yml --id web-f5-advanced-waf --live-mode false
```

## Sample Output

A blocked request from the default-on capture (second step of an episode):

```json
{"@timestamp": "2026-09-26T08:59:12+00:00", "destination": {"ip": "203.0.113.12", "port": 443}, "ecs": {"version": "8.17.0"}, "event": {"action": "blocked", "category": ["web", "intrusion_detection"], "code": "200002273", "dataset": "f5.asm", "kind": "alert", "original": "\u003c131\u003eSep 26 08:59:13 bigip-waf-01.example.com ASM:CEF:0|F5|ASM|11.3.0|200002273|SQL-INJ exec()|5|dvchost=bigip-waf-01.example.com dvc=10.60.0.5 cs1=partner-portal cs1Label=policy_name cs2=/Common/partner-portal cs2Label=http_class_name deviceCustomDate1=Sep 17 2026 14:33:52 deviceCustomDate1Label=policy_apply_date externalId=13481800479857545456 act=blocked cn1=0 cn1Label=response_code src=192.0.2.241 spt=44054 dst=203.0.113.12 dpt=443 requestMethod=GET app=HTTPS cs5=N/A cs5Label=x_forwarded_for_header_value rt=Sep 26 2026 08:59:12 deviceExternalId=0 cs4=SQL-Injection cs4Label=attack_type cs6=GB cs6Label=geo_location c6a1= c6a1Label=device_address c6a2= c6a2Label=source_address c6a3= c6a3Label=destination_address c6a4=N/A c6a4Label=ip_address_intelligence msg=N/A suid=ae658d149e4cc25d suser=N/A request=/documents?id\\=1;exec(char(0x73656c656374)) cs3Label=full_request cs3=GET /documents?id\\=1;exec(char(0x73656c656374)) HTTP/1.1\\r\\nHost: partners.example.com\\r\\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36\\r\\nAccept: text/html,application/xhtml+xml,application/xml;q\\=0.9,*/*;q\\=0.8\\r\\nAccept-Language: en-US,en;q\\=0.9\\r\\nAccept-Encoding: gzip, deflate, br\\r\\nConnection: keep-alive\\r\\n\\r\\n", "outcome": "failure", "severity": 5, "type": ["access", "denied"]}, "f5": {"asm": {"attack_type": "SQL-Injection", "http_class_name": "/Common/partner-portal", "policy_apply_date": "Sep 17 2026 14:33:52", "policy_name": "partner-portal", "request_status": "blocked", "response_code": 0, "session_id": "ae658d149e4cc25d", "support_id": "13481800479857545456"}}, "http": {"request": {"method": "GET"}}, "network": {"protocol": "https"}, "observer": {"ip": ["10.60.0.5"], "name": "bigip-waf-01.example.com", "product": "ASM", "type": "waf", "vendor": "F5", "version": "11.3.0"}, "related": {"ip": ["192.0.2.241", "203.0.113.12"]}, "rule": {"id": "200002273", "name": "SQL-INJ exec()"}, "source": {"geo": {"country_iso_code": "GB"}, "ip": "192.0.2.241", "port": 44054}, "url": {"original": "/documents?id=1;exec(char(0x73656c656374))", "path": "/documents", "query": "id=1;exec(char(0x73656c656374))"}, "user_agent": {"original": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"}}
```

## Limitations

- The layout is the ASM 11.3.0 CEF request message as published by F5 (Successful Request and signature examples). Headers for non-signature violations follow the 10.1.0 ArcSight guide example and third-party 11.6.1 and 15.1 raw logs; severities 5 and 2 and the syslog PRI mapping (`<131>` for severity 5, `<134>` otherwise) are inferred from those examples. Newer releases (14.x and later) add keys such as `violation_rating` and `microservice`, which are not modelled.
- One violation per request; multi-violation requests, `violation_details`, brute force, web scraping, DoS and bot defense messages, request bodies and XFF values are not modelled. `geo_location` is a synthetic country code per client.
- Signature IDs are limited to three documented ones (200002273, 200000098, 200021069). Rates, weights, sessions and payloads are synthetic; all times are UTC with whole-second resolution, as in `rt`.
- The syslog header time equals `rt` or is one second later, as in the vendor examples. The day is space-padded per RFC 3164.
- Episodes are weighted to busy hours more strongly than background (load squared); the chain actor is taken from recent traffic, so its per-actor weighting follows background request volume rather than attack-burst weighting.
- SIEM parser compatibility (for example KUMA or Elastic CEF) has not been tested.

## References

- [F5 External Monitoring of BIG-IP Systems: Implementations - event messages and ASM CEF examples](https://techdocs.f5.com/en-us/bigip-15-0-0/external-monitoring-of-big-ip-systems-implementations/event-messages-and-attack-types.html)
- [F5 BIG-IP ASM: logging application security events](https://techdocs.f5.com/en-us/bigip-17-5-0/big-ip-asm-implementations/logging-application-security-events.html)
- [ArcSight F5 ASM Certified CEF Configuration Guide examples, as Graylog CEF test fixtures](https://github.com/Graylog2/graylog2-server/tree/master/graylog2-server/src/test/resources/fixtures)
- [Wazuh F5 BIG-IP ruleset tests with ASM 14.1.2 CEF logs](https://github.com/wazuh/wazuh/blob/master/ruleset/testing/tests/f5_big_ip.ini)
