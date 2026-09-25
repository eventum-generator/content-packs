# Solar webProxy SIEM log

Synthetic Solar webProxy 4.3.1 request events in the vendor-documented `siem-log` syslog format. This pack models web filtering decisions and traffic sizes, not administrator audit or policy-change logs.

## Event types

| Action | Approximate share with anomaly mode | ECS category | Meaning |
| --- | ---: | --- | --- |
| `http-allowed` | 83.7% | `web` | Filtered web request allowed (HTTP 200) |
| `http-denied` | 16.3% | `web` | Web request blocked (HTTP 403) |

The template uses FSM mode and emits one event per 30 simulated seconds from one proxy. Background-only mode has about 87.5% allowed and 12.5% blocked requests. These weights are scenario choices; Solar does not publish fleet-wide ratios.

## Anomaly Chain

With `anomaly_mode: true` (the default), `ivan` at `10.20.4.23` makes two blocked GET requests to `fileshare.example.test/restricted`, then sends a 12 MiB POST to `uploads.example.test/ingest` within 90 seconds. A detection can group by `host.name`, `user.name`, and `source.ip`, sort by `@timestamp`, and look for the two 403 decisions followed by a large allowed `source.bytes` value to another destination. File row order is not the detection clock. With `anomaly_mode: false`, only routine requests by `anna` are emitted; `ivan` and the linked sequence are absent.

This is suspicious temporal correlation, not proof that the POST contains the blocked resource or that a policy changed. The log format records request and filter decisions, not the uploaded content. The event values and domains are synthetic.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include the linked blocked-request-to-upload sequence; `false` produces background only |
| `proxy_host` | `webproxy-01` | Syslog host name |
| `account_domain` | `CORP` | Account domain in `acc-domain` |
| `ordinary_user` | `anna` | Background account |
| `ordinary_ip` | `10.20.4.41` | Background client address |
| `suspect_user` | `ivan` | Account in the anomaly chain |
| `suspect_ip` | `10.20.4.23` | Client address in the anomaly chain |
| `ordinary_destination_ip` | `192.0.2.10` | Destination address for allowed background requests |
| `blocked_destination_ip` | `192.0.2.20` | Destination address for blocked requests |
| `upload_destination_ip` | `192.0.2.30` | Destination address for chain POST requests |

### Output Parameters

No top-level `${params.*}` or `${secrets.*}` are required. Output defaults to `output/events.json`; edit the file output section to deliver events elsewhere.

## Usage

From the content-packs repository:

```bash
eventum generate --path generators/proxy-solar-webproxy/generator.yml --id solar --live-mode false
```

For continuous generation, use `--live-mode true`. Set `event.template.params.anomaly_mode` to `false` for background only. The file output is overwritten when a run starts.

## Sample output

This JSON event was copied from an anomaly-mode run, not handwritten:

```json
{
  "@timestamp": "2026-09-25T14:28:00+00:00",
  "destination": {
    "bytes": 2048,
    "ip": "192.0.2.30",
    "port": 443
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "http-allowed",
    "category": [
      "web"
    ],
    "kind": "event",
    "original": "Sep 25 14:28:00 webproxy-01 java: [acc-domain:CORP] [acc-groups:Employees] [acc-ip:10.20.4.23] [acc-name:ivan] [acc-port:54721] [bytes-in:2048] [bytes-out:12582912] [flt-categories:0] [flt-codes:11,0,0,0] [flt-policy:Standard web access] [flt-rules:https,web-filter] [flt-status:200] [flt-time:8] [req-hostname:uploads.example.test] [req-method:POST] [req-pathname:/ingest] [req-protocol:https] [req-query:] [req-referer:] [req-time:2026-09-25T14:28:00.000Z] [req-user-agent:Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36] [res-datatype:application/json] [res-ip:192.0.2.30] [traf-mode:forward] [req-port:443] [flt-reason:]",
    "outcome": "success",
    "type": [
      "access"
    ]
  },
  "host": {
    "name": "webproxy-01"
  },
  "http": {
    "request": {
      "method": "POST"
    },
    "response": {
      "status_code": 200
    }
  },
  "related": {
    "ip": [
      "10.20.4.23",
      "192.0.2.30"
    ],
    "user": [
      "ivan"
    ]
  },
  "solar_webproxy": {
    "account_groups": "Employees",
    "filter_codes": "11,0,0,0",
    "filter_policy": "Standard web access",
    "filter_reason": "",
    "filter_rules": "https,web-filter",
    "filter_time_ms": 8,
    "request_time": "2026-09-25T14:28:00.000Z",
    "response_mime_type": "application/json",
    "traffic_mode": "forward"
  },
  "source": {
    "bytes": 12582912,
    "ip": "10.20.4.23",
    "port": 54721
  },
  "url": {
    "domain": "uploads.example.test",
    "full": "https://uploads.example.test/ingest",
    "path": "/ingest",
    "scheme": "https"
  },
  "user": {
    "domain": "CORP",
    "name": "ivan"
  },
  "user_agent": {
    "original": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36"
  }
}
```

## Format and coverage

`event.original` uses the `siem-log` bracketed key-value syntax and syslog-ng header in Solar's 4.3.1 manual. The vendor's raw 403 example and field table define the format. The pack emits the header and all 26 named key-value fields present in that example. It omits the optional `[x-virus-id]` marker (26/27 named fields, 96.3% coverage), because the modeled events contain no ICAP antivirus detection. The HTTP 200 and POST values are synthetic instances of that documented field schema; they are not captured vendor lines. Filter codes and policy names are scenario values, not decoded vendor policy semantics.

The 4.3.1 manual is the format reference. KUMA 4.2 lists a Solar webProxy `siem-log` normalizer for product version 4.2; this pack's compatibility with that normalizer has not been tested. The chosen format requires the product's SIEM syslog logging option. Variations in deployment, policy and syslog relay configuration can change the emitted header or optional fields.

## References

- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)
- [Solar webProxy 4.3.1 installation and configuration manual, `siem-log` field table and sample](https://rt-solar.ru/products/solar_webproxy/doc/solar-webproxy-rukovodstvo-po-nastroyke-i-ustanovke-431-astra.pdf)
- [Solar webProxy syslog format options](https://rt-solar.ru/products/solar_webproxy/specifications/)
