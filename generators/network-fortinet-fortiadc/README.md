# Fortinet FortiADC 7.1 SLB HTTP traffic

Eventum content pack for FortiADC 7.1 `traffic/slb_http` key-value records. Each event is ECS JSON with the complete native line in `event.original`. `anomaly_mode: true` is the default; `false` produces background only.

## Run

From the content-packs repository root:

```bash
eventum generate --path generators/network-fortinet-fortiadc/generator.yml --id network-fortinet-fortiadc --live-mode true
```

For a bounded sample, run `timeout 3s eventum generate --path generators/network-fortinet-fortiadc/generator.yml --id network-fortinet-fortiadc-batch --live-mode false`. Exit code 124 is expected for this continuous source. Output is written to `generators/network-fortinet-fortiadc/output/events.json`.

## Events

| ID | Meaning | Background frequency | ECS category |
| --- | --- | --- | --- |
| `0101008001` | HTTP request routed through a virtual server | 100%; responses are about 82% 200, 8% 301, 8% 404, 2% 500 | `web` |

The response mix and three-step injection interval are synthetic workload settings, not measured FortiADC rates. The 37 native fields in the FortiADC 7.1 vendor traffic sample are present in the generated record. The pack covers one HTTP virtual server and three real servers. It does not model HTTPS, WAF/DoS alerts, administrative logs, or syslog transport headers. Send `event.original` via syslog when exercising KUMA's native FortiADC KV normalizer; the shipped file is an ECS JSON envelope.

## Anomaly Chain

A single client, `10.41.9.77`, requests `/admin` three times through `vs_web` at `10.41.20.15`. FortiADC routes the requests to `app01`, `app02`, and `app03`, which return 404, 403, and 200 respectively. Correlate `source.ip`, `destination.ip`, `fortinet.fortiadc.policy`, `url.path`, `fortinet.fortiadc.real_server`, and `@timestamp` to detect inconsistent path exposure across backends. A 200 response only records an HTTP result; it does not establish authentication or data access. Sort by `@timestamp`; file-line order is not guaranteed under concurrent generation.

`anomaly_mode: false` keeps ordinary HTTP traffic but never uses the chain source or `/admin` path.

## Parameters

### Event Parameters

| Parameter | Default | Meaning |
| --- | --- | --- |
| `device_name` | `fortiadc-01.example.test` | ECS host name of the ADC |
| `virtual_server` | `vs_web` | Native `policy` value |
| `virtual_ip` | `10.41.20.15` | Stable virtual-server destination |
| `anomaly_mode` | `true` | Include the chain; `false` emits background only |
| `anomaly_interval_events` | `80` | Routine pairs between chain injections |
| `probe_source_ip` | `10.41.9.77` | Stable chain source |

### Output Parameters

No top-level `${params.*}` or `${secrets.*}` placeholders are shipped. File output works without credentials. For SIEM delivery, replace the `output` block with a suitable plugin and configure its endpoint there.

## Sample output

This complete anomaly event was captured from a run with `anomaly_mode: true`:

```json
{
  "@timestamp": "2026-09-25T13:50:19+00:00",
  "destination": {
    "ip": "10.41.20.15",
    "port": 80
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "slb-http-response",
    "category": [
      "web"
    ],
    "code": "0101008001",
    "dataset": "fortinet_fortiadc.log",
    "kind": "event",
    "original": "date=2026-09-25 time=13:50:19 log_id=0101008001 type=traffic subtype=slb_http pri=information vd=root msg_id=39233960 duration=2 ibytes=337 obytes=586 proto=6 service=http src=10.41.9.77 src_port=59614 dst=10.41.20.15 dst_port=80 trans_src=10.41.30.1 trans_src_port=29613 trans_dst=10.41.30.11 trans_dst_port=80 policy=vs_web action=none http_method=get http_host=10.41.20.15 http_agent=curl/8.0 http_url=/admin http_qry=none http_referer=none http_cookie=none http_retcode=404 user=none usrgrp=none auth_status=none srccountry=Reserved dstcountry=Reserved real_server=app01",
    "type": [
      "access"
    ]
  },
  "fortinet": {
    "fortiadc": {
      "action": "none",
      "auth_status": "none",
      "date": "2026-09-25",
      "dst": "10.41.20.15",
      "dst_port": 80,
      "dstcountry": "Reserved",
      "duration": 2,
      "http_agent": "curl/8.0",
      "http_cookie": "none",
      "http_host": "10.41.20.15",
      "http_method": "get",
      "http_qry": "none",
      "http_referer": "none",
      "http_retcode": 404,
      "http_url": "/admin",
      "ibytes": 337,
      "log_id": "0101008001",
      "msg_id": 39233960,
      "obytes": 586,
      "policy": "vs_web",
      "pri": "information",
      "proto": 6,
      "real_server": "app01",
      "service": "http",
      "src": "10.41.9.77",
      "src_port": 59614,
      "srccountry": "Reserved",
      "subtype": "slb_http",
      "time": "13:50:19",
      "trans_dst": "10.41.30.11",
      "trans_dst_port": 80,
      "trans_src": "10.41.30.1",
      "trans_src_port": 29613,
      "type": "traffic",
      "user": "none",
      "usrgrp": "none",
      "vd": "root"
    }
  },
  "host": {
    "name": "fortiadc-01.example.test"
  },
  "http": {
    "request": {
      "method": "GET"
    },
    "response": {
      "status_code": 404
    }
  },
  "network": {
    "protocol": "http",
    "transport": "tcp"
  },
  "related": {
    "ip": [
      "10.41.9.77",
      "10.41.20.15",
      "10.41.30.11"
    ]
  },
  "source": {
    "ip": "10.41.9.77",
    "port": 59614
  },
  "url": {
    "path": "/admin"
  }
}
```

## References

- [FortiADC 7.1.0 log reference: raw event and traffic records](https://docs.fortinet.com/document/fortiadc/7.1.0/log-reference/378226/anatomy-of-a-log-message)
- [KUMA 4.2 supported event sources: FortiADC 7.1 KV syslog](https://support.kaspersky.ru/kuma/4.2/255782)
