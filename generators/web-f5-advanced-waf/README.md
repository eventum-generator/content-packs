# F5 BIG-IP ASM / Advanced WAF CEF

Eventum content pack for F5 application-security request logs in the vendor's ArcSight CEF profile. It uses the complete ASM 11.3.0 CEF examples published in F5's BIG-IP documentation. Output is ECS JSON with the native syslog CEF line in `event.original`. `anomaly_mode: true` is the default; `false` emits background only.

## Run

From the content-packs repository root:

```bash
eventum generate --path generators/web-f5-advanced-waf/generator.yml --id web-f5-advanced-waf --live-mode true
```

For a bounded batch sample, use `timeout 3s eventum generate --path generators/web-f5-advanced-waf/generator.yml --id web-f5-advanced-waf-batch --live-mode false`. Exit code 124 is expected for this continuous source. Events go to `generators/web-f5-advanced-waf/output/events.json`.

## Events

| CEF event class | Meaning | Routine distribution | ECS category |
| --- | --- | --- | --- |
| `Successful Request` | Request passed the policy | 93%; one per chain | `web` |
| `200021069` | Automated-client signature request blocked | 7%; two per chain | `web` |

These percentages are synthetic workload weights. The CEF `externalId` is unique per request; it is a support ID, not a session identifier.

## Anomaly Chain

The same source requests `/admin/export` twice with a wget user agent and is blocked under signature `200021069`. A third request to the same URI from that source, now with a browser user agent, is passed by the same policy. Correlate `source.ip`, `destination.ip`, `url.path`, policy name and a short time window. This can suggest a client fingerprint change after WAF blocks; a passed request alone does not prove evasion or data access. Sort by `@timestamp` when reconstructing the sequence because output line order is not guaranteed.

The generator is pinned to the F5-published ASM 11.3.0 CEF message layout. F5's 17.5 manual confirms CEF remote logging remains an option, but the 17.5 extension field layout has not been verified against this older sample. KUMA 4.2 lists F5 Advanced WAF with a syslog regexp normalizer, not a guaranteed match for this CEF profile. Use a suitable CEF parser for `event.original` and verify mapping on a target SIEM before claiming parser compatibility. The generator does not model policy changes, bot-defense events, or the local `/var/log/asm` format.

## Parameters

### Event Parameters

| Parameter | Default | Meaning |
| --- | --- | --- |
| `device_name` | `bigip-waf-01.corp.example` | Syslog sender and ECS host |
| `device_ip` | `10.60.0.5` | BIG-IP management address |
| `device_version` | `11.3.0` | Documented CEF Device Version profile |
| `policy_name` | `corporate-web` | ASM security policy |
| `policy_class` | `/Common/corporate-web` | CEF HTTP classifier |
| `virtual_server_ip` | `10.60.20.15` | Protected virtual server |
| `anomaly_mode` | `true` | Add blocked-to-passed chain; `false` emits background only |
| `anomaly_interval_events` | `250` | Routine requests between chains |
| `attack_source_ip` | `10.60.9.77` | Stable chain source |

### Output Parameters

No top-level `${params.*}` or `${secrets.*}` placeholders are shipped. Local file output requires no credentials. Replace the `output` block to forward to a SIEM, then configure its endpoint and credentials there.

## Sample output

This complete event was captured from an `anomaly_mode: true` run:

```json
{
  "@timestamp": "2026-09-25T13:31:27+00:00",
  "destination": {
    "ip": "10.60.20.15",
    "port": 443
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "request-blocked",
    "category": [
      "web"
    ],
    "code": "200021069",
    "dataset": "f5.asm",
    "kind": "alert",
    "original": "<131>Sep 25 13:31:27 bigip-waf-01.corp.example ASM:CEF:0|F5|ASM|11.3.0|200021069|Automated client access \"wget\"|5|dvchost=bigip-waf-01.corp.example dvc=10.60.0.5 cs1=corporate-web cs1Label=policy_name cs2=/Common/corporate-web cs2Label=http_class_name externalId=18205860747014045251 act=blocked cn1=0 cn1Label=response_code src=10.60.9.77 spt=50002 dst=10.60.20.15 dpt=443 requestMethod=GET app=HTTPS deviceCustomDate1=Sep 01 2026 00:00:00 deviceCustomDate1Label=policy_apply_date cs5=N/A cs5Label=x_forwarded_for_header_value rt=Sep 25 2026 13:31:27 deviceExternalId=0 cs4=Non-browser Client cs4Label=attack_type cs6=N/A cs6Label=geo_location c6a1= c6a1Label=device_address c6a2= c6a2Label=source_address c6a3= c6a3Label=destination_address c6a4=N/A c6a4Label=ip_address_intelligence msg=N/A suid=cd2a715fedcbbee6 suser=N/A request=/admin/export cs3Label=full_request cs3=GET /admin/export HTTP/1.1\\r\\nHost: app.corp.example\\r\\nUser-Agent: Wget/1.21\\r\\n\\r\\n",
    "outcome": "failure",
    "type": [
      "denied"
    ]
  },
  "f5": {
    "asm": {
      "attack_type": "Non-browser Client",
      "http_class_name": "/Common/corporate-web",
      "policy_name": "corporate-web",
      "request_status": "blocked",
      "support_id": 18205860747014045251
    }
  },
  "host": {
    "ip": [
      "10.60.0.5"
    ],
    "name": "bigip-waf-01.corp.example"
  },
  "http": {
    "request": {
      "method": "GET"
    },
    "response": {
      "status_code": 0
    }
  },
  "related": {
    "ip": [
      "10.60.9.77",
      "10.60.20.15"
    ]
  },
  "source": {
    "ip": "10.60.9.77",
    "port": 50002
  },
  "url": {
    "path": "/admin/export"
  }
}
```

## References

- [F5 ASM CEF passed and blocked request examples](https://techdocs.f5.com/en-us/bigip-15-0-0/external-monitoring-of-big-ip-systems-implementations/event-messages-and-attack-types.html)
- [F5 17.5 application-security logging and CEF export option](https://techdocs.f5.com/en-us/bigip-17-5-0/big-ip-asm-implementations/logging-application-security-events.html)
- [KUMA 4.2 supported event sources](https://support.kaspersky.ru/kuma/4.2/255782)
