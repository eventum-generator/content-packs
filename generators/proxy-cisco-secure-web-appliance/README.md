# Cisco Secure Web Appliance access log

Synthetic standard access-log entries for Cisco Secure Web Appliance (WSA), using the field order and result codes illustrated in the AsyncOS 15.2 guide.

## Event Types

| Action | Baseline weight | Result |
| --- | ---: | --- |
| `proxy-miss` | 80% | `TCP_MISS/200` |
| `proxy-hit` | 15% | `TCP_HIT/200` |
| `proxy-denied` | 5% | `TCP_DENIED/403` |

Weights describe synthetic background traffic, not measured WSA usage. The template plugin uses `fsm` for the denial-and-retry sequence.

## Anomaly Chain

A client receives three `TCP_DENIED/403` responses with a `BLOCK_WEBCAT` decision for `/tools/agent.bin` on `blocked-download.example.test`, then receives `TCP_MISS/200` for the same path on `cdn.example.test`. Correlate client IP, path, and time. A rule can flag a denied resource followed by a successful fetch through another domain. Equal path names do not prove identical file content; confirm with hashes or endpoint telemetry when available. Sort by `@timestamp` before sequence matching because output line order is not guaranteed.

`event.template.params.anomaly_mode` defaults to `true`. Set it to `false` for ordinary allowed and denied proxy traffic only.

## Parameters

### Event Parameters

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include the denied-then-alternate-fetch sequence |
| `host_name` | `swa-01.example.test` | Appliance name |
| `suspect_ip` | `192.0.2.72` | Client IP used by the sequence |
| `blocked_domain` | `blocked-download.example.test` | Denied URL host |
| `alternate_domain` | `cdn.example.test` | Allowed alternate URL host |
| `target_path` | `/tools/agent.bin` | Common path used by the sequence |

### Output Parameters

The shipped configuration writes `output/events.json` with no connection parameters or secrets. To send events to a SIEM, replace the file output in a local copy and use `${params.siem_host}` and `${secrets.siem_token}` as required by the selected output plugin.

## Usage

```bash
eventum generate --path generators/proxy-cisco-secure-web-appliance/generator.yml --id swa --live-mode false
eventum generate --path generators/proxy-cisco-secure-web-appliance/generator.yml --id swa --live-mode true
```

## Sample Output

Copied from an `anomaly_mode: true` run:

```json
{
  "@timestamp": "2026-09-25T13:29:24+00:00",
  "cisco": {
    "swa": {
      "acl_decision_tag": "DEFAULT_CASE_11-DefaultGroup-DefaultGroup-NONE-NONE-DefaultRouting-NONE",
      "elapsed_ms": 131,
      "hierarchy": "DIRECT/cdn.example.test",
      "mime_type": "application/octet-stream",
      "result_code": "TCP_MISS",
      "scan_verdict": "<IW_comp,6.9,-,\"-\",-,-,-,-,\"-\",-,-,-,\"-\",-,-,\"-\",\"-\",-,-,IW_comp,-,\"-\",\"-\",\"Unknown\",\"Unknown\",\"-\",\"-\",198.34,0,-,[Local],\"-\",37,\"-\",33,0,\"-\",\"-\">"
    }
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "proxy-miss",
    "category": [
      "web"
    ],
    "kind": "event",
    "original": "1790342964.000 131 192.0.2.72 TCP_MISS/200 7402 GET http://cdn.example.test/tools/agent.bin - DIRECT/cdn.example.test application/octet-stream DEFAULT_CASE_11-DefaultGroup-DefaultGroup-NONE-NONE-DefaultRouting-NONE <IW_comp,6.9,-,\"-\",-,-,-,-,\"-\",-,-,-,\"-\",-,-,\"-\",\"-\",-,-,IW_comp,-,\"-\",\"-\",\"Unknown\",\"Unknown\",\"-\",\"-\",198.34,0,-,[Local],\"-\",37,\"-\",33,0,\"-\",\"-\"> -",
    "outcome": "success",
    "type": [
      "access"
    ]
  },
  "host": {
    "name": "swa-01.example.test"
  },
  "http": {
    "request": {
      "method": "GET"
    },
    "response": {
      "body": {
        "bytes": 7402
      },
      "status_code": 200
    }
  },
  "network": {
    "protocol": "http"
  },
  "related": {
    "ip": [
      "192.0.2.72"
    ]
  },
  "source": {
    "ip": "192.0.2.72"
  },
  "url": {
    "domain": "cdn.example.test",
    "full": "http://cdn.example.test/tools/agent.bin",
    "path": "/tools/agent.bin",
    "scheme": "http"
  }
}
```

## Coverage and Limits

The selected standard access-log fields are present in `event.original`: Unix timestamp, elapsed time, client IP, result/HTTP status, response bytes, request method and URL, username placeholder, hierarchy/origin, MIME type, ACL decision tag, scanning verdict, and optional user-agent placeholder. The generator uses `-` for absent authenticated usernames and user agents. Scan-verdict tokens are representative values following Cisco's sample layout; policy names and verdict details vary by subscription and deployment. This models standard HTTP access logs, not W3C or decrypted HTTPS logs. KUMA 4.2 lists WSA file normalizers for AsyncOS 14.2 and 15.0 with a specified subscription template; this pack follows an AsyncOS 15.2 guide example, so direct normalizer compatibility is unverified.

## References

- [Cisco AsyncOS 15.2 standard access-log fields and sample](https://www.cisco.com/c/en/us/td/docs/security/wsa/wsa-15-2/user-guide/swa-userguide-15-2/m-monitoring-troubleshooting.html)
- [Cisco AsyncOS 15.2 blocked access-log example](https://www.cisco.com/c/en/us/td/docs/security/wsa/wsa-15-2/user-guide/swa-userguide-15-2/m-network-security.html)
- [KUMA 4.2 source catalog](https://support.kaspersky.ru/kuma/4.2/255782)
