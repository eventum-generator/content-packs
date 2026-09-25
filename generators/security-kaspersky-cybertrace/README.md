# Kaspersky CyberTrace ArcSight CEF

Indicator-match events using the documented CyberTrace for ArcSight CEF pattern. Eventum writes ECS JSON and preserves the native CEF record in `event.original`.

## Event types

| Detection category | Meaning | Approximate background frequency |
| --- | --- | --- |
| `KL_Malicious_URL` | Malicious URL match | 65% |
| `KL_Phishing_URL` | Phishing URL match | 25% |
| `KL_Malicious_Hash_MD5` | Malicious MD5 match | 10% |

These are synthetic scenario weights, not production measurements. The CEF signature `2` is the documented CyberTrace Detection Event for all three categories; the category is in `reason`.

## Anomaly Chain

After 60 routine records, one endpoint and user produce a malicious URL match, a malicious MD5 match, and a repeat of the same URL match. Correlate by CEF `src` and `suser`, then compare `cs5` and `reason` over the time window. This supports a rule for multiple indicator categories followed by renewed contact with the first URL.

`anomaly_mode: true` is the default and mixes the sequence with background. Set it to `false` for background only. Sort by `@timestamp` when checking the sequence; concurrent output may reorder lines.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`.

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Enable the multi-indicator chain. |
| `anomaly_interval_events` | `60` | Routine records between chains. |
| `target_endpoint_ip` | `192.0.2.44` | Endpoint for all chain matches. |
| `target_user` | `operator` | User for all chain matches. |
| `target_url` | `https://malware.example.test/dropper` | Repeated URL indicator. |
| `target_md5` | `C912705B4BBB14EC7E78FA8B370532C9` | MD5 indicator. |

### Output Parameters

The shipped file output needs no overrides. Replace `output.file` with another output plugin and use top-level `${params.*}` or `${secrets.*}` substitutions for destination settings when needed.

## Usage

From the content-packs repository:

```bash
eventum generate --path generators/security-kaspersky-cybertrace/generator.yml --id cybertrace --live-mode false
eventum generate --path generators/security-kaspersky-cybertrace/generator.yml --id cybertrace --live-mode true
```

Output: `generators/security-kaspersky-cybertrace/output/events.json`. Extract `event.original` for a collector that expects raw CEF.

## Sample output

Copied from an actual anomaly-mode run:

```json
{
  "@timestamp": "2026-09-25T13:21:05+00:00",
  "destination": {
    "ip": "198.51.100.10"
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "indicator_match",
    "category": [
      "threat"
    ],
    "code": "KL_Malicious_URL",
    "dataset": "kaspersky.cybertrace",
    "kind": "alert",
    "original": "CEF:0|Kaspersky Lab|Kaspersky CyberTrace for ArcSight|2.0|2|CyberTrace Detection Event|8| reason=KL_Malicious_URL dst=198.51.100.10 src=192.0.2.44 fileHash=- request=https://malware.example.test/dropper sourceServiceName=ExampleVendor sproc=EndpointSecurity suser=operator msg=CyberTrace detected KL_Malicious_URL externalId=10060 cs5Label=MatchedIndicator cs5=https://malware.example.test/dropper cs6Label=Context cs6=feed=Example_Feed.json",
    "type": [
      "indicator"
    ]
  },
  "kaspersky": {
    "cybertrace": {
      "external_id": 10060,
      "feed": "Example_Feed.json",
      "matched_indicator": "https://malware.example.test/dropper"
    }
  },
  "related": {
    "ip": [
      "192.0.2.44",
      "198.51.100.10"
    ],
    "user": [
      "operator"
    ]
  },
  "source": {
    "ip": "192.0.2.44"
  },
  "user": {
    "name": "operator"
  }
}
```

## Scope and validation

The selected CEF pattern fields are covered 21/21, including the seven header segments and fourteen populated extension keys. Configurable actionable fields are omitted. Both modes were parsed and checked for the complete chain or its absence.

KUMA 4.2 lists a CyberTrace regexp normalizer. This pack uses Kaspersky's ArcSight CEF pattern; compatibility with that regexp normalizer is not established. Use a suitable CEF parser or adapt the CyberTrace event pattern to the target SIEM.

## References

- [Kaspersky CyberTrace event format patterns](https://support.kaspersky.com/cybertrace/2020/en-us/197106.htm)
- [Kaspersky CyberTrace detection categories](https://support.kaspersky.com/cybertrace/2020/en-us/171634.htm)
- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)
