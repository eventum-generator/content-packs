# Fortinet FortiPAM Secret Events

FortiPAM secret-request and clear-text-view key-value logs based on Fortinet's published raw examples. Eventum writes ECS JSON and preserves the native message body in `event.original`.

## Event types

| Log ID | Action | Approximate background frequency | ECS category |
| --- | --- | --- | --- |
| `2304064604` | Secret request created | 30% | iam |
| `2303064603` | Clear-text view allowed | 70% | iam |

Weights are synthetic scenario choices, not measured production frequencies.

## Anomaly Chain

After 60 routine records, the same user creates a request for one privileged secret and views its clear text three times within a short window. Correlate by `user`, `secretid`, `secret`, and `account`; use each log's `uuid` only as its event identifier. A rule can flag repeated clear-text exposure shortly after a request.

The request and views do not prove approval bypass or misuse. The raw examples do not provide an approval decision, so this chain makes no such claim.

`anomaly_mode: true` is the default and mixes the sequence with background. Set it to `false` for background only. Sort by `@timestamp` when checking the sequence; concurrent output may reorder lines.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`.

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Enable the repeated-view chain. |
| `anomaly_interval_events` | `60` | Routine records between chains. |
| `device_name` | `FPAVULTM1234567` | FortiPAM source name. |
| `target_user` | `operator` | Chain user. |
| `target_secret_id` | `2820` | Chain secret ID. |
| `target_secret` | `prod-vault` | Chain secret name. |
| `target_account` | `svc-admin` | Privileged account. |
| `target_ip` | `10.20.30.15` | View target. |

### Output Parameters

The shipped file output needs no overrides. Replace `output.file` with another output plugin and use top-level `${params.*}` or `${secrets.*}` substitutions for destination settings when needed.

## Usage

From the content-packs repository:

```bash
eventum generate --path generators/identity-fortinet-fortipam/generator.yml --id fortipam --live-mode false
eventum generate --path generators/identity-fortinet-fortipam/generator.yml --id fortipam --live-mode true
```

Output: `generators/identity-fortinet-fortipam/output/events.json`. Extract `event.original` when a collector expects FortiPAM key-value messages.

## Sample output

Copied from an actual anomaly-mode run:

```json
{
  "@timestamp": "2026-09-25T13:30:24+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "secret_request",
    "category": [
      "iam"
    ],
    "code": "2304064604",
    "dataset": "fortinet.fortipam",
    "kind": "event",
    "original": "date=2026-09-25 time=13:30:24 devname=\"FPAVULTM1234567\" devid=\"FPAVULTM1234567\" eventtime=1790343024000000000 tz=\"+0000\" logid=\"2304064604\" type=\"secret\" subtype=\"secret-request\" eventtype=\"secret-request\" action=\"pass\" operation=\"request\" secretid=2820 secret=\"prod-vault\" account=\"svc-admin\" uuid=\"c6f7b2d9-823d-4249-968d-b6f36b401de3\" user=\"operator\" starttime=\"2026-09-25 13:30:24\" expirytime=\"2026-09-25 14:00:24\" msg=\"Created secret request.\"",
    "type": [
      "info"
    ]
  },
  "fortinet": {
    "fortipam": {
      "account": "svc-admin",
      "secret_id": 2820,
      "secret_name": "prod-vault",
      "target": null,
      "uuid": "c6f7b2d9-823d-4249-968d-b6f36b401de3"
    }
  },
  "host": {
    "name": "FPAVULTM1234567"
  },
  "related": {
    "user": [
      "operator"
    ]
  },
  "user": {
    "name": "operator"
  }
}
```

## Scope and validation

The request layout covers 20/20 selected fields in FortiSIEM's FortiPAM example; clear-text view covers 19/19 fields in the FortiPAM 1.7.0 example. Both modes were generated, parsed, and checked for a complete time-sorted chain or its absence. Background secret, account, and target combinations stay consistent.

The FortiSIEM page identifies its tested FortiPAM release as 1.3.0, while the clear-text-view example is from FortiPAM 1.7.0. This pack combines those documented event classes as a synthetic scenario; byte-for-byte compatibility of both records within one FortiPAM release has not been established. The examples show message bodies, not a complete syslog envelope. KUMA 4.2 lists a FortiPAM syslog KV normalizer, but its exact compatibility with these samples is unverified.

## References

- [FortiSIEM FortiPAM configuration and secret-request sample](https://docs.fortinet.com/document/fortisiem/7.4.1/external-systems-configuration-guide/521441/fortinet-fortipam)
- [FortiPAM 1.7.0 clear-text-view sample](https://docs.fortinet.com/document/fortipam/1.7.0/examples/779148/creating-an-automation-trigger)
- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)
