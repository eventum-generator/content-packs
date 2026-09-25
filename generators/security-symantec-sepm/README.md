# Symantec Endpoint Protection Manager External Logs

SEPM administrative, policy-audit, and agent-activity records in the documented default comma-delimited external-log payload. Eventum writes ECS JSON with the native field-order payload in `event.original`.

## Event types

| Log type | Meaning | Approximate background frequency |
| --- | --- | --- |
| Administrative | Administrator login succeeded | 15% |
| Policy | Policy added (`0`) | 10% |
| Agent Activity | Client downloaded policy | 75% |
| Policy | Policy edited (`2`) | Chain only |

These are synthetic scenario weights, not measured rates.

## Anomaly Chain

After 60 routine records, the same administrator logs in and edits `Endpoint Protection Policy` twice. Soon after, `ws-fin-07.example.test` downloads a policy from the same SEPM server and site. Correlate the login and edits by administrator, site, server, and domain; then look for client policy downloads at that site and server. This supports a rule for repeated policy edits followed by client uptake.

The Agent Activity record does not contain the policy name. The final step therefore shows temporal association, not proof that the client downloaded the edited policy.

`anomaly_mode: true` is the default and mixes this sequence with background. Set it to `false` for background only. Sort by `@timestamp` when checking the sequence; concurrent output may reorder lines.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`.

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Enable the policy-change sequence. |
| `anomaly_interval_events` | `60` | Routine records between chains. |
| `site_name` | `PrimarySite` | SEPM site. |
| `server_name` | `sepm-01.example.test` | SEPM server. |
| `sepm_domain` | `Default` | SEPM domain. |
| `target_admin` | `svc-policy` | Chain administrator. |
| `target_policy` | `Endpoint Protection Policy` | Edited policy. |
| `target_client` | `ws-fin-07.example.test` | Client observed after edits. |

### Output Parameters

The shipped file output needs no overrides. Replace `output.file` with another output plugin and use top-level `${params.*}` or `${secrets.*}` substitutions for destination settings when needed.

## Usage

From the content-packs repository:

```bash
eventum generate --path generators/security-symantec-sepm/generator.yml --id sepm --live-mode false
eventum generate --path generators/security-symantec-sepm/generator.yml --id sepm --live-mode true
```

Output: `generators/security-symantec-sepm/output/events.json`. Extract `event.original` for a collector that accepts the external-log payload.

## Sample output

Copied from an actual anomaly-mode run:

```json
{
  "@timestamp": "2026-09-25T13:17:07+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "admin_login",
    "category": [
      "authentication"
    ],
    "dataset": "symantec.sepm_administrative",
    "kind": "event",
    "original": "PrimarySite,sepm-01.example.test,Default,svc-policy,Administrator log on succeeded",
    "type": [
      "start"
    ]
  },
  "host": {
    "name": "sepm-01.example.test"
  },
  "symantec": {
    "sepm": {
      "client_host": null,
      "description": "Administrator log on succeeded",
      "domain": "Default",
      "policy_name": null,
      "site": "PrimarySite"
    }
  },
  "user": {
    "name": "svc-policy"
  }
}
```

## Scope and validation

The three selected record layouts cover 5/5 Administrative, 6/6 Policy, and 7/7 Agent Activity fields for external syslog payloads. Conditional dump-file timestamp and severity columns are excluded; `@timestamp` comes from Eventum. Both modes were parsed and checked for the complete chain or its absence.

Broadcom documents field order and the default comma delimiter for SEP 14.x, but does not give a complete wire sample for these three log types. This pack models the external-log message body, without a syslog envelope. KUMA 4.2 lists a Symantec regexp normalizer; compatibility with that specific normalizer is not verified.

## References

- [Broadcom SEPM external log field order and event IDs](https://knowledge.broadcom.com/external/article/155205)
- [Broadcom default external-log delimiter](https://knowledge.broadcom.com/external/article/205271)
- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)
