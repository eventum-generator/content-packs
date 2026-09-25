# Aruba ClearPass Policy Manager audit syslog

Synthetic RFC5424 ClearPass 6.11 administrative audit records. `event.original` carries the vendor's `clearPass@14823` structured-data form; ECS fields expose the actor and outcome.

## Event Types

| Action | Baseline frequency | Category |
| --- | ---: | --- |
| WebUI login success (`Logged in`) | 84% | Authentication |
| WebUI login failure (`Login Failed`) | 12% | Authentication |
| `Account Settings` modify | 4% | Configuration |
| `Log Service Configuration` modify and `SSH Public Key` add | Chain only | Configuration |

The baseline weights are synthetic assumptions, not vendor frequency measurements.

## Anomaly Chain

Four failed WebUI logins for `admin` from `192.0.2.91` lead to a successful login, followed by a modification of `Log Service Configuration` and addition of an `SSH Public Key` on the same ClearPass node. A SIEM rule can correlate by administrator, node and a short time window, using the login client IP for the first five records. Sort by `@timestamp` when evaluating order; file line order is not the contract. ClearPass configuration-change audit records contain `User` but no login session ID or client IP, so the last two links are temporal correlations rather than a proven session join.

`anomaly_mode` defaults to `true`. Set it to `false` in `event.template.params` for ordinary administrative activity only.

## Parameters

### Event Parameters

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include the suspicious administrative sequence |
| `node_ip` | `10.20.0.10` | ClearPass node address |
| `admin_user` | `admin` | Account in the chain |
| `suspicious_client_ip` | `192.0.2.91` | WebUI client IP in the chain |
| `software_version` | `6.11.11.261850` | Example ClearPass version in `origin` |

### Output Parameters

The shipped configuration writes `output/events.json` and needs no connection parameters or secrets. Replace the `file` output in a local copy for SIEM delivery and add `${params.siem_host}` and `${secrets.siem_token}` for that output plugin where applicable.

## Usage

```bash
eventum generate --path generators/identity-aruba-clearpass/generator.yml --id clearpass --live-mode false
eventum generate --path generators/identity-aruba-clearpass/generator.yml --id clearpass --live-mode true
```

## Sample Output

This event was copied from a generator run with `anomaly_mode: true`.

```json
{
  "@timestamp": "2026-09-25T12:42:05+00:00",
  "clearpass": {
    "action": "None",
    "category": "Login Failed",
    "component": "Policy Manager UI",
    "entity_name": null,
    "event_id": 3003,
    "software_version": "6.11.11.261850"
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "login-failure",
    "category": [
      "authentication"
    ],
    "kind": "event",
    "original": "2026-09-25T12:42:05Z 10.20.0.10 ClearPass 18202 34-1-0 [timeQuality tzKnown=\"1\"][origin swVersion=\"6.11.11.261850\" software=\"PolicyManager\" ip=\"10.20.0.10\" enterpriseId=\"1.3.6.1.4.1.14823\"][clearPass@14823 eventId=\"3003\" Action=\"None\" Category=\"Login Failed\" Description=\"User: admin\\nClient IP Address: 192.0.2.91\" Level=\"WARN\" Component=\"Policy Manager UI\" CppmNode.CPPM-Node=\"10.20.0.10\" Timestamp=\"2026-09-25T12:42:05Z\"]",
    "outcome": "failure",
    "type": [
      "denied"
    ]
  },
  "host": {
    "ip": [
      "10.20.0.10"
    ],
    "name": "10.20.0.10"
  },
  "related": {
    "ip": [
      "192.0.2.91"
    ],
    "user": [
      "admin"
    ]
  },
  "source": {
    "ip": "192.0.2.91"
  },
  "user": {
    "name": "admin"
  }
}
```

## Coverage and Limits

The selected vendor examples expose 13 source fields, all retained in `event.original`: syslog timestamp, node, app, software version, enterprise ID, event ID, action, category, description or user, level or entity name, component where applicable, ClearPass node, and audit timestamp (13/13). The ECS projection extracts the fields needed for detection; it is not a complete RFC5424 parser. ClearPass defaults to Standard/raw export; select RFC5424 for this format. KUMA 4.2 lists ClearPass CEF, so its CEF normalizer is not a direct match for these RFC5424 messages. The version shown is an example and the source documentation says the version string varies by release.

## References

- [ClearPass 6.11 Common Criteria auditable-event examples](https://arubanetworking.hpe.com/techdocs/ClearPass/6.11/PolicyManager/Content/CPPM_UserGuide/Common%20Compliance/cc_Appendix_A_FAU_GEN.1%20AUDITABLE%20EVENTS_new.htm)
- [KUMA 4.2 supported event sources](https://support.kaspersky.ru/kuma/4.2/255782)
