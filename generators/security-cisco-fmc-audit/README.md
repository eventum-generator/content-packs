# Cisco Secure Firewall Management Center audit

Cisco Secure Firewall Management Center 7.4.0 audit Syslog records for console views, object changes, policy saves, and task completion. This is the management-center audit stream, not managed FTD traffic or intrusion events. Eventum emits ECS JSON and preserves the Cisco Syslog line in `event.original`.

## Event types

| Audit action | Synthetic background frequency | ECS category |
| --- | --- | --- |
| NAT policy editor Page View | 65% | web |
| NAT Page View | 25% | web |
| `csm_processes` Login Success | 10% | authentication |
| NetworkObject create | Anomaly sequence only | configuration |
| NAT policy save | Anomaly sequence only | configuration |
| Pre-deploy Global Configuration Generation task completion | Anomaly sequence only | configuration |

Weights and one-record-per-second input are synthetic demo settings, not measured FMC frequencies.

## Anomaly Chain

After 60 routine records, an administrator from an unusual address opens the NAT policy editor, creates a network object, and saves a NAT policy. The next record is a successful pre-deploy global configuration generation task on the same management center. Correlate the first three steps by `user.name`, `source.ip`, `observer.name`, and time; associate the task record by `observer.name` and close timing. A rule can surface an object creation and NAT policy save from a previously unseen management address.

Cisco's task-completion line uses `admin@localhost` and does not name the policy or object. It does not prove which change caused the task, that deployment completed, or that traffic behavior changed. `anomaly_mode: true` is the default; `false` emits only routine Page View and Login Success records. Sort by `@timestamp` because output lines can be reordered.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`.

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Enable the management-change sequence. |
| `anomaly_interval_events` | `60` | Routine records before each sequence. |
| `management_center` | `firepower` | Synthetic FMC hostname in Syslog and ECS. |
| `unusual_admin_ip` | `198.51.100.44` | Synthetic source of the correlated administrator actions. |
| `network_object` | `csm-lab` | Synthetic network object created in the sequence. |
| `nat_policy` | `NATPolicy` | Synthetic policy saved in the sequence. |

### Output Parameters

The shipped file output needs no overrides. Replace `output.file` with another output plugin and use top-level `${params.*}` or `${secrets.*}` substitutions for destination settings when needed.

## Usage

From the content-packs repository:

```bash
eventum generate --path generators/security-cisco-fmc-audit/generator.yml --id fmc --live-mode false
eventum generate --path generators/security-cisco-fmc-audit/generator.yml --id fmc --live-mode true
```

Output: `generators/security-cisco-fmc-audit/output/events.json`. Extract `event.original` if a collector expects Cisco's audit Syslog line.

## Sample output

Copied from an actual anomaly-mode run:

```json
{
  "@timestamp": "2026-09-25T14:23:14+00:00",
  "cisco": {
    "fmc": {
      "audit": {
        "component": "sfdccsm",
        "detail": "Objects > Object Management > NetworkObject, create csm-lab"
      }
    }
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "network_object_create",
    "category": [
      "configuration"
    ],
    "code": "FMC-AUDIT",
    "dataset": "cisco.fmc.audit",
    "kind": "event",
    "original": "Sep 25 14:23:14 firepower: [FMC-AUDIT] sfdccsm: admin@198.51.100.44, Objects > Object Management > NetworkObject, create csm-lab",
    "type": [
      "creation"
    ]
  },
  "observer": {
    "name": "firepower",
    "product": "Secure Firewall Management Center",
    "vendor": "Cisco"
  },
  "related": {
    "ip": [
      "198.51.100.44"
    ]
  },
  "source": {
    "ip": "198.51.100.44"
  },
  "user": {
    "name": "admin"
  }
}
```

## Scope and validation

The published Cisco examples include a collector-side timestamp, `localhost`, and receiver address before the FMC Syslog line. `event.original` contains the FMC-originating portion beginning with the `Sep ... firepower:` header. The `[FMC-AUDIT]` marker, components, action text, and field order follow Cisco's examples; addresses, object/policy names, and times are synthetic. All fields in the selected FMC-originating examples are present in `event.original` and mapped where meaningful to ECS or `cisco.fmc.audit`.

Both modes were generated and parsed as JSON. The four-step management sequence appeared only in anomaly mode. Cisco's cited example is FMC 7.4.0 native audit Syslog. KUMA 4.2 lists Secure Firewall Management Center CEF; this pack does not generate CEF, and compatibility with that out-of-the-box normalizer is not established.

## References

- [Cisco FMC 7.4.0 audit Syslog setup and complete examples](https://www.cisco.com/c/en/us/support/docs/security/secure-firewall-management-center/221019-configure-fmc-to-send-audit-logs-to-a-sy.html)
- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)
