# Active Directory domain controller audit

Generates Windows Security events from one Active Directory domain controller as ECS JSON. The stream covers Kerberos, NTLM, privileged group membership, and directory changes. It complements `windows-security`, which models host audit events rather than this domain-controller sequence. Six event IDs share one emitting template across seven FSM states. Security record IDs increase on this one controller.

## Event types

With `anomaly_mode: true`, the FSM emits 250 routine events, then one 11-event intrusion chain. The overall shares below assume that mode. Routine event weights are illustrative, not a measured production distribution. Microsoft documents Kerberos ticket events as high volume on domain controllers; the exact mix depends on audit policy and workload.

| Event ID | Action | Routine weight | Overall share | ECS category |
|---|---|---:|---:|---|
| 4768 | Kerberos TGT issued | 48% | ~46.4% | `authentication` |
| 4769 | Kerberos service ticket issued | 44% | ~43.3% | `authentication` |
| 4776 | NTLM credential validated | 6% | ~5.7% | `authentication` |
| 4771 | Kerberos pre-authentication failed | 2% | ~3.4% | `authentication` |
| 4728 | Member added to Domain Admins | chain | ~0.4% | `iam` |
| 5136 | Directory attribute value deleted or added | chain | ~0.8% | `iam`, `configuration` |

## Anomaly Chain

The linked chain starts with four 4771 failures for four accounts from `10.99.4.22`. The last targeted account, `helpdesk.admin`, then gets a successful 4768. It requests three RC4 service tickets for distinct service accounts, adds `svc_sync` to Domain Admins, and changes that account's `msDS-AllowedToDelegateTo` value. The 5136 delete/add pair shares `OpCorrelationID`; the administrative events share `SubjectLogonId`. Detection ideas: password spraying across accounts from one IP followed by a successful TGT; three RC4 service tickets for distinct service accounts from the compromised principal; a Domain Admins group addition followed by a delegation attribute change. Join 4771, 4768, and 4769 on source IP and principal, then link administrative events by `SubjectLogonId`. Match the 5136 delete/add pair by `OpCorrelationID`. Set `anomaly_mode: false` for only routine 4768, 4769, 4776, and 4771 events; no chain step is emitted.

Validation covered 258 of 263 field paths in six Elastic expected-event fixtures (98.1%). The five omitted paths are `log.file.path`, which identifies the fixture XML file rather than a live Windows Event Log source.

The generator uses the updated 4768/4769 event fields introduced on patched Windows Server 2016 and later, including encryption capabilities and ticket hashes. Events are normalized ECS JSON, not Windows XML. The 5136 pair requires Directory Service Changes auditing and a matching SACL on the modified object in a real domain.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml` to change the synthetic domain.

| Parameter | Default | Purpose |
|---|---|---|
| `domain` | `CONTOSO` | NetBIOS domain name |
| `dns_domain` | `contoso.local` | Kerberos realm and DNS suffix |
| `domain_dn` | `DC=contoso,DC=local` | Distinguished-name suffix |
| `domain_sid` | `S-1-5-21-3457937927-2839227994-823803824` | Base domain SID |
| `dc_host` | `dc01.contoso.local` | Controller hostname |
| `dc_agent_id` | `a51465f9-72f4-4761-89bb-55de00ec6701` | Stable collector ID |
| `dc_ephemeral_id` | `943942bd-09ec-48aa-957d-2f12ecb83866` | Collector session ID |
| `agent_version` | `8.17.0` | Filebeat version |
| `attack_ip` | `10.99.4.22` | Source address of the linked chain |
| `attack_member` | `svc_sync` | Account added to Domain Admins and modified |
| `attack_member_rid` | `2108` | RID of that account |
| `attack_object_guid` | `{62ae5b92-0fab-4f0d-9393-1cfab99c9742}` | Stable directory object GUID |
| `anomaly_mode` | `true` | Emit the linked intrusion chain; `false` emits only routine events |

The user and service pools are in `samples/users.json` and `samples/services.json`. Change those files when changing account names, RIDs, or service accounts; `helpdesk.admin` is the fourth user and the compromise target.

### Output Parameters

The shipped output is `output/events.json` and needs no placeholders. To send events to OpenSearch, replace the output block and supply these top-level substitution values through Eventum:

```yaml
output:
  - opensearch:
      hosts:
        - ${params.opensearch_host}
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: ${params.opensearch_index}
```

| Placeholder | Purpose |
|---|---|
| `${params.opensearch_host}` | OpenSearch URL |
| `${params.opensearch_user}` | Username |
| `${secrets.opensearch_password}` | Password from the Eventum keyring |
| `${params.opensearch_index}` | Destination index |

## Usage

Run from the `content-packs` root. Live mode emits ten events per second. Sample mode advances simulated ticks as fast as the process can render, so bound its run time.

```bash
# Bounded batch sample
timeout 2 eventum generate --path generators/windows-active-directory/generator.yml --id ad --live-mode false

# Continuous live stream
eventum generate --path generators/windows-active-directory/generator.yml --id ad --live-mode true
```

## Sample output

This complete 4728 event was copied from a validation run:

```json
{
  "@timestamp": "2026-09-25T10:24:12+00:00",
  "agent": {
    "ephemeral_id": "943942bd-09ec-48aa-957d-2f12ecb83866",
    "id": "a51465f9-72f4-4761-89bb-55de00ec6701",
    "name": "dc01.contoso.local",
    "type": "filebeat",
    "version": "8.17.0"
  },
  "ecs": {
    "version": "8.11.0"
  },
  "event": {
    "action": "added-member-to-group",
    "category": [
      "iam"
    ],
    "code": "4728",
    "kind": "event",
    "outcome": "success",
    "provider": "Microsoft-Windows-Security-Auditing",
    "sequence": 900259,
    "type": [
      "group",
      "change"
    ]
  },
  "group": {
    "domain": "CONTOSO",
    "id": "S-1-5-21-3457937927-2839227994-823803824-512",
    "name": "Domain Admins"
  },
  "host": {
    "name": "dc01.contoso.local",
    "os": {
      "family": "windows",
      "type": "windows"
    }
  },
  "log": {
    "level": "information"
  },
  "related": {
    "user": [
      "helpdesk.admin",
      "svc_sync"
    ]
  },
  "user": {
    "domain": "CONTOSO",
    "id": "S-1-5-21-3457937927-2839227994-823803824-1114",
    "name": "helpdesk.admin",
    "target": {
      "domain": "CONTOSO",
      "group": {
        "domain": "CONTOSO",
        "id": "S-1-5-21-3457937927-2839227994-823803824-512",
        "name": "Domain Admins"
      },
      "id": "S-1-5-21-3457937927-2839227994-823803824-2108",
      "name": "svc_sync"
    }
  },
  "winlog": {
    "channel": "Security",
    "computer_name": "dc01.contoso.local",
    "event_data": {
      "MemberName": "CN=svc_sync,CN=Users,DC=contoso,DC=local",
      "MemberSid": "S-1-5-21-3457937927-2839227994-823803824-2108",
      "SubjectDomainName": "CONTOSO",
      "SubjectLogonId": "0xb085d1",
      "SubjectUserName": "helpdesk.admin",
      "SubjectUserSid": "S-1-5-21-3457937927-2839227994-823803824-1114",
      "TargetDomainName": "CONTOSO",
      "TargetSid": "S-1-5-21-3457937927-2839227994-823803824-512",
      "TargetUserName": "Domain Admins"
    },
    "event_id": "4728",
    "keywords": [
      "Audit Success"
    ],
    "level": "information",
    "logon": {
      "id": "0xb085d1"
    },
    "opcode": "Info",
    "outcome": "success",
    "process": {
      "pid": 516,
      "thread": {
        "id": 6448
      }
    },
    "provider_guid": "{54849625-5478-4994-a5ba-3e3b0328c30d}",
    "provider_name": "Microsoft-Windows-Security-Auditing",
    "record_id": "900259",
    "task": "Security Group Management",
    "time_created": "2026-09-25T10:24:12+00:00",
    "version": 0
  }
}
```

## References

- [Microsoft: Advanced Audit Policy Configuration](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration)
- [Microsoft: 4768 Kerberos TGT](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [Microsoft: 4769 Kerberos service ticket](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [Microsoft: 4771 pre-authentication failure](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4771)
- [Microsoft: 4776 NTLM credential validation](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4776)
- [Microsoft: Audit Security Group Management](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-group-management)
- [Microsoft: 5136 directory service object changed](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5136)
- [Elastic: System Security data stream fixtures and fields](https://github.com/elastic/integrations/tree/main/packages/system/data_stream/security)
