# Active Directory domain controller audit

Generates Windows Security events from one Active Directory domain controller as ECS JSON. The stream covers Kerberos, NTLM, privileged group membership, and directory changes. It complements `windows-security`, which models host audit events rather than this domain-controller sequence. Six event IDs share one emitting template across nine FSM states. The controller's Security record IDs increase with event time; the file output can arrive slightly out of order under concurrent rendering.

## Event types

The default is a small synthetic controller emitting one event per second. The authentication weights are illustrative, not a measured production distribution; real ratios depend on workload and audit policy. The background also contains one legitimate administrative maintenance sequence, so neither event 4728 nor 5136 alone identifies the attack. The incident sequence occurs once in anomaly mode.

| Event ID | Action | Ordinary authentication weight | Additional use | ECS category |
|---|---|---:|---|---|
| 4768 | Kerberos TGT issued | 48% | One compromised-account TGT | `authentication` |
| 4769 | Kerberos service ticket issued | 44% | Three RC4 service-account tickets | `authentication` |
| 4776 | NTLM credential validated | 6% | Background only | `authentication` |
| 4771 | Kerberos pre-authentication failed | 2% | Four-account password spray | `authentication` |
| 4728 | Member added to Domain Admins | one maintenance event | One attacker-controlled member added | `iam` |
| 5136 | Directory attribute modified | one maintenance pair | One attack delete/add pair | `iam`, `configuration` |

## Anomaly Chain

After 250 ordinary events, four 4771 failures target distinct accounts from `10.99.4.22` at one-second intervals. The last account, `helpdesk.admin`, then obtains a 4768 TGT. After 30 seconds of background traffic it requests three RC4 service tickets for distinct service accounts. Another 90 seconds of background traffic precedes a 4728 addition of `svc_sync` to Domain Admins and a 5136 delete/add pair changing that account's `msDS-AllowedToDelegateTo` list from `cifs/filesrv01.contoso.local` to `ldap/dc01.contoso.local`. The first failure and last change are about 130 seconds apart. The chain runs once; normal traffic continues afterward.

Correlate 4771 failures by source IP and distinct user, then join the successful 4768 and subsequent 4769 events by source IP, account, and a bounded time window. Join 4728 and 5136 by `SubjectUserSid` and `SubjectLogonId`; join the 5136 value pair by `OpCorrelationID` and object GUID. Event 4768 does not contain a logon ID, so its connection to the later directory changes is temporal and account-based, not an ID equality. The source IP also occurs in benign authentication traffic. A one-off approved Domain Admins addition and delegation edit appear in both modes, on different objects; alerting on event ID, actor, or IP alone is insufficient.

Set `anomaly_mode: false` to emit only the ordinary traffic and the one-off approved maintenance. It never emits the four-account spray, the RC4 sweep, or the `svc_sync` privilege/delegation changes.

Validation covers 258 of 263 field paths in six Elastic System Security expected-event fixtures (98.1%). The five omitted paths are `log.file.path`, which points to Elastic's local XML fixture files rather than a live Windows Event Log source. Microsoft Security event XML is the source for the native `winlog.event_data` values; this generator emits normalized ECS JSON, not raw XML.

The 4768/4769 version-2 fields model Windows Server 2016, 2019, or 2022 with the January 14, 2025 or later security update. Successful Kerberos ticket events require the relevant Kerberos audit subcategories; 4728 requires Security Group Management auditing. The 5136 pair requires Directory Service Changes auditing and a matching SACL on the modified object. RC4 tickets in this scenario require service accounts and policy that still permit RC4; this is not a recommended security setting.

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
| `attack_ip` | `10.99.4.22` | Shared bastion address used by the chain and some ordinary authentications |
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

Run from the `content-packs` root. Live mode emits one event per second. Sample mode advances simulated ticks as fast as the process can render, so bound its run time.

```bash
# Bounded batch sample
timeout 2 eventum generate --path generators/windows-active-directory/generator.yml --id ad --live-mode false

# Continuous live stream
eventum generate --path generators/windows-active-directory/generator.yml --id ad --live-mode true
```

## Sample output

This complete 4728 event was copied from the post-review anomaly-mode run:

```json
{
  "@timestamp": "2026-09-25T16:38:19+00:00",
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
    "sequence": 900379,
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
      "SubjectLogonId": "0x9648a9",
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
      "id": "0x9648a9"
    },
    "opcode": "Info",
    "outcome": "success",
    "process": {
      "pid": 516,
      "thread": {
        "id": 8007
      }
    },
    "provider_guid": "{54849625-5478-4994-a5ba-3e3b0328c30d}",
    "provider_name": "Microsoft-Windows-Security-Auditing",
    "record_id": "900379",
    "task": "Security Group Management",
    "time_created": "2026-09-25T16:38:19+00:00",
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
- [Microsoft: msDS-AllowedToDelegateTo attribute schema](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/86261ca1-154c-41fb-8e5f-c6446e77daaa)
- [Microsoft: RC4 Kerberos audit and remediation](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Microsoft: Audit Security Group Management](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-group-management)
- [Microsoft: 5136 directory service object changed](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5136)
- [Elastic: System Security data stream fixtures and fields](https://github.com/elastic/integrations/tree/main/packages/system/data_stream/security)
