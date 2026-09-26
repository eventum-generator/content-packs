# Active Directory domain controller audit

Generates Windows Security events from one Active Directory domain controller as ECS JSON. The stream covers Kerberos, NTLM, privileged group membership, and directory changes. It complements `windows-security`, which models host audit events rather than this domain-controller sequence. Six event IDs share one emitting template across nine FSM states. The controller's Security record IDs increase with event time; the file output can arrive slightly out of order under concurrent rendering.

## Event types

The default is a small synthetic controller emitting one event per second. The authentication weights are illustrative, not a measured production distribution; real ratios depend on workload and audit policy. Each cycle includes legitimate administrative maintenance, so neither event 4728 nor 5136 alone identifies the incident. Anomaly mode repeats the correlated sequence after configurable periods of ordinary traffic.

| Event ID | Action | Ordinary authentication weight | Additional use | ECS category |
|---|---|---:|---|---|
| 4768 | Kerberos TGT issued | 48% | One compromised-account TGT | `authentication` |
| 4769 | Kerberos service ticket issued | 44% | Three RC4 service-account tickets | `authentication` |
| 4776 | NTLM credential validated | 6% | Background only | `authentication` |
| 4771 | Kerberos pre-authentication failed | 2% | Four-account password spray | `authentication` |
| 4728 | Member added to Domain Admins | One approved addition per cycle | One additional member per episode | `iam` |
| 5136 | Directory attribute modified | One maintenance pair per cycle | One additional delete/add pair per episode | `iam`, `configuration` |

## Anomaly Chain

`anomaly_mode` defaults to `true`. After 3,600 ordinary events, four 4771 failures target distinct accounts from `10.99.4.22` at one-second intervals. The last account, `helpdesk.admin`, obtains a 4768 TGT. After 30 ordinary events it requests three RC4 tickets for distinct service accounts. Another 90 ordinary events precede a 4728 Domain Admins addition and a 5136 delete/add pair replacing that target's `msDS-AllowedToDelegateTo` value from `cifs/filesrv01.contoso.local` to `ldap/dc01.contoso.local`. The first failure and last change are 130 seconds apart.

After the episode, another 3,600 ordinary events precede the next one. At one event per second, episode starts are about 1 hour and 2 minutes apart. Each cycle uses another pre-existing service account, with a new name and RID; its object GUID stays fixed within the cycle. Episode logon IDs and change-correlation GUIDs are new. The first two targets are `svc_sync_001` and `svc_sync_003`; approved group additions use `svc_sync_002` and `svc_sync_004`. No membership is added twice. The model assumes these accounts already exist and do not belong to Domain Admins before their addition.

Ordinary delegation maintenance touches the same object later used by the episode. It first replaces `cifs/backup01.contoso.local` with `cifs/filesrv01.contoso.local`, establishing the value subsequently removed by the correlated change. The same actor, source IP, service-account family, event types and RC4 tickets also appear in the background. A target name or event ID alone does not label the incident. The sensitive `ldap/<controller>` delegation value is specific to the episode and can itself be a useful detection condition; background maintenance changes CIFS values.

Correlate distinct 4771 users by IP, then join the 4768 `ResponseTicket` to each 4769 `RequestTicketHash`, checking account, IP and time. The three sweep requests reuse that issued TGT and one client `LogonGuid`; each response has its own service-ticket hash. Join 4728 and 5136 by `SubjectUserSid` and `SubjectLogonId`, and the 5136 pair by `OpCorrelationID` and object GUID. Event 4768 does not contain a logon ID, so its connection to administrative activity is temporal and account-based. Changing `msDS-AllowedToDelegateTo` alone is not asserted to enable delegation.

`anomaly_mode: false` emits ordinary traffic and recurring approved maintenance, without the correlated spray/TGT/RC4 sweep/group/delegation episode. Four finite 2.5-hour default/custom runs produced 9,001 records each: two complete episodes in each anomaly run and zero in each background run.

Validation covers 258 of 263 field paths in six Elastic System Security expected-event fixtures (98.1%). The five omitted paths are `log.file.path`, which points to Elastic's local XML fixture files rather than a live Windows Event Log source. Microsoft Security event XML is the source for the native `winlog.event_data` values; this generator emits normalized ECS JSON, not raw XML.

The selected client model keeps one current TGT per user SID and client IP, replacing it after each successful 4768. Background requests reuse credentials by the same rule. Requests before the first observed 4768 use a pre-existing TGT; ticket lifetimes, renewals and simultaneous credentials for one client are outside this model. State has at most one entry per user sample plus the shared bastion client. RC4-only requests negotiate an RC4 session key, while AES-capable requests use AES256. Ticket encryption and session-key encryption are separate fields and need not always match in real deployments.

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
| `attack_member` | `svc_sync` | Prefix for pre-existing service accounts in both modes; cycle targets receive numeric suffixes |
| `attack_member_rid` | `2108` | First target RID; later account RIDs increase without reuse |
| `attack_object_guid` | `{62ae5b92-0fab-4f0d-9393-1cfab99c9742}` | First target GUID; later objects get new GUIDs, stable within their cycle |
| `anomaly_mode` | `true` | Emit periodic linked episodes; `false` emits only routine events |
| `anomaly_after_events` | `3600` | Ordinary records before the first episode |
| `anomaly_interval_events` | `3600` | Ordinary records between episodes; both timing values are clamped to at least 102 for complete maintenance |

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

From the `content-packs` root, create a finite configuration and generate a 2.5-hour batch:

```bash
uv run --project ../eventum python - <<'PYCODE'
from pathlib import Path
p = Path("generators/windows-active-directory")
source = (p / "generator.yml").read_text()
finite = source.replace(
    "      count: 1\n",
    '      count: 1\n      start: "2026-09-25T00:00:00+00:00"\n'
    '      end: "2026-09-25T02:30:00+00:00"\n',
    1,
)
(p / "generator.batch.yml").write_text(finite)
PYCODE
flock -x /tmp/eventum-generator-heavy.lock uv run --project ../eventum eventum generate --path generators/windows-active-directory/generator.batch.yml --id ad --live-mode false --keep-order true
rm generators/windows-active-directory/generator.batch.yml
```

For continuous generation at one event per second:

```bash
uv run --project ../eventum eventum generate --path generators/windows-active-directory/generator.yml --id ad --live-mode true --keep-order true
```

## Sample output

This complete synthetic ECS 4728 event was copied from the first validated periodic episode. It is normalized output, not raw Windows XML:

```json
{
  "@timestamp": "2026-09-25T01:02:08+00:00",
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
    "sequence": 903729,
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
      "svc_sync_001"
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
      "name": "svc_sync_001"
    }
  },
  "winlog": {
    "channel": "Security",
    "computer_name": "dc01.contoso.local",
    "event_data": {
      "MemberName": "CN=svc_sync_001,CN=Users,DC=contoso,DC=local",
      "MemberSid": "S-1-5-21-3457937927-2839227994-823803824-2108",
      "SubjectDomainName": "CONTOSO",
      "SubjectLogonId": "0x338f51",
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
      "id": "0x338f51"
    },
    "opcode": "Info",
    "outcome": "success",
    "process": {
      "pid": 516,
      "thread": {
        "id": 4703
      }
    },
    "provider_guid": "{54849625-5478-4994-a5ba-3e3b0328c30d}",
    "provider_name": "Microsoft-Windows-Security-Auditing",
    "record_id": "903729",
    "task": "Security Group Management",
    "time_created": "2026-09-25T01:02:08+00:00",
    "version": 0
  }
}
```

## References

- [IETF RFC 4120: Kerberos TGS and session-key negotiation](https://www.rfc-editor.org/rfc/rfc4120.html#section-3.3)

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
- [Elastic: real 5136 normalized field example](https://github.com/elastic/integrations/issues/16965)
