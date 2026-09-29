# Active Directory domain controller audit

Windows Security audit events from one synthetic domain controller, normalized as Elastic System Security ECS JSON. The data covers Kerberos and NTLM authentication, temporary global-group membership, and directory attribute changes.

## Event types

A small domain generates about 21,800 records per day. Human activity rises from 0.01 records/s outside 08:00-18:00 UTC to 0.4 records/s during that window. Twelve monitoring accounts contribute another 0.08 records/s throughout the day. Daily volume varies by about 3%. Each administrator has a fixed workstation address and an assigned maintenance account.

| Event ID | Action | Ordinary frequency | Category |
|---|---|---|---|
| 4768 | Kerberos TGT issued | About 47% of authentication | authentication |
| 4769 | Service ticket issued | About 45%; approximately 2% use RC4 | authentication |
| 4776 | NTLM credentials validated | About 6% | authentication |
| 4771 | Kerberos pre-authentication failed | About 2% | authentication |
| 4728 | Member added to a global group | About 12 temporary grants/day, mainly Maintenance Operators | iam |
| 4729 | Member removed from a global group | Each grant ends after 20-40 minutes | iam |
| 5136 | Directory attribute replaced | About six delete/add pairs/day | iam, configuration |

Most temporary grants use the synthetic global group `Maintenance Operators`; approximately one in ten ordinary grants uses `Domain Admins`. At most one temporary membership is active for each of three maintenance accounts. Each grant receives a matching removal by the same administrator. Directory maintenance changes `msDS-AllowedToDelegateTo` among two CIFS targets and the controller LDAP service, preserving the old value and pairing delete/add records by `OpCorrelationID`.

## Anomaly Chain

`anomaly_mode: true` adds a correlated sequence: 4771 failure, successful 4768, RC4 4769, then a 4728 Domain Admins grant by the same administrator within ten minutes. The authentication records share the account SID and client IP. The service request presents the TGT issued in the preceding 4768. Membership ends after the same 20-40 minutes used for ordinary grants.

The default interval is 24 hours. The first episode starts within 24 hours, weighted toward office hours. Later starts are centered on the preceding actual start plus the configured interval, with a window of `min(interval/4, 6 hours)` and stronger preference for busy hours. Administrators rotate between episodes. No missed episodes are replayed. Ordinary authentication and ongoing maintenance continue during episodes.

`anomaly_mode: false` has no complete four-step chain. Each event class, administrator, client address and administrator/member pair also occurs in ordinary traffic. Enabled episodes add their own authentication and membership records. A single RC4 ticket, failure or group addition does not by itself identify a complete episode.

## Parameters

Edit `event.template.params` in `generator.yml`.

| Parameter | Default | Meaning |
|---|---|---|
| `domain` | `CONTOSO` | NetBIOS domain |
| `dns_domain` | `contoso.local` | DNS domain and Kerberos realm |
| `domain_dn` | `DC=contoso,DC=local` | Distinguished-name suffix |
| `domain_sid` | `S-1-5-21-3457937927-2839227994-823803824` | Domain SID prefix |
| `dc_host` | `dc01.contoso.local` | Controller hostname |
| `dc_agent_id` | `a51465f9-72f4-4761-89bb-55de00ec6701` | Stable collector ID |
| `dc_ephemeral_id` | `943942bd-09ec-48aa-957d-2f12ecb83866` | Collector session ID |
| `agent_version` | `8.17.0` | Filebeat version |
| `anomaly_mode` | `true` | Enable correlated episodes |
| `anomaly_interval_hours` | `24` | Episode interval in hours, from 6 to 8760 |

Account names, workstation addresses, service identities and maintenance-account GUIDs are in `samples/`. All defaults are synthetic. No secrets or substitution placeholders are required.

## Usage

From the content-packs root:

```bash
eventum generate --path generators/windows-active-directory/generator.yml --id ad --live-mode true --keep-order true
```

For a finite batch, copy the generator directory, set every `patterns/*.yml` oscillator `start` and `end` to midnight UTC dates, then run:

```bash
eventum generate --path /tmp/ad-batch/generator.yml --id ad-batch --live-mode false --keep-order true
```

Output defaults to `output/events.json`, relative to the configuration. To change volume or office hours, edit the pattern ratios and spread ranges. Keep the sample addresses and domain parameters consistent when changing the environment.

## Source fidelity and limitations

- The output is normalized ECS JSON, not native Windows XML. It represents selected Security events rather than the complete audit log. No live domain-controller capture calibrated the synthetic volume or action shares.
- Kerberos 4768/4769 use version 2 from Windows Server 2016/2019/2022 with the January 14, 2025 or later update. The profile assumes RC4 remains permitted for some service accounts. Ticket expiry and renewal are omitted; concurrent credentials can coexist while an episode is active.
- Domain accounts, global groups and their initial directory values already exist. Account creation, unrelated group memberships and object deletion are omitted. The selected temporary access policy ends every modeled grant after 20-40 minutes.
- Related records can be seconds apart. Background 5136 pairs describe value replacements and do not assert that delegation became usable. Directory Service Changes auditing and an appropriate object SACL are assumed, alongside the corresponding authentication and group-management audit policies.

## Sample output

One complete synthetic normalized event:

```json
{"@timestamp": "2026-09-01T07:02:05.777167+00:00", "agent": {"ephemeral_id": "943942bd-09ec-48aa-957d-2f12ecb83866", "id": "a51465f9-72f4-4761-89bb-55de00ec6701", "name": "dc01.contoso.local", "type": "filebeat", "version": "8.17.0"}, "ecs": {"version": "8.11.0"}, "event": {"action": "added-member-to-group", "category": ["iam"], "code": "4728", "kind": "event", "outcome": "success", "provider": "Microsoft-Windows-Security-Auditing", "sequence": 902240, "type": ["group", "change"]}, "group": {"domain": "CONTOSO", "id": "S-1-5-21-3457937927-2839227994-823803824-2601", "name": "Maintenance Operators"}, "host": {"name": "dc01.contoso.local", "os": {"family": "windows", "type": "windows"}}, "log": {"level": "information"}, "related": {"user": ["olga.sokolova", "svc_maintenance_2"]}, "user": {"domain": "CONTOSO", "id": "S-1-5-21-3457937927-2839227994-823803824-1109", "name": "olga.sokolova", "target": {"domain": "CONTOSO", "group": {"domain": "CONTOSO", "id": "S-1-5-21-3457937927-2839227994-823803824-2601", "name": "Maintenance Operators"}, "id": "S-1-5-21-3457937927-2839227994-823803824-2202", "name": "svc_maintenance_2"}}, "winlog": {"channel": "Security", "computer_name": "dc01.contoso.local", "event_data": {"MemberName": "CN=svc_maintenance_2,CN=Users,DC=contoso,DC=local", "MemberSid": "S-1-5-21-3457937927-2839227994-823803824-2202", "SubjectDomainName": "CONTOSO", "SubjectLogonId": "0x91e545", "SubjectUserName": "olga.sokolova", "SubjectUserSid": "S-1-5-21-3457937927-2839227994-823803824-1109", "TargetDomainName": "CONTOSO", "TargetSid": "S-1-5-21-3457937927-2839227994-823803824-2601", "TargetUserName": "Maintenance Operators"}, "event_id": "4728", "keywords": ["Audit Success"], "level": "information", "logon": {"id": "0x91e545"}, "opcode": "Info", "outcome": "success", "process": {"pid": 516, "thread": {"id": 1467}}, "provider_guid": "{54849625-5478-4994-a5ba-3e3b0328c30d}", "provider_name": "Microsoft-Windows-Security-Auditing", "record_id": "902240", "task": "Security Group Management", "time_created": "2026-09-01T07:02:05.777167+00:00", "version": 0}}
```

## References

- [Microsoft Security Group Management and 4728/4729](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-group-management)
- [Microsoft 4768](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [Microsoft 4769](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [Microsoft 4771](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4771)
- [Microsoft 4776](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4776)
- [Microsoft 5136](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5136)
- [Microsoft delegation attribute schema](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/86261ca1-154c-41fb-8e5f-c6446e77daaa)
- [Elastic System Security integration](https://github.com/elastic/integrations/tree/main/packages/system/data_stream/security)
- [RFC 4120: Kerberos ticket exchange](https://www.rfc-editor.org/rfc/rfc4120.html#section-3.3)
