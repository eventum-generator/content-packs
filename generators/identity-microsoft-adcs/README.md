# Microsoft AD CS Audit Generator

Produces ECS JSON for the Security-channel audit of one Windows Server 2012 Certification Authority. `event.original` contains reconstructed version 0 Event XML; `winlog.event_data` preserves the selected native field names and values.

## Event Types

| Event ID | Activity | Approximate background share |
| --- | --- | ---: |
| 4886 | Certificate request received | 50% |
| 4887 | Certificate issued | 49% |
| 4888 | Request denied because of a short public key | 1% |
| 4885 | CA audit-filter change or restoration | Less than 1% |

About 2,040 selected records/day represent approximately 1,020 enrollments. Volume is one record/minute overnight and two/minute from 08:00 to 18:00 UTC. Thirty device accounts provide round-the-clock enrollment traffic; twenty human accounts are much less active at night. Two administrators perform ordinary enrollment, approved supplied-UPN exercises and audit maintenance. The workload is a synthetic training CA, not measured production traffic.

Every request is followed by its disposition after 30 or 60 seconds, with unchanged request ID, requester, attributes, process and thread. Request IDs increase once per receipt; Security record IDs increase with gaps for other channel events. Ordinary denials affect about 2% of requests. Error `-2146875375` (`CERTSRV_E_KEY_LENGTH`, `0x80094811`) means the submitted key is too short for the template.

Routine audit maintenance runs twice daily with a variable initial phase. A reduction from 127 to 119 is restored after 15–32 minutes. Both modes use that same calendar and restoration duration. Changes are applied through a modeled successful CA restart lasting 15 seconds; subsequent requests use the new process. Service start/stop events are outside this selected feed.

## Anomaly Chain

`anomaly_mode: true` adds a linked sequence:

1. An administrator changes the CA audit filter from 127 to 119 (4885).
2. The same administrator submits a supplied-UPN request on the enrollment template (4886).
3. The CA issues the certificate for that request ID (4887), within three minutes of the reduction.

Filter 119 disables revocation/CRL auditing, bit 8. Request/issuance auditing, bit 4, and security-setting auditing, bit 16, remain enabled. The records do not prove that the issued certificate can authenticate as the supplied UPN.

The first episode starts within `min(interval, 24 hours)`. Later starts lie within half of `min(interval / 4, 6 hours)` around one interval after the previous actual start. Timing follows the daily activity curve, with stronger daytime weighting for later starts, using available periods outside routine audit maintenance. The two administrators alternate between episodes. Default interval is 24 hours, with a minimum of six hours. Missed historical episodes are not replayed.

With `anomaly_mode: false`, ordinary audit changes, supplied-UPN requests and issuance remain, but the complete short sequence is absent. Enabled episodes contribute their own linked records. Each reduction is restored on the ordinary 15–32-minute schedule. Existing enrollment pairs finish before a configuration change, and routine audit maintenance keeps its own calendar.

## Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include recurring correlations |
| `anomaly_interval_hours` | `24` | Recurrence hours, minimum 6 |
| `ca_host` | `ca01.corp.example` | CA server hostname |
| `domain` | `CORP` | Account domain |
| `ca_name` | `CORP-CA` | Configured CA name, collector context |
| `suspicious_requester` | `svc-enroll` | First administrator, shared by ordinary work and episodes |
| `privileged_upn` | `administrator@corp.example` | Requested UPN shared by both modes |
| `routine_template` | `CorpUserCN` | Fictional CN-from-AD enrollment template |
| `enrollment_template` | `CorpUserSuppliedSAN` | Fictional supplied-subject enrollment template |

The other administrator and requester inventory live in `samples/accounts.json`. Both administrators have enrollment, CA administration and restart permissions. Account names used as CNs must not require DN escaping. Template names assume the equivalent published template policy below.

## Usage

From the content-packs repository root:

```bash
eventum generate --path generators/identity-microsoft-adcs/generator.yml --id adcs --live-mode true --keep-order true
```

For a finite batch, copy the directory, add UTC `start` and `end` bounds to both cron inputs, and run:

```bash
eventum generate --path /path/to/copy/generator.yml --id adcs-batch --live-mode false --keep-order true
```

The default file is `output/events.json`. No endpoint or secrets are required. Replace the file output to send records elsewhere. A finite window can end between a request and its disposition. Keep the default input spacing when interpreting the 15-second restart assumption.

Performance: approximately 3,900 events/second for a four-day batch on the authoring machine.

## Sample Output

One complete synthetic event:

```json
{"@timestamp": "2026-09-20T00:01:00+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "certificate-issued", "category": ["iam"], "code": "4887", "kind": "event", "original": "\u003cEvent xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"\u003e\u003cSystem\u003e\u003cProvider Name=\"Microsoft-Windows-Security-Auditing\" Guid=\"{54849625-5478-4994-A5BA-3E3B0328C30D}\"/\u003e\u003cEventID\u003e4887\u003c/EventID\u003e\u003cVersion\u003e0\u003c/Version\u003e\u003cLevel\u003e0\u003c/Level\u003e\u003cTask\u003e12805\u003c/Task\u003e\u003cOpcode\u003e0\u003c/Opcode\u003e\u003cKeywords\u003e0x8020000000000000\u003c/Keywords\u003e\u003cTimeCreated SystemTime=\"2026-09-20T00:01:00.000000Z\"/\u003e\u003cEventRecordID\u003e310040\u003c/EventRecordID\u003e\u003cCorrelation/\u003e\u003cExecution ProcessID=\"652\" ThreadID=\"724\"/\u003e\u003cChannel\u003eSecurity\u003c/Channel\u003e\u003cComputer\u003eca01.corp.example\u003c/Computer\u003e\u003cSecurity/\u003e\u003c/System\u003e\u003cEventData\u003e\u003cData Name=\"RequestId\"\u003e3001\u003c/Data\u003e\u003cData Name=\"Requester\"\u003eCORP\\device28$\u003c/Data\u003e\u003cData Name=\"Attributes\"\u003eCertificateTemplate:CorpUserCN\u003c/Data\u003e\u003cData Name=\"Disposition\"\u003e3\u003c/Data\u003e\u003cData Name=\"SubjectKeyIdentifier\"\u003ed2 e2 10 0e 83 83 55 37 58 e3 26 db 96 e0 24 df e6 03 58 26\u003c/Data\u003e\u003cData Name=\"Subject\"\u003eCN=device28$\u003c/Data\u003e\u003c/EventData\u003e\u003c/Event\u003e", "outcome": "success", "provider": "Microsoft-Windows-Security-Auditing", "type": ["creation"]}, "host": {"name": "ca01.corp.example"}, "observer": {"name": "CORP-CA", "type": "certificate-authority"}, "related": {"user": ["device28$"]}, "user": {"domain": "CORP", "name": "device28$"}, "winlog": {"channel": "Security", "computer_name": "ca01.corp.example", "event_data": {"Attributes": "CertificateTemplate:CorpUserCN", "Disposition": "3", "RequestId": "3001", "Requester": "CORP\\device28$", "Subject": "CN=device28$", "SubjectKeyIdentifier": "d2 e2 10 0e 83 83 55 37 58 e3 26 db 96 e0 24 df e6 03 58 26"}, "event_id": "4887", "keywords": ["Audit Success"], "level": "information", "opcode": "Info", "process": {"pid": 652, "thread": {"id": 724}}, "provider_guid": "{54849625-5478-4994-A5BA-3E3B0328C30D}", "provider_name": "Microsoft-Windows-Security-Auditing", "record_id": "310040", "task": "Certification Services", "time_created": "2026-09-20T00:01:00.000000Z"}}
```

## Source Fidelity and Limits

The version 0 profile has five EventData fields for 4885, three for 4886, and six each for 4887/4888. It follows Microsoft's event descriptions and a Windows Server 2012 provider-metadata dump. The XML envelope is reconstructed; byte parity with complete same-version live events and a downstream parser has not been established. Newer event versions, cryptographic CSR/certificate contents, serial numbers, thumbprints, validity dates and revocation/CRL actions are outside this feed. The 20-byte spaced SKI is synthetic and is not derived from a real public key.

`CorpUserCN` uses `CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME` with neither supplied-subject nor directory-path flags. Its AD account CN equals the account name. `CorpUserSuppliedSAN` uses `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, with a CSR supplying the same simple CN. Both templates permit automatic issuance without manager approval or authorized signatures. The CA separately enables `EDITF_ATTRIBUTESUBJECTALTNAME2` so the supplied request attribute can be honored; the template's supplied-subject setting alone does not establish this. Issued Subject is `CN=<account>` and denied Subject is empty.

Rates, scheduled audit maintenance and the successful 15-second restart are training-environment assumptions. Frequent audit configuration changes are unusual on a production CA. One request is outstanding at a time. The selected records alone do not establish the effective restart time, certificate contents or authentication capability. Native and ECS clocks use UTC.

## References

- [Microsoft PKI event appendix](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn786423(v=ws.11)) defines the four event meanings and displayed fields.
- [CA audit-filter table](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn786422(v=ws.11)) and [MS-CSRA GetAuditFilter](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-csra/58fed3ab-91fe-43a8-bebb-447eb2f8f694) establish the mask and affected operations. The filter table requires CA service restart after registry changes.
- [Audit Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services) must be enabled, with the applicable success/failure audit policy, in addition to the CA audit filter.
- [Windows Server 2012 provider metadata](https://gist.github.com/andrewkroh/cf48e95aa2f80f33484126e421f888ba) supplies version 0 EventData names and order. It is a firsthand provider-binary dump, not a complete live four-event fixture.
- [MS-WCCE request attributes](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/92f07a54-2889-45e3-afd0-94b60daa80ec), [template name flags](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/cf805c29-6f58-4087-a395-3d0233a89f3c) and [Microsoft's CA SAN-setting assessment](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-insecure-adcs-certificate-enrollment) distinguish request attributes, supplied extensions and CA policy.
- [MS-CRTD name-flag values](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/1192823c-d839-4bc3-9b6b-fa8c53507ae1) and [MS-WCCE CA subject processing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/a1f27ffb-7f74-4fa1-8841-7cde4ba0bcfe) define the CN-from-AD and supplied-subject profiles.
- [Microsoft error codes](https://learn.microsoft.com/en-us/windows/win32/com/com-error-codes-4) defines the minimum-key-length denial.
- [Public-key identifier algorithms](https://learn.microsoft.com/en-us/windows/win32/api/certenroll/ne-certenroll-keyidentifierhashalgorithm) distinguish SKI from a certificate thumbprint or serial number.
- [Elastic System integration](https://www.elastic.co/docs/reference/integrations/system) collects Security-channel data. Its [generic Security fixture](https://github.com/elastic/integrations/blob/main/packages/system/data_stream/security/_dev/test/pipeline/test-security-windows2012-4768.json-expected.json) informs shared winlog types; an AD CS-specific fixture is unavailable for this profile.
