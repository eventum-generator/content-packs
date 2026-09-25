# Microsoft AD CS Audit Generator

Produces ECS JSON for certificate activity in the Windows Security channel of a Windows Server 2012 Certification Authority. `event.original` contains reconstructed version 0 Event XML, and `winlog.event_data` preserves the native event fields.

## Event Types

| Event ID | Activity | Illustrative background rate |
|---|---|---:|
| 4886 | Certificate request received | One per request |
| 4887 | Certificate issued | 94% of ordinary dispositions |
| 4888 | Certificate denied | 6% of ordinary dispositions |
| 4885 | CA audit filter changed | Once per 240 ordinary request/disposition pairs |

Every 4886 is followed by a 4887 or 4888 with the same CA host, `RequestId`, `Requester`, and `Attributes`. The synthetic CA accepts a supplied UPN on the fictional `CorpUserSuppliedSAN` template. That behavior requires a template configured to accept a requester-supplied subject alternative name and an account allowed to enroll; it is not a property of the default Windows `User` template. Ordinary 4888 records use `-2146875375` (`CERTSRV_E_KEY_LENGTH`), meaning the request's public key does not meet the template minimum. The request key itself is outside these event fields. The weights and maintenance frequency are exercise settings, not measured AD CS production rates.

## Anomaly Chain

With `anomaly_mode: true` (the default), one sequence is inserted after 50 ordinary request/disposition pairs:

1. 4885 changes `AuditFilter` from the scenario's initial 127 to 119. This removes bit 8, which audits certificate revocation and CRL publication, but retains bit 4, which audits certificate requests and disposition.
2. On the next minute tick, the same `CORP\svc-enroll` account submits a 4886 request on `CorpUserSuppliedSAN` with `SAN:upn=administrator@corp.example`.
3. On the following minute tick, 4887 records issuance for that request. Its `RequestId`, `Requester`, and `Attributes` match the 4886 record.

A detection can correlate a 4885 reduction of the CA audit filter with a sensitive UPN request and successful issue on the same CA within three minutes. The 4885 event records the new filter and actor, not the previous value or a request ID; the previous 127 is scenario state. It cannot independently prove an audit reduction. Routine traffic in **both** modes also contains 4885 changes and individual privileged-UPN request/issue pairs, separated by much longer intervals. No single event identifies the injected sequence. `anomaly_mode: false` emits only this background activity and never inserts the three-event sequence.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
|---|---|---|
| `anomaly_mode` | `true` | Insert one three-event anomaly sequence; `false` generates background only |
| `ca_host` | `ca01.corp.example` | CA server name |
| `domain` | `CORP` | Requester domain |
| `ca_name` | `CORP-CA` | CA display name |
| `suspicious_requester` | `svc-enroll` | Synthetic account used in the sequence and some background events |
| `privileged_upn` | `administrator@corp.example` | Requested UPN in the sequence and some background events |
| `routine_template` | `User` | Ordinary certificate template |
| `enrollment_template` | `CorpUserSuppliedSAN` | Fictional template that accepts a supplied SAN |

### Output Parameters

The shipped configuration writes to `output/events.json` and needs no output parameters or secrets. Replace the `file` output with a SIEM output plugin and configure that plugin's endpoint and credentials to send events elsewhere.

## Usage

Run from the content-packs repository root:

```bash
eventum generate --path generators/identity-microsoft-adcs/generator.yml --id microsoft-adcs --live-mode false --keep-order true
eventum generate --path generators/identity-microsoft-adcs/generator.yml --id microsoft-adcs --live-mode true --keep-order true
```

Batch mode generates continuously until interrupted. Live mode emits one event per minute (the final cron field is seconds). `--keep-order true` preserves timestamp order in the file. To test background mode, set `event.template.params.anomaly_mode: false` in `generator.yml`.

## Sample Output

This complete record is copied from an actual anomaly-mode generation run:

```json
{
  "@timestamp": "2026-09-25T17:13:00.839382+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "certificate-requested",
    "category": [
      "iam"
    ],
    "code": "4886",
    "kind": "event",
    "original": "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Microsoft-Windows-Security-Auditing\" Guid=\"{54849625-5478-4994-A5BA-3E3B0328C30D}\"/><EventID>4886</EventID><Version>0</Version><Level>0</Level><Task>12805</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime=\"2026-09-25T17:13:00.839382Z\"/><EventRecordID>310040</EventRecordID><Correlation/><Execution ProcessID=\"652\" ThreadID=\"368\"/><Channel>Security</Channel><Computer>ca01.corp.example</Computer><Security/></System><EventData><Data Name=\"RequestId\">3001</Data><Data Name=\"Requester\">CORP\\pavel</Data><Data Name=\"Attributes\">CertificateTemplate:User</Data></EventData></Event>",
    "provider": "Microsoft-Windows-Security-Auditing",
    "type": [
      "info"
    ]
  },
  "host": {
    "name": "ca01.corp.example"
  },
  "observer": {
    "name": "CORP-CA",
    "type": "certificate-authority"
  },
  "related": {
    "user": [
      "pavel"
    ]
  },
  "user": {
    "domain": "CORP",
    "name": "pavel"
  },
  "winlog": {
    "channel": "Security",
    "computer_name": "ca01.corp.example",
    "event_data": {
      "Attributes": "CertificateTemplate:User",
      "RequestId": "3001",
      "Requester": "CORP\\pavel"
    },
    "event_id": "4886",
    "keywords": [
      "Audit Success"
    ],
    "level": "information",
    "opcode": "Info",
    "process": {
      "pid": 652,
      "thread": {
        "id": 368
      }
    },
    "provider_guid": "{54849625-5478-4994-A5BA-3E3B0328C30D}",
    "provider_name": "Microsoft-Windows-Security-Auditing",
    "record_id": "310040",
    "task": "Certification Services",
    "time_created": "2026-09-25T17:13:00.839382Z"
  }
}
```

## Source and Scope

[Microsoft's PKI event appendix](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn786423(v=ws.11)) defines the 4885-4888 meanings and displayed fields. The [Microsoft CA audit-filter table](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn786422(v=ws.11)) defines bits 4 and 8 and requires restarting the CA service after a filter change. [Windows Server 2012 provider metadata](https://gist.github.com/andrewkroh/cf48e95aa2f80f33484126e421f888ba) supplies the version 0 EventData names and order. [Microsoft's certificate request protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/f4eb50d5-62f6-470b-8846-9489af9dea62) documents the SAN request attribute, and [Microsoft's error-code table](https://learn.microsoft.com/en-us/windows/win32/com/com-error-codes-4) defines the denial disposition.

The [Elastic System integration](https://www.elastic.co/docs/reference/integrations/system) collects the Security channel. Its [Windows Security fixture](https://github.com/elastic/integrations/blob/main/packages/system/data_stream/security/_dev/test/pipeline/test-security-windows2012-4768.json-expected.json) informed the shared `winlog.*` field types, but no AD CS-specific fixture for these four IDs was available during this audit. This generator covers all version 0 EventData fields (5/5 for 4885, 3/3 for 4886, 6/6 for 4887 and 4888). Newer 4886/4887 version 1 records can contain extra fields, as shown by a [first-hand 2026 event capture](https://www.nextron-systems.com/2026/08/04/detecting-certighost-cve-2026-54121-sigma-coverage-across-the-full-attack-chain/); they are outside this version 0 scope. The XML envelope is reconstructed from the provider schema and generic Windows Security examples. Complete live version 0 XML captures for all four IDs have not been obtained, so exact envelope fidelity remains unverified.
