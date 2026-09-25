# Microsoft AD CS Audit Generator

Produces ECS JSON for Active Directory Certificate Services activity from the Windows Security channel. `event.original` preserves Event XML, while `winlog.event_data` carries native certificate-request fields.

## Event Types

| Event ID | Baseline frequency | Category |
|---|---:|---|
| 4886, certificate request received | 50% | Certificate request |
| 4887, certificate issued | 47% | Certificate disposition |
| 4888, certificate denied | 3% | Certificate disposition |
| 4885, CA audit filter changed | Chain only | Configuration |

Each baseline 4886 request is followed by one disposition sharing `RequestId`. The 4887/4888 split is 94%/6% of dispositions. These weights are synthetic; Microsoft describes AD CS event volume as low to medium but does not publish production proportions. The FSM adds one anomaly chain after 50 routine request/disposition pairs.

## Anomaly Chain

A 4885 change to the CA audit filter by `CORP\svc-enroll` is followed by a 4886 request from the same account using the `User` template and a supplied privileged UPN, then a 4887 issue event with the same `RequestId` and `Requester`. Detect a CA audit-setting change near sensitive certificate enrollment, and correlate the request and issue on CA host plus `winlog.event_data.RequestId`. The supplied UPN is visible in `Attributes`; real exploitability depends on the template configuration and CA permissions. The 4885 event identifies the changing account but does not show the previous filter value or prove auditing was disabled, so the detection should treat that step as a contextual signal.

Set `anomaly_mode: false` for only routine request/issue/deny pairs. It removes the 4885 change and the privileged-UPN enrollment chain.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
|---|---|---|
| `anomaly_mode` | `true` | Include the CA-change and enrollment chain; `false` emits only background |
| `ca_host` | `ca01.corp.example` | CA server name |
| `domain` | `CORP` | Requester domain |
| `ca_name` | `CORP-CA` | CA display name |
| `suspicious_requester` | `svc-enroll` | Requesting account in the chain |
| `privileged_upn` | `administrator@corp.example` | UPN supplied in request attributes |
| `enrollment_template` | `User` | Certificate template name |

### Output Parameters

The shipped configuration writes to `output/events.json` and needs no output parameters or secrets. To send events to a SIEM, replace the `file` output with the required output plugin and configure its endpoint and credentials there.

## Usage

Run from the content-packs repository root:

```bash
eventum generate --path generators/identity-microsoft-adcs/generator.yml --id microsoft-adcs --live-mode false
eventum generate --path generators/identity-microsoft-adcs/generator.yml --id microsoft-adcs --live-mode true
```

The first command generates as fast as possible until interrupted. Live mode emits one event per second.

## Sample Output

This complete event was copied from the generated `output/events.json`:

```json
{
  "@timestamp": "2026-09-25T12:04:47+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "certificate-requested",
    "category": [
      "configuration"
    ],
    "code": "4886",
    "kind": "event",
    "original": "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Microsoft-Windows-Security-Auditing\" Guid=\"{54849625-5478-4994-A5BA-3E3B0328C30D}\"/><EventID>4886</EventID><Version>0</Version><Level>0</Level><Task>12805</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime=\"2026-09-25T12:04:47+00:00\"/><EventRecordID>310001</EventRecordID><Correlation/><Execution ProcessID=\"652\" ThreadID=\"368\"/><Channel>Security</Channel><Computer>ca01.corp.example</Computer><Security/></System><EventData><Data Name=\"RequestId\">3001</Data><Data Name=\"Requester\">CORP\\boris</Data><Data Name=\"Attributes\">CertificateTemplate:User</Data></EventData></Event>",
    "outcome": "success",
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
  "winlog": {
    "channel": "Security",
    "computer_name": "ca01.corp.example",
    "event_data": {
      "Attributes": "CertificateTemplate:User",
      "RequestId": "3001",
      "Requester": "CORP\\boris"
    },
    "event_id": 4886,
    "provider_name": "Microsoft-Windows-Security-Auditing",
    "record_id": 310001,
    "task": "Certification Services"
  }
}
```

## Source and Scope

[Microsoft's AD CS audit catalog](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services) defines the 4885-4888 event purposes and low-to-medium expected volume. The [Microsoft PKI event appendix](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn786423(v=ws.11)) lists request, requester, attributes, disposition, SKI and subject. [NXLog's provider field catalog](https://docs.nxlog.co/agent/current/im/msvistalog_providers.html) provides the native 4885 and 4888 field names.

Coverage: 5/5 selected 4885 fields, 3/3 4886 fields, and 6/6 4887/4888 fields in `winlog.event_data` and `event.original`. AD CS must have its audit subcategory and CA audit options enabled for these events to appear. Other CA operations, template directory-service changes and certificate contents are outside this generator. Certificate issuance alone does not prove misuse; the chain assumes a template accepts a supplied subject UPN.
