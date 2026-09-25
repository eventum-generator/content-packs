# Microsoft Network Policy Server Audit Generator

Produces ECS JSON for Network Policy Server (NPS) RADIUS decisions from the Windows Security channel. `event.original` preserves a complete Security Event XML record and `winlog.event_data` exposes the corresponding named fields.

## Event Types

| Event ID | Baseline weight | Category |
|---|---:|---|
| 6272, access granted | 86% | Authentication |
| 6273, access denied | 12% | Authentication |
| 6274, request discarded | 2% | Authentication |

Weights are synthetic defaults, not measured NPS rates. The FSM emits four 6273 failures followed by one 6272 success after every 100 routine events when `anomaly_mode` is enabled.

## Anomaly Chain

Four denied RADIUS requests for `finance.admin` from station MAC `02-42-AC-11-00-91` are followed by a granted request for the same account, station, RADIUS client and connection policy. Correlate on `winlog.event_data.SubjectUserName`, `CallingStationID`, `ClientName`, `ProxyPolicyName` and time. A detection can alert on repeated failures followed by success, especially for an administrative account or a previously unseen station.

`ClientIPAddress` is the RADIUS client or access point, not the end user's IP address; `CallingStationID` is the useful station identifier. The sequence does not assert that a network policy changed. Set `anomaly_mode: false` to generate only independent routine grants, denials and discards.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
|---|---|---|
| `anomaly_mode` | `true` | Include the failure-to-success chain; `false` emits only background |
| `host_name` | `nps01.corp.example` | NPS server name |
| `domain` | `CORP` | Account domain |
| `radius_client_name` | `office-wifi-ap` | RADIUS client name |
| `radius_client_ip` | `10.20.1.20` | RADIUS client IP |
| `network_policy` | `Corporate WiFi` | Grant policy |
| `connection_policy` | `Corporate WiFi RADIUS` | Connection request policy |
| `suspicious_station` | `02-42-AC-11-00-91` | Anomalous station MAC |
| `target_user` | `finance.admin` | Account in the chain |

### Output Parameters

The shipped configuration writes to `output/events.json` and needs no output parameters or secrets. To send events to a SIEM, replace the `file` output with the required output plugin and configure its endpoint and credentials there.

## Usage

Run from the content-packs repository root:

```bash
eventum generate --path generators/identity-microsoft-nps/generator.yml --id microsoft-nps --live-mode false
eventum generate --path generators/identity-microsoft-nps/generator.yml --id microsoft-nps --live-mode true
```

The first command generates as fast as possible until interrupted. Live mode emits one event per second.

## Sample Output

This complete event was copied from the generated `output/events.json`:

```json
{
  "@timestamp": "2026-09-25T12:07:53+00:00",
  "client": {
    "ip": "10.20.1.20"
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "radius-access-granted",
    "category": [
      "authentication"
    ],
    "code": "6272",
    "kind": "event",
    "original": "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Microsoft-Windows-Security-Auditing\" Guid=\"{54849625-5478-4994-A5BA-3E3B0328C30D}\"/><EventID>6272</EventID><Version>1</Version><Level>0</Level><Task>12552</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime=\"2026-09-25T12:07:53+00:00\"/><EventRecordID>210001</EventRecordID><Correlation/><Execution ProcessID=\"584\" ThreadID=\"4712\"/><Channel>Security</Channel><Computer>nps01.corp.example</Computer><Security/></System><EventData><Data Name=\"SubjectUserSid\">S-1-0-0</Data><Data Name=\"SubjectUserName\">marina</Data><Data Name=\"SubjectDomainName\">CORP</Data><Data Name=\"FullyQualifiedSubjectUserName\">CORP\\marina</Data><Data Name=\"SubjectMachineSID\">S-1-0-0</Data><Data Name=\"SubjectMachineName\">-</Data><Data Name=\"FullyQualifiedSubjectMachineName\">-</Data><Data Name=\"MachineInventory\">-</Data><Data Name=\"CalledStationID\">02-42-AC-11-00-01:CORP</Data><Data Name=\"CallingStationID\">02-42-AC-11-00-3A</Data><Data Name=\"NASIPv4Address\">10.20.1.20</Data><Data Name=\"NASIPv6Address\">-</Data><Data Name=\"NASIdentifier\">office-wifi-ap</Data><Data Name=\"NASPortType\">Wireless - IEEE 802.11</Data><Data Name=\"NASPort\">0</Data><Data Name=\"ClientName\">office-wifi-ap</Data><Data Name=\"ClientIPAddress\">10.20.1.20</Data><Data Name=\"ProxyPolicyName\">Corporate WiFi RADIUS</Data><Data Name=\"NetworkPolicyName\">Corporate WiFi</Data><Data Name=\"AuthenticationProvider\">Windows</Data><Data Name=\"AuthenticationServer\">nps01.corp.example</Data><Data Name=\"AuthenticationType\">PEAP</Data><Data Name=\"EAPType\">Microsoft: Secured password (EAP-MSCHAP v2)</Data><Data Name=\"AccountSessionIdentifier\">-</Data><Data Name=\"ReasonCode\">0</Data><Data Name=\"Reason\">The connection request was successfully authenticated</Data><Data Name=\"LoggingResult\">Accounting information was written to the local log file.</Data></EventData></Event>",
    "outcome": "success",
    "provider": "Microsoft-Windows-Security-Auditing",
    "type": [
      "start"
    ]
  },
  "host": {
    "name": "nps01.corp.example"
  },
  "observer": {
    "name": "nps01.corp.example",
    "type": "radius"
  },
  "related": {
    "ip": [
      "10.20.1.20"
    ],
    "user": [
      "marina"
    ]
  },
  "source": {
    "mac": "02-42-AC-11-00-3A"
  },
  "user": {
    "domain": "CORP",
    "name": "marina"
  },
  "winlog": {
    "channel": "Security",
    "computer_name": "nps01.corp.example",
    "event_data": {
      "AccountSessionIdentifier": "-",
      "AuthenticationProvider": "Windows",
      "AuthenticationServer": "nps01.corp.example",
      "AuthenticationType": "PEAP",
      "CalledStationID": "02-42-AC-11-00-01:CORP",
      "CallingStationID": "02-42-AC-11-00-3A",
      "ClientIPAddress": "10.20.1.20",
      "ClientName": "office-wifi-ap",
      "EAPType": "Microsoft: Secured password (EAP-MSCHAP v2)",
      "FullyQualifiedSubjectMachineName": "-",
      "FullyQualifiedSubjectUserName": "CORP\\marina",
      "LoggingResult": "Accounting information was written to the local log file.",
      "MachineInventory": "-",
      "NASIPv4Address": "10.20.1.20",
      "NASIPv6Address": "-",
      "NASIdentifier": "office-wifi-ap",
      "NASPort": "0",
      "NASPortType": "Wireless - IEEE 802.11",
      "NetworkPolicyName": "Corporate WiFi",
      "ProxyPolicyName": "Corporate WiFi RADIUS",
      "Reason": "The connection request was successfully authenticated",
      "ReasonCode": "0",
      "SubjectDomainName": "CORP",
      "SubjectMachineName": "-",
      "SubjectMachineSID": "S-1-0-0",
      "SubjectUserName": "marina",
      "SubjectUserSid": "S-1-0-0"
    },
    "event_id": 6272,
    "provider_name": "Microsoft-Windows-Security-Auditing",
    "record_id": 210001,
    "task": "Network Policy Server"
  }
}
```

## Source and Scope

[Microsoft's NPS audit catalog](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-network-policy-server) defines events 6272-6280. The [NPS troubleshooting guide](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/troubleshoot-network-policy-server) explains denial reasons. A [published NPS Security Event XML](https://learn.microsoft.com/en-us/answers/questions/2617618/network-policy-server-no-domain-controller-availab) establishes the named payload fields and Windows Event XML shape used here.

Coverage: 27/27 selected NPS `EventData` fields from that XML sample and the common Security XML envelope. Event IDs 6275-6280, NPS operational logs, and accounting files are outside this generator. The 6274 branch models a malformed RADIUS request with reason code 3. Reason text and fields can vary by Windows version and policy; the source's actual volume depends on RADIUS deployment. The generator never emits a user's endpoint IP because these Security events do not provide one.
