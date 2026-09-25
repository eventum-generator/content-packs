# Microsoft Network Policy Server Audit Generator

Produces ECS JSON for Network Policy Server (NPS) RADIUS decisions from the Windows Security channel. `event.original` preserves a complete Security Event XML record and `winlog.event_data` exposes the corresponding named fields.

## Event Types

| Event ID | Baseline weight | Category |
|---|---:|---|
| 6272, access granted | 88% | Authentication |
| 6273, access denied | 11.8% | Authentication |
| 6274, request discarded | 0.2% | Authentication |

Weights and the one-event-per-30-seconds cadence are illustrative defaults, not measured rates. The 6274 branch represents an internal EAP processing error (reason code 1), not a credential denial.

## Anomaly Chain

With `anomaly_mode: true` (the default), the generator emits one incident after 100 routine requests: four 6273 credential denials followed by one 6272 grant for `finance.admin` from station `DA-7A-11-B2-6F-48`. Each decision is 30 seconds apart, so the five-event sequence spans two minutes. Correlate on `winlog.event_data.SubjectUserName`, `CallingStationID`, `ClientName`, and `ProxyPolicyName` within a five-minute window. The same account and station also produce ordinary grants and occasional denials in both modes; one account, station, event ID, reason code, or policy alone is not an anomaly marker.

`ClientIPAddress` identifies the RADIUS client or access point, not the user's device. `CallingStationID` identifies the station MAC, while `CalledStationID` contains the access point BSSID and SSID. The sequence does not imply a policy change. Set `anomaly_mode: false` for background decisions without the five-event chain.

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
| `access_point_bssid` | `00-19-92-74-3C-A1` | Access point BSSID |
| `ssid` | `CORP` | Wireless network name |
| `network_policy` | `Corporate WiFi` | Matched network policy |
| `connection_policy` | `Corporate WiFi RADIUS` | Connection request policy |
| `suspicious_station` | `DA-7A-11-B2-6F-48` | Station MAC used in the incident and baseline |
| `target_user` | `finance.admin` | Account in the chain |

### Output Parameters

The shipped configuration writes to `output/events.json` and needs no output parameters or secrets. To send events to a SIEM, replace the `file` output with the required output plugin and configure its endpoint and credentials there.

## Usage

Run from the content-packs repository root:

```bash
eventum generate --path generators/identity-microsoft-nps/generator.yml --id microsoft-nps --live-mode false
eventum generate --path generators/identity-microsoft-nps/generator.yml --id microsoft-nps --live-mode true
```

The first command generates as fast as possible until interrupted. Live mode emits one event every 30 seconds. Eventum croniter reads seconds from the sixth cron field (`*/30`).

## Sample Output

This complete 6272 event was copied from a final generated run:

```json
{
  "@timestamp": "2026-09-25T16:50:30+00:00",
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
    "original": "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Microsoft-Windows-Security-Auditing\" Guid=\"{54849625-5478-4994-A5BA-3E3B0328C30D}\"/><EventID>6272</EventID><Version>1</Version><Level>0</Level><Task>12552</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime=\"2026-09-25T16:50:30.000000000Z\"/><EventRecordID>210001</EventRecordID><Correlation/><Execution ProcessID=\"584\" ThreadID=\"4712\"/><Channel>Security</Channel><Computer>nps01.corp.example</Computer><Security/></System><EventData><Data Name=\"SubjectUserSid\">S-1-5-21-3124921703-1242075836-1035668124-1111</Data><Data Name=\"SubjectUserName\">olga</Data><Data Name=\"SubjectDomainName\">CORP</Data><Data Name=\"FullyQualifiedSubjectUserName\">CORP\\olga</Data><Data Name=\"SubjectMachineSID\">S-1-0-0</Data><Data Name=\"SubjectMachineName\">-</Data><Data Name=\"FullyQualifiedSubjectMachineName\">-</Data><Data Name=\"MachineInventory\">-</Data><Data Name=\"CalledStationID\">00-19-92-74-3C-A1:CORP</Data><Data Name=\"CallingStationID\">DA-7A-11-45-D8-1F</Data><Data Name=\"NASIPv4Address\">10.20.1.20</Data><Data Name=\"NASIPv6Address\">-</Data><Data Name=\"NASIdentifier\">office-wifi-ap</Data><Data Name=\"NASPortType\">Wireless - IEEE 802.11</Data><Data Name=\"NASPort\">0</Data><Data Name=\"ClientName\">office-wifi-ap</Data><Data Name=\"ClientIPAddress\">10.20.1.20</Data><Data Name=\"ProxyPolicyName\">Corporate WiFi RADIUS</Data><Data Name=\"NetworkPolicyName\">Corporate WiFi</Data><Data Name=\"AuthenticationProvider\">Windows</Data><Data Name=\"AuthenticationServer\">nps01.corp.example</Data><Data Name=\"AuthenticationType\">PEAP</Data><Data Name=\"EAPType\">Microsoft: Secured password (EAP-MSCHAP v2)</Data><Data Name=\"AccountSessionIdentifier\">-</Data><Data Name=\"QuarantineState\">Full Access</Data><Data Name=\"QuarantineSessionIdentifier\">-</Data><Data Name=\"LoggingResult\">Accounting information was written to the local log file.</Data></EventData></Event>",
    "outcome": "success",
    "provider": "Microsoft-Windows-Security-Auditing",
    "type": [
      "end"
    ]
  },
  "host": {
    "name": "nps01.corp.example"
  },
  "log": {
    "level": "information"
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
      "olga"
    ]
  },
  "source": {
    "mac": "DA-7A-11-45-D8-1F"
  },
  "user": {
    "domain": "CORP",
    "id": "S-1-5-21-3124921703-1242075836-1035668124-1111",
    "name": "olga"
  },
  "winlog": {
    "channel": "Security",
    "computer_name": "nps01.corp.example",
    "event_data": {
      "AccountSessionIdentifier": "-",
      "AuthenticationProvider": "Windows",
      "AuthenticationServer": "nps01.corp.example",
      "AuthenticationType": "PEAP",
      "CalledStationID": "00-19-92-74-3C-A1:CORP",
      "CallingStationID": "DA-7A-11-45-D8-1F",
      "ClientIPAddress": "10.20.1.20",
      "ClientName": "office-wifi-ap",
      "EAPType": "Microsoft: Secured password (EAP-MSCHAP v2)",
      "FullyQualifiedSubjectMachineName": "-",
      "FullyQualifiedSubjectUserName": "CORP\\olga",
      "LoggingResult": "Accounting information was written to the local log file.",
      "MachineInventory": "-",
      "NASIPv4Address": "10.20.1.20",
      "NASIPv6Address": "-",
      "NASIdentifier": "office-wifi-ap",
      "NASPort": "0",
      "NASPortType": "Wireless - IEEE 802.11",
      "NetworkPolicyName": "Corporate WiFi",
      "ProxyPolicyName": "Corporate WiFi RADIUS",
      "QuarantineSessionIdentifier": "-",
      "QuarantineState": "Full Access",
      "SubjectDomainName": "CORP",
      "SubjectMachineName": "-",
      "SubjectMachineSID": "S-1-0-0",
      "SubjectUserName": "olga",
      "SubjectUserSid": "S-1-5-21-3124921703-1242075836-1035668124-1111"
    },
    "event_id": "6272",
    "keywords": [
      "Audit Success"
    ],
    "opcode": "Info",
    "provider_name": "Microsoft-Windows-Security-Auditing",
    "record_id": "210001",
    "task": "Network Policy Server",
    "time_created": "2026-09-25T16:50:30.000000000Z"
  }
}
```

## Source and Scope

The generator targets version 1 of the NPS `Microsoft-Windows-Security-Auditing` records in the Windows Security channel. [Microsoft's audit catalog](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-network-policy-server) defines 6272 as grant, 6273 as deny, and 6274 as discard. [Microsoft's NPS troubleshooting guide](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/troubleshoot-network-policy-server) identifies 6273 reason code 16 as invalid credentials. The full reason string and a matched network policy are shown in a [published NPS reason-16 record](https://techcommunity.microsoft.com/discussions/windowsserver/aovpn--reasoncode-16/4479484).

The `EventData` names and per-event shape follow published Windows records: a [version-1 wireless 6272 record](https://airheads.hpe.com/discussion/server2008-r2-aruba-620-radius-issues) and an [independent complete 6272 XML export](https://al.twohill.nz/2018/Filtering-Windows-Event-Logs-and-Exporting-Into-Excel/), a [version-1 wireless 6273 XML record](https://learn.microsoft.com/en-us/answers/questions/2617618/network-policy-server-no-domain-controller-availab), and a [version-1 6274 XML record with reason code 1](https://learn.microsoft.com/en-us/answers/questions/1251168/network-policy-server-discarded-the-request-for-a). The 6274 capture is from a PEAP deployment rather than this sample Wi-Fi access point. [Elastic's Windows Security integration fixture](https://github.com/elastic/integrations/blob/main/packages/system/data_stream/security/_dev/test/pipeline/test-security-6272-nps-subject.json-expected.json) informs the ECS and `winlog` field layout; the XML remains the source record.

These captures establish 27, 27, and 25 `EventData` fields for the selected 6272, 6273, and 6274 variants respectively. The 6272 grant has quarantine fields and no reason fields; the 6274 discard has neither `MachineInventory` nor `LoggingResult`. Event IDs 6275-6280, NPS operational logs, and accounting files are outside this generator. Actual event rates and optional field values depend on Windows version, access point, authentication method, and policy. No client endpoint IP is synthesized from the RADIUS client IP.
