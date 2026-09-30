# Microsoft Network Policy Server Audit Generator

Produces ECS JSON for Network Policy Server (NPS) RADIUS decisions from the Windows Security channel. `event.original` preserves a complete Security Event XML record and `winlog.event_data` exposes the corresponding named fields. The ECS timestamp and Windows `TimeCreated` are normalized to UTC.

## Event Types

| Event ID | Share of records | Category |
|---|---:|---|
| 6272, access granted | 87.2% | Authentication |
| 6273, access denied | 12.7% | Authentication |
| 6274, request discarded | 0.2% | Authentication |

Shares are for background (`anomaly_mode: false`). There is one decision every 30 seconds: the next retry of a running burst, or else an ordinary decision for a random account (91.8% grant, 8% denial, 0.2% discard). An ordinary denial starts a retry burst in 30% of cases: one to six more denials of the same account and station (weights 40/25/15/10/6/4), 30, 60, 90 or 120 seconds apart (weights 45/30/15/10), and 80% of bursts end with a grant. Consecutive decisions of one account and station include runs of one to ten denials; a week holds about 60 runs of four, 45 of five and 30 of six. Weights, the cadence and the retry law are illustrative defaults, not measured rates. 6274 records represent an internal EAP processing error (reason code 1), not a credential denial.

## Anomaly Chain

With `anomaly_mode: true` (the default), each episode is four 6273 credential denials followed by one 6272 grant for `finance.admin` from station `DA-7A-11-B2-6F-48`. The steps follow the same retry law as background bursts - 30, 60, 90 or 120 seconds apart (weights 45/30/15/10), redrawn until the grant falls at most 270 seconds after the first denial - and ordinary decisions fall between the steps, so the five-event sequence spans two to four and a half minutes. Every episode has fresh native `EventRecordID` values. The selected wireless profile carries `AccountSessionIdentifier: -`, so it does not supply a session key. Correlate on `winlog.event_data.SubjectUserName` and `CallingStationID` (with `ClientName` and `ProxyPolicyName` as context) within a five-minute window: four denials followed by a grant, the first denial at most 300 seconds before the grant. The same account and station also produce ordinary grants, denials and retry bursts in both modes; one account, station, event ID, reason code, or policy alone is not an anomaly marker.

Recurrence: the first episode starts at a time drawn uniformly within the first `min(anomaly_interval_seconds, 24 h)` of the run; the background has no hour-of-day curve, so no hour is preferred. Each next episode is due `anomaly_interval_seconds` after the actual start of the previous one and starts at a time drawn uniformly within a window of `w = min(interval / 4, 6 h)` centred on that due time. Consecutive starts are therefore `interval ± w/2` apart (6 h ± 45 min by default), start times do not drift, and missed intervals are never caught up. A week holds about 27 episodes at the default interval, with gaps of about 5.40-6.70 h, and about 56 with a three-hour interval, with gaps of about 2.64-3.36 h.

Only the complete ordered chain is absent from background: an ordinary grant that would complete four denials of the same account and station, the first at most 300 seconds earlier, does not happen - the retrying user gives up - and that 30-second slot has no record. An episode's own denials count too, so each episode completes the chain exactly once: an ordinary grant of `finance.admin` from the station within 300 seconds of the episode's first denial does not happen either (none after the 27 episodes of a default week, 2 after the 56 episodes of a week at a three-hour interval). No other record is changed or moved. Such empty slots are 104-143 a week in background (about 0.6% of slots); they are the only gaps in the 30-second grid. A week of background holds about 157 sequences of four denials of one account and station within 300 seconds; a grant of the same account and station never follows inside the window, and in each of the five minutes after it 8-10% of these sequences get one, while the share of grants among other accounts' decisions stays level (90.6-91.6% in the minutes inside the window, 87.9-90.0% after it).

`ClientIPAddress` identifies the RADIUS client or access point, not the user's device. `CallingStationID` identifies the station MAC, while `CalledStationID` contains the access point BSSID and SSID. The sequence does not imply a policy change. Set `anomaly_mode: false` for background decisions without the five-event chain.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
|---|---|---|
| `anomaly_mode` | `true` | Include recurring failure-to-success episodes; `false` emits only background |
| `anomaly_interval_seconds` | `21600` | Mean time between episode starts (each start within ± `min(interval / 8, 3 h)` of its due time); the first falls within `min(interval, 24 h)` of the run start; use a value above 600 seconds |
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
uv run --project ../eventum eventum generate --path generators/identity-microsoft-nps/generator.yml --id microsoft-nps --live-mode false
uv run --project ../eventum eventum generate --path generators/identity-microsoft-nps/generator.yml --id microsoft-nps --live-mode true
```

For a finite batch, copy `generator.yml` beside the original, add `start` and `end` to `input.cron`, and use `--live-mode false --keep-order true`. Without these bounds, the first command generates as fast as possible until interrupted. Live mode emits one event every 30 seconds; each record carries a random sub-second offset in 100-nanosecond units: the native XML `SystemTime` has nine fractional digits (the last two zero), as in the published 6274 record, and `winlog.time_created` has seven, as in Elastic's 6272 fixture. Eventum croniter reads seconds from the sixth cron field (`*/30`).


## Sample Output

This complete 6272 grant ends the first episode of a default run:

```json
{
  "@timestamp": "2026-09-01T03:29:30.495859+00:00",
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
    "original": "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Microsoft-Windows-Security-Auditing\" Guid=\"{54849625-5478-4994-A5BA-3E3B0328C30D}\"/><EventID>6272</EventID><Version>1</Version><Level>0</Level><Task>12552</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime=\"2026-09-01T03:29:30.495859700Z\"/><EventRecordID>210419</EventRecordID><Correlation/><Execution ProcessID=\"584\" ThreadID=\"4712\"/><Channel>Security</Channel><Computer>nps01.corp.example</Computer><Security/></System><EventData><Data Name=\"SubjectUserSid\">S-1-5-21-3124921703-1242075836-1035668124-1120</Data><Data Name=\"SubjectUserName\">finance.admin</Data><Data Name=\"SubjectDomainName\">CORP</Data><Data Name=\"FullyQualifiedSubjectUserName\">CORP\\finance.admin</Data><Data Name=\"SubjectMachineSID\">S-1-0-0</Data><Data Name=\"SubjectMachineName\">-</Data><Data Name=\"FullyQualifiedSubjectMachineName\">-</Data><Data Name=\"MachineInventory\">-</Data><Data Name=\"CalledStationID\">00-19-92-74-3C-A1:CORP</Data><Data Name=\"CallingStationID\">DA-7A-11-B2-6F-48</Data><Data Name=\"NASIPv4Address\">10.20.1.20</Data><Data Name=\"NASIPv6Address\">-</Data><Data Name=\"NASIdentifier\">office-wifi-ap</Data><Data Name=\"NASPortType\">Wireless - IEEE 802.11</Data><Data Name=\"NASPort\">0</Data><Data Name=\"ClientName\">office-wifi-ap</Data><Data Name=\"ClientIPAddress\">10.20.1.20</Data><Data Name=\"ProxyPolicyName\">Corporate WiFi RADIUS</Data><Data Name=\"NetworkPolicyName\">Corporate WiFi</Data><Data Name=\"AuthenticationProvider\">Windows</Data><Data Name=\"AuthenticationServer\">nps01.corp.example</Data><Data Name=\"AuthenticationType\">PEAP</Data><Data Name=\"EAPType\">Microsoft: Secured password (EAP-MSCHAP v2)</Data><Data Name=\"AccountSessionIdentifier\">-</Data><Data Name=\"QuarantineState\">Full Access</Data><Data Name=\"QuarantineSessionIdentifier\">-</Data><Data Name=\"LoggingResult\">Accounting information was written to the local log file.</Data></EventData></Event>",
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
      "finance.admin"
    ]
  },
  "source": {
    "mac": "DA-7A-11-B2-6F-48"
  },
  "user": {
    "domain": "CORP",
    "id": "S-1-5-21-3124921703-1242075836-1035668124-1120",
    "name": "finance.admin"
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
      "CallingStationID": "DA-7A-11-B2-6F-48",
      "ClientIPAddress": "10.20.1.20",
      "ClientName": "office-wifi-ap",
      "EAPType": "Microsoft: Secured password (EAP-MSCHAP v2)",
      "FullyQualifiedSubjectMachineName": "-",
      "FullyQualifiedSubjectUserName": "CORP\\finance.admin",
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
      "SubjectUserName": "finance.admin",
      "SubjectUserSid": "S-1-5-21-3124921703-1242075836-1035668124-1120"
    },
    "event_id": "6272",
    "keywords": [
      "Audit Success"
    ],
    "opcode": "Info",
    "provider_name": "Microsoft-Windows-Security-Auditing",
    "record_id": "210419",
    "task": "Network Policy Server",
    "time_created": "2026-09-01T03:29:30.4958597Z"
  }
}
```

## Source and Scope

The generator targets version 1 of the NPS `Microsoft-Windows-Security-Auditing` records in the Windows Security channel. [Microsoft's audit catalog](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-network-policy-server) defines 6272 as grant, 6273 as deny, and 6274 as discard. [Microsoft's NPS troubleshooting guide](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/troubleshoot-network-policy-server) identifies 6273 reason code 16 as invalid credentials. The full reason string and a matched network policy are shown in a [published NPS reason-16 record](https://techcommunity.microsoft.com/discussions/windowsserver/aovpn--reasoncode-16/4479484).

The `EventData` names and per-event shape follow published Windows records: a [version-1 wireless 6272 record](https://airheads.hpe.com/discussion/server2008-r2-aruba-620-radius-issues) and an [independent complete 6272 XML export](https://al.twohill.nz/2018/Filtering-Windows-Event-Logs-and-Exporting-Into-Excel/), a [version-1 wireless 6273 XML record](https://learn.microsoft.com/en-us/answers/questions/2617618/network-policy-server-no-domain-controller-availab), and a [version-1 6274 XML record with reason code 1](https://learn.microsoft.com/en-us/answers/questions/1251168/network-policy-server-discarded-the-request-for-a). The 6274 capture is from a PEAP deployment rather than this sample Wi-Fi access point. [Elastic's Windows Security integration fixture](https://github.com/elastic/integrations/blob/main/packages/system/data_stream/security/_dev/test/pipeline/test-security-6272-nps-subject.json-expected.json) informs the ECS and `winlog` field layout; the XML remains the source record.

These captures establish 27, 27, and 25 `EventData` fields for the selected 6272, 6273, and 6274 variants respectively. The 6272 grant has quarantine fields and no reason fields; the 6274 discard has neither `MachineInventory` nor `LoggingResult`. Event IDs 6275-6280, NPS operational logs, and accounting files are outside this generator. Actual event rates and optional field values depend on Windows version, access point, authentication method, and policy. No client endpoint IP is synthesized from the RADIUS client IP.
