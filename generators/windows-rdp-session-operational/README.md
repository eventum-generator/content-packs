# Windows RDP Session Operational

Remote Desktop session events from `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational`, represented as ECS JSON with native Windows XML in `event.original`.

## Run

```bash
eventum generate --path generators/windows-rdp-session-operational/generator.yml --id windows-rdp-session-operational --live-mode true
```

The continuous source writes to `output/events.json` relative to the pack. For a finite historical capture, set an explicit end time in both files under `patterns/` and use `--live-mode false --keep-order true`.

## Events and population

| ID | Meaning | Native UserData fields |
| --- | --- | --- |
| 21 | Session logon succeeded | User, SessionID, Address |
| 22 | Shell startup notification | User, SessionID, Address |
| 23 | Session logoff succeeded | User, SessionID |
| 24 | Session disconnected | User, SessionID, Address |
| 25 | Session reconnection succeeded | User, SessionID, Address |

One RDS host serves 200 domain accounts. Day operators use individual workstations, shift operators remain active overnight, and 20 administrators share four jump-host addresses. Administrators also appear in ordinary traffic. The dataset contains approximately 3,000 events per day, with higher volume between 08:00 and 18:00 UTC and small daily variation.

Each session has a stable user, address and SessionID. Logon precedes shell startup. Sessions either log off directly or disconnect first. Some disconnected sessions reconnect before logoff. Ordinary sessions last approximately 20 minutes to two hours, with overlapping sessions and up to two active sessions per account. Session IDs are reused over long runs. Correlate them with the host and the surrounding logon/logoff events.

`winlog.user_data` preserves all native fields for each selected event, including `xml_name: EventXML`. Event 23 has no Address field, so its JSON record has no `source.ip`. The XML preserves the provider GUID, channel, version, level, task, opcode, keyword mask, record ID, process/thread IDs and `Event_NS` UserData namespace. ActivityID links a session's selected events except reconnection, whose reference example has an empty Correlation element.

## Detection scenario

With `anomaly_mode: true`, five distinct accounts log on from one shared jump host to the RDS host within one hour. Group Event 21 by `host.name` and `source.ip`, then count distinct `winlog.user_data.User` values. Consecutive episodes rotate among the four administrator groups. All accounts and addresses also occur in background traffic, and their sessions follow the same disconnect, reconnect and logoff behavior.

The first episode starts within the first configured interval, capped at 24 hours. Later starts are centered on the interval after the preceding actual start, with a limited time variation and a preference for busier hours. The default is approximately one episode per day. With `anomaly_mode: false`, background sessions continue without completing the five-account sequence.

These records describe successful sessions. They do not include failed credential checks, process execution, network traffic or logon reasons. A shared jump host can produce this pattern during legitimate administration. The sequence alone does not prove compromise. Only remote IP sessions are modeled, not LOCAL addresses or the complete provider event catalog.

## Parameters

| Parameter | Default | Meaning |
| --- | --- | --- |
| `host_name` | `rds-01.corp.example` | RDS host name |
| `host_ip` | `10.170.0.21` | RDS host address |
| `anomaly_mode` | `true` | Include recurring multi-account logon episodes |
| `anomaly_interval_hours` | `24` | Approximate interval between episode starts, from 6 to 8,760 hours |

Accounts, addresses and population roles are in `samples/sessions.json`. Input volume and UTC active hours are in `patterns/`. No credentials or top-level output parameters are required for the local file output.

## Sample output

Captured Event 21 from this pack:

```json
{
  "@timestamp": "2026-09-01T00:00:37.464584+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "session-logon",
    "category": [
      "authentication",
      "session"
    ],
    "code": "21",
    "kind": "event",
    "original": "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Microsoft-Windows-TerminalServices-LocalSessionManager\" Guid=\"{5d896912-022d-40aa-a3a8-4fa5515c76d7}\"/><EventID>21</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x1000000000000000</Keywords><TimeCreated SystemTime=\"2026-09-01T00:00:37.4645845Z\"/><EventRecordID>40001</EventRecordID><Correlation ActivityID=\"{3b848838-005c-40b7-a0bf-283e9fb5c247}\"/><Execution ProcessID=\"3452\" ThreadID=\"432\"/><Channel>Microsoft-Windows-TerminalServices-LocalSessionManager/Operational</Channel><Computer>rds-01.corp.example</Computer><Security UserID=\"S-1-5-18\"/></System><UserData><EventXML xmlns=\"Event_NS\"><User>CORP\\operator156</User><SessionID>101</SessionID><Address>10.170.1.175</Address></EventXML></UserData></Event>",
    "provider": "Microsoft-Windows-TerminalServices-LocalSessionManager",
    "type": [
      "start"
    ]
  },
  "host": {
    "ip": [
      "10.170.0.21"
    ],
    "name": "rds-01.corp.example"
  },
  "log": {
    "level": "information"
  },
  "related": {
    "ip": [
      "10.170.1.175"
    ],
    "user": [
      "CORP\\operator156"
    ]
  },
  "source": {
    "ip": "10.170.1.175"
  },
  "user": {
    "domain": "CORP",
    "name": "operator156"
  },
  "winlog": {
    "activity_id": "{3b848838-005c-40b7-a0bf-283e9fb5c247}",
    "channel": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "computer_name": "rds-01.corp.example",
    "event_id": "21",
    "process": {
      "pid": 3452,
      "thread": {
        "id": 432
      }
    },
    "provider_guid": "{5d896912-022d-40aa-a3a8-4fa5515c76d7}",
    "provider_name": "Microsoft-Windows-TerminalServices-LocalSessionManager",
    "record_id": 40001,
    "user": {
      "identifier": "S-1-5-18"
    },
    "user_data": {
      "Address": "10.170.1.175",
      "SessionID": "101",
      "User": "CORP\\operator156",
      "xml_name": "EventXML"
    },
    "version": 0
  }
}
```

## References

- [Microsoft-published Event 21 XML](https://learn.microsoft.com/en-us/answers/questions/4053644/someone-has-a-remote-access-to-my-pc-how-to-block)
- [Microsoft-published Event 24 XML](https://learn.microsoft.com/es-mx/answers/questions/3153134/windows-10-filtrar-por-campo-usuario-en-el-visor-d)
- [EVTX provider maps and captured XML examples](https://github.com/EricZimmerman/evtx/tree/master/evtx/Maps)
- [Elastic Winlog fields](https://www.elastic.co/docs/reference/integrations/winlog)
- [Elastic Windows event XML decoding](https://www.elastic.co/docs/reference/fleet/decode_xml_wineventlog-processor)
