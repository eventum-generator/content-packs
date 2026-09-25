# Windows RDP Session Operational

Eventum content pack for the `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` Windows Event Log channel. Emits ECS JSON with the native XML event in `event.original`. Default `anomaly_mode: true` mixes background and a repeatable anomaly chain; `false` emits background only.

## Run

From the content-packs repository root:

```bash
eventum generate --path generators/windows-rdp-session-operational/generator.yml --id windows-rdp-session-operational --live-mode true
```

For a bounded batch sample, run `timeout 3s eventum generate --path generators/windows-rdp-session-operational/generator.yml --id windows-rdp-session-operational-batch --live-mode false` (exit code 124 is expected for this continuous source). The file output is `generators/windows-rdp-session-operational/output/events.json`.

## Events

| Event ID | Meaning | Frequency | ECS category |
| --- | --- | --- | --- |
| `21` | Session logon succeeded | 1 per session | `authentication` |
| `24` | Session disconnected | 1 per session | `session` |

## Anomaly Chain

Five distinct Windows accounts log on to the same RDP host from one source IP and disconnect, each with a separate SessionID. Group Event 21 by host.name and source.ip in a short window; alert on five distinct user.name values and use Event 24 with the same SessionID to bound each session.

Events 21 and 24 describe session logon/disconnect, not credential failures or command execution. The chain does not prove compromise; a shared administrative jump host can produce the same multi-account pattern. RDP source address may be LOCAL for local sessions; this pack models remote IP sessions.

## Parameters

### Event Parameters

| Parameter | Default | Meaning |
| --- | --- | --- |
| `host_name` | `rds-01.corp.example` | RDP host name |
| `host_ip` | `10.170.0.21` | RDP host address |
| `anomaly_ip` | `10.99.4.51` | Chain client address |
| `anomaly_users` | `['CORP\svc_backup', 'CORP\it_admin', 'CORP\finance_admin', 'CORP\hr_admin', 'CORP\domain_admin']` | Accounts used in chain |
| `anomaly_interval_sessions` | `50` | Routine sessions between chains |
| `anomaly_mode` | `true` | Enable chain; false emits background only |

### Output Parameters

No top-level `${params.*}` or `${secrets.*}` placeholders are shipped. Local file output works without credentials. Replace the `output` block with a destination plugin and keep credentials in Eventum secrets when forwarding events.

## Sample output

This complete event was captured from a run with `anomaly_mode: true`:

```json
{
  "@timestamp": "2026-09-25T13:05:03+00:00",
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
    "dataset": "windows.rdp_session_operational",
    "kind": "event",
    "original": "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Microsoft-Windows-TerminalServices-LocalSessionManager\" Guid=\"{5d896912-022d-40aa-a3a8-4fa5515c76d7}\"/><EventID>21</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x1000000000000000</Keywords><TimeCreated SystemTime=\"2026-09-25T13:05:03.0000000Z\"/><EventRecordID>40101</EventRecordID><Correlation ActivityID=\"{5d4d5a90-98a3-4694-bd02-67b7fef72e24}\"/><Execution ProcessID=\"1152\" ThreadID=\"1636\"/><Channel>Microsoft-Windows-TerminalServices-LocalSessionManager/Operational</Channel><Computer>rds-01.corp.example</Computer><Security UserID=\"S-1-5-18\"/></System><UserData><EventXML xmlns=\"Event_NS\"><User>CORP\\svc_backup</User><SessionID>151</SessionID><Address>10.99.4.51</Address></EventXML></UserData></Event>",
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
  "message": "Remote Desktop Services: Session logon succeeded",
  "related": {
    "ip": [
      "10.99.4.51"
    ],
    "user": [
      "CORP\\svc_backup"
    ]
  },
  "source": {
    "ip": "10.99.4.51"
  },
  "tags": [
    "rdp-session-operational",
    "preserve_original_event"
  ],
  "user": {
    "name": "CORP\\svc_backup"
  },
  "windows": {
    "rdp_session": {
      "address": "10.99.4.51",
      "session_id": 151,
      "user": "CORP\\svc_backup"
    }
  },
  "winlog": {
    "activity_id": "{5d4d5a90-98a3-4694-bd02-67b7fef72e24}",
    "channel": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "event_id": 21,
    "provider_name": "Microsoft-Windows-TerminalServices-LocalSessionManager",
    "record_id": 40101
  }
}
```

## Format and references

Selected reference-field coverage: 3/3 UserData fields for Events 21 and 24. Event 21 and 24 retain the three published UserData/EventXML fields: User, SessionID and Address. Logon/disconnect pairs reuse a SessionID; separate sessions get distinct IDs. Fifty routine user/address samples vary the background.

- [Microsoft-published Event 21 XML](https://learn.microsoft.com/en-us/answers/questions/4053644/someone-has-a-remote-access-to-my-pc-how-to-block)
- [Microsoft-published Event 24 XML](https://learn.microsoft.com/es-mx/answers/questions/3153134/windows-10-filtrar-por-campo-usuario-en-el-visor-d)
- [Microsoft RDP logon semantics](https://learn.microsoft.com/en-us/answers/questions/486771/how-to-collect-rdp-access-logs-for-my-windows-mach)
- [Kaspersky KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)
