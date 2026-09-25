# Microsoft AD FS Event XML

Eventum content pack for AD FS Security Event 1200 XML. Emits ECS JSON with the native source record in `event.original`. The native parsed fields are under the source namespace. Default mode includes background and a repeatable anomaly chain; `anomaly_mode: false` emits background only.

## Run

From the content-packs repository root:

```bash
eventum generate --path generators/identity-adfs-audit/generator.yml --id identity-adfs-audit --live-mode true
```

For a bounded local batch sample, run `timeout 3s eventum generate --path generators/identity-adfs-audit/generator.yml --id identity-adfs-audit-batch --live-mode false` (timeout exit code 124 is expected for this continuous source).

The file output is `generators/identity-adfs-audit/output/events.json`. Set `event.template.params.anomaly_mode: false` to generate only routine activity. The generator emits one event per input tick; timing depends on the Eventum input configuration.

## Events

| Native event | Meaning | Frequency | ECS category |
| --- | --- | --- | --- |
| `1200` | Successful token issuance | 1 per routine tick; 5 per chain | `authentication` |

## Anomaly Chain

One user and client address receive five successful tokens for five distinct relying parties in a short window, each with its own Activity ID. Group Event 1200 by user.name and source.ip in a short window; alert when the count of distinct adfs.audit.relying_party values rises to five. Do not group the separate token requests by winlog.activity_id.

This generator implements only successful token issuance Event 1200. It does not claim to model Event 1201/1202/1203 or failed logins because a complete vendor-published XML payload for those events was not verified. The AppTokenAudit inner XML follows the published Microsoft example; placement inside the generic Windows EventData envelope is a conservative model. Activity ID is unique per request and does not join the five requests.

## Parameters

### Event Parameters

| Parameter | Default | Meaning |
| --- | --- | --- |
| `server_name` | `adfs-01.corp.example` | Federation server name |
| `anomaly_user` | `CORP\finance_admin` | Chain principal |
| `anomaly_ip` | `10.99.4.51` | Chain client address |
| `anomaly_interval_events` | `250` | Routine events between chains |
| `anomaly_mode` | `true` | Enable chain; false emits background only |

### Output Parameters

No top-level `${params.*}` or `${secrets.*}` placeholders are shipped. The file output works without credentials. To send to another destination, replace the `output` block with that plugin configuration and keep credentials in Eventum secrets.

## Sample output

This event was captured from an actual generator run with `anomaly_mode: true`:

```json
{
  "@timestamp": "2026-09-25T12:43:46+00:00",
  "adfs": {
    "audit": {
      "activity_id": "{6e65d788-1692-4bc0-8e27-15dffa73c8f1}",
      "audit_result": "Success",
      "audit_type": "AppToken",
      "ip_address": "10.99.4.51",
      "relying_party": "urn:corp:admin",
      "user_id": "CORP\\finance_admin"
    }
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "token-issued",
    "category": [
      "authentication"
    ],
    "code": "1200",
    "dataset": "adfs.audit",
    "kind": "event",
    "original": "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"AD FS Auditing\"/><EventID>1200</EventID><Version>0</Version><Level>0</Level><Task>3</Task><Opcode>0</Opcode><TimeCreated SystemTime=\"2026-09-25T12:43:46+00:00\"/><EventRecordID>10255</EventRecordID><Correlation ActivityID=\"{6e65d788-1692-4bc0-8e27-15dffa73c8f1}\"/><Channel>Security</Channel><Computer>adfs-01.corp.example</Computer></System><EventData><Data>{6e65d788-1692-4bc0-8e27-15dffa73c8f1}</Data><Data>&lt;AuditBase xmlns:xsd=&#34;http://www.w3.org/2001/XMLSchema&#34; xmlns:xsi=&#34;http://www.w3.org/2001/XMLSchema-instance&#34; xsi:type=&#34;AppTokenAudit&#34;&gt;&lt;AuditType&gt;AppToken&lt;/AuditType&gt;&lt;AuditResult&gt;Success&lt;/AuditResult&gt;&lt;FailureType&gt;None&lt;/FailureType&gt;&lt;ErrorCode&gt;N/A&lt;/ErrorCode&gt;&lt;ContextComponents&gt;&lt;Component xsi:type=&#34;ResourceAuditComponent&#34;&gt;&lt;RelyingParty&gt;urn:corp:admin&lt;/RelyingParty&gt;&lt;ClaimsProvider&gt;AD AUTHORITY&lt;/ClaimsProvider&gt;&lt;UserId&gt;CORP\\finance_admin&lt;/UserId&gt;&lt;/Component&gt;&lt;Component xsi:type=&#34;AuthNAuditComponent&#34;&gt;&lt;PrimaryAuth&gt;urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport&lt;/PrimaryAuth&gt;&lt;DeviceAuth&gt;false&lt;/DeviceAuth&gt;&lt;DeviceId&gt;N/A&lt;/DeviceId&gt;&lt;MfaPerformed&gt;false&lt;/MfaPerformed&gt;&lt;MfaMethod&gt;N/A&lt;/MfaMethod&gt;&lt;TokenBindingProvidedId&gt;true&lt;/TokenBindingProvidedId&gt;&lt;TokenBindingReferredId&gt;false&lt;/TokenBindingReferredId&gt;&lt;SsoBindingValidationLevel&gt;TokenBoundAndValid&lt;/SsoBindingValidationLevel&gt;&lt;/Component&gt;&lt;Component xsi:type=&#34;ProtocolAuditComponent&#34;&gt;&lt;OAuthClientId&gt;N/A&lt;/OAuthClientId&gt;&lt;OAuthGrant&gt;N/A&lt;/OAuthGrant&gt;&lt;/Component&gt;&lt;Component xsi:type=&#34;RequestAuditComponent&#34;&gt;&lt;Server&gt;https://adfs-01.corp.example/adfs/services/trust&lt;/Server&gt;&lt;AuthProtocol&gt;WSFederation&lt;/AuthProtocol&gt;&lt;NetworkLocation&gt;Intranet&lt;/NetworkLocation&gt;&lt;IpAddress&gt;10.99.4.51&lt;/IpAddress&gt;&lt;ForwardedIpAddress /&gt;&lt;ProxyIpAddress&gt;N/A&lt;/ProxyIpAddress&gt;&lt;NetworkIpAddress&gt;N/A&lt;/NetworkIpAddress&gt;&lt;ProxyServer&gt;N/A&lt;/ProxyServer&gt;&lt;UserAgentString&gt;Mozilla/5.0&lt;/UserAgentString&gt;&lt;Endpoint&gt;/adfs/ls&lt;/Endpoint&gt;&lt;/Component&gt;&lt;/ContextComponents&gt;&lt;/AuditBase&gt;</Data></EventData></Event>",
    "outcome": "success",
    "type": [
      "allowed"
    ]
  },
  "host": {
    "name": "adfs-01.corp.example"
  },
  "message": "The Federation Service issued a valid token. See XML for details.",
  "related": {
    "ip": [
      "10.99.4.51"
    ],
    "user": [
      "CORP\\finance_admin"
    ]
  },
  "source": {
    "ip": "10.99.4.51"
  },
  "tags": [
    "adfs-audit",
    "preserve_original_event"
  ],
  "user": {
    "name": "CORP\\finance_admin"
  },
  "winlog": {
    "activity_id": "{6e65d788-1692-4bc0-8e27-15dffa73c8f1}",
    "channel": "Security",
    "event_id": 1200,
    "provider_name": "AD FS Auditing",
    "record_id": 10255
  }
}
```

## Format and references

The native XML includes the Event 1200 ID and published AppTokenAudit result, relying party, user and client address fields (5/5 key fields used by this scenario). The full documented AppTokenAudit inner payload is retained in event.original.

Windows Event XML with the documented AppTokenAudit content is retained in event.original. Each token issue has its own EventRecordID and Activity ID. Fifty relying-party samples vary routine users, client addresses and applications.

- [Microsoft AD FS troubleshooting and event IDs](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/troubleshooting/ad-fs-tshoot-logging)
- [Microsoft published Event 1200 AppTokenAudit XML](https://learn.microsoft.com/en-us/answers/questions/23405/adfs-possibility-to-determine-to-which-application)
- [Kaspersky KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)
