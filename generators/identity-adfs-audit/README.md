# Microsoft AD FS Audit Events

Security-log audit events of one Active Directory Federation Services farm node (Windows Server 2016 or later, basic audit level), as collected by NXLog `im_msvistalog` and wrapped in ECS. Each event keeps the NXLog JSON record verbatim in `event.original`: the Windows event fields plus the `Message` text with the `AuditBase` XML that AD FS attaches. The generator models about 500 users signing in from their workstations or, through a Web Application Proxy, from home, including mistyped passwords, give-ups, stale saved passwords and SSO token requests, at about 14,800 events a day. With `anomaly_mode: true` (default) it adds a recurring password-guessing episode that succeeds; with `anomaly_mode: false` it emits the same background only.

## Event Types

Approximate shares with default settings:

| Event ID | Event | Share | Category |
| --- | --- | --- | --- |
| `1200` | Application Token Success - token issued to a relying party (fresh sign-in or SSO) | 75.2% | `authentication` |
| `1202` | Fresh Credential Validation Success - password validated | 19.7% | `authentication` |
| `1203` | Fresh Credential Validation Error - password rejected | 3.5% | `authentication` |
| `1201` | Application Token Failure - token issuance failed | 1.6% | `authentication` |

Each fresh sign-in is zero or more `1203`, then a `1202` and its `1200` (same Activity ID), unless the user gives up. The SSO session then yields more `1200` events, each with its own Activity ID, for the user's usual relying parties. Remote sign-ins (about 35% of events) carry `NetworkLocation` `Extranet`, the proxy name and the forwarded client address.

## Volume and Timing

Event rate by hour of day (UTC), the same every day; daily volume varies by about 3%:

| Hours (UTC) | Events per second |
| --- | --- |
| 07:00-17:00 | 0.30 |
| 06:00-07:00, 17:00-19:00 | 0.15 |
| 19:00-22:00 | 0.09 |
| 22:00-06:00 | 0.05 |

Each user has at most one sign-in session at a time and signs in with a password three to eight times a day, more often the more active the user; 20-50% of a user's sign-ins are remote, from the user's home address. 91% of sign-ins are clean; 8% start with a burst of 1-8 mistyped passwords (each extra failure about a third as likely; the chance of finally getting the password right falls by a quarter per failure, otherwise the user gives up); 1% come from a device with a stale saved password that retries 2-14 times, tens of minutes apart. Failures of one burst are about 15 s apart (median). The `1202` and its first `1200` are a few seconds apart (median 4 s). SSO tokens follow at log-normal gaps (median 15 minutes) for up to 8 hours; sessions run longer in office hours. About 2% of tokens fail (`1201`). About 15% of password submissions fail.

## Anomaly Chain

Password guessing that succeeds from one of a user's usual addresses:

1. Five to eight `1203` for one `user.name` and `source.ip`, seconds apart.
2. `1202` for the same user and address: the password is accepted.
3. `1200` for the same user and address, same Activity ID as the `1202`, followed by ordinary SSO tokens for the user's relying parties.

**Linking fields:** `user.name` + `source.ip` (`adfs.audit.user_id` carries the typed UPN on 1201-1203 and `CORP\user` on 1200); `winlog.activity_id` joins the `1202` to its first token. Failures each have their own Activity ID.

**Recurrence:** by source time, every `anomaly_interval_hours` (default 24, allowed 2-720). The first start falls within min(interval, 24 h) of the first event, its hour drawn from the hour-of-day curve above. Each later start is due one interval after the actual previous start and falls at a random time in a window of w = min(interval/4, 6 h) centred on the due time, weighted by the squared hour curve plus a small floor, so starts drift toward busy hours and stay there; there is no catch-up. At intervals of 8 h or less the due times cover the whole clock, so some episodes start at night.

**Variation:** the user is drawn with the ordinary activity weights among users with no sign-in session in progress, and the previous episode's user is skipped; the episode is one more sign-in session of that user. Address (workstation or the home address via the proxy), device, relying parties, failure count, gaps and the SSO tokens follow the ordinary laws of that user. Every user, address, user-address pair and relying party in an episode also occurs in ordinary traffic of both modes.

**Background near misses:** repeated failures of one user and address within minutes, bursts of five or more failures, give-ups, and bursts followed by a validated password occur in both modes; five or more failures followed by a sign-in come mostly from stale saved passwords, whose sign-in usually follows an hour or more later. Within 15 minutes of the first of five or more failures of one user and address, a token that follows a validated password is denied (`1201`) instead of issued, about three times a day, in both modes; this also covers the tokens after an episode's own first token and any later sign-in of the same user and address in that window. Outside that window nothing changes.

**Detection idea:** per `user.name` + `source.ip`, five or more `1203` followed by `1202` and `1200` within 15 minutes. Background contains every part of this sequence, but only the episode completes it, once per episode.

**Modes:** `anomaly_mode: true` (default) adds the episodes; `anomaly_mode: false` emits background only, with no complete chain.

## Parameters

### Event Parameters

Set under `event.template.params` in `generator.yml`.

| Parameter | Default | Description |
| --- | --- | --- |
| `anomaly_mode` | `true` | Add the password-guessing episodes; `false` emits background only |
| `anomaly_interval_hours` | `24` | Episode recurrence interval in hours (2-720) |
| `federation_service` | `sts.corp.example` | Federation service name, used in `Server` and the fresh-credential `RelyingParty` |
| `host_name` | `adfs-01.corp.example` | AD FS server name (`Hostname`, `host.name`) |
| `proxy_server` | `wap-01` | Web Application Proxy name on extranet requests |
| `domain` | `CORP` | NetBIOS domain of users and of the service account |
| `service_account` | `gmsa-adfs$` | AD FS service account (`AccountName`) |
| `service_account_sid` | `S-1-5-21-3623811015-3361044348-30300820-1613` | Service account SID (`UserID`) |

Users come from `samples/users.json` (500 users, each with a workstation address and one home address), relying parties and their popularity from `samples/relying_parties.json`.

### Output Parameters

The shipped `generator.yml` writes to `output/events.json` and declares no `${params.*}` or `${secrets.*}`. To send events elsewhere, replace the `output` block and keep credentials in the Eventum keyring, for example:

```yaml
output:
  - opensearch:
      hosts:
        - ${params.opensearch_host}
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: adfs-audit
```

## Usage

```bash
# Live
eventum generate --path generators/identity-adfs-audit/generator.yml --id identity-adfs-audit --live-mode true

# Batch, as fast as possible
eventum generate --path generators/identity-adfs-audit/generator.yml --id identity-adfs-audit --live-mode false
```

The event rate and hour curve come from the four files in `patterns/`. They start at `2026-01-01T00:00:00Z` and never end, which suits live mode; for a batch run set a finite `end` (and, if needed, a later `start` at midnight UTC so the hour bands stay aligned) in all four files. To change the volume, scale the `ratio` of all four files together and the number of users in `samples/users.json` with it.

**Performance:** about 2,000 events/s on one CPU core (14 days, 207,653 events, in 105 s of CPU time).

## Sample Output

The completing `1200` of an episode, with default settings:

```json
{"@timestamp": "2026-09-01T04:54:45+00:00", "ecs": {"version": "8.17.0"}, "event": {"kind": "event", "module": "adfs", "dataset": "adfs.audit", "code": "1200", "action": "token-issued", "category": ["authentication"], "type": ["info"], "outcome": "success", "original": "{\"EventTime\":\"2026-09-01 04:54:45\",\"Hostname\":\"adfs-01.corp.example\",\"Keywords\":-9178336040581070848,\"EventType\":\"AUDIT_SUCCESS\",\"SeverityValue\":2,\"Severity\":\"INFO\",\"EventID\":1200,\"SourceName\":\"AD FS Auditing\",\"Task\":3,\"RecordNumber\":66897109,\"ProcessID\":0,\"ThreadID\":0,\"Channel\":\"Security\",\"Domain\":\"CORP\",\"AccountName\":\"gmsa-adfs$\",\"UserID\":\"S-1-5-21-3623811015-3361044348-30300820-1613\",\"AccountType\":\"User\",\"Message\":\"The Federation Service issued a valid token. See XML for details. \\r\\n\\r\\nActivity ID: 33f2a194-5b29-4517-bad1-aef1dd1e1abe \\r\\n\\r\\nAdditional Data \\r\\nXML: <?xml version=\\\"1.0\\\" encoding=\\\"utf-16\\\"?>\\r\\n<AuditBase xmlns:xsd=\\\"http://www.w3.org/2001/XMLSchema\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" xsi:type=\\\"AppTokenAudit\\\">\\r\\n  <AuditType>AppToken</AuditType>\\r\\n  <AuditResult>Success</AuditResult>\\r\\n  <FailureType>None</FailureType>\\r\\n  <ErrorCode>N/A</ErrorCode>\\r\\n  <ContextComponents>\\r\\n    <Component xsi:type=\\\"ResourceAuditComponent\\\">\\r\\n      <RelyingParty>https://hr.corp.example/</RelyingParty>\\r\\n      <ClaimsProvider>AD AUTHORITY</ClaimsProvider>\\r\\n      <UserId>CORP\\\\irina.lebedeva</UserId>\\r\\n    </Component>\\r\\n    <Component xsi:type=\\\"AuthNAuditComponent\\\">\\r\\n      <PrimaryAuth>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</PrimaryAuth>\\r\\n      <DeviceAuth>false</DeviceAuth>\\r\\n      <DeviceId>N/A</DeviceId>\\r\\n      <MfaPerformed>false</MfaPerformed>\\r\\n      <MfaMethod>N/A</MfaMethod>\\r\\n      <TokenBindingProvidedId>false</TokenBindingProvidedId>\\r\\n      <TokenBindingReferredId>false</TokenBindingReferredId>\\r\\n      <SsoBindingValidationLevel>NotSet</SsoBindingValidationLevel>\\r\\n    </Component>\\r\\n    <Component xsi:type=\\\"ProtocolAuditComponent\\\">\\r\\n      <OAuthClientId>N/A</OAuthClientId>\\r\\n      <OAuthGrant>N/A</OAuthGrant>\\r\\n    </Component>\\r\\n    <Component xsi:type=\\\"RequestAuditComponent\\\">\\r\\n      <Server>http://sts.corp.example/adfs/services/trust</Server>\\r\\n      <AuthProtocol>WSFederation</AuthProtocol>\\r\\n      <NetworkLocation>Extranet</NetworkLocation>\\r\\n      <IpAddress>192.0.2.107</IpAddress>\\r\\n      <ForwardedIpAddress>192.0.2.107</ForwardedIpAddress>\\r\\n      <ProxyIpAddress>N/A</ProxyIpAddress>\\r\\n      <NetworkIpAddress>N/A</NetworkIpAddress>\\r\\n      <ProxyServer>wap-01</ProxyServer>\\r\\n      <UserAgentString>Mozilla/5.0 (Linux; Android 11; SM-A217F Build/RP1A.200720.012; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/94.0.4606.85 Mobile Safari/537.36</UserAgentString>\\r\\n      <Endpoint>/adfs/ls/</Endpoint>\\r\\n    </Component>\\r\\n  </ContextComponents>\\r\\n</AuditBase>\",\"Opcode\":\"Info\",\"EventReceivedTime\":\"2026-09-01 04:54:46\",\"SourceModuleName\":\"in\",\"SourceModuleType\":\"im_msvistalog\"}"}, "message": "The Federation Service issued a valid token. See XML for details.", "host": {"name": "adfs-01.corp.example"}, "winlog": {"channel": "Security", "provider_name": "AD FS Auditing", "event_id": "1200", "record_id": 66897109, "activity_id": "33f2a194-5b29-4517-bad1-aef1dd1e1abe", "computer_name": "adfs-01.corp.example", "keywords": ["Audit Success", "Classic"]}, "user": {"name": "irina.lebedeva", "domain": "CORP"}, "source": {"ip": "192.0.2.107"}, "user_agent": {"original": "Mozilla/5.0 (Linux; Android 11; SM-A217F Build/RP1A.200720.012; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/94.0.4606.85 Mobile Safari/537.36"}, "related": {"user": ["irina.lebedeva"], "ip": ["192.0.2.107"]}, "adfs": {"audit": {"audit_type": "AppToken", "audit_result": "Success", "failure_type": "None", "error_code": "N/A", "relying_party": "https://hr.corp.example/", "claims_provider": "AD AUTHORITY", "user_id": "CORP\\irina.lebedeva", "primary_auth": "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport", "mfa_performed": false, "server": "http://sts.corp.example/adfs/services/trust", "auth_protocol": "WSFederation", "network_location": "Extranet", "ip_address": "192.0.2.107", "proxy_server": "wap-01", "endpoint": "/adfs/ls/", "forwarded_ip_address": "192.0.2.107"}}}
```

## Limitations

- No capture from a running AD FS server was available. The NXLog record layout and the `1201`/`1203` XML follow public intake fixtures; the `1200` XML follows Microsoft's published example; `1202` uses the `1203` layout with a successful result, and its message text comes from secondary sources.
- The record keeps the fixture's static fields (`Task` 3, `ProcessID`/`ThreadID` 0, `SourceModuleName` `in`). `Keywords` is Classic plus Audit Failure (0x8090000000000000, which the fixtures show rounded to -9182839640208441000) or Classic plus Audit Success (0x80A0000000000000, derived, no fixture). `EventTime` is written in UTC, as for a server in UTC.
- Only WS-Federation passive sign-in to `/adfs/ls/` with forms authentication is modelled: no WS-Trust, OAuth, SAML-P, MFA, device authentication, Extranet Smart Lockout (`1210`), password change or sign-out events, and no `1201` failure types other than `GenericError`.
- On extranet requests `IpAddress` and `ForwardedIpAddress` hold the single client address; a real proxy chain can list several.
- Fresh-credential events and `1201` name the federation service as relying party and carry the typed UPN, as in the fixtures; only `1200` names the requested relying party and `CORP\user`, as in Microsoft's example. `Endpoint` is `/adfs/ls/` on every record, as in the fixtures, so all records of one request agree; Microsoft's example writes `/adfs/ls`.
- Office hours are UTC with no weekday or weekend cycle; one server node, no farm load balancing.
- Records that AD FS writes within the same second (a `1202` and its first `1200`) are a few seconds apart here (median 4 s, up to about 3 minutes at night), and failures of one burst are at least a few seconds apart.
- Each user has one home address and at most one sign-in session at a time.
- The data starts with no open single sign-on sessions, so in about the first hour new password sign-ins (`1202`) make up a larger share of records (about 39% in the first hour against about 27-33% in the same hour on later days).
- The denial of tokens within 15 minutes of five or more failures (see Anomaly Chain) is a modelled policy, not documented AD FS behaviour.
- With `anomaly_mode: true` each episode adds its own records, so bursts of five or more failures followed by a sign-in within 15 minutes are about one per episode more frequent.

## References

- [Microsoft: Auditing enhancements to AD FS in Windows Server 2016](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/technical-reference/auditing-enhancements-to-ad-fs-in-windows-server)
- [Microsoft: Troubleshoot AD FS with events and logging](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/troubleshooting/ad-fs-tshoot-logging)
- [Microsoft Q&A: Event 1200 AppTokenAudit XML example](https://learn.microsoft.com/en-us/answers/questions/23405/adfs-possibility-to-determine-to-which-application)
- [Microsoft Entra Connect Health for AD FS: audit event names](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-health-adfs)
- [SEKOIA intake fixtures: NXLog AD FS 1201/1203 records](https://github.com/SEKOIA-IO/intake-formats/tree/main/Windows/windows/tests)
- [NXLog im_msvistalog module](https://docs.nxlog.co/refman/current/im/msvistalog.html)
- No Elastic integration exists for AD FS audit events; the ECS mapping is inferred.
