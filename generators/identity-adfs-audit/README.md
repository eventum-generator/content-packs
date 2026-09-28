# Microsoft AD FS Audit Events

Security-log audit events of one Active Directory Federation Services farm node (Windows Server 2016 or later, basic audit level), as collected by NXLog `im_msvistalog` and wrapped in ECS. Each event keeps the NXLog JSON record verbatim in `event.original`: the Windows event fields plus the `Message` text with the `AuditBase` XML that AD FS attaches. The generator models about 150 users signing in from their workstations or, through a Web Application Proxy, from home, including mistyped passwords, give-ups, stale saved passwords and SSO token requests. With `anomaly_mode: true` (default) it adds a recurring password-guessing episode that succeeds; with `anomaly_mode: false` it emits the same background only.

## Event Types

Shares measured on a 120 h default capture (`anomaly_mode: true`, 9,433 events).

| Event ID | Event | Share | Category |
| --- | --- | --- | --- |
| `1200` | Application Token Success - token issued to a relying party (fresh sign-in or SSO) | 64.3% | `authentication` |
| `1202` | Fresh Credential Validation Success - password validated | 26.9% | `authentication` |
| `1203` | Fresh Credential Validation Error - password rejected | 7.4% | `authentication` |
| `1201` | Application Token Failure - token issuance failed | 1.5% | `authentication` |

Each fresh sign-in is zero or more `1203`, then a `1202` and its `1200` (same Activity ID), unless the user gives up. The SSO session then yields more `1200` events, each with its own Activity ID, for the user's usual relying parties over up to 8 hours. Remote sign-ins carry `NetworkLocation` `Extranet`, the proxy name and the forwarded client address.

Background behaviour, per user and independent of other users: lognormal idle gaps between fresh sign-ins, thinned by a UTC office-hours curve; 86% of sign-ins are clean, 12% start with a burst of 1-8 mistyped passwords seconds apart (each extra failure about a third as likely; the chance of finally getting the password right falls by a quarter per failure, otherwise the user gives up), 2% come from a device with a stale saved password retrying every few tens of minutes. About 2% of token requests fail (`1201`).

## Anomaly Chain

Password guessing that succeeds from one of a user's usual addresses:

1. Five to eight `1203` for one `user.name` and `source.ip`, seconds apart.
2. `1202` for the same user and address: the password is accepted.
3. `1200` for the same user and address, same Activity ID as the `1202`, followed by ordinary SSO tokens for the user's relying parties.

**Linking fields:** `user.name` + `source.ip` (`adfs.audit.user_id` carries the typed UPN on 1201-1203 and `CORP\user` on 1200); `winlog.activity_id` joins the `1202` to its first token. Failures each have their own Activity ID.

**Recurrence:** by source time, every `anomaly_interval_hours` (default 24, allowed 2-720). The first start falls within min(interval, 24 h) of the first event, its hour drawn from the background hour-of-day curve. Each later start is due one interval after the actual previous start and falls at a random time in a window of w = min(interval/4, 6 h) centred on the due time, weighted by the squared hour curve plus a small floor, so starts stay in busy hours; there is no catch-up. At intervals of 8 h or less the due times cover the whole clock, so some episodes start at night. Measured: default 5 episodes in 120 h at 07:17, 07:12, 07:52, 08:11, 08:59 UTC (gaps 23.9-24.8 h); 8 h interval 15 episodes (gaps 7.1-8.6 h; 7 office, 3 shoulder, 5 night hours).

**Variation:** the user is drawn with the background activity weights among idle users whose own next sign-in comes after the episode, and the previous episode's user is skipped; address (workstation or a home address via the proxy), device, relying parties, failure count, gaps and the SSO tail follow the background laws of that user. Every user, address, user-address pair and relying party in an episode also occurs in ordinary traffic of both modes.

**Background near misses:** repeated failures of one user and address within minutes (934 failure pairs within 5 minutes in 5 x 120 h off captures), bursts of five or more failures, give-ups, and bursts followed by a validated password occur in both modes. Five or more failures followed by a sign-in within 900 s are a thin tail of the typo law; five or more followed by a sign-in later come from stale saved passwords. A background token that would complete the chain (five failures, a `1202` and a `1200` of one user and address within 900 s of the first failure) is denied at its own time (`1201`); outside the window nothing changes. Measured over 5 x 120 h off captures, first tokens after five or more failures and a `1202`: 10 within 900 s, all denied by this guard; 161 beyond 900 s (2 at 15-20 min, 1 at 20-30 min, 6 at 30-60 min, 84 at 1-2 h, 68 later), 3 of them denied at the 2% base rate. The guard's denials are about 2.0 per 120 h in either mode; the denial itself is a modelled policy, not documented AD FS behaviour.

**Detection idea:** per `user.name` + `source.ip`, five or more `1203` followed by `1202` and `1200` within 15 minutes. Background contains every part of this sequence, but only the episode completes it.

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

Users and addresses come from `samples/users.json`, relying parties and their popularity from `samples/relying_parties.json`.

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
# Live, one tick per second
eventum generate --path generators/identity-adfs-audit/generator.yml --id identity-adfs-audit --live-mode true

# Batch, as fast as possible (add start/end to the cron input for a bounded range)
eventum generate --path generators/identity-adfs-audit/generator.yml --id identity-adfs-audit --live-mode false
```

## Sample Output

The final `1200` of the first episode, copied from a default-mode capture:

```json
{"@timestamp": "2026-03-02T07:18:40+00:00", "ecs": {"version": "8.17.0"}, "event": {"kind": "event", "module": "adfs", "dataset": "adfs.audit", "code": "1200", "action": "token-issued", "category": ["authentication"], "type": ["info"], "outcome": "success", "original": "{\"EventTime\":\"2026-03-02 07:18:40\",\"Hostname\":\"adfs-01.corp.example\",\"Keywords\":-9178336040581070848,\"EventType\":\"AUDIT_SUCCESS\",\"SeverityValue\":2,\"Severity\":\"INFO\",\"EventID\":1200,\"SourceName\":\"AD FS Auditing\",\"Task\":3,\"RecordNumber\":60039641,\"ProcessID\":0,\"ThreadID\":0,\"Channel\":\"Security\",\"Domain\":\"CORP\",\"AccountName\":\"gmsa-adfs$\",\"UserID\":\"S-1-5-21-3623811015-3361044348-30300820-1613\",\"AccountType\":\"User\",\"Message\":\"The Federation Service issued a valid token. See XML for details. \\r\\n\\r\\nActivity ID: 9bfa2086-82e9-4410-a4e7-e185e2d8fa25 \\r\\n\\r\\nAdditional Data \\r\\nXML: <?xml version=\\\"1.0\\\" encoding=\\\"utf-16\\\"?>\\r\\n<AuditBase xmlns:xsd=\\\"http://www.w3.org/2001/XMLSchema\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" xsi:type=\\\"AppTokenAudit\\\">\\r\\n  <AuditType>AppToken</AuditType>\\r\\n  <AuditResult>Success</AuditResult>\\r\\n  <FailureType>None</FailureType>\\r\\n  <ErrorCode>N/A</ErrorCode>\\r\\n  <ContextComponents>\\r\\n    <Component xsi:type=\\\"ResourceAuditComponent\\\">\\r\\n      <RelyingParty>https://intranet.corp.example/</RelyingParty>\\r\\n      <ClaimsProvider>AD AUTHORITY</ClaimsProvider>\\r\\n      <UserId>CORP\\\\adam.petrova</UserId>\\r\\n    </Component>\\r\\n    <Component xsi:type=\\\"AuthNAuditComponent\\\">\\r\\n      <PrimaryAuth>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</PrimaryAuth>\\r\\n      <DeviceAuth>false</DeviceAuth>\\r\\n      <DeviceId>N/A</DeviceId>\\r\\n      <MfaPerformed>false</MfaPerformed>\\r\\n      <MfaMethod>N/A</MfaMethod>\\r\\n      <TokenBindingProvidedId>false</TokenBindingProvidedId>\\r\\n      <TokenBindingReferredId>false</TokenBindingReferredId>\\r\\n      <SsoBindingValidationLevel>NotSet</SsoBindingValidationLevel>\\r\\n    </Component>\\r\\n    <Component xsi:type=\\\"ProtocolAuditComponent\\\">\\r\\n      <OAuthClientId>N/A</OAuthClientId>\\r\\n      <OAuthGrant>N/A</OAuthGrant>\\r\\n    </Component>\\r\\n    <Component xsi:type=\\\"RequestAuditComponent\\\">\\r\\n      <Server>http://sts.corp.example/adfs/services/trust</Server>\\r\\n      <AuthProtocol>WSFederation</AuthProtocol>\\r\\n      <NetworkLocation>Intranet</NetworkLocation>\\r\\n      <IpAddress>10.20.12.152</IpAddress>\\r\\n      <ForwardedIpAddress />\\r\\n      <ProxyIpAddress>N/A</ProxyIpAddress>\\r\\n      <NetworkIpAddress>N/A</NetworkIpAddress>\\r\\n      <ProxyServer>N/A</ProxyServer>\\r\\n      <UserAgentString>Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.80</UserAgentString>\\r\\n      <Endpoint>/adfs/ls/</Endpoint>\\r\\n    </Component>\\r\\n  </ContextComponents>\\r\\n</AuditBase>\",\"Opcode\":\"Info\",\"EventReceivedTime\":\"2026-03-02 07:18:40\",\"SourceModuleName\":\"in\",\"SourceModuleType\":\"im_msvistalog\"}"}, "message": "The Federation Service issued a valid token. See XML for details.", "host": {"name": "adfs-01.corp.example"}, "winlog": {"channel": "Security", "provider_name": "AD FS Auditing", "event_id": "1200", "record_id": 60039641, "activity_id": "9bfa2086-82e9-4410-a4e7-e185e2d8fa25", "computer_name": "adfs-01.corp.example", "keywords": ["Audit Success", "Classic"]}, "user": {"name": "adam.petrova", "domain": "CORP"}, "source": {"ip": "10.20.12.152"}, "user_agent": {"original": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.80"}, "related": {"user": ["adam.petrova"], "ip": ["10.20.12.152"]}, "adfs": {"audit": {"audit_type": "AppToken", "audit_result": "Success", "failure_type": "None", "error_code": "N/A", "relying_party": "https://intranet.corp.example/", "claims_provider": "AD AUTHORITY", "user_id": "CORP\\adam.petrova", "primary_auth": "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport", "mfa_performed": false, "server": "http://sts.corp.example/adfs/services/trust", "auth_protocol": "WSFederation", "network_location": "Intranet", "ip_address": "10.20.12.152", "proxy_server": "N/A", "endpoint": "/adfs/ls/"}}}
```

## Limitations

- No capture from a running AD FS server was available. The NXLog record layout and the `1201`/`1203` XML follow public intake fixtures; the `1200` XML follows Microsoft's published example; `1202` uses the `1203` layout with a successful result, and its message text comes from secondary sources.
- The record keeps the fixture's static fields (`Task` 3, `ProcessID`/`ThreadID` 0, `SourceModuleName` `in`). `Keywords` is Classic plus Audit Failure (0x8090000000000000, which the fixtures show rounded to -9182839640208441000) or Classic plus Audit Success (0x80A0000000000000, derived, no fixture). `EventTime` is written in UTC, as for a server in UTC.
- Only WS-Federation passive sign-in to `/adfs/ls/` with forms authentication is modelled: no WS-Trust, OAuth, SAML-P, MFA, device authentication, Extranet Smart Lockout (`1210`), password change or sign-out events, and no `1201` failure types other than `GenericError`.
- On extranet requests `IpAddress` and `ForwardedIpAddress` hold the single client address; a real proxy chain can list several.
- Fresh-credential events and `1201` name the federation service as relying party and carry the typed UPN, as in the fixtures; only `1200` names the requested relying party and `CORP\user`, as in Microsoft's example. `Endpoint` is `/adfs/ls/` on every record, as in the fixtures, so all records of one request agree; Microsoft's example writes `/adfs/ls`.
- Office hours are UTC with no weekday cycle; one server node, no farm load balancing.
- The background denial of chain-completing tokens is a modelling device (see Anomaly Chain): the rare in-window completions are all denied, while sign-ins after long stale-password runs are denied only at the 2% base rate.

## References

- [Microsoft: Auditing enhancements to AD FS in Windows Server 2016](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/technical-reference/auditing-enhancements-to-ad-fs-in-windows-server)
- [Microsoft: Troubleshoot AD FS with events and logging](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/troubleshooting/ad-fs-tshoot-logging)
- [Microsoft Q&A: Event 1200 AppTokenAudit XML example](https://learn.microsoft.com/en-us/answers/questions/23405/adfs-possibility-to-determine-to-which-application)
- [Microsoft Entra Connect Health for AD FS: audit event names](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-health-adfs)
- [SEKOIA intake fixtures: NXLog AD FS 1201/1203 records](https://github.com/SEKOIA-IO/intake-formats/tree/main/Windows/windows/tests)
- [NXLog im_msvistalog module](https://docs.nxlog.co/refman/current/im/msvistalog.html)
- No Elastic integration exists for AD FS audit events; the ECS mapping is inferred.
