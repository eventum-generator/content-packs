# FreeIPA Directory Server security log

Generates the security log that the 389 Directory Server of one FreeIPA server writes (`/var/log/dirsrv/slapd-<REALM>/security`, enabled by default in current 389-ds-base, per the main-branch source), as ECS JSON, for training SIEM content on LDAP password guessing, account misuse and authorization errors. `event.original` holds the native record byte for byte as 389-ds-base produces it (`slapi_log_security` and `slapi_log_security_tcp` in `log.c`, serialised by json-c: spaced layout, keys in source order, `/` escaped as `\/`, the `date` string with its trailing space); `freeipa.security.*` carries the same native keys except `date` and `utc_time` (which become `@timestamp`), and the other ECS fields are projections of them.

## Event Types

Shares measured on the final default capture (108 h, `anomaly_mode: true`, 9,657 records):

| Native `event` | `msg` | Actor | Share | Category |
|---|---|---|---:|---|
| `BIND_SUCCESS` | empty | user (via an application) | 43.11% (4163) | authentication |
| `BIND_SUCCESS` | empty | service account | 39.75% (3839) | authentication |
| `BIND_FAILED` | `INVALID_PASSWORD` | user | 6.29% (607) | authentication |
| `BIND_FAILED` | `INVALID_PASSWORD` | service account | 3.57% (345) | authentication |
| `BIND_SUCCESS` | `ANONYMOUS_BIND` | anonymous (empty DN) | 2.35% (227) | authentication |
| `BIND_FAILED` | `ACCOUNT_LOCKED` | disabled user | 2.09% (202) | authentication |
| `TCP_ERROR` | `Bad Ber Tag or uncleanly closed connection - B1` | client address only | 0.78% (75) | network |
| `BIND_FAILED` | `NO_SUCH_ENTRY` | mistyped user name | 0.59% (57) | authentication |
| `AUTHZ_ERROR` | `target_dn=(...)` | service account | 0.51% (49) | iam |
| `AUTHZ_ERROR` | `target_dn=(...)` | user | 0.45% (43) | iam |
| `BIND_SUCCESS` | empty | `cn=directory manager` | 0.40% (39) | authentication |
| `BIND_FAILED` | `INVALID_PASSWORD` | `cn=directory manager` | 0.05% (5) | authentication |
| `TCP_ERROR` | `Ber peak tag - B3` / `Ber Too Big (nsslapd-maxbersize) - B2` | client address only | 0.06% (6) | network |

The security log records simple binds, SASL EXTERNAL binds and their failures, authorization errors (`err=50`) and malformed or uncleanly closed connections. SASL/GSSAPI binds (SSSD clients, the IPA web framework) are not written to it, so the traffic here is the part of a FreeIPA directory that authenticates with passwords: applications that check user passwords by binding as the user, their lookup accounts under `cn=sysaccounts,cn=etc`, administrators using `cn=Directory Manager`, anonymous rootDSE reads, and stray clients. Users, applications, addresses and rates are an assumed mid-size organisation, not measured production data. Every user, application address and user|address pair the chain uses occurs in ordinary background in both modes. No field labels an episode.

## Background Model

Each one-second tick emits at most one record: the earliest due one, otherwise nothing. The organisation (44 users, each with 1-4 of six LDAP-authenticating applications and fixed random per-user and per-application weights) comes from a fixed seed; behaviour is random.

- **User logins**: one merged Poisson stream (0.011 per second, scaled by an office-hours factor: 07:00-17:00 UTC 1.80, 17:00-21:00 0.79, night 0.28). A login picks a user by weight and one of that user's applications by weight; the application's address is `client_ip`. Each attempt is a new connection, op 1 behind StartTLS (GitLab, Grafana, VPN, portal) or op 0. 7% of logins start with 1-6 wrong passwords (weights 52/22/11/7/5/3, gaps log-normal, median 12 s); after at most four the user usually gets in (90%), after five or six the user gives up. 1.2% start with a mistyped user name (`NO_SUCH_ENTRY`). 7% of self-service portal logins are followed on the same connection by a denied modification (`AUTHZ_ERROR`, own entry or a group).
- **Lookup accounts**: every application re-binds its `uid=<app>,cn=sysaccounts,cn=etc` account at random (Poisson, mean 10 min, any hour) on one of 2-4 pooled connections, whose op numbers grow; a quarter of re-binds open a new connection. The provisioning account occasionally hits `AUTHZ_ERROR` on a user entry.
- **Stale service password** (about one incident every two days): one application keeps reconnecting with an old password every ~40 s for a log-normal duration (median 25 min); its pooled re-binds fail as well until the incident ends.
- **Directory Manager**: about seven administrator sessions a day from three admin hosts, 20% starting with 1-4 typos, then 1-4 binds minutes apart; `root_dn` is `true` on every attempt, successful or not, as in `bind.c`.
- **Disabled accounts**: two former users whose devices still try (`ACCOUNT_LOCKED`, bursts of 1-4).
- **Anonymous binds** (`BIND_SUCCESS` / `ANONYMOUS_BIND`, empty DN) and **TCP errors** (B1, rarely B3 and B2) from monitoring, applications and workstations.

`conn_id` is one server-wide counter that grows between logged connections by the number of unlogged (GSSAPI) connections, so its step varies.

Over 108 h an `anomaly_mode: false` capture holds 22-27 windows in which one DN failed five times from one address within 10 minutes without a success, 19-39 logins that succeeded after exactly four wrong passwords, and 326-449 wrong-password pairs by the same DN and address within 60 s.

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the generator emits the background only and the complete chain never occurs.

Sequence, all for one user U through one application A that U normally uses (so `client_ip` is A's address): five `BIND_FAILED` / `INVALID_PASSWORD` binds for U's DN, each on a new connection, then `BIND_SUCCESS` for the same DN, all within 10 minutes: password guessing through an application that stops one attempt short of FreeIPA's default lockout (six failures), and then gets in.

Linking fields: `dn` and `client_ip` in all six records; `conn_id` differs per attempt and grows; `op_id` is the application's usual 0 or 1; `root_dn` is `false`.

Recurrence: an episode becomes due every `anomaly_interval_hours` of source time (default 24, minimum 6), first one interval after generation starts. At the due time the start is drawn within the following min(interval / 4, 6 h) - 6 h at the default - from the background load curve (clock-hour slots weighted by the office-hours factor and their length, uniform inside a slot), so episodes lean towards the hours of ordinary logins and start with a random delay after they are due; the gap between starts is one interval plus 0 to min(interval / 4, 6 h). The next due time counts from the actual start, so a late episode never causes catch-up. In the final captures episodes started at 05:53, 11:40 and 14:02 UTC at the default interval (gaps 29.8 and 26.4 h) and twelve times at 8 h (gaps 8.0-10.0 h); episodes spanned 39-158 s.

Variation: U differs from the previous episode's user and is picked by the same per-user weights as ordinary logins, and A by U's own application weights; a user with records still queued sits that moment out, so an episode never merges with a real login. Gaps follow the ordinary retry law; a portal episode can be followed by a denied modification like any portal login. A bind changes no directory state, so there is nothing to restore.

Detection idea: five or more wrong passwords for one DN from one client within 10 minutes followed by a success (successful brute force under the lockout threshold). Each fragment occurs in background: repeated failures by the same DN and address within a minute, successes after one to four failures, five or six failures that end without success, and stale service passwords that fail for half an hour. Only the complete run is kept out of the background: an ordinary success for a DN and address with five wrong passwords in the preceding 10 minutes is not written.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
|---|---|---|
| `anomaly_mode` | `true` | Add periodic episodes to the background |
| `anomaly_interval_hours` | `24` | Episode interval in source hours, 6-8760 |
| `server_host` | `ipa-01.example.test` | `host.name` of the FreeIPA server |
| `server_ip` | `10.20.0.10` | Server address (`server_ip`, `host.ip`) |
| `realm` | `EXAMPLE.TEST` | Kerberos realm; names the 389 DS instance in `log.file.path` |
| `directory_suffix` | `dc=example,dc=test` | Directory suffix of all DNs |

### Output Parameters

The shipped config writes `output/events.json` with the `json` formatter and needs no `${params.*}` or `${secrets.*}`. To send events elsewhere, replace the `output` section and put destination settings behind top-level placeholders, for example:

```yaml
output:
  - opensearch:
      hosts:
        - ${params.opensearch_host}
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: freeipa-security
```

A parser for the native log needs `event.original`, one JSON object per line.

## Usage

Live mode:

```bash
eventum generate --path generators/identity-freeipa-security/generator.yml --id freeipa --live-mode true
```

Batch mode needs a bounded input: add `start` and `end` to the `cron` input, then run:

```bash
eventum generate --path generators/identity-freeipa-security/generator.yml --id freeipa --live-mode false
```

## Limitations

- The record layout follows the 389-ds-base source (main branch, 2026) and two raw lines in the 389 DS design pages; no complete production capture from a FreeIPA server was available. Older 389-ds-base 2.x releases may differ in detail (for example `utc_time` as a whole number in the 2022 design example).
- FreeIPA's own lockout (`ipa-lockout`, six failures by default) rejects binds before 389 DS checks the password; whether those rejections reach the security log is not documented, so the background stops at six failures and lockout rejections are not modelled. `ACCOUNT_LOCKED` stands for accounts disabled through `nsAccountLock`.
- Only `SIMPLE` binds are generated. `SIMPLE/MFA` (OTP), `TLSCLIENTAUTH`, `LDAPI`, `CERT_MAP_FAILED` and `HAPROXY_SUCCESS` exist in the source but are not modelled.
- Clocks are UTC (`+0000`); one server; IPv4 only; one record per second at most. Rates, users and applications are training assumptions.

## Sample Output

The success that completes the first episode, copied byte for byte from the final default capture (line 2439; the five failures are lines 2433 and 2435-2438, each on a new `conn_id`):

```json
{"@timestamp": "2026-09-27T05:53:53.769Z", "ecs": {"version": "8.17.0"}, "event": {"action": "bind_success", "category": ["authentication"], "dataset": "freeipa.security", "kind": "event", "module": "freeipa", "original": "{ \"date\": \"[27\\/Sep\\/2026:05:53:53.769065469 +0000] \", \"utc_time\": \"1790488433.769065469\", \"event\": \"BIND_SUCCESS\", \"dn\": \"uid=liam.taylor,cn=users,cn=accounts,dc=example,dc=test\", \"bind_method\": \"SIMPLE\", \"root_dn\": false, \"client_ip\": \"10.20.3.15\", \"server_ip\": \"10.20.0.10\", \"ldap_version\": 3, \"conn_id\": 364118, \"op_id\": 0, \"msg\": \"\" }", "outcome": "success", "type": ["start"]}, "freeipa": {"security": {"bind_method": "SIMPLE", "client_ip": "10.20.3.15", "conn_id": 364118, "dn": "uid=liam.taylor,cn=users,cn=accounts,dc=example,dc=test", "event": "BIND_SUCCESS", "ldap_version": 3, "msg": "", "op_id": 0, "root_dn": false, "server_ip": "10.20.0.10"}}, "host": {"ip": ["10.20.0.10"], "name": "ipa-01.example.test"}, "log": {"file": {"path": "/var/log/dirsrv/slapd-EXAMPLE-TEST/security"}}, "related": {"ip": ["10.20.3.15", "10.20.0.10"], "user": ["liam.taylor"]}, "source": {"ip": "10.20.3.15"}, "user": {"name": "liam.taylor"}}
```

## References

- [389-ds-base `log.c`](https://github.com/389ds/389-ds-base/blob/main/ldap/servers/slapd/log.c): `slapi_log_security`, `slapi_log_security_tcp` - keys, order, `date` / `utc_time` formatting.
- [389-ds-base `bind.c`](https://github.com/389ds/389-ds-base/blob/main/ldap/servers/slapd/bind.c), [`result.c`](https://github.com/389ds/389-ds-base/blob/main/ldap/servers/slapd/result.c), [`slap.h`](https://github.com/389ds/389-ds-base/blob/main/ldap/servers/slapd/slap.h), [`disconnect_error_strings.h`](https://github.com/389ds/389-ds-base/blob/main/ldap/servers/slapd/disconnect_error_strings.h): which outcomes are logged, event and message constants.
- [389 DS: Security Audit log design](https://www.port389.org/docs/389ds/design/security-audit-log-design.html): purpose, fields, file location.
- [389 DS: MFA Operation Note](https://www.port389.org/docs/389ds/design/mfa-operation-note-design.html): a verbatim security-log line.
- [json-c `json_object.c`](https://github.com/json-c/json-c/blob/master/json_object.c): spaced output and `/` escaping.
- [FreeIPA: Directory Server](https://www.freeipa.org/page/Directory_Server): 389 DS as the FreeIPA LDAP backend.

No Elastic integration covers this log, so the ECS envelope is a projection of the native keys rather than a copy of an integration document. [KUMA 4.2 lists a FreeIPA normalizer](https://support.kaspersky.ru/kuma/4.2/255782), but its [collection instructions](https://support.kaspersky.ru/kuma/4.2/258520) wrap the access, audit, error, HTTP and Kerberos logs in an rsyslog envelope, not this file; compatibility with it is not established.
