# FreeIPA Directory Server security log

Generates the security log that the 389 Directory Server of one FreeIPA server writes (`/var/log/dirsrv/slapd-<REALM>/security`, enabled by default in current 389-ds-base, per the main-branch source), as ECS JSON, for training SIEM content on LDAP password guessing, account misuse and authorization errors. `event.original` holds the native record byte for byte as 389-ds-base produces it (`slapi_log_security` and `slapi_log_security_tcp` in `log.c`, serialised by json-c: spaced layout, keys in source order, `/` escaped as `\/`, the `date` string with its trailing space); `freeipa.security.*` carries the same native keys except `date` and `utc_time` (which become `@timestamp`), and the other ECS fields are projections of them.

## Event Types

Shares over four days with the default settings (`anomaly_mode: true`, 33,232 records, about 8,300 a day):

| Native `event` | `msg` | Actor | Share | Category |
|---|---|---|---:|---|
| `BIND_SUCCESS` | empty | user (via an application) | 53.42% | authentication |
| `BIND_SUCCESS` | empty | service account | 34.43% | authentication |
| `BIND_FAILED` | `INVALID_PASSWORD` | user | 7.50% | authentication |
| `BIND_SUCCESS` | `ANONYMOUS_BIND` | anonymous (empty DN) | 2.12% | authentication |
| `BIND_FAILED` | `NO_SUCH_ENTRY` | mistyped user name | 0.74% | authentication |
| `AUTHZ_ERROR` | `target_dn=(...)` | user | 0.64% | iam |
| `BIND_FAILED` | `ACCOUNT_LOCKED` | disabled user | 0.46% | authentication |
| `TCP_ERROR` | `Bad Ber Tag or uncleanly closed connection - B1` | client address only | 0.24% | network |
| `BIND_SUCCESS` | empty | `cn=directory manager` | 0.18% | authentication |
| `AUTHZ_ERROR` | `target_dn=(...)` | service account | 0.13% | iam |
| `BIND_FAILED` | `INVALID_PASSWORD` | service account | 0.08% | authentication |
| `BIND_FAILED` | `INVALID_PASSWORD` | `cn=directory manager` | 0.03% | authentication |
| `TCP_ERROR` | `Ber peak tag - B3` / `Ber Too Big (nsslapd-maxbersize) - B2` | client address only | 0.01% | network |

The security log records simple binds, SASL EXTERNAL binds and their failures, authorization errors (`err=50`) and malformed or uncleanly closed connections. SASL/GSSAPI binds (SSSD clients, the IPA web framework) are not written to it, so the traffic here is the part of a FreeIPA directory that authenticates with passwords: applications that check user passwords by binding as the user, their lookup accounts under `cn=sysaccounts,cn=etc`, administrators using `cn=Directory Manager`, anonymous rootDSE reads, and stray clients. Users, applications, addresses and rates are an assumed mid-size organisation, not measured production data. Every user, application address and user|address pair the chain uses occurs in ordinary traffic in both modes. No field labels an episode.

## Volume and Activity

About 8,300 records a day. Two populations make them, with UTC hours:

| Population | 00-07 | 07-17 | 17-21 | 21-24 |
|---|---:|---:|---:|---:|
| People (user logins, administrators, anonymous binds), records/s | 0.017 | 0.108 | 0.047 | 0.017 |
| Automated clients (lookup accounts, disabled devices, stray connections), records/s | 0.036 | 0.036 | 0.036 | 0.036 |

Daily volume varies by about 3%. The organisation (200 users in `samples/users.csv`, each with 1-4 of the six LDAP-authenticating applications in `samples/applications.csv`, with fixed per-user and per-application weights) is the same in every run; behaviour is random.

- **User logins** (about 4,400 a day, 22 per user on average): a login picks a user by weight and one of that user's applications by weight; the application's address is `client_ip`. Each attempt is a new connection, op 1 behind StartTLS (GitLab, Grafana, VPN, portal) or op 0. 7% of logins start with 1-6 wrong passwords (weights 52/22/11/7/5/3, retyped after a median of about 20 s); after at most four the user usually gets in (90%), after five or six the user gives up. FreeIPA's default lockout applies to every user account: six failures, each within a minute of the previous one and across all applications, lock the account for 10 minutes, and a locked account produces no records until the lock expires. A user does not start a new login while another one is in progress, while locked, or right after five quick failures; failures still within a minute of earlier ones count towards the six, so such a login stops at the lockout and gives up once the quick failures reach five. About 7 accounts a day are locked this way. 1.2% start with a mistyped user name (`NO_SUCH_ENTRY`). 7% of self-service portal logins are followed on the same connection by a denied modification (`AUTHZ_ERROR`, own entry or a group).
- **Lookup accounts**: every application re-binds its `uid=<app>,cn=sysaccounts,cn=etc` account about every three minutes, any hour, on one of 2-4 pooled connections whose op numbers grow; a quarter of re-binds open a new connection. The provisioning account occasionally hits `AUTHZ_ERROR` on a user entry (about 9 a day).
- **Stale service password** (about one incident every two days): one application keeps reconnecting with an old password every ~40 s for a median 25 minutes; its pooled re-binds fail as well until the incident ends. Service accounts are not Kerberos principals, so the lockout does not apply to them and the failures go on for the whole incident.
- **Directory Manager**: about ten administrator sessions a day from the three admin hosts in `samples/admin_hosts.csv`, mostly in office hours, 20% starting with 1-4 typos, then 1-4 binds minutes apart; `root_dn` is `true` on every attempt, successful or not, as in `bind.c`.
- **Disabled accounts**: the two former users in `samples/disabled_accounts.csv` whose devices still try (`ACCOUNT_LOCKED`, about 20 bursts of 1-4 a day). These failures count towards the lockout as well, so a device never logs more than six of them within a minute of each other.
- **Anonymous binds** (`BIND_SUCCESS` / `ANONYMOUS_BIND`, empty DN, about 160 a day) and **TCP errors** (B1, rarely B3 and B2, about 27 a day) from monitoring, applications and workstations.

`conn_id` is one server-wide counter that grows between logged connections by the number of unlogged (GSSAPI) connections, so its step varies.

Ordinary traffic holds, per day, about 20-40 windows in which one DN failed five times from one address within 10 minutes without a success (about 29 on average), 16-31 logins that succeeded after exactly four wrong passwords (about 24), 260-450 wrong-password pairs by the same DN and address within 60 s (about 330), and 1-15 lockouts (about 7).

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the generator emits ordinary traffic only and the complete chain never occurs.

Sequence, all for one user U through one application A that U normally uses (so `client_ip` is A's address): five `BIND_FAILED` / `INVALID_PASSWORD` binds for U's DN, each on a new connection, then `BIND_SUCCESS` for the same DN, all within 10 minutes: password guessing through an application that stops one attempt short of FreeIPA's default lockout (six failures), and then gets in.

Linking fields: `dn` and `client_ip` in all six records; `conn_id` differs per attempt and grows; `op_id` is the application's usual 0 or 1; `root_dn` is `false`.

Recurrence: the first episode starts within min(`anomaly_interval_hours`, 24 h) of the start of generation, at an hour drawn from the people activity curve above. Every later episode is due one interval after the previous start and starts within a window of min(interval / 4, 6 h) centred on that due time, favouring busy hours strongly (squared activity plus a small floor), so start hours do not drift and a late episode never causes catch-up. At the default interval (24 h, window 6 h) about four in five episodes start in office hours (07-17 UTC), the rest in the evening or at night; an episode that starts late tends to be followed by others near the same hour. Consecutive episodes are about 21-27 h apart; at 8 h, about 7.4-9 h apart, including night starts. An episode spans about 1-4 minutes.

Variation: U differs from the previous episode's user and is picked by the same per-user weights as ordinary logins, and A by U's own application weights; a user in the middle of a login, with a recent wrong password at A, or with a wrong password anywhere in the last minute sits that moment out, so an episode never merges with a real login and its five failures never reach the lockout. Pauses between attempts follow the ordinary retype law; a portal episode can be followed by a denied modification like any portal login. U's own logins go on as usual during and after the episode. A bind changes no directory state, so there is nothing to restore.

Detection idea: five or more wrong passwords for one DN from one client within 10 minutes followed by a success (successful brute force under the lockout threshold). Each fragment occurs in ordinary traffic: repeated failures by the same DN and address within a minute, successes after one to four failures, five or six failures that end without success, and stale service passwords that fail for half an hour. Only the complete run is kept out of ordinary traffic: a login or re-bind that already had five wrong passwords for its DN and address in the preceding 10 minutes fails once more instead of succeeding (about three user logins and two lookup-account re-binds a day).

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

Live generation at the configured rate, until stopped:

```bash
eventum generate --path generators/identity-freeipa-security/generator.yml --id freeipa --live-mode true
```

Batch generation: set `start` and `end` of the `oscillator` in every `patterns/*.yml` file to the same range, with `start` at 00:00 UTC so the hour curve stays in place (for example `start: "2026-10-01T00:00:00Z"` and `end: "2026-10-08T00:00:00Z"`), then run:

```bash
eventum generate --path generators/identity-freeipa-security/generator.yml --id freeipa --live-mode false --keep-order true
```

The people hour curve is the sum of `patterns/people-base.yml`, `people-day.yml` and `people-office.yml`, each adding a flat rate over one UTC hour range; `patterns/service.yml` is the flat automated rate. To change the volume, scale the `ratio` of every pattern file by the same factor. Episode start hours follow the shipped curve even if you reshape the pattern files.

Performance: about 1,400 records/s on one core (14 days, 116,000 records, in 82 s).

## Limitations

- The record layout follows the 389-ds-base source (main branch, 2026) and two raw lines in the 389 DS design pages; no complete production capture from a FreeIPA server was available. Older 389-ds-base 2.x releases may differ in detail (for example `utc_time` as a whole number in the 2022 design example).
- After six quick failures (each within a minute of the previous one) a user account is locked for 10 minutes and produces no records: the directory refuses its binds before checking them and writes nothing to this log. Only the default global password policy is modelled (no per-group policies, no administrator unlocks), and Kerberos failures, which count towards the same lockout on a real server, are not part of this log. `ACCOUNT_LOCKED` stands for accounts disabled through `nsAccountLock`, not for the lockout.
- Only `SIMPLE` binds are generated. `SIMPLE/MFA` (OTP), `TLSCLIENTAUTH`, `LDAPI`, `CERT_MAP_FAILED` and `HAPROXY_SUCCESS` exist in the source but are not modelled.
- Retries within one login are a little slower than typical retyping: wrong passwords of one login follow each other after a median of about 20 s in office hours and 28 s at night.
- In ordinary traffic a DN and address never succeed after five wrong passwords within 10 minutes; a real directory also sees forgetful users do exactly that, so a detector for the chain has no false positives here.
- With `anomaly_mode: true` each episode adds its own records, so counts of the chain parts (runs of five wrong passwords by one DN and address, successes after wrong passwords) are about one per episode higher than in ordinary traffic.
- Clocks are UTC (`+0000`); one server; IPv4 only; the hour curve repeats every day, with no weekday cycle. Rates, users and applications are training assumptions.

## Sample Output

The success that completes an episode; the five wrong passwords for the same DN and address came at 15:44:54-15:46:03, each on a new `conn_id`:

```json
{"@timestamp": "2026-10-02T15:46:14.148Z", "ecs": {"version": "8.17.0"}, "event": {"action": "bind_success", "category": ["authentication"], "dataset": "freeipa.security", "kind": "event", "module": "freeipa", "original": "{ \"date\": \"[02\\/Oct\\/2026:15:46:14.148015846 +0000] \", \"utc_time\": \"1790955974.148015846\", \"event\": \"BIND_SUCCESS\", \"dn\": \"uid=thomas.scott,cn=users,cn=accounts,dc=example,dc=test\", \"bind_method\": \"SIMPLE\", \"root_dn\": false, \"client_ip\": \"10.20.3.13\", \"server_ip\": \"10.20.0.10\", \"ldap_version\": 3, \"conn_id\": 369251, \"op_id\": 1, \"msg\": \"\" }", "outcome": "success", "type": ["start"]}, "freeipa": {"security": {"bind_method": "SIMPLE", "client_ip": "10.20.3.13", "conn_id": 369251, "dn": "uid=thomas.scott,cn=users,cn=accounts,dc=example,dc=test", "event": "BIND_SUCCESS", "ldap_version": 3, "msg": "", "op_id": 1, "root_dn": false, "server_ip": "10.20.0.10"}}, "host": {"ip": ["10.20.0.10"], "name": "ipa-01.example.test"}, "log": {"file": {"path": "/var/log/dirsrv/slapd-EXAMPLE-TEST/security"}}, "related": {"ip": ["10.20.3.13", "10.20.0.10"], "user": ["thomas.scott"]}, "source": {"ip": "10.20.3.13"}, "user": {"name": "thomas.scott"}}
```

## References

- [389-ds-base `log.c`](https://github.com/389ds/389-ds-base/blob/main/ldap/servers/slapd/log.c): `slapi_log_security`, `slapi_log_security_tcp` - keys, order, `date` / `utc_time` formatting.
- [389-ds-base `bind.c`](https://github.com/389ds/389-ds-base/blob/main/ldap/servers/slapd/bind.c), [`result.c`](https://github.com/389ds/389-ds-base/blob/main/ldap/servers/slapd/result.c), [`slap.h`](https://github.com/389ds/389-ds-base/blob/main/ldap/servers/slapd/slap.h), [`disconnect_error_strings.h`](https://github.com/389ds/389-ds-base/blob/main/ldap/servers/slapd/disconnect_error_strings.h): which outcomes are logged, event and message constants.
- [389 DS: Security Audit log design](https://www.port389.org/docs/389ds/design/security-audit-log-design.html): purpose, fields, file location.
- [389 DS: MFA Operation Note](https://www.port389.org/docs/389ds/design/mfa-operation-note-design.html): a verbatim security-log line.
- [json-c `json_object.c`](https://github.com/json-c/json-c/blob/master/json_object.c): spaced output and `/` escaping.
- [FreeIPA: Directory Server](https://www.freeipa.org/page/Directory_Server): 389 DS as the FreeIPA LDAP backend.

No Elastic integration covers this log, so the ECS envelope is a projection of the native keys rather than a copy of an integration document. [KUMA 4.2 lists a FreeIPA normalizer](https://support.kaspersky.ru/kuma/4.2/255782), but its [collection instructions](https://support.kaspersky.ru/kuma/4.2/258520) wrap the access, audit, error, HTTP and Kerberos logs in an rsyslog envelope, not this file; compatibility with it is not established.
