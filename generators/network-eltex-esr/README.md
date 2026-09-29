# Eltex ESR Router Syslog

Generates Eltex ESR-series (software 1.40) remote syslog records as ECS JSON for training SIEM content on router administration and firewall logs. `event.original` holds the RFC 5424 frame and `message` the documented `%GROUP-SEVERITY-MNEMONIC: text` body. The source is one router with two local SSH administrators, an automated backup and monitoring account, five temporary local accounts and a small fixed IPv4 traffic inventory.

## Event Types

Approximate shares with the default settings and `anomaly_mode: true` (about 8,900 records a day).

| Native message | `event.action` | Share | Category |
|---|---|---:|---|
| `%FIREWALL-I-LOG` | `firewall_permitted` | 59.09% (34160) | Network |
| `%FIREWALL-I-LOG` | `firewall_denied` | 19.21% (11106) | Network |
| `%NAT-I-LOG` | `snat_translation` | 14.29% (8263) | Network |
| `%IPS-I-INFO` | `ips_drop` | 1.45% (836) | Intrusion detection |
| `%AAA-I-SSH` | `ssh_password_accepted` | 1.31% (756) | Authentication |
| `%AAA-LOCAL-I-SESSION` | `session_opened` | 1.31% (756) | Authentication |
| `%AAA-LOCAL-I-SESSION` | `session_closed` | 1.31% (756) | Authentication |
| `%SYS-W-EVENT` | `configuration_applied` | 0.54% (313) | Configuration |
| `%TIME-I-INFO` | `system_time_changed` | 0.32% (186) | Configuration |
| `%USER-I-INFO` | `user_privilege_changed` | 0.29% (169) | IAM |
| `%USER-I-INFO` | `enable_password_changed` | 0.29% (165) | IAM, configuration |
| `%USER-I-ADD` | `user_created` | 0.23% (135) | IAM |
| `%USER-I-ADD` | `user_removed` | 0.23% (133) | IAM |
| `%AAA-I-SSH` | `ssh_password_failed` | 0.07% (38) | Authentication |
| `%USER-I-INFO` | `user_password_changed` | 0.06% (37) | IAM |

Of the 756 successful logins, 308 are the automation account, 220 the two administrators and 228 the temporary accounts.

Every action, both administrators, both administrator addresses, the automation account and all five temporary accounts occur in ordinary background in both modes. No field labels an episode.

## Volume and Timing

About 8,900 records a day, by hour of the generator timezone (UTC by default): 609 an hour in 06:00-16:00, 336 in 16:00-20:00 and 147 at night. Each day's volume varies by up to 10%, and records are spread at random within each band. SSH and maintenance records are part of this volume; firewall, NAT and IPS records make up the rest, so the total does not depend on how busy the administrators are.

Administrator activity and temporary-account logins follow the same hourly curve (1.64 / 0.91 / 0.40 of the daily mean); automated logins are flat around the clock. Steps of one session are seconds apart (see Limitations).

## Background Model

- **Administrator sessions.** Each administrator starts about 16 sessions a day, at random times following the hourly curve and a daily workload factor (log-normal, mean 1, sigma 0.25) shared by both administrators. Most logins succeed at once; a connection has 0, 1, 2 or 3 failed passwords on the same TCP source port before success (92 / 5.5 / 1.5 / 1%): a single typo is the common case, a wrong keyboard layout or a stale saved password occasionally fails several times in a row. 1.5% of connections give up after 1-3 failures and 70% of those retry from a new port. The failure counter is assumed to reset after 300 seconds without failures; within that window failures never reach the five-attempt lockout threshold. A session holds 0-6 maintenance operations: create an absent temporary account (default privilege 1), change an account privilege (often the one just created), remove an applied idle account whose planned lifetime has passed, change a password, change the privilege 15 enable password, set the system clock. Half of the creations are followed directly by a privilege change of the new account. Configuration changes are followed by `Configuration is applied` either immediately or after further changes, and always before logout. Changes pending in another session are not visible: privilege and password changes touch only applied accounts or accounts changed in the same session.
- **Onboarding routine.** Half of the administrator sessions, when an account is absent, run a fixed routine instead: rotate the enable password, create an absent account, raise it from 1 to 14, apply, set the clock, then test the new account's login from the administrator's address.
- **Automated access.** The backup and monitoring account logs in from its own address around the clock, about 48 times a day at random times, with a stored password that does not fail; each session lasts about 15 seconds and changes nothing.
- **Temporary accounts.** Each created account gets a planned lifetime (log-normal, median 40 minutes); every ordinary administrator session starts by removing each expired idle account, so all five accounts are present at about 5% of administrator logins (2-9% in a week). An account logs in only after its creation is applied and never after its removal; a test login is not attempted when another session has meanwhile removed the account. Applied accounts log in on their own about eight times a day from either administrator address (0, 1, 2 or 3 failed passwords first: 96.5 / 2.5 / 0.7 / 0.3%), and 45% of applied account changes are followed by a test login from the administrator's address.
- **Traffic.** Permit, deny, SNAT and IPS drop records (weights 620/200/150/15) over `samples/flows.json`, with fresh ephemeral source and NAT ports. Rules 10/20/30 permit and rule 40 denies throughout.
- **Sequence numbers** grow by one, or by 2-7 in 15% of records to account for device messages outside this subset.

All gaps (between password attempts, operations, session length) are drawn from log-normal distributions; there are no fixed periods, rotations or per-actor cooldowns.

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the generator emits the background only and the complete chain never occurs.

Sequence, all on one router:

1. `ssh_password_failed` three times for administrator A from address I on one TCP source port P.
2. `ssh_password_accepted` for A from I on port P, then `session_opened`.
3. `enable_password_changed` by A.
4. `user_created` for an absent temporary account T, then `user_privilege_changed` of T from 1 to 14.
5. `configuration_applied`.
6. `system_time_changed` by A.
7. `ssh_password_accepted` for T from address I on a new port, then T's session opens and closes; A's session closes independently.

Steps 3-7 are the onboarding routine of the background; the episode is that routine after three failed passwords on one connection.

Linking fields: `user.name` (A, then T), `source.ip` (I), `source.port` (P for steps 1-2), `user.target.name` (T). USER messages carry only the target account, so linking steps 3-6 to A relies on the surrounding session.

Recurrence: the first episode starts within the first `anomaly_interval_hours` or 24 hours, whichever is shorter (default interval 168 hours, one episode a week; minimum 6), at a time following the hourly curve. Each later episode is due one interval after the previous start and starts in a window centred on that due time, a quarter of the interval wide but at most 6 hours (default: 165 to 171 hours after the previous start), with start times weighted by the squared hourly curve plus a small floor. The window is narrow, so later episodes keep roughly the hour of day of the first one, pulled toward working hours. An episode starts later than its time when no temporary account is absent or both administrators are between failed password attempts; a late episode is not made up. Episode starts are 165-171 hours apart at the default interval, about 72 hours at 72 and 5-7 hours at 6, occasionally a few minutes later when no temporary account is free; an episode typically spans 3-14 minutes (median about 6).

An episode is one extra administrator session on top of the background: background sessions, routines and failed-password connections keep their usual rate and timing around it, and the account it creates is taken from absent accounts only.

Variation: the administrator is chosen at random, the account is an absent one different from the previous episode's, and every gap is drawn from the same distributions as background sessions. The account is later removed and the removal applied by an ordinary maintenance session, like any other temporary account, so the changed state is visibly restored; data that ends soon after an episode may not yet contain the removal.

Detection idea: three failed passwords followed by success on the same connection, then enable-password change, a new account raised to privilege 14, a clock change by the same administrator and the new account's first login from the administrator's address, all within 30 minutes. Each fragment occurs in background: repeated failures on one connection, the complete onboarding routine with its test login, and the routine right after three failures (about one a week). Only the complete sequence is absent from the background: after a background routine that follows three failed passwords, the new account first logs in from that administrator's address more than 30 minutes after the first failure (about two routines a week have no test login for this reason). After an episode, the same holds for its account for the rest of that 30-minute window.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
|---|---|---|
| `router_name` | `esr-edge-01` | Router hostname in the syslog frame and `observer.*` |
| `router_ip` | `10.50.0.1` | Management address (`destination.ip` of SSH records) |
| `normal_user` | `netops` | First privilege 15 administrator |
| `normal_source_ip` | `10.50.1.25` | First administrator's client address |
| `unusual_user` | `admin` | Second privilege 15 administrator |
| `unusual_source_ip` | `10.99.4.33` | Second administrator's client address |
| `automation_user` | `netbackup` | Backup and monitoring account |
| `automation_source_ip` | `10.50.1.60` | Backup and monitoring server address |
| `service_user_prefix` | `svc_remote_` | Temporary accounts are this prefix plus `001`-`005` |
| `anomaly_mode` | `true` | Add periodic episodes to the background |
| `anomaly_interval_hours` | `168` | Episode interval in source hours, 6-8760 |

Account names use ASCII letters, digits, `_` and `-`, start with a letter and have at most 31 characters including the suffix; the administrators, the automation account and the temporary accounts must be distinct, and the three client addresses must differ. The hostname is an ASCII label of up to 64 characters; addresses are IPv4. The traffic inventory is `samples/flows.json`.

### Output Parameters

The shipped config writes `output/events.json` with the `json` formatter and needs no `${params.*}` or `${secrets.*}`. To send events elsewhere, replace the `output` section, for example:

```yaml
output:
  - opensearch:
      hosts: ["${params.opensearch_url}"]
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: eltex-esr
```

## Usage

Live mode:

```bash
eventum generate --path generators/network-eltex-esr/generator.yml --id esr --live-mode true
```

The three volume patterns under `patterns/` start at midnight of the current day and never end. For a finite batch, set `start` and `end` in the three files under `patterns/` (for example `start: "2026-09-01T00:00:00Z"`, `end: "+7d"`), then run:

```bash
eventum generate --path generators/network-eltex-esr/generator.yml --id esr --live-mode false --keep-order true
```

## Limitations

- The vendor reference gives field-complete message bodies and one complete remote frame (`<86>1 ... vesr login - - - 1: %AAA-LOCAL-I-SESSION: console: session opened for user admin`). SSH logins use `ssh`, a documented value of that session slot; no SSH capture from a real device was available.
- App name `login` and facility authpriv (10) for AAA records come from the vendor example. The group-derived app names are an assumption; other families use facility local0 (16), which assumes `syslog facility local0` is configured (the CLI default is local7, 23).
- CLI `commit`/`confirm` records are documented only with `console` input and are omitted. The profile assumes every commit is confirmed within the 600-second rollback timer, so `Configuration is applied` stands for a confirmed change.
- The time-change body has no old or new clock value; nothing about clock rollback is implied, and the record clock stays monotonic UTC with second precision.
- Steps of one session are seconds apart rather than instant: `ssh_password_accepted` to `session_opened` takes a median of 6 s in office hours and about 20 s at night (p90 16 s and about 65 s; at most about 80 s and 200 s), where a router logs them within a second. Records of one second share a timestamp; the sequence number keeps their order.
- Administration is far busier than on a production router: temporary accounts are created and removed many times a day, the enable password changes several times a day, and half of the administrator sessions run the onboarding routine. Failed passwords are about 5.5% of SSH password records (4-8% in a week; about 9% of logins by people and temporary accounts).
- With `anomaly_mode: true` each episode adds its own records, so counts of the chain's parts are about one per episode higher than without episodes. At the default weekly interval a week holds about one more of each: administrator logins after three failed passwords (about 2 a week without episodes), onboarding routines right after three failures (about 1) and chain openings up to the clock change (about 1). At shorter intervals the excess grows accordingly.
- IPv6, Telnet/console logins, public-key authentication, remote AAA, lockout records, configuration rollback and full traffic session lifecycles are outside this subset. Rates are training assumptions, not measured production volume. No Elastic integration exists for ESR, so the ECS mapping is inferred.

## Performance

About 1,800 records per second on one core: 14 days (123,846 records) in about 68 s of CPU time.

## Sample Output

The privilege change of the episode of a generated default week (line 8592):

```json
{"@timestamp": "2026-09-01T21:52:43+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "user_privilege_changed", "category": ["iam"], "dataset": "eltex.esr.syslog", "kind": "event", "module": "eltex", "original": "\u003c134\u003e1 2026-09-01T21:52:43+00:00 esr-edge-01 user - - - 15506: %USER-I-INFO: Privilege level of user svc_remote_001 was changed from 1 to 14", "outcome": "success", "type": ["change"]}, "message": "%USER-I-INFO: Privilege level of user svc_remote_001 was changed from 1 to 14", "log": {"level": "info", "syslog": {"priority": 134, "facility": {"code": 16}, "severity": {"code": 6}, "appname": "user", "version": "1"}}, "observer": {"hostname": "esr-edge-01", "ip": ["10.50.0.1"], "name": "esr-edge-01", "product": "ESR", "type": "router", "vendor": "Eltex"}, "eltex": {"esr": {"group": "USER", "mnemonic": "INFO", "severity_code": "I", "sequence_number": 15506, "details": {"privilege": {"new": 14, "old": 1}}}}, "user": {"target": {"name": "svc_remote_001"}}, "related": {"user": ["svc_remote_001"]}}
```

## References

- [Eltex ESR 1.40 Syslog reference](https://docs.eltex-co.ru/download/attachments/52497571/ESR-Series_Syslog_reference_1.40.pdf?api=v2): remote frame, message catalogue, sequence-number option.
- [Eltex ESR 1.40 CLI reference](https://docs.eltex-co.ru/download/attachments/52497571/ESR-Series_CLI_1.40.pdf?api=v2): local users and default privilege, commit confirmation timer, login lockout defaults.
- [Elastic ECS field reference](https://www.elastic.co/docs/reference/ecs/ecs-field-reference)
