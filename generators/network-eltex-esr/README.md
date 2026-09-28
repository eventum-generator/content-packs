# Eltex ESR Router Syslog

Generates Eltex ESR-series (software 1.40) remote syslog records as ECS JSON for training SIEM content on router administration and firewall logs. `event.original` holds the RFC 5424 frame and `message` the documented `%GROUP-SEVERITY-MNEMONIC: text` body. The source is one router with two local SSH administrators, five temporary local accounts and a small fixed IPv4 traffic inventory.

## Event Types

Shares measured on the final default capture (156 h, `anomaly_mode: true`, 57,885 records).

| Native message | `event.action` | Share | Category |
|---|---|---:|---|
| `%FIREWALL-I-LOG` | `firewall_permitted` | 60.88% (35240) | Network |
| `%FIREWALL-I-LOG` | `firewall_denied` | 19.60% (11348) | Network |
| `%NAT-I-LOG` | `snat_translation` | 14.73% (8526) | Network |
| `%IPS-I-INFO` | `ips_drop` | 1.45% (837) | Intrusion detection |
| `%AAA-I-SSH` | `ssh_password_accepted` | 0.62% (356) | Authentication |
| `%AAA-LOCAL-I-SESSION` | `session_opened` | 0.62% (356) | Authentication |
| `%AAA-LOCAL-I-SESSION` | `session_closed` | 0.62% (356) | Authentication |
| `%SYS-W-EVENT` | `configuration_applied` | 0.40% (229) | Configuration |
| `%AAA-I-SSH` | `ssh_password_failed` | 0.36% (210) | Authentication |
| `%USER-I-INFO` | `user_privilege_changed` | 0.18% (104) | IAM |
| `%USER-I-ADD` | `user_created` | 0.13% (75) | IAM |
| `%TIME-I-INFO` | `system_time_changed` | 0.13% (73) | Configuration |
| `%USER-I-ADD` | `user_removed` | 0.13% (73) | IAM |
| `%USER-I-INFO` | `enable_password_changed` | 0.11% (66) | IAM, configuration |
| `%USER-I-INFO` | `user_password_changed` | 0.06% (36) | IAM |

Every action, both administrators, both administrator addresses and all five temporary accounts occur in ordinary background in both modes. No field labels an episode.

## Background Model

Each one-second tick emits at most one record: the earliest due step of an open SSH connection or session, otherwise a traffic record with probability 0.1 scaled by an office-hours factor (06:00-16:00 UTC 1.64, 16:00-20:00 0.91, night 0.40), otherwise nothing. The result averages about one record per ten seconds with random gaps.

- **Administrator sessions.** Each administrator starts sessions independently at about 16 per day (same office-hours factor). A connection has 0-3 failed passwords on the same TCP source port before success (weights 76/10/6/8); 12% of connections give up after 1-3 failures and 70% of those retry from a new port. The failure counter is assumed to reset after 300 seconds without failures; within that window failures never reach the five-attempt lockout threshold. A session holds 0-6 maintenance operations: create an absent temporary account (default privilege 1), change an account privilege (often the one created in the same session), remove an applied idle account, change a password, change the privilege 15 enable password, set the system clock. Half of the creations are followed directly by a privilege change of the new account. Configuration changes are followed by `Configuration is applied` either immediately or after further changes, and always before logout. Changes pending in another session are not visible: privilege and password changes touch only applied accounts or accounts changed in the same session.
- **Temporary accounts.** An account can log in only after its creation is applied. Applied accounts log in on their own at about five per day from either administrator address, and 45% of applied account changes are followed by a test login from the administrator's address.
- **Traffic.** Permit, deny, SNAT and IPS drop records (weights 620/200/150/15) over `samples/flows.json`, with fresh ephemeral source and NAT ports. Rules 10/20/30 permit and rule 40 denies throughout.
- **Sequence numbers** grow by one, or by 2-7 in 15% of records to account for device messages outside this subset.

All gaps (between password attempts, operations, session length) are drawn from log-normal distributions; there are no fixed periods, rotations or per-actor cooldowns. State holds five account records, open connections and the partial chains of the last 30 minutes.

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

Linking fields: `user.name` (A, then T), `source.ip` (I), `source.port` (P for steps 1-2), `user.target.name` (T). USER messages carry only the target account, so linking steps 3-6 to A relies on the surrounding session.

Recurrence: the first episode starts within the first `anomaly_interval_hours` or 24 hours of generation, whichever is shorter (default interval 24, minimum 6), at a time drawn with the office-hours factor above as its density. Each later episode is due one interval after the previous actual start and starts in a window centred on that due time, a quarter of the interval wide but at most 6 hours (default: 21 to 27 hours after the previous start), at a time drawn with density proportional to the squared office-hours factor plus a small floor, so across runs most episodes start in working hours; the window is narrow at short intervals, so a single run can place every other episode at night. An episode starts at its drawn time, or as soon as afterwards an administrator has no pending failures and at least one account is absent; a late episode never causes catch-up. At short intervals an episode can wait hours for an absent account, since accounts are removed only by ordinary maintenance. Measured on 156-hour captures: 7 episodes at 24 hours (start gaps 21.5-26.0 hours, start hours 08-12 UTC), 14 and 12 at 12 hours (10.8-13.5 hours), 26 at 6 hours (5.3-6.8 hours); spans 2.4-8.7 minutes at 12 and 24 hours, up to 20 minutes at 6 hours.

Variation: the administrator is chosen at random, the account is an absent one different from the previous episode's, and every gap is drawn from the same distributions as background sessions. The account is later removed and the removal applied by an ordinary maintenance session, like any other temporary account, so the changed state is visibly restored (a finite run may end before that).

Detection idea: three failed passwords followed by success on the same connection, then enable-password change, a new account raised to privilege 14, a clock change by the same administrator and the new account's first login from the administrator's address, all within 30 minutes. Each fragment occurs in background: repeated failures on one connection, enable and clock changes in one session, create-and-raise in one session, test logins after creation. Only the complete sequence is kept out of the background, by a check on its last step alone: an ordinary account login that would complete it, with the first failed password at most 30 minutes earlier, does not happen: its record is not emitted and the account's session does not open. Nothing else changes. The check stays active after an episode completes, so its own sequence keeps blocking such logins until its 30-minute window ends and no ordinary login completes it a second time.

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
| `service_user_prefix` | `svc_remote_` | Temporary accounts are this prefix plus `001`-`005` |
| `anomaly_mode` | `true` | Add periodic episodes to the background |
| `anomaly_interval_hours` | `24` | Episode interval in source hours, 6-8760 |

Account names use ASCII letters, digits, `_` and `-`, start with a letter and have at most 31 characters including the suffix; the administrators and the accounts must be distinct, and the two client addresses must differ. The hostname is an ASCII label of up to 64 characters; addresses are IPv4. The traffic inventory is `samples/flows.json`.

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

Batch mode needs a bounded input: add `start` and `end` to the `cron` input, then run:

```bash
eventum generate --path generators/network-eltex-esr/generator.yml --id esr --live-mode false
```

## Limitations

- The vendor reference gives field-complete message bodies and one complete remote frame (`<86>1 ... vesr login - - - 1: %AAA-LOCAL-I-SESSION: console: session opened for user admin`). The `ssh:` session prefix substitutes that documented `console:` slot for SSH logins; an SSH capture was not available.
- App name `login` and facility authpriv (10) for AAA records come from the vendor example. The group-derived app names are an assumption; other families use facility local0 (16), which assumes `syslog facility local0` is configured (the CLI default is local7, 23).
- CLI `commit`/`confirm` records are documented only with `console` input and are omitted. The profile assumes every commit is confirmed within the 600-second rollback timer, so `Configuration is applied` stands for a confirmed change.
- The time-change body has no old or new clock value; nothing about clock rollback is implied, and the generated clock stays monotonic UTC with second precision.
- IPv6, Telnet/console logins, public-key authentication, remote AAA, lockout records, configuration rollback and full traffic session lifecycles are outside this subset. Rates are training assumptions, not measured production volume. No Elastic integration exists for ESR, so ECS mapping is inferred.

## Sample Output

The privilege change of the first episode, copied byte for byte from the final default capture (line 4804):

```json
{"@timestamp": "2026-09-26T12:27:17+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "user_privilege_changed", "category": ["iam"], "dataset": "eltex.esr.syslog", "kind": "event", "module": "eltex", "original": "\u003c134\u003e1 2026-09-26T12:27:17+00:00 esr-edge-01 user - - - 12333: %USER-I-INFO: Privilege level of user svc_remote_001 was changed from 1 to 14", "outcome": "success", "type": ["change"]}, "message": "%USER-I-INFO: Privilege level of user svc_remote_001 was changed from 1 to 14", "log": {"level": "info", "syslog": {"priority": 134, "facility": {"code": 16}, "severity": {"code": 6}, "appname": "user", "version": "1"}}, "observer": {"hostname": "esr-edge-01", "ip": ["10.50.0.1"], "name": "esr-edge-01", "product": "ESR", "type": "router", "vendor": "Eltex"}, "eltex": {"esr": {"group": "USER", "mnemonic": "INFO", "severity_code": "I", "sequence_number": 12333, "details": {"privilege": {"new": 14, "old": 1}}}}, "user": {"target": {"name": "svc_remote_001"}}, "related": {"user": ["svc_remote_001"]}}
```

## References

- [Eltex ESR 1.40 Syslog reference](https://docs.eltex-co.ru/download/attachments/52497571/ESR-Series_Syslog_reference_1.40.pdf?api=v2): remote frame, message catalogue, sequence-number option.
- [Eltex ESR 1.40 CLI reference](https://docs.eltex-co.ru/download/attachments/52497571/ESR-Series_CLI_1.40.pdf?api=v2): local users and default privilege, commit confirmation timer, login lockout defaults.
- [Elastic ECS field reference](https://www.elastic.co/docs/reference/ecs/ecs-field-reference)
