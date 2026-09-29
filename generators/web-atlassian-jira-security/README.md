# Atlassian Jira security log

Synthetic Jira Data Center 9.5+ `atlassian-jira-security.log` messages preserved in `event.original`, with an ECS JSON wrapper. The profile represents one Jira node and 512 accounts, including sixteen frequently active users.

## Event types

About 6,600 records per day. Activity rises from roughly 100 records per hour overnight to 520 per hour at 08:00-18:00 UTC. Most records describe ordinary login, logout and session replacement. Password mistakes account for a few percent of authentication attempts; one mistake is more frequent than two or three.

| Action | Approximate share | Category |
| --- | ---: | --- |
| `session-created` | 42.55% | Session lifecycle |
| `session-destroyed` | 28.35% | Session lifecycle |
| `authentication-passed` | 14.19% | Authentication |
| `logout` | 14.15% | Authentication |
| `authentication-failed` | 0.64% | Authentication |
| `captcha-required` | 0.11% | Authentication |

Accounts normally use their own workstation, with occasional access from an alternate address. Jira requests a CAPTCHA after three failed passwords. Ordinary users can answer one or two CAPTCHA challenges and then sign in successfully. Failure counts belong to the account and reset after successful authentication. Existing authenticated sessions can overlap a new login.

## Anomaly Chain

For one account, source address and anonymous session: three failed password attempts, three successive CAPTCHA refusals, then a successful login within one hour. This is a persistent retry sequence for detection testing, not proof of compromise. A single CAPTCHA followed by successful login remains ordinary activity.

The first sequence begins within the smaller of 24 hours and the configured interval, with hours weighted by the daily activity curve. Later starts fall around the previous actual start plus the interval, in a window of width `min(interval / 4, 6 hours)`, with stronger preference for active hours. Consecutive episodes use different accounts. Episodes use frequent workstation/account pairs and retain independent sessions. Successful sessions end on the same schedule as ordinary sessions, typically tens of minutes later.

With `anomaly_mode: false`, all message types and the episode accounts remain present without this complete sequence. Enabling it adds one correlated sequence per episode. Correlate `jira.security.target_user` and `source.ip`, and require the same `jira.security.session_id` through the failed attempts and successful authentication. The session column retains the old anonymous session ID on the successful login request even though that request creates a new authenticated session.

## Parameters

| Parameter | Default | Meaning |
| --- | --- | --- |
| `host_name` | `jira-dc-01.example.test` | Jira node name in the ECS wrapper |
| `context_path` | `/jira` | Application context in the thread's request URL |
| `anomaly_mode` | `true` | Include the recurring retry sequence |
| `anomaly_interval_hours` | `24` | Recurrence interval, from 1 to 8760 hours |

Edit values under `event.template.params` in `generator.yml`.

## Usage

```bash
eventum generate --path generators/web-atlassian-jira-security/generator.yml --id jira-security --live-mode true
```

For a finite batch, set the same explicit UTC start/end dates in every `patterns/*.yml` oscillator. Start at midnight to retain the working-day hours. Then run:

```bash
eventum generate --path generators/web-atlassian-jira-security/generator.yml --id jira-security-batch --live-mode false --keep-order true
```

Output is `output/events.json` relative to the generator directory. Replace the output block to deliver records to a SIEM. Performance: about 5,500 events/second for a four-day batch on the development machine.

## Sample output

```json
{"@timestamp": "2026-09-01T00:01:23.300000+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "authentication-passed", "category": ["authentication"], "kind": "event", "original": "2026-09-01 00:01:23,300+0000 http-nio-8080-exec-8 url: /jira/login.jsp user0029 0x103x1 4mk6er2 10.20.10.29 /login.jsp The user \u0027user0029\u0027 has PASSED authentication.", "outcome": "success", "type": ["start"]}, "host": {"name": "jira-dc-01.example.test"}, "jira": {"security": {"context_url": "/jira/login.jsp", "message": "The user \u0027user0029\u0027 has PASSED authentication.", "request_id": "0x103x1", "request_url": "/login.jsp", "session_id": "4mk6er2", "target_user": "user0029"}}, "log": {"file": {"path": "atlassian-jira-security.log"}}, "process": {"thread": {"name": "http-nio-8080-exec-8"}}, "related": {"ip": ["10.20.10.29"], "user": ["user0029"]}, "source": {"ip": "10.20.10.29"}, "user": {"name": "user0029"}}
```

## Limitations

- This selected security-message profile omits remember-me-cookie diagnostics, application-permission failures, REST authentication, SSO, directory errors and anonymous-session timeout messages. It does not reproduce a complete Jira log file.
- Related messages from one request are emitted on consecutive timestamps, typically seconds apart and occasionally minutes apart at low volume. They retain the same request ID and thread, including across a minute boundary. Session durations, account activity and message frequencies are synthetic.
- The CAPTCHA threshold is three failed passwords. External-directory lockouts and password policy are outside this profile. Successful CAPTCHA authentication clears the local failure count; abandoned anonymous sessions expire outside the selected message set.
- ECS fields and `jira.security` are this pack's enrichment. The target account on session-only messages is inferred from the associated synthetic activity. Native authentication messages name the account explicitly.

## References

- [Atlassian: analyzing the Jira security log](https://support.atlassian.com/jira/kb/how-to-analyze-the-atlassian-jira-securitylog-file/)
- [Atlassian: repeated CAPTCHA failures and login outcomes](https://support.atlassian.com/jira/kb/user-unable-to-login-with-you-do-not-have-permission-error/)
- [Atlassian LoginStore API: account failure counters and reset](https://docs.atlassian.com/software/jira/docs/api/10.5.0/com/atlassian/jira/security/login/LoginStore.html)

No matching Elastic integration is asserted for this custom wrapper.
