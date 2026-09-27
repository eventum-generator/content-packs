# Atlassian Jira security log

Synthetic `atlassian-jira-security.log` records for Jira Data Center 9.5 and later, where Jira uses the Log4j2 layout. Each event wraps one raw log line in ECS JSON: the line sits in `event.original`, and the eight documented columns (timestamp, thread, Jira username, request ID, session ID, source IP, request URL, message) are also parsed into structured fields under `jira.security`.

The log records user login and session activity. Ten accounts sign in mostly from their own workstation, sometimes from a neighbouring desk or through a shared VPN pool, so every address carries several accounts. They mistype passwords, trip the CAPTCHA check after three failures and give up, and log out. Against that background the generator can weave a credential-guessing episode.

## Event Types

Measured shares from a default 5-day `anomaly_mode: true` capture (1926 rows):

| Action | Share | ECS category |
| --- | ---: | --- |
| `session-created` | 39.2% | session |
| `session-destroyed` | 26.0% | session |
| `authentication-passed` | 12.8% | authentication |
| `logout` | 12.7% | authentication |
| `authentication-failed` | 8.7% | authentication |
| `captcha-required` | 0.7% | authentication |

Shares describe synthetic traffic, not measured Jira frequencies. Every action appears in both modes; `captcha-required` occurs in ordinary traffic when a user fails three times, is refused by the CAPTCHA check on the fourth attempt, and gives up.

## Anomaly Chain

An episode is a credential-guessing run against one account from one address: three `authentication-failed` records (failure counts 1-3), a fourth attempt refused by `captcha-required` (failure count 4), then an `authentication-passed` for that account - the compromise - followed later by a logout.

- **Linking fields.** Every step of the run shares one anonymous pre-login `jira.security.session_id`; Jira keeps the anonymous session across attempts and reports it on the successful login too. The failed and CAPTCHA records carry `user.name: anonymous`; the guessed account is in the message and in `jira.security.target_user`. The source IP is constant across the run.
- **Recurrence.** Episodes recur by source time on a configurable interval (`anomaly_interval_hours`, default 24, minimum 1). The next episode is due one interval after the previous episode's actual start, with no catch-up, and starts after a short random delay past the due time.
- **Variation.** The target is an account idle for at least 30 minutes, never the previous episode's target. The address is one the target already uses in ordinary traffic - a neighbouring desk or a VPN address - never the previous episode's address. Gaps between attempts and the session length after the compromise are drawn from skewed random distributions.
- **Detection idea.** Group by `jira.security.session_id`; flag a session with three failed logins and a CAPTCHA refusal followed by a successful login. Ordinary lockouts reach the CAPTCHA refusal but never produce a successful login in that session, so the full ordered run does not occur in the background. Sort by `@timestamp` before applying sequence logic; output line order is not guaranteed.

`event.template.params.anomaly_mode` defaults to `true`. Set it to `false` for realistic background records only, with no complete chain.

## Parameters

### Event Parameters

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Weave the credential-guessing episodes into the stream |
| `anomaly_interval_hours` | `24` | Source-time interval between episodes (minimum 1) |
| `host_name` | `jira-dc-01.example.test` | Jira node emitting the log (`host.name`) |
| `context_path` | `/jira` | Servlet context path prefixing each request URL |

The episode's target account and address are chosen at runtime from the built-in workstation pool; they are not parameters.

### Output Parameters

The shipped configuration writes `output/events.json` with no connection parameters or secrets. To deliver events to a SIEM, replace the file output in a local copy with the required output plugin, using `${params.*}` and `${secrets.*}` placeholders for hosts and credentials as that plugin needs.

## Usage

```bash
eventum generate --path generators/web-atlassian-jira-security/generator.yml --id jira --live-mode false
eventum generate --path generators/web-atlassian-jira-security/generator.yml --id jira --live-mode true
```

## Sample Output

One record, copied byte-for-byte from the default `anomaly_mode: true` capture - the successful login that completes an episode:

```json
{"@timestamp": "2026-09-02T00:20:04.060000+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "authentication-passed", "category": ["authentication"], "kind": "event", "original": "2026-09-02 00:20:04,060+0000 http-nio-8080-exec-11 url: /jira/login.jsp pnovak 20x318x1 0k70cem 10.20.9.52 /login.jsp The user \u0027pnovak\u0027 has PASSED authentication.", "outcome": "success", "type": ["start"]}, "host": {"name": "jira-dc-01.example.test"}, "jira": {"security": {"context_url": "/jira/login.jsp", "message": "The user \u0027pnovak\u0027 has PASSED authentication.", "request_id": "20x318x1", "request_url": "/login.jsp", "session_id": "0k70cem", "target_user": "pnovak"}}, "log": {"file": {"path": "atlassian-jira-security.log"}}, "process": {"thread": {"name": "http-nio-8080-exec-11"}}, "related": {"ip": ["10.20.9.52"], "user": ["pnovak"]}, "source": {"ip": "10.20.9.52"}, "user": {"name": "pnovak"}}
```

## Coverage and Limits

- The eight columns Atlassian documents are represented in `event.original` and in `jira.security` fields. In Atlassian's examples the first request ID segment equals the minutes since midnight (the article text says seconds); the pack follows the examples. The second segment is a per-restart request counter, the third the concurrent-request count. Session IDs are 6-7 lowercase base-36 characters, as in the examples.
- The CAPTCHA refusal after three failures matches Atlassian's example (`Failure count equals 4` on the CAPTCHA line) and assumes the default of three allowed attempts; a changed limit shifts where the refusal appears.
- An episode targets only an account that has been signed out for at least 30 minutes, while about 7% of ordinary sign-ins follow a logout more quickly. Over roughly 65 episodes (about 65 days at the default interval, about 3 days at the 1 h minimum) this gap becomes statistically visible.
- Failure counts restart at 1 on every new sign-in. Jira keeps the count per user until a successful login, so a real user returning after a lockout would meet the CAPTCHA check at once.
- The pack models the login, failed-login, CAPTCHA, session lifecycle and logout messages. It does not emit the secondary `login : '<user>' tried to login ...` diagnostic line, the "NOT AUTHORIZED" no-application-access variant, session expiry, or REST API 403 records. As Atlassian notes, the security log is not comprehensive and excludes exceptions such as LDAP connection errors.
- The raw line's timestamp offset is fixed to `+0000`, and the IP column carries a single origin address; proxy deployments may log an `origin,proxy` pair.
- Compatibility with a specific SIEM normalizer (for example KUMA) is unverified.

## References

- [How to analyze the atlassian-jira-security.log file](https://support.atlassian.com/jira/kb/how-to-analyze-the-atlassian-jira-securitylog-file/) - column definitions and raw examples (Jira Data Center 9.5+, Log4j2 layout).
