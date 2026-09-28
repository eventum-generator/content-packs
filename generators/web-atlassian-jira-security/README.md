# Atlassian Jira security log

Synthetic `atlassian-jira-security.log` records for Jira Data Center 9.5 and later, where Jira uses the Log4j2 layout. Each event wraps one raw log line in ECS JSON: the line sits in `event.original`, and the eight documented columns (timestamp, thread, Jira username, request ID, session ID, source IP, request URL, message) are also parsed into structured fields under `jira.security`.

The log records user login and session activity. Ten accounts sign in mostly from their own workstation, sometimes from a neighbouring desk or through a shared VPN pool, so every address carries several accounts. They mistype passwords, trip the CAPTCHA check after three failures - then give up, answer the CAPTCHA at once, or come back to the open login page later - and log out. Against that background the generator can weave a credential-guessing episode.

## Event Types

Measured shares from a default 6-day `anomaly_mode: true` capture (2032 rows):

| Action | Share | ECS category |
| --- | ---: | --- |
| `session-created` | 38.5% | session |
| `session-destroyed` | 25.3% | session |
| `authentication-passed` | 12.6% | authentication |
| `logout` | 12.5% | authentication |
| `authentication-failed` | 10.2% | authentication |
| `captcha-required` | 0.8% | authentication |

Shares describe synthetic traffic, not measured Jira frequencies. Every action appears in both modes; `captcha-required` occurs in ordinary traffic when a user fails three times and is refused by the CAPTCHA check on the fourth attempt (failure count 4).

## Anomaly Chain

An episode is a credential-guessing run against one account from one address: three `authentication-failed` records (failure counts 1-3), a fourth attempt refused by `captcha-required` (failure count 4), then an `authentication-passed` for that account - the compromise - followed later by a logout.

- **Linking fields.** Every step of the run shares one anonymous pre-login `jira.security.session_id`; Jira keeps the anonymous session across attempts and reports it on the successful login too. The failed and CAPTCHA records carry `user.name: anonymous`; the guessed account is in the message and in `jira.security.target_user`. The source IP is constant across the run.
- **Recurrence.** Episodes recur by source time on a configurable interval (`anomaly_interval_hours`, default 24, 1-8760). The first episode is scheduled at a uniformly random time within the first `min(interval, 24 h)` of the run; each next one is due one interval after the previous episode's actual start and is scheduled uniformly within a window of `w = min(interval / 4, 6 h)` centred on the due time (the background has no hour-of-day profile). No catch-up. At the scheduled time the episode starts as soon as such an account is available (see Variation). Measured: two default 6-day captures 6 episodes each, 21.4-26.9 h apart; 6-hour interval 11 episodes in three days, 5.4-6.8 h apart.
- **Variation.** The target is an account idle for at least 30 minutes, never the previous episode's target, and one whose own next sign-in is due more than 10 minutes after the episode's logout, so the episode never overlaps the account's own sessions; ordinary activity of the account is not moved to make room. The address is one the target already uses in ordinary traffic - a neighbouring desk or a VPN address - never the previous episode's address. Gaps between attempts and the session length after the compromise are drawn from skewed random distributions.
- **Detection idea.** Group by `jira.security.session_id`; flag a session with three failed logins and a CAPTCHA refusal followed by a successful login within an hour of the first failure. Ordinary users reach the CAPTCHA refusal too, and some of them sign in later in the same anonymous session after leaving the login page open; the full ordered run is kept out of the background only inside that hour: an ordinary successful login that would complete it within 3600 s of the session's first failed login is not logged and no other record takes its place: that anonymous session ends there without a logged teardown, and the account stays quiet until the time its logout would have come, then keeps its usual schedule. Sort by `@timestamp` before applying sequence logic; output line order is not guaranteed.

`event.template.params.anomaly_mode` defaults to `true`. Set it to `false` for realistic background records only, with no complete chain.

## Parameters

### Event Parameters

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Weave the credential-guessing episodes into the stream |
| `anomaly_interval_hours` | `24` | Source-time interval between episodes (1-8760) |
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
{"@timestamp": "2026-09-01T10:59:24.403000+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "authentication-passed", "category": ["authentication"], "kind": "event", "original": "2026-09-01 10:59:24,403+0000 http-nio-8080-exec-8 url: /jira/login.jsp pnovak 659x463x3 saw5wm7 10.20.9.52 /login.jsp The user \u0027pnovak\u0027 has PASSED authentication.", "outcome": "success", "type": ["start"]}, "host": {"name": "jira-dc-01.example.test"}, "jira": {"security": {"context_url": "/jira/login.jsp", "message": "The user \u0027pnovak\u0027 has PASSED authentication.", "request_id": "659x463x3", "request_url": "/login.jsp", "session_id": "saw5wm7", "target_user": "pnovak"}}, "log": {"file": {"path": "atlassian-jira-security.log"}}, "process": {"thread": {"name": "http-nio-8080-exec-8"}}, "related": {"ip": ["10.20.9.52"], "user": ["pnovak"]}, "source": {"ip": "10.20.9.52"}, "user": {"name": "pnovak"}}
```

## Coverage and Limits

- The eight columns Atlassian documents are represented in `event.original` and in `jira.security` fields. In Atlassian's examples the first request ID segment equals the minutes since midnight (the article text says seconds); the pack follows the examples. The second segment is a per-restart request counter, the third the concurrent-request count. Session IDs are 6-7 lowercase base-36 characters, as in the examples.
- The CAPTCHA refusal after three failures matches Atlassian's example (`Failure count equals 4` on the CAPTCHA line) and assumes the default of three allowed attempts; a changed limit shifts where the refusal appears.
- An episode targets only an account that has been signed out for at least 30 minutes, while about 7% of ordinary sign-ins follow a logout more quickly. Over roughly 65 episodes (about 65 days at the default interval, about 3 days at the 1 h minimum) this gap becomes statistically visible.
- As a result, episode targets have been idle longer before the episode than accounts usually are before a session (median about 223 vs 139 minutes in the review captures). Idle time alone flags about one episode per ten ordinary sessions at a 600-minute cutoff.
- Failure counts restart at 1 on every new sign-in. Jira keeps the count per user until a successful login, so a real user returning after a lockout would meet the CAPTCHA check at once.
- The pack models the login, failed-login, CAPTCHA, session lifecycle and logout messages. It does not emit the secondary `login : '<user>' tried to login ...` diagnostic line, the "NOT AUTHORIZED" no-application-access variant, session expiry, or REST API 403 records. As Atlassian notes, the security log is not comprehensive and excludes exceptions such as LDAP connection errors.
- The raw line's timestamp offset is fixed to `+0000`, and the IP column carries a single origin address; proxy deployments may log an `origin,proxy` pair.
- Compatibility with a specific SIEM normalizer (for example KUMA) is unverified.

## References

- [How to analyze the atlassian-jira-security.log file](https://support.atlassian.com/jira/kb/how-to-analyze-the-atlassian-jira-securitylog-file/) - column definitions and raw examples (Jira Data Center 9.5+, Log4j2 layout).
