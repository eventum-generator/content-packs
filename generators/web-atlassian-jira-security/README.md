# Atlassian Jira security log

Synthetic `atlassian-jira-security.log` events in the Jira Data Center 9.5+ Log4j2 layout. The raw line in `event.original` follows Atlassian's published authentication and session examples.

## Event Types

| Action | Baseline weight | ECS category |
| --- | ---: | --- |
| `authentication-passed` | 65% | authentication |
| `authentication-failed` | 20% | authentication |
| `logout` | 15% | authentication |
| `captcha-required` | Chain only | authentication |

Weights describe synthetic background traffic, not measured Jira frequencies. The template plugin uses `fsm` so a complete chain appears between ordinary events.

## Anomaly Chain

Four failed authentication records for `target_user` from `suspect_ip` with failure counts 1–4 are followed by a CAPTCHA requirement, a passed authentication, and logout. The first six records share the source IP, target username, and pre-login Atlassian session ID. Jira destroys sessions on login; the logout uses a different session ID, so correlate that last step by source IP, username, and a short time window. The Jira username column is `anonymous` on failed and CAPTCHA records; the attempted username is in the message and `jira.security.target_user`. This supports rules for credential guessing followed by successful access and for CAPTCHA escalation. Sort by `@timestamp` before applying sequence logic because output line order is not guaranteed.

`event.template.params.anomaly_mode` defaults to `true`. Set it to `false` for background records only.

## Parameters

### Event Parameters

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include the multi-event authentication chain |
| `host_name` | `jira-dc-01.example.test` | Jira node emitting the log |
| `target_user` | `admin` | Account targeted by the chain |
| `suspect_ip` | `192.0.2.91` | Synthetic source IP for the chain |

### Output Parameters

The shipped configuration writes `output/events.json` with no connection parameters or secrets. To send events to a SIEM, replace the file output in a local copy and use `${params.siem_host}` and `${secrets.siem_token}` as required by the selected output plugin.

## Usage

```bash
eventum generate --path generators/web-atlassian-jira-security/generator.yml --id jira --live-mode false
eventum generate --path generators/web-atlassian-jira-security/generator.yml --id jira --live-mode true
```

## Sample Output

Copied from an `anomaly_mode: true` run:

```json
{
  "@timestamp": "2026-09-25T13:16:05+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "captcha-required",
    "category": [
      "authentication"
    ],
    "kind": "event",
    "original": "2026-09-25 13:16:05,000+0000 http-nio-8080-exec-12 url: /jira/login.jsp anonymous 1054x153x1 scswrbt 192.0.2.91 /login.jsp The user 'admin' is required to answer a CAPTCHA elevated security check. Failure count equals 4",
    "type": [
      "denied"
    ]
  },
  "host": {
    "name": "jira-dc-01.example.test"
  },
  "jira": {
    "security": {
      "context_url": "/jira/login.jsp",
      "failure_count": 4,
      "message": "The user 'admin' is required to answer a CAPTCHA elevated security check. Failure count equals 4",
      "request_id": "1054x153x1",
      "request_url": "/login.jsp",
      "session_id": "scswrbt",
      "target_user": "admin"
    }
  },
  "log": {
    "file": {
      "path": "atlassian-jira-security.log"
    }
  },
  "process": {
    "thread": {
      "name": "http-nio-8080-exec-12"
    }
  },
  "related": {
    "ip": [
      "192.0.2.91"
    ],
    "user": [
      "admin"
    ]
  },
  "source": {
    "ip": "192.0.2.91"
  },
  "user": {
    "name": "anonymous"
  }
}
```

## Coverage and Limits

The eight columns described by Atlassian are represented in structured fields and `event.original`: timestamp, thread, Jira username, request ID, session ID, source IP, request URL, and message. The initial thread context URL includes `/jira`, while the request URL column follows Atlassian's `/login.jsp` example. The context path is configurable in real deployments; this pack fixes it to `/jira`. The security log is not comprehensive and does not include LDAP connection exceptions. Proxy deployments may log an `origin,proxy` IP pair; this pack emits one origin IP. The line layout targets Jira Data Center 9.5+; compatibility with a specific KUMA normalizer is unverified.

## References

- [Atlassian security log format and raw examples](https://support.atlassian.com/jira/kb/how-to-analyze-the-atlassian-jira-securitylog-file/)
- [KUMA 4.2 source catalog](https://support.kaspersky.ru/kuma/4.2/255782)
