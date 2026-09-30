# Fortinet FortiPAM Secret Events

Secret-request and clear-text-view logs of one Fortinet FortiPAM appliance, for testing privileged-access analytics. Records are ECS JSON; the native FortiPAM key-value message is kept byte-for-byte in `event.original` and parsed under `fortinet.fortipam.*` with its native key names.

Sixty users in seven roles (PAM, Windows, Unix, DBA, network, helpdesk, cloud; `samples/users.csv`) work with 43 secrets in seven folders (`samples/secrets.csv`). Each user opens sessions at random, weighted per user: most sessions view one to five secret passwords in clear text, sometimes opening the previous one again; about one in five starts with a request for an approval-gated secret, usually followed by a view of it after approval and sometimes by more views or a second request. A user's secrets come from the role's folders, weighted by folder and by the secret's popularity.

## Event types

| Log ID | Operation | Share | ECS category / type |
| --- | --- | --- | --- |
| `2303064603` | `clear-text-view` - clear text view allowed | 90.4% | iam / info |
| `2304064604` | `request` - secret request created | 9.6% | iam / creation |

## Volume and Timing

About 2,200 records a day, with a working-day curve in UTC:

| Hours (UTC) | 00-07 | 07-08 | 08-18 | 18-21 | 21-24 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Records per hour | 15 | 81 | 173 | 81 | 15 |

Daily volume varies by about 3%. Users are present in proportion to this curve; at night the records come from the same users (on-call work). The busiest users log about 80 records a day, the quietest about 16.

A user's consecutive records are a median of about 4 minutes apart (10% within 40 seconds). A view of a requested secret follows its request after a median of about 9 minutes (10% within 2 minutes); 78% of requests are followed by such a view. Records of one session are logged in order, seconds to minutes apart in office hours and several minutes apart at night.

## Anomaly Chain

Clear-text password harvesting after an access request:

1. User U creates a request for an approval-gated secret S (`2304064604`).
2. After an approval delay, U views the clear text of S (`2303064603`).
3. U views the clear text of five more distinct secrets; ordinary re-views of already opened secrets may come in between.

All steps fall within 30 minutes of the request (measured 23-29 minutes, 7-18 records per episode, median 8). Linking fields: `user`, `secretid` (with `secret`, `account`, `uuid`); the window is the detection rule's window.

- **Recurrence.** `anomaly_interval_hours` (default 24, minimum 2, maximum 8760) sets the interval by source time. The first episode starts within the first min(interval, 24 h) of generation, at a time drawn from the hourly volume. Each later episode is due one interval after the previous episode's actual start and starts in a window of width w = min(interval / 4, 6 h) centred on that due time, weighted by the squared hourly volume plus a small floor, so it leans towards busy hours. Missed time is never caught up. Episodes start between 07:00 and 19:30 UTC; when the whole window falls outside those hours, the episode starts at the next 07:00-08:00 instead. Measured gaps: 21.6-26.8 h (mean 24.3) at the default, 10.5-21.9 h (mean 12.6) with 12 h.
- **Variation.** The user is one of six busy users (those who request an approval-gated secret about twice a day or more and open five other secrets three or more times a day), drawn with their ordinary weights, and never the previous episode's user. S is one of the approval-gated secrets the user requests about twice a day or more, drawn by how often the user requests it, and never the previous episode's first secret; the other five are secrets that the user opens at least three times a day in ordinary work, drawn by how often the user opens them. The first view of S comes 2-23 minutes after the request (median 15; in ordinary work, a quarter of the views that follow their request within an hour come 15 minutes or more after it); the views that follow are seconds to minutes apart, as in ordinary sessions.
- **Background realism.** Every event type, every episode user and every user-secret pair of an episode also occur in ordinary activity of both modes: each user requests each possible S about twice a day or more and opens each of the other secrets at least three times a day. Requests, a request followed by a view of the same secret, sessions of several distinct views, re-views and second requests all occur in ordinary work. Only the complete sequence within 30 minutes is absent from it: after viewing a requested secret, a user views at most four other distinct secrets within 30 minutes of the request, and further views in that time are of those secrets or of the requested one. The same sequence spread over 30-60 minutes occurs in ordinary work, about 20 times a day.
- **Detection idea.** Per user, a secret request followed within 30 minutes by clear-text views of that secret and of at least five other distinct secrets.
- A match does not prove misuse. The documented logs carry no approval decision, source address or view reason.

`anomaly_mode` defaults to `true`. Set it to `false` for background only: the same users, secrets, volume and event types, with no complete chain.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`.

| Name | Default | Description |
| --- | --- | --- |
| `anomaly_mode` | `true` | Add harvesting episodes to the background. |
| `anomaly_interval_hours` | `24` | Hours between episodes by source time (2-8760). |
| `device_name` | `FPAVULTM1234567` | Appliance name, written to `devname`/`devid` and `observer.*`. |

### Output Parameters

The shipped file output needs no overrides. To deliver elsewhere, replace `output.file` with another output plugin and reference top-level placeholders, for example `hosts: ['${params.opensearch_host}']`, `username: ${params.opensearch_user}`, `password: ${secrets.opensearch_password}`, then pass the values at startup.

## Usage

From the content-packs repository. Live generation at the configured rate, until stopped:

```bash
eventum generate --path generators/identity-fortinet-fortipam/generator.yml --id fortipam --live-mode true
```

Batch generation: set `start` and `end` of the `oscillator` in every `patterns/*.yml` file to the same range, with `start` at 00:00 UTC so the hour curve stays in place (for example `start: "2026-10-01T00:00:00Z"` and `end: "2026-10-08T00:00:00Z"`), then run:

```bash
eventum generate --path generators/identity-fortinet-fortipam/generator.yml --id fortipam --live-mode false --keep-order true
```

Output: `generators/identity-fortinet-fortipam/output/events.json`. Extract `event.original` when a collector expects FortiPAM key-value messages.

The hour curve is the sum of `patterns/baseline.yml`, `extended.yml` and `office.yml`, each adding a flat rate over one UTC hour range. To change the volume, scale the `ratio` of every pattern file by the same factor. Episode start hours and episode secrets follow the shipped volume even if you reshape the pattern files.

Performance: about 2,300 records/s on one core (14 days, 30,900 records, in 13 s).

## Sample output

The request that opens an episode, copied from a default-mode run:

```json
{"@timestamp": "2026-09-01T16:03:57.422325Z", "ecs": {"version": "8.17.0"}, "event": {"action": "request", "category": ["iam"], "code": "2304064604", "dataset": "fortinet.fortipam", "kind": "event", "module": "fortinet", "original": "date=2026-09-01 time=16:03:57 devname=\"FPAVULTM1234567\" devid=\"FPAVULTM1234567\" eventtime=1788278637422325394 tz=\"+0000\" logid=\"2304064604\" type=\"secret\" subtype=\"secret-request\" eventtype=\"secret-request\" action=\"pass\" operation=\"request\" secretid=777 secret=\"aws-prod-root\" account=\"root\" uuid=\"d45fdd32-a650-594a-9758-3f8f1f70a449\" user=\"s.lewis\" starttime=\"2026-09-01 16:03:00\" expirytime=\"2026-09-01 16:33:00\" msg=\"Created secret request.\"", "outcome": "success", "type": ["creation"]}, "fortinet": {"fortipam": {"account": "root", "action": "pass", "eventtime": 1788278637422325394, "eventtype": "secret-request", "expirytime": "2026-09-01 16:33:00", "logid": "2304064604", "msg": "Created secret request.", "operation": "request", "secret": "aws-prod-root", "secretid": 777, "starttime": "2026-09-01 16:03:00", "subtype": "secret-request", "type": "secret", "tz": "+0000", "user": "s.lewis", "uuid": "d45fdd32-a650-594a-9758-3f8f1f70a449"}}, "observer": {"hostname": "FPAVULTM1234567", "product": "FortiPAM", "serial_number": "FPAVULTM1234567", "vendor": "Fortinet"}, "related": {"user": ["s.lewis"]}, "user": {"name": "s.lewis"}}
```

## Limitations

- Only two log IDs are modeled, because Fortinet publishes raw lines only for these: secret request created (FortiSIEM's FortiPAM page, sample dated 2023-08, release not stated) and clear text view allowed (FortiPAM 1.7.0). Request approval and denial, launches, check-in/out and password changes are logged by FortiPAM but have no published raw layout, so they are absent.
- Each record keeps exactly the key set and order of its source example. The clear-text-view example comes from `execute log display` and has no `devname`/`devid`; the pack does not add them. Whether syslog output adds them, or a syslog header, is not documented; no syslog envelope is emitted.
- `uuid` is assumed to be the secret object's UUID and is stable per secret. `starttime` is the request minute and `expirytime` a preset duration (30 min to 8 h); the example shows a 30-minute request starting at the minute. `agent` is always `GUI`, the only documented value. Time zone is UTC (`tz="+0000"`).
- Consecutive records of one session are never a sub-second burst: they are seconds to minutes apart in office hours and several minutes apart at night.
- Episodes happen only between 07:00 and 19:30 UTC and only for six busy users, with secrets those users request and open often. With an interval that is not a multiple of 24 h, episodes that fall due at night move to 07:00-08:00, so some gaps are longer than the interval (up to 22 h with 12 h).
- With `anomaly_mode: true` each episode adds its own records, so counts of the chain parts (requests followed by views of five other secrets) are about one per episode higher. From an episode's request until 30 minutes after it, the user has no records other than the episode's; the last episode view comes 1-7 minutes before the end of that time.
- Volumes, shares, session shapes and the hour curve are synthetic choices, not measured production frequencies; the curve repeats every day, with no weekday cycle. Secret, account and address names are fictional, on RFC 1918 addresses.

## References

- [FortiSIEM: Fortinet FortiPAM / FortiSRA (secret-request sample, syslog settings)](https://docs.fortinet.com/document/fortisiem/7.4.1/external-systems-configuration-guide/521441/fortinet-fortipam)
- [FortiPAM 1.7.0: Creating an automation trigger (clear-text-view sample)](https://docs.fortinet.com/document/fortipam/1.7.0/examples/779148/creating-an-automation-trigger)
- [FortiPAM 1.9.2: Secret event & video (secret log categories)](https://docs.fortinet.com/document/fortipam/1.9.2/administration-guide/205262/secret-event-video)
- [FortiPAM 1.7.0: Sending a request to access a secret (request duration)](https://docs.fortinet.com/document/fortipam/1.7.0/examples/133951/sending-a-request-to-access-a-secret)
- No Elastic integration exists for FortiPAM; the ECS projection is inferred.
