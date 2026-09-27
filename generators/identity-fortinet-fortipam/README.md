# Fortinet FortiPAM Secret Events

Secret-request and clear-text-view logs of one Fortinet FortiPAM appliance, for testing privileged-access analytics. Records are ECS JSON; the native FortiPAM key-value message is kept byte-for-byte in `event.original` and parsed under `fortinet.fortipam.*` with its native key names.

Sixty users in seven roles (PAM, Windows, Unix, DBA, network, helpdesk, cloud) work with 43 secrets in seven folders. Each user opens sessions at random, weighted per user and by the hour of day: most sessions view one to five secret passwords in clear text; about one in five starts with a request for an approval-gated secret, usually followed by a view of it after approval and sometimes by more views or a second request.

## Event types

| Log ID | Operation | Share (6 background captures, 10 days each) | ECS category / type |
| --- | --- | --- | --- |
| `2303064603` | `clear-text-view` - clear text view allowed | 90.2% | iam / info |
| `2304064604` | `request` - secret request created | 9.8% | iam / creation |

Volume is about 700 records per day, mostly 08:00-18:00 UTC. Shares, volumes and session shapes are synthetic choices, not measured production frequencies.

## Anomaly Chain

Clear-text password harvesting after an access request:

1. User U creates a request for an approval-gated secret S (`2304064604`).
2. After an approval delay, U views the clear text of S (`2303064603`).
3. U views the clear text of five more distinct secrets from U's own folders; ordinary re-views of already opened secrets may come in between.

All steps fall within 30 minutes of the request (measured spans 4-28 minutes (design cap 28)). Linking fields: `user`, `secretid` (with `secret`, `account`, `uuid`); the window is the detection rule's window.

- **Recurrence.** `anomaly_interval_hours` (default 24, minimum 2, maximum 8760) sets the interval by source time. The first episode starts within the first min(interval, 24 h) of generation, at a time drawn from the background hour-of-day load. Each later episode is due one interval after the previous episode's actual start and starts in a window of width w = min(interval / 4, 6 h) centred on that due time, weighted by the squared hour-of-day load plus a small floor, so it leans towards busy hours. Missed time is never caught up. Gaps therefore stay within interval ± w/2: measured 22.5-26.1 h (mean 24.0) at the default, 10.6-13.4 h (mean 11.8) with 12 h.
- **Variation.** The user is drawn with the same per-user weights as the background and never repeats the previous episode's user; S is one of that user's approval-gated secrets, never the previous episode's first secret; the other secrets, the approval delay and the gaps between views come from the background distributions (the draw is repeated when the episode would not fit in 28 minutes).
- **Background realism.** Every element of the chain also occurs in background of both modes: requests, request followed by a view of the same secret, sessions of several distinct views, re-views, second requests, and near misses (request, view and four more distinct secrets). The chains' user-secret pairs are ordinary ones: 57 of 60 in the default capture and 122 of 126 in the 12 h capture also occur outside the chains. Only the complete sequence within 30 minutes is kept out of the background: an ordinary view that would complete it reopens one of the secrets already in the sequence instead, at the same time. This is rare (a simulation of the background without it gives 0-2 such sequences per 8 days), and in background captures complete sequences of 30-40 minutes are as sparse as those of 40-60 minutes, with no pile-up just past the window.
- **Detection idea.** Per user, a secret request followed within 30 minutes by clear-text views of that secret and of at least five other distinct secrets.
- A match does not prove misuse. The documented logs carry no approval decision, source address or view reason.

`anomaly_mode` defaults to `true`. Set it to `false` for background only: the same users, secrets and event types, with no complete chain.

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

From the content-packs repository:

```bash
# Batch: generate as fast as possible
eventum generate --path generators/identity-fortinet-fortipam/generator.yml --id fortipam --live-mode false

# Live: follow the wall clock
eventum generate --path generators/identity-fortinet-fortipam/generator.yml --id fortipam --live-mode true
```

Output: `generators/identity-fortinet-fortipam/output/events.json`. Extract `event.original` when a collector expects FortiPAM key-value messages. In batch mode add `start` and `end` to the `cron` input for a finite window; the first episode starts within min(interval, 24 h) of source time.

## Sample output

The request that opens an episode, copied from a default-mode capture:

```json
{"@timestamp": "2026-09-16T15:37:37.824160Z", "ecs": {"version": "8.17.0"}, "event": {"action": "request", "category": ["iam"], "code": "2304064604", "dataset": "fortinet.fortipam", "kind": "event", "module": "fortinet", "original": "date=2026-09-16 time=15:37:37 devname=\"FPAVULTM1234567\" devid=\"FPAVULTM1234567\" eventtime=1789573057824160174 tz=\"+0000\" logid=\"2304064604\" type=\"secret\" subtype=\"secret-request\" eventtype=\"secret-request\" action=\"pass\" operation=\"request\" secretid=564 secret=\"ws-laps-hr\" account=\"localadmin\" uuid=\"3b844f7c-a4e3-52dd-9fb1-0a9ec1309254\" user=\"k.reyes\" starttime=\"2026-09-16 15:37:00\" expirytime=\"2026-09-16 16:07:00\" msg=\"Created secret request.\"", "outcome": "success", "type": ["creation"]}, "fortinet": {"fortipam": {"account": "localadmin", "action": "pass", "eventtime": 1789573057824160174, "eventtype": "secret-request", "expirytime": "2026-09-16 16:07:00", "logid": "2304064604", "msg": "Created secret request.", "operation": "request", "secret": "ws-laps-hr", "secretid": 564, "starttime": "2026-09-16 15:37:00", "subtype": "secret-request", "type": "secret", "tz": "+0000", "user": "k.reyes", "uuid": "3b844f7c-a4e3-52dd-9fb1-0a9ec1309254"}}, "observer": {"hostname": "FPAVULTM1234567", "product": "FortiPAM", "serial_number": "FPAVULTM1234567", "vendor": "Fortinet"}, "related": {"user": ["k.reyes"]}, "user": {"name": "k.reyes"}}
```

## Limitations

- Only two log IDs are modeled, because Fortinet publishes raw lines only for these: secret request created (FortiSIEM's FortiPAM page, sample dated 2023-08, release not stated) and clear text view allowed (FortiPAM 1.7.0). Request approval and denial, launches, check-in/out and password changes are logged by FortiPAM but have no published raw layout, so they are absent.
- Each record keeps exactly the key set and order of its source example. The clear-text-view example comes from `execute log display` and has no `devname`/`devid`; the pack does not add them. Whether syslog output adds them, or a syslog header, is not documented; no syslog envelope is emitted.
- `uuid` is assumed to be the secret object's UUID and is stable per secret. `starttime` is the request minute and `expirytime` a preset duration (30 min to 8 h); the example shows a 30-minute request starting at the minute. `agent` is always `GUI`, the only documented value. Time zone is UTC (`tz="+0000"`).
- Episode hours follow the background only loosely. Because each start is anchored to the previous one, episodes keep a phase: at the default 24 h all 10 measured starts fell between 13:51 and 16:37 UTC (background: 78% of records at 08:00-18:00). With an interval that is not a multiple of 24 h, some episodes land at night: with 12 h, 9 of 21 starts fell at 21:00-07:00, where the background has 8% of its records; the squared-load weighting only drifts them towards busier hours by up to w/2 per episode.
- Secret, account and address names are fictional, on RFC 1918 addresses.

## References

- [FortiSIEM: Fortinet FortiPAM / FortiSRA (secret-request sample, syslog settings)](https://docs.fortinet.com/document/fortisiem/7.4.1/external-systems-configuration-guide/521441/fortinet-fortipam)
- [FortiPAM 1.7.0: Creating an automation trigger (clear-text-view sample)](https://docs.fortinet.com/document/fortipam/1.7.0/examples/779148/creating-an-automation-trigger)
- [FortiPAM 1.9.2: Secret event & video (secret log categories)](https://docs.fortinet.com/document/fortipam/1.9.2/administration-guide/205262/secret-event-video)
- [FortiPAM 1.7.0: Sending a request to access a secret (request duration)](https://docs.fortinet.com/document/fortipam/1.7.0/examples/133951/sending-a-request-to-access-a-secret)
- No Elastic integration exists for FortiPAM; the ECS projection is inferred.
