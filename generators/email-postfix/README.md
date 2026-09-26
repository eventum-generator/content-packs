# Postfix SMTP Syslog

Generates Postfix 3.8.3+ submission-relay messages for `smtpd`, `cleanup`, `qmgr` and `smtp`. The complete native syslog line is in `event.original`; the output file contains parsed ECS JSON, not bare syslog lines. The selected profile has SASL LOGIN enabled on the submission service, `enable_long_queue_ids=no`, `smtp_destination_recipient_limit=1`, `local_header_rewrite_clients=permit_sasl_authenticated`, and conventional local mail-log timestamps in UTC. It models ordinary server load, without stress-mode connection limits. It does not emit a remote syslog packet.

## Event Types

| Native record | Purpose | Background selection |
| --- | --- | ---: |
| `postfix/smtpd` with `client=`, `sasl_method=LOGIN`, `sasl_username=` | Queue ID assigned to an authenticated submission | 90% of routine decisions |
| `postfix/smtpd` `NOQUEUE: reject: RCPT` | Unknown recipient rejected before queueing | 7% of routine decisions |
| `postfix/smtpd` `SASL LOGIN authentication failed` | Isolated failed login | 3% of routine decisions, at least 20 generated records apart |
| `postfix/cleanup` `message-id=` | Message enters the queue | After every queue creation |
| `postfix/qmgr` `from=`, `size=`, `nrcpt=` | Queue activation | After cleanup; ordinary `nrcpt` is 1/2/5 with weights 85/13/2 |
| `postfix/smtp` `to=`, `relay=`, `delay=`, `delays=`, `dsn=`, `status=sent` | One successful recipient delivery | One per queued recipient |
| `postfix/qmgr` `removed` | Message leaves the queue | After every modeled delivery completes |

The weights are synthetic configuration choices for a mostly successful submission relay, not measured Postfix frequencies. The one-second input tick is also a configurable synthetic traffic rate. Routine senders and recipients vary. Short queue IDs contain a valid five-hex microsecond component and a synthetic inode component; the subsecond creation value is not exposed by the second-resolution log prefix. IDs do not represent files on a real filesystem. The model keeps one queued message active at a time. Submitted messages omit their own Message-ID; the selected authenticated-client header-rewrite policy allows cleanup to supply one. Its date prefix comes from the queue-file creation time in UTC, rather than the later cleanup log time. Envelope sender equals the selected authenticated account as a scenario choice, rather than a claimed Postfix authorization requirement.

The single-recipient SMTP transport profile permits separate delivery records with different completion times and worker PIDs even when recipients share a relay. `delay` runs from modeled MAIL FROM arrival to recipient delivery. This synthetic arrival and queue creation share a generated second; real Postfix can create the queue file later, so that equality is a model assumption. The normalized timestamps represent second-resolution log prefixes, not actual filesystem times. The four `delays` phases describe arrival to active-queue entry, active wait, connection setup, and transmission. Setup latency varies, and transmission latency depends on message size and a synthetic bounded throughput. Printed values follow Postfix 3.8.3 integer-microsecond HALF-UP rounding, with two significant digits and at most two decimals, trimming trailing zeros. Rounded phases need not sum exactly. The shipped cadence is one second with count 1; changing cadence requires adjusting the latency and lifecycle model together.

## Anomaly Chain

Episodes recur every six hours of generated event time by default. If the interval expires while ordinary mail is queued, that queue completes first. The next routine decision schedules the episode, so the first failure waits at most one ordinary message lifecycle plus a tick. With the shipped integer-hour intervals and one-second tick, this is at most nine seconds; fractional-hour due times can approach ten seconds. Each episode emits three failed SASL LOGIN attempts from the same user, IP and `smtpd` PID, followed by a queue-ID assignment from that authenticated session. Its new queue ID links `cleanup`, `qmgr nrcpt=5`, five distinct `smtp status=sent` deliveries and `qmgr removed`. The twelve records span eleven seconds. Consecutive episodes use new queue IDs and different recipient sets; a bounded rotating recipient cursor can reuse a set after a cycle.

A rule can correlate repeated failures followed by a successful submission, then count delivered recipients by queue ID. Failed authentications have no queue ID, so the correlation into the queued message uses user, IP, host, PID and time. PID alone is not a session ID and is reused by routine clients; connection/TLS records are omitted from this selected stream. `sasl_username` on the queue-creation record provides evidence of successful authentication. That line alone does not prove final DATA acceptance; subsequent qmgr activation and successful deliveries show the modeled message progressed. No separate AUTH-success record is invented.

`anomaly_mode: true` is the default. With `false`, only background is emitted. The target user and IP, isolated failures and five-recipient deliveries also occur in background; no individual value or record marks the episode. The mode changes the sequence, not the event schema.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `mail_host`, `mail_ip` | `mail-01.corp.example`, `10.80.0.5` | Postfix host identity |
| `normal_user`, `normal_ip` | `service@corp.example`, `10.80.1.20` | First routine sender; seven more are in `samples/senders.json`; use an ASCII username of at most 100 bytes |
| `anomaly_user`, `anomaly_ip` | `payroll@corp.example`, `10.99.3.51` | Episode identity, also used by routine mail and isolated failures; use an ASCII username of at most 100 bytes |
| `anomaly_interval_hours` | `6` | Recurrence in generated hours; minimum supported interval is 1 hour, smaller values are clamped to 1 |
| `anomaly_mode` | `true` | Include recurring episodes; `false` emits background only |

### Output Parameters

The shipped configuration writes `output/events.json` and has no `${params.*}` or `${secrets.*}` placeholders. Change `output.file.path` or replace the output plugin for a SIEM. A collector expecting raw syslog should extract `event.original`.

## Usage

From the content-packs repository root:

```bash
uv run --project ../eventum eventum generate --path generators/email-postfix/generator.yml --id email-postfix --live-mode true
```

For a finite sample covering three default episodes, create a temporary config beside the original so sample/template paths stay relative:

```bash
uv run --project ../eventum python - <<'PY'
from pathlib import Path
import yaml
root = Path('generators/email-postfix')
config = yaml.safe_load((root / 'generator.yml').read_text())
config['input'][0]['cron'].update({
    'start': '2026-09-25T00:00:00+00:00',
    'end': '2026-09-25T18:15:00+00:00',
})
(root / '.finite.yml').write_text(yaml.safe_dump(config, sort_keys=False))
PY
flock -x /tmp/eventum-generator-heavy.lock uv run --project ../eventum eventum generate --path generators/email-postfix/.finite.yml --id email-postfix-sample --live-mode false --keep-order true
rm generators/email-postfix/.finite.yml
```

This produces 65,701 events. Setting `anomaly_mode: false` in the temporary config covers the same background window. The final ordinary queue may be incomplete when finite input ends; the generator neither fabricates completion nor keeps an unbounded queue history.

## Sample Output

This synthetic cleanup record was copied from a verified anomaly-mode run. Its Message-ID date precedes the cleanup log timestamp because it uses queue-file creation time. The same shape also appears in background; it is not a vendor capture.

```json
{
  "@timestamp": "2026-09-25T06:00:09+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "message-cleanup",
    "category": [
      "email"
    ],
    "dataset": "postfix.syslog",
    "kind": "event",
    "original": "Sep 25 06:00:09 mail-01.corp.example postfix/cleanup[2421]: 11375C0580: message-id=<20260925060008.11375C0580@mail-01.corp.example>",
    "outcome": "success",
    "type": [
      "info"
    ]
  },
  "host": {
    "ip": [
      "10.80.0.5"
    ],
    "name": "mail-01.corp.example"
  },
  "log": {
    "level": "info",
    "syslog": {
      "appname": "postfix/cleanup"
    }
  },
  "message": "11375C0580: message-id=<20260925060008.11375C0580@mail-01.corp.example>",
  "observer": {
    "hostname": "mail-01.corp.example",
    "ip": "10.80.0.5",
    "product": "Postfix",
    "type": "mail",
    "vendor": "Postfix"
  },
  "postfix": {
    "message_id": "<20260925060008.11375C0580@mail-01.corp.example>",
    "queue_id": "11375C0580",
    "service": "cleanup"
  },
  "process": {
    "name": "postfix/cleanup",
    "pid": 2421
  },
  "related": {
    "hosts": [
      "mail-01.corp.example"
    ]
  },
  "tags": [
    "postfix",
    "preserve_original_event"
  ]
}
```

## References and Limits

- [Postfix 3.8.3 generated Message-ID](https://github.com/vdukhovni/postfix/blob/v3.8.3/postfix/src/cleanup/cleanup_message.c#L694) uses queue-file creation time and requires header rewriting or `always_add_missing_headers`. This pack selects [authenticated header rewriting](https://www.postfix.org/postconf.5.html#local_header_rewrite_clients), keeping the broader missing-header setting at its default. [Versioned delay formatting](https://github.com/vdukhovni/postfix/blob/v3.8.3/postfix/src/util/format_tv.c#L70) supplies the HALF-UP precision rule.
- [Postfix 3.8.3 smtpd source](https://github.com/vdukhovni/postfix/blob/v3.8.3/postfix/src/smtpd/smtpd.c#L2316) logs queue-ID/client/SASL information while initializing cleanup, before final DATA acceptance. [Versioned SASL logging](https://github.com/vdukhovni/postfix/blob/v3.8.3/postfix/src/smtpd/smtpd_sasl_glue.c#L344) uses the client name/address and username on failure.
- [Postfix architecture](https://www.postfix.org/OVERVIEW.html) documents the `smtpd` → `cleanup` → queue manager → `smtp` path.
- [Postfix 3.8.3 announcement](https://www.postfix.org/announcements/postfix-3.8.3.html) documents `sasl_username` after authentication failure. The field was also backported to 3.7.8, 3.6.12 and 3.5.22; this generator models 3.8.3+.
- [Postfix ETRN examples](https://www.postfix.org/ETRN_README.html) show queue activation with `from=`, `size=` and `nrcpt=`.
- [Postfix connection-cache examples](https://www.postfix.org/CONNECTION_CACHE_README.html) show outbound `to=`, `relay=`, `delay=`, `delays=`, `dsn=` and `status=sent`.
- [Postfix backscatter examples](https://www.postfix.org/BACKSCATTER_README.html) show `NOQUEUE: reject: RCPT` syntax.
- [Postfix queue-ID specification](https://www.postfix.org/postconf.5.html#enable_long_queue_ids) defines short queue IDs and Message-ID headers. [Delay specification](https://www.postfix.org/postconf.5.html#delay_logging_resolution_limit) defines phases and rounding. [Single-recipient SMTP transport](https://www.postfix.org/postconf.5.html#smtp_destination_recipient_limit) is the selected delivery profile.
- [Postfix users list trace](https://www.mail-archive.com/postfix-users%40postfix.org/msg83417.html) shows one real queue ID through `smtpd`, `cleanup`, `qmgr`, `smtp` and `removed`.
- [Postfix users list explanation](https://www.mail-archive.com/search?f=1&l=postfix-users%40postfix.org&o=newest&q=date%3A20110309) explains that `smtpd client=` creates a queue ID and `qmgr removed` closes that queue lifecycle.

This is a selected successful-delivery path, not a complete Postfix mail log. It omits connection/TLS logs, postscreen, local delivery, bounce and deferred retries. **BLOCKED_RAW_EVIDENCE:** an exact Postfix 3.8.3+ raw trace containing the complete three-failure-to-acceptance episode is not available after a bounded search. The current audit could load official documents, but the older mailing-list capture was inaccessible; the chain joins documented line formats and is a synthetic scenario. The generic `linux-syslog` pack includes uncorrelated Postfix connect/disconnect/delivery lines as part of a multi-service host stream. This existing pack covers a dedicated SASL submission and queue lifecycle with correlations; it is not a new source added by this audit. There is no source-specific Elastic integration sample used as a schema reference; `postfix.syslog` is the generator's ECS dataset name.
