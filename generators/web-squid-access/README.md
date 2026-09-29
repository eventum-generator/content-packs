# Squid 6.x Native Access Log

Generates a small office proxy's Squid 6.x `access.log` traffic. The output is ECS JSON, with the native `squid` format line preserved in `event.original`.

The [Squid 6 native format](https://www.squid-cache.org/Doc/config/logformat/) has ten whitespace-separated values: transaction-end Unix time with milliseconds, elapsed milliseconds, client address, result/HTTP status, bytes sent to the client, request method, URL, user, hierarchy/peer, and content type. This profile assumes the built-in `squid` format, no `log_mime_hdrs` suffix, and one proxy. It has one record every five seconds from 24 synthetic clients, 24 resources, eight CONNECT targets, and seven ACL-restricted paths.

The generated stream covers **43/54 field paths** in the [Elastic Squid sample event](https://github.com/elastic/integrations/blob/main/packages/squid/data_stream/log/sample_event.json), or **43/43** after excluding 11 environment-specific fields. The missing paths are `destination.geo.city_name`, `continent_name`, `country_iso_code`, `country_name`, `location.lat`, `location.lon`, `region_iso_code`, `region_name`; and `log.file.device_id`, `fingerprint`, `inode`. GeoIP cannot be inferred from private addresses. File identity depends on the actual collector filesystem; inventing it would imply a real Filebeat observation. Proxy identity, fixed synthetic agent IDs and monotonically increasing UTF-8 line offset are collector context for one unrotated file. `event.ingested` equals completion time under a synthetic zero-delay collector assumption. These are not native Squid observations.

## Event Types

| Native result | Request | Routine selection weight | Condition |
| --- | --- | ---: | --- |
| `TCP_MISS/200`, `HIER_DIRECT/<ip>` or `TCP_HIT/200`, `HIER_NONE/-` | `GET` | 70% | Miss for a cold, expired or uncacheable URL; hit for a fresh cached object |
| `TCP_TUNNEL/200`, `HIER_DIRECT/<ip>` | `CONNECT` | 18% | Tunnel to host and port |
| `TCP_DENIED/403` or `/407`, `HIER_NONE/-` | `GET` | 7% | Restricted path; anonymous clients receive 407 |
| `TCP_IMS_HIT/304`, `HIER_NONE/-` | `GET` | 5% | Conditional request for a cached object |

These are configured weights, not measured Squid traffic ratios. Users also reload blocked pages: 10% of ordinary 403 denials of a named user start one to four more denials of the same user and URL (weights 50/25/15/10), 5, 10, 15, 20 or 30 seconds apart (weights 50/20/12/10/8). In background, 403 denials are 7.0% and 407 denials 1.0% of records; four days hold about 216, 105, 62 and 41 runs of two, three, four and five denials of one user and URL within 31 seconds of each other, and a run of six occurs about once in ten days. Cacheable public resources use an explicitly synthetic origin profile: `Cache-Control: public, max-age=3600`, fixed response headers within an object lifetime, and no `Vary` or authentication-dependent representation. The proxy cache keeps each cached URL's response bytes and expiry. A fresh hit returns the stored response size; expired entries are removed. Conditional requests become misses for cold, expired or uncacheable URLs. Only cacheable resources can produce hits. The cache has at most 24 entries; the shipped resource pool has 12 cacheable URLs. Successful `CONNECT` logs the `host:port` target; it does not reveal an HTTPS path. The native byte count is the response sent to the client, including headers. Elastic maps it to `destination.bytes` even on cache hits and denials; it is not origin-server traffic or upload volume.

## Anomaly Chain

The default mode emits three `TCP_DENIED/403` records followed by two `TCP_MISS/200` responses for the same user, client IP, and HTTP URL. The two returned responses are 1.8-2.8 MB. All five transactions finish in about 20 seconds, and their logged durations keep their lifetimes in order. A detection can group by `source.user.name` and `url.original` and flag three denials followed by two successful `GET` responses, the first denial at most 300 seconds before the last response.

Recurrence: with `anomaly_mode: true` (the default) the first episode starts at a time drawn uniformly within the first `min(anomaly_interval_hours, 24 h)` of generated time; the background has no hour-of-day curve, so no hour is preferred. Each next episode is due `anomaly_interval_hours` after the actual start of the previous one and starts at a time drawn uniformly within a window of `w = min(interval / 4, 6 h)` centred on that due time. Consecutive starts are therefore `interval ± w/2` apart (6 h ± 45 min by default), start times do not drift, and missed intervals are never caught up. Four days hold about 16 episodes at the default interval, with gaps of about 5.26-6.74 h, and about 32 with a three-hour interval, with gaps of about 2.64-3.37 h.

Only the complete ordered chain is absent from background: an ordinary `GET` that would return 200 and complete three denials and one 200 `GET` of the same user and URL, the first denial at most 300 seconds earlier, goes to another URL of the resource pool instead, at the same time. An episode's own requests count too, so each episode completes the chain once (in about 0.2% of episodes a background prefix of the same user and URL started in the 300 seconds before the episode is completed by the episode's own download, giving a second chain): an ordinary download of the episode URL by `analyst` within 300 seconds of the episode's first denial goes to another URL the same way. No other record is changed or moved. Four days of background hold about 2.6 sequences of three denials and one 200 `GET` of the same user and URL within 300 seconds; none is followed by a second 200 `GET` of that user and URL within 600 seconds of the first denial, and the share of 200 `GET` responses among other users' and URLs' records has no step at the window edge (70% in the last minute inside the window, 68% in the first minute after it; 51-79% in the sparse earlier minutes, 68-77% up to 600 seconds).

This is an unusual access-outcome transition, not proof that a policy was changed or data was exfiltrated. `access.log` has no policy-change event, and the bytes are delivered to the client. The user, IP, URL, origin, large responses, and individual result codes also occur in ordinary background. Each episode has varied response sizes, durations and completion milliseconds. No session or policy-change ID is fabricated. `false` emits only background. Ordinary traffic also denies the exact target URL for the target user, so a single denial does not identify the mode. In both modes the target client sends an extra 10% of requests on top of its share of the 24-client pool, approximately 13.75% overall. The selected background models mixed access-decision contexts without logging their cause, so later success is not evidence of an ACL change.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `proxy_name`, `proxy_ip` | `squid-01`, `10.70.0.5` | Synthetic collector/proxy identity |
| `anomaly_user`, `anomaly_ip` | `analyst`, `10.70.4.17` | Client identity in both background and sequence |
| `anomaly_url`, `anomaly_origin_ip` | `http://files.corp.example/export.csv`, `10.70.8.14` | Absolute HTTP URL and origin used in both modes |
| `anomaly_interval_hours` | `6` | Mean time between episode starts (each start within ± `min(interval / 8, 3 h)` of its due time); finite numeric values below one hour are clamped to one |
| `anomaly_mode` | `true` | Include repeated sequences; `false` emits background only |

Use a short ASCII username without whitespace or native quoting characters (`%`, brackets, quotes, backslashes or controls). The selected URL profile is an absolute HTTP URL with ASCII or already escaped path characters, no user information, query or fragment. Arbitrary Unicode/native username quoting and URL normalization are outside this profile. Keep the shipped cadence of one record every five seconds for the stated chain timings.

### Output Parameters

The shipped config writes `output/events.json` and uses no `${params.*}` or `${secrets.*}` placeholders. Edit `output.file.path` or replace the output plugin to send data to a SIEM. A collector expecting raw Squid lines can extract `event.original`.

## Usage

From the content-packs repository root, run continuously:

```bash
uv run --project ../eventum eventum generate --path generators/web-squid-access/generator.yml --id squid --live-mode true
```

For a bounded batch, copy `generator.yml`, add `input[0].cron.start` and `end` (ISO timestamps), then run:

```bash
uv run --project ../eventum eventum generate --path generators/web-squid-access/generator-batch.yml --id squid-batch --live-mode false --keep-order true
```

For example, set `start: 2026-09-01T00:00:00+00:00` and `end: 2026-09-05T00:00:00+00:00`. This finite four-day range contains 69,121 events and 15-17 complete default chains at randomized times. Repeat with `anomaly_mode: false` for zero complete injected chains. A three-hour interval produces about twice as many. Native and ECS timestamps normalize to UTC even with a non-UTC CLI timezone.


## Sample Output

This complete event is the second download of the first episode of a default run:

```json
{
  "@timestamp": "2026-09-01T01:13:35.589000+00:00",
  "agent": {
    "ephemeral_id": "5a110000-1111-4444-8888-123456789abc",
    "id": "5a110000-1111-4444-8888-123456789abc",
    "name": "squid-01",
    "type": "filebeat",
    "version": "8.17.0"
  },
  "data_stream": {
    "dataset": "squid.log",
    "namespace": "default",
    "type": "logs"
  },
  "destination": {
    "address": "10.70.8.14",
    "bytes": 1891810,
    "ip": "10.70.8.14"
  },
  "ecs": {
    "version": "8.17.0"
  },
  "elastic_agent": {
    "id": "5a110000-1111-4444-8888-123456789abc",
    "snapshot": false,
    "version": "8.17.0"
  },
  "event": {
    "agent_id_status": "verified",
    "category": [
      "web"
    ],
    "dataset": "squid.log",
    "duration": 2188000000,
    "ingested": "2026-09-01T01:13:35.589000+00:00",
    "kind": "event",
    "module": "squid",
    "original": "1788225215.589   2188 10.70.4.17 TCP_MISS/200 1891810 GET http://files.corp.example/export.csv analyst HIER_DIRECT/10.70.8.14 text/csv",
    "outcome": "success",
    "type": [
      "access"
    ]
  },
  "http": {
    "request": {
      "method": "GET"
    }
  },
  "input": {
    "type": "filestream"
  },
  "log": {
    "file": {
      "path": "/var/log/squid/access.log"
    },
    "offset": 116818
  },
  "observer": {
    "hostname": "squid-01",
    "ip": "10.70.0.5",
    "product": "Squid",
    "type": "proxy",
    "vendor": "Squid"
  },
  "related": {
    "hosts": [
      "files.corp.example"
    ],
    "ip": [
      "10.70.4.17",
      "10.70.8.14"
    ],
    "user": [
      "analyst"
    ]
  },
  "source": {
    "address": "10.70.4.17",
    "ip": "10.70.4.17",
    "user": {
      "name": "analyst"
    }
  },
  "squid": {
    "content_type": "text/csv",
    "peer_status": "HIER_DIRECT",
    "result_code": "TCP_MISS",
    "status_code": 200
  },
  "tags": [
    "preserve_original_event",
    "squid-log"
  ],
  "url": {
    "domain": "files.corp.example",
    "original": "http://files.corp.example/export.csv",
    "path": "/export.csv",
    "scheme": "http"
  }
}
```

## References and Limits

- [Squid built-in logformat and field meanings](https://www.squid-cache.org/Doc/config/logformat/) and [native format guide](https://wiki.squid-cache.org/Features/LogFormat) define field order, completion time, and response-byte semantics.
- [Squid 6.9 native formatter](https://github.com/squid-cache/squid/blob/SQUID_6_9/src/log/FormatSquidNative.cc) establishes completion time, response byte count and native username quoting. Arbitrary native quoted usernames are outside this token-only profile.
- [Squid 6.9 source tag](https://github.com/squid-cache/squid/blob/SQUID_6_9/src/LogTags.cc) lists the result tags used here. A [Squid 6.9 native log excerpt](https://ml-archives.squid-cache.org/squid-users/2024-April/026587.html) shows `TCP_MISS/200 HIER_DIRECT` followed by `TCP_HIT/200 HIER_NONE` for one URL. The [Squid mailing-list raw CONNECT examples](https://ml-archives.squid-cache.org/squid-users/2020-January/021654.html) show `TCP_TUNNEL/200 HIER_DIRECT`.
- [Squid raw 403/407 examples](https://ml-archives.squid-cache.org/squid-users/2024-September/027101.html) and [conditional cache-hit example](https://ml-archives.squid-cache.org/squid-users/2017-October/016750.html) support the other result/status combinations. The conditional example is from an older version; the tag remains in the Squid 6.9 source, but a full Squid 6.9 raw example of this exact combination has not been located. The synthetic distribution and chain timing are scenario choices, not vendor-measured rates.
- [Elastic Squid ingest pipeline](https://github.com/elastic/integrations/blob/main/packages/squid/data_stream/log/elasticsearch/ingest_pipeline/default.yml) maps the native line to ECS. Its [older native fixture](https://github.com/elastic/integrations/blob/main/packages/squid/data_stream/log/_dev/test/pipeline/test-access.log) includes legacy `DIRECT`/`NONE` hierarchy codes and `TCP_MISS/200 CONNECT`; those are not used for this Squid 6.x profile.
- [KUMA supported sources](https://support.kaspersky.com/kuma/4.0/en-US/255782.htm) lists Squid `access.log` as an integration source.

Reload-burst rates and lengths are synthetic assumptions.
