# Squid Native Access Log

Generates Squid's native 10-field `access.log` records, with the original line in `event.original` and ECS fields for analysis.

Reference coverage: **43/43 source-derived fields** in the [Elastic Squid sample event](https://github.com/elastic/integrations/blob/main/packages/squid/data_stream/log/sample_event.json), including destination fields on allowed requests. GeoIP enrichment and Filebeat file identity are excluded because Squid does not emit them.

## Event Types

| Native result | Meaning | Routine weight |
| --- | --- | ---: |
| `TCP_MISS/200` `GET` | Origin fetch | 55% |
| `TCP_HIT/200` `GET` | Cache hit | 25% |
| `TCP_MISS/200` `CONNECT` | HTTPS tunnel request | 15% |
| `TCP_DENIED/403` `GET` | ACL denial | 5% |
| Denials followed by allowed large fetches | Same user, IP and URL | Anomaly only |

These are configured weights, not measured Squid rates. Each line keeps Squid's timestamp, elapsed milliseconds, client, result/status, byte count, method, URL, RFC 931 username, peer and content type in the native order.

## Anomaly Chain

`analyst` at `10.70.4.17` receives three `TCP_DENIED/403` results for `http://files.corp.example/export.csv`, then two `TCP_MISS/200` results with large response byte counts for the same URL. Correlate `source.ip`, `source.user.name`, `url.original` and timestamp. A rule can spot access changing from denied to allowed for one resource. `access.log` alone cannot establish why access changed, and the bytes measure returned responses rather than uploads.

`anomaly_mode: true` is the default. Set `event.template.params.anomaly_mode: false` for background only; the anomaly URL, user and IP then disappear.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `proxy_name`, `proxy_ip` | `squid-01`, `10.70.0.5` | Proxy identity |
| `anomaly_user`, `anomaly_ip` | `analyst`, `10.70.4.17` | Chain actor |
| `anomaly_url`, `anomaly_origin_ip` | `http://files.corp.example/export.csv`, `10.70.8.14` | Resource and origin |
| `anomaly_interval_events` | `250` | Background events between chains |
| `anomaly_mode` | `true` | Include anomaly sequence; `false` emits background only |

### Output Parameters

The shipped config writes `output/events.json` and has no `${params.*}` or `${secrets.*}` placeholders. Change `output.file.path` or replace the output plugin to connect a SIEM.

## Usage

From the content-packs repository root:

```bash
eventum generate --path generators/web-squid-access/generator.yml --id web-squid-access --live-mode true
```

For a short local sample, use `--live-mode false` and stop the command after enough events.

## Sample Output

The following event came from an enabled-mode run:

```json
{
  "@timestamp": "2026-09-25T12:18:46+00:00",
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
    "bytes": 2320812,
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
    "duration": 3862000000,
    "ingested": "2026-09-25T12:18:46+00:00",
    "kind": "event",
    "module": "squid",
    "original": "1790338726.000 3862 10.70.4.17 TCP_MISS/200 2320812 GET http://files.corp.example/export.csv analyst DIRECT/10.70.8.14 text/csv",
    "outcome": "success",
    "type": [
      "access"
    ]
  },
  "http": {
    "request": {
      "method": "GET"
    },
    "response": {
      "bytes": 2320812,
      "status_code": 200
    }
  },
  "input": {
    "type": "filestream"
  },
  "log": {
    "file": {
      "path": "/var/log/squid/access.log"
    },
    "offset": 29855
  },
  "observer": {
    "hostname": "squid-01",
    "ip": "10.70.0.5",
    "product": "Squid",
    "type": "proxy",
    "vendor": "Squid"
  },
  "related": {
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
    "peer_status": "DIRECT",
    "result_code": "TCP_MISS",
    "status_code": 200
  },
  "tags": [
    "preserve_original_event",
    "squid-log"
  ],
  "url": {
    "original": "http://files.corp.example/export.csv"
  }
}
```

## References and Limits

- [Squid native logformat](https://wiki.squid-cache.org/Features/LogFormat) defines the 10 fields.
- [Elastic Squid raw test lines](https://github.com/elastic/integrations/blob/main/packages/squid/data_stream/log/_dev/test/pipeline/test-access.log) anchor parsed examples.
- [KUMA 4.0 supported sources](https://support.kaspersky.com/kuma/4.0/en-US/255782.htm) lists Squid `access.log`.

The file output is ECS JSON with the native line in `event.original`; a raw `access.log` collector needs that field extracted. The log does not contain policy-change records, and `TCP_MISS` says the response came via the origin, not why a prior denial changed.
