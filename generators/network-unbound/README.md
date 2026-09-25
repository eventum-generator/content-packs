# Unbound DNS query and reply logs

Synthetic syslog events for Unbound's `log-queries` and `log-replies` output, with the tagged `query:`/`reply:` format retained in `event.original`.

## Event Types

| Event | Baseline frequency | Meaning |
| --- | ---: | --- |
| Query + reply for `A` | 80% of pairs | Routine IPv4 lookup |
| Query + reply for `AAAA` | 15% of pairs | Routine IPv6 lookup |
| Query + reply for `MX` | 5% of pairs | Routine mail lookup |
| Beacon `A`, then unique `TXT` pairs | Chain only | DNS tunneling-like sequence |

The baseline weights are synthetic assumptions. Each ordinary request emits one query and one reply before the next request.

## Anomaly Chain

One client (`10.20.30.91`) first looks up `sync-updates.example`, then sends eight distinct long hexadecimal labels as `TXT` questions under that suffix. Each question is followed by an `NXDOMAIN` reply from the same resolver. Correlate by client IP, question name and type, and short time window; flag the jump in unique long labels or repeated `TXT` queries to one suffix. This pattern suggests tunneling or reconnaissance but the log does not expose DNS answer content or prove exfiltration.

`anomaly_mode` defaults to `true`. Set it to `false` in `event.template.params` to produce only ordinary query/reply pairs.

## Parameters

### Event Parameters

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include the tagged beacon and TXT sequence |
| `host_name` | `dns01.corp.example` | Resolver hostname |
| `suspicious_client_ip` | `10.20.30.91` | Client in the chain |
| `tunnel_domain` | `sync-updates.example` | Suffix queried in the chain |

### Output Parameters

The shipped configuration writes `output/events.json` with no connection parameters or secrets. Replace the `file` output in a local copy for a SIEM destination, using `${params.siem_host}` and `${secrets.siem_token}` placeholders for that output plugin when needed.

## Usage

```bash
eventum generate --path generators/network-unbound/generator.yml --id unbound --live-mode false
eventum generate --path generators/network-unbound/generator.yml --id unbound --live-mode true
```

## Sample Output

This event was copied from a real generator run.

```json
{
  "@timestamp": "2026-09-25T12:21:13+00:00",
  "dns": {
    "question": {
      "class": "IN",
      "name": "01fe1171b135e76812f858197c.sync-updates.example.",
      "type": "TXT"
    },
    "response_code": "NXDOMAIN",
    "type": "answer"
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "dns-reply",
    "category": [
      "network"
    ],
    "kind": "event",
    "original": "Sep 25 12:21:13 dns01.corp.example unbound[2137:0]: reply: 10.20.30.91 01fe1171b135e76812f858197c.sync-updates.example. TXT IN NXDOMAIN 0.041357 0 97",
    "type": [
      "info"
    ]
  },
  "host": {
    "name": "dns01.corp.example"
  },
  "process": {
    "name": "unbound",
    "pid": 2137
  },
  "related": {
    "ip": [
      "10.20.30.91"
    ]
  },
  "source": {
    "ip": "10.20.30.91"
  },
  "unbound": {
    "reply": {
      "from_cache": 0,
      "response_size": 97,
      "time_to_resolve": 0.041357
    },
    "worker_id": 0
  }
}
```

## Coverage and Limits

The tagged log's nine selected data fields are present across query/reply events: timestamp, client IP, question name, type, class, reply code, resolution time, cache flag, and response size (9/9). Reply-only fields are null for queries. Unbound requires `log-queries: yes`, `log-replies: yes`, and `log-tag-queryreply: yes` for this stream and format; all three default to `no`. Query/reply logging can significantly slow a busy resolver. Syslog wrappers vary by host and logging configuration. The log has no request ID and no answer RDATA, so pairing concurrent identical questions by client/name/type/time can be ambiguous.

## References

- [Unbound `unbound.conf` logging settings](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html)
- [NLnet Labs Unbound query/reply sample](https://github.com/NLnetLabs/unbound/issues/451)
