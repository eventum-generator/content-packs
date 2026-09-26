# MikroTik RouterOS Syslog

Produces ECS-wrapped RouterOS account, mangle configuration, DHCP and UDP firewall messages from one router. The JSON output contains a constructed BSD Syslog `event.original`; exact remote framing remains **BLOCKED_RAW_EVIDENCE**.

## Event Types

| Action | Background pattern | Category |
| --- | --- | --- |
| DHCP assigned / deassigned | 5% of ordinary non-session slots, toggled per client | Network |
| UDP firewall packet | 95% of ordinary non-session slots | Network |
| Winbox login / logout | Paired normal, external administrator and internal maintenance sessions | Authentication |
| Mangle rule added / moved / changed / removed | One temporary rule lifecycle during daily internal maintenance | Configuration |

These are synthetic workload weights, not measured production frequencies. The generator emits one record per minute, about 1,440 per day. Eight clients retain bounded lease state. Firewall packets retain the documented input-chain UDP grammar; the emitted MAC, IPs, ports and packet length agree with their parsed ECS fields. Packet logging does not establish an accept/drop decision. This pack does not model TCP connection tracking, NAT or filter-rule policy changes, and mangle edits do not alter the unrelated UDP packet workload.

## Anomaly Chain

`anomaly_mode: true` is the default. The default `anomaly_interval_hours: 24` schedules repeated administrator episodes using generated UTC event time:

1. The administrator logs in from an external address via Winbox.
2. A temporary mangle rule is added.
3. The existing rule is moved and changed.
4. The temporary rule is removed.
5. The administrator logs out from the same address.

The six records span five minutes. The first episode starts 24 hours and one minute after the first record, then every 24 hours at the shipped cadence. Scheduling waits for ordinary sessions and their rule lifecycle to finish and reserves their upcoming daily slots. Custom or fractional intervals can therefore be delayed or rounded to the next minute. Intervals below one hour are clamped to one hour.

Episodes rotate through `anomaly_source_ip` and `additional_external_source_ips`. That same pool rotates through ordinary external logins in both modes. Native account messages identify user, source IP and Winbox, but provide no session ID. Generic mangle messages identify only user and operation, with no rule ID, command, target or client IP. Correlate the external login, edit burst and matching logout by router, user and time; the editing session and single temporary rule are scenario assumptions, not links proven by those raw lines. No episode ID is inserted into source fields. Addresses may be reused after a pool cycle.

Both modes also emit daily external administrator sessions from minute 20 to 25 without configuration changes, internal administrator maintenance from minute 600 to 608, and normal operator sessions from minute 900 to 910, relative to the first event. Internal maintenance adds, moves, changes and removes the same modeled temporary rule among pre-existing unchanged mangle rules. Each operation and actor occurs in background. Set `anomaly_mode: false` for this background without the close external-login-and-edit sequence. All modeled temporary rules are removed before logout; there is no silent reset or growing rule collection.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `router_name`, `router_ip` | `mt-edge-01`, `10.30.0.1` | Router identity and UDP packet destination |
| `normal_user`, `normal_source_ip` | `netops`, `10.30.1.12` | Ordinary operator and management address |
| `admin_internal_source_ip` | `10.30.1.11` | Internal administrator maintenance address |
| `anomaly_user` | `admin` | Administrator used in both background and incident sessions |
| `anomaly_source_ip` | `198.51.100.83` | First address in the shared external administrator pool |
| `additional_external_source_ips` | `[198.51.100.84, 198.51.100.85]` | Other addresses in that pool, used by both modes |
| `anomaly_interval_hours` | `24` | First wait and recurrence, minimum one hour; ordinary sessions can delay scheduling |
| `anomaly_mode` | `true` | Include periodic external-login-and-edit episodes |

Keep the external pool to at least two distinct addresses, separate from the two internal management addresses. The example external addresses are RFC 5737 documentation addresses. Recurrence uses event time, not a count of ordinary selections. Keep the shipped one-minute/count-one input profile when interpreting the stated timings.

### Output Parameters

The generator writes `output/events.json` relative to its directory. It has no top-level `${params.*}` or `${secrets.*}` placeholders. Change `output.file.path` or the output plugin to deliver elsewhere.

## RouterOS Logging Profile and Evidence Limits

The selected profile follows the current RouterOS 7 manual's BSD Syslog path, with `target=remote`, `remote-log-format=syslog`, `syslog-facility=local0`, `syslog-severity=info`, `syslog-time-format=bsd-syslog` and `add-topics-string=yes`. Syslog uses UDP in this path. The modeled router clock is UTC, yielding priority 134. Logging topics include `system`, `dhcp` and `firewall`; packet records require a logging-enabled firewall rule.

The manual supplies local account, mangle add/move/change, DHCP and UDP packet examples. A firsthand RouterOS 6.35rc record supplies the generic mangle removal text; its continued use in RouterOS 7 is an explicit **inference**, pending a versioned capture. The manual's Elasticsearch guide also documents parsing MAC, protocol, packet endpoints and length. The pack parses those packet values but does not reproduce that whole ingest pipeline.

The BSD header, hostname and topic placement in `event.original` remain **BLOCKED_RAW_EVIDENCE**: a complete remote UDP frame from this exact configuration was not found in the bounded vendor search. No RouterOS point release or full native parity is claimed. ECS metadata and selection frequencies are synthetic. Source grammar checks do not clear this missing-capture limit.

## Usage

From the content-packs repository root:

```bash
uv run --project ../eventum eventum generate --path generators/network-mikrotik-routeros/generator.yml --id network-mikrotik-routeros --live-mode true --keep-order true
```

For a finite accelerated 73-hour run with three complete default episodes:

~~~bash
uv run --project ../eventum python - <<'PYCODE'
from pathlib import Path
from yaml import safe_load, safe_dump
root = Path("generators/network-mikrotik-routeros")
config = safe_load((root / "generator.yml").read_text())
config["input"][0]["cron"].update(
    start="2026-09-25T00:00:00+00:00",
    end="2026-09-28T01:00:00+00:00",
)
(root / ".sample-finite.yml").write_text(safe_dump(config, sort_keys=False))
PYCODE
flock -x /tmp/eventum-generator-heavy.lock uv run --project ../eventum eventum generate --path generators/network-mikrotik-routeros/.sample-finite.yml --id network-mikrotik-routeros-sample --live-mode false --keep-order true
rm generators/network-mikrotik-routeros/.sample-finite.yml
~~~

This produces 4,381 records and exits normally. Set `anomaly_mode: false` in the temporary configuration for the same background window with no complete incidents. Extend the window when increasing the interval. The custom validation uses a 12-hour interval and `--timezone Europe/Moscow`; emitted native/ECS timestamps remain UTC.

## Sample Output

Complete synthetic event copied from the final enabled run; its remote envelope has the evidence limit described above:

```json
{
  "@timestamp": "2026-09-26T00:04:00+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "kind": "event",
    "module": "mikrotik",
    "dataset": "mikrotik.routeros.syslog",
    "category": [
      "configuration"
    ],
    "type": [
      "info"
    ],
    "action": "mangle_rule_changed",
    "original": "<134>Sep 26 00:04:00 mt-edge-01 system,info mangle rule changed by admin"
  },
  "message": "mangle rule changed by admin",
  "observer": {
    "hostname": "mt-edge-01",
    "ip": "10.30.0.1",
    "vendor": "MikroTik",
    "product": "RouterOS",
    "type": "router"
  },
  "log": {
    "syslog": {
      "priority": 134,
      "facility": {
        "code": 16
      },
      "severity": {
        "code": 6
      }
    }
  },
  "mikrotik": {
    "topics": [
      "system",
      "info"
    ]
  },
  "user": {
    "name": "admin"
  }
}
```

## References

- [RouterOS Log manual](https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/log/) - local message examples and remote-action properties.
- [RouterOS Syslog with Elasticsearch](https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/log/syslog-with-elasticsearch/) - source packet fields and custom UDP collection.
- [MikroTik common firewall actions](https://help.mikrotik.com/docs/spaces/ROS/pages/250708064/Common+Firewall+Matchers+and+Actions) - `action=log` continues rule processing and does not establish outcome.
- [Firsthand RouterOS 6.35rc mangle removal record](https://forum.mikrotik.com/t/v6-35rc-release-candidate-is-released-new-wireless-package/94918?page=5) - older removal vocabulary; RouterOS 7 parity remains inferred.
- [RFC 3164](https://www.rfc-editor.org/rfc/rfc3164) - priority and space-padded BSD timestamp.
- [KUMA supported event sources](https://support.kaspersky.com/kuma/4.0/en-US/255782.htm) - source inventory, not wire-format validation.
