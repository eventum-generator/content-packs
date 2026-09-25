# MikroTik RouterOS Syslog

Produces ECS-wrapped RouterOS account, configuration, DHCP and firewall messages from one router. `event.original` models a configured BSD Syslog UDP message; the shipped output is a JSON file, not a UDP sender.

## Event Types

| Action | Background pattern | Category |
| --- | --- | --- |
| DHCP assigned / deassigned | 5% of non-session routine slots, toggled per client | Network |
| Firewall packet | 95% of non-session routine slots; requires a RouterOS firewall logging rule | Network |
| Winbox login / logout | Paired sessions for `netops`, internal `admin` and external `admin` | Authentication |
| Mangle rule added / moved / changed | Internal `admin` maintenance session | Configuration |

These are synthetic workload weights, not measured RouterOS production rates. Eight synthetic DHCP clients retain bounded lease state. The background runs on a one-day cycle with one external administrator session and one internal maintenance session. Firewall source IP, ports and packet length vary. A single router emits one event per minute, or about 1,440 events per day, because the sixth cron field is seconds in Eventum.

## Anomaly Chain

`event.template.params.anomaly_mode` defaults to `true`. After 120 routine events, the generator adds a five-event Winbox session, one minute between steps:

1. `admin` logs in from `198.51.100.83`.
2. `admin` adds a mangle rule.
3. `admin` moves and then changes a mangle rule.
4. `admin` logs out from the same IP.

The configured cadence places the first chain about two hours after startup and emits it once per run. The ordinary background already contains external `admin` logins and all three rule-edit messages, but its external session ends several hours before the internal maintenance session starts. A useful detection correlates the external login with several rule edits on the same router and user within five minutes. RouterOS's documented rule-edit lines contain neither client IP nor rule ID, so this is temporal correlation, not proof of the editing session.

Set `anomaly_mode: false` for background only. It keeps the same event types and values but does not produce the close external-login-and-edit sequence.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `router_name`, `router_ip` | `mt-edge-01`, `10.30.0.1` | Router identity and firewall destination |
| `normal_user`, `normal_source_ip` | `netops`, `10.30.1.12` | Routine Winbox session |
| `admin_internal_source_ip` | `10.30.1.11` | Routine administrator maintenance session |
| `anomaly_user`, `anomaly_source_ip` | `admin`, `198.51.100.83` | Administrator identity and synthetic external address, used in both modes |
| `anomaly_delay_events` | `120` | Routine events before the one enabled-mode chain |
| `anomaly_mode` | `true` | Add the close external-login-and-edit chain |

### Output Parameters

The shipped configuration writes `output/events.json` relative to the generator. It has no top-level `${params.*}` or `${secrets.*}` placeholders. Change `output.file.path` or the output plugin to deliver elsewhere.

## RouterOS Logging Profile

The model targets the current RouterOS 7 manual's BSD Syslog path. It does not model RFC 5424 or CEF. A matching remote action needs `target=remote`, `remote-log-format=syslog`, `syslog-facility=local0`, `syslog-severity=info`, `syslog-time-format=bsd-syslog`, and `add-topics-string=yes`; that last setting is off by default. Enable remote logging topics `dhcp`, `firewall`, and `system`, and configure a firewall rule with logging enabled. The modeled router clock uses UTC. The resulting priority is `16*8+6=134`.

The RouterOS manual publishes the local message bodies and remote-action properties, but no complete remote UDP frame for this exact profile. Thus the BSD header and placement of the topics in `event.original` remain **BLOCKED_RAW_EVIDENCE** until compared with a RouterOS packet capture from this configuration. No exact RouterOS 7 point release is claimed. Event frequencies and DHCP lease churn are synthetic and depend on a site's logging and client behavior.

## Usage

From the content-packs repository root:

```bash
eventum generate --path generators/network-mikrotik-routeros/generator.yml --id network-mikrotik-routeros --live-mode true
```

Use `--live-mode false` for a fast sample run.

## Sample Output

This complete event was copied from an enabled-mode run:

```json
{"@timestamp": "2026-09-25T19:11:00+00:00", "ecs": {"version": "8.17.0"}, "event": {"kind": "event", "module": "mikrotik", "dataset": "mikrotik.routeros.syslog", "category": ["configuration"], "type": ["info"], "action": "mangle_rule_moved", "original": "<134>Sep 25 19:11:00 mt-edge-01 system,info mangle rule moved by admin"}, "message": "mangle rule moved by admin", "observer": {"hostname": "mt-edge-01", "ip": "10.30.0.1", "vendor": "MikroTik", "product": "RouterOS", "type": "router"}, "log": {"syslog": {"priority": 134, "facility": {"code": 16}, "severity": {"code": 6}}}, "mikrotik": {"topics": ["system", "info"]}, "user": {"name": "admin"}}
```

## References

- [MikroTik RouterOS Log manual](https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/log/) — local account, mangle, firewall and DHCP examples; BSD Syslog action and topic settings.
- [RFC 3164](https://www.rfc-editor.org/rfc/rfc3164) — priority calculation and space-padded BSD timestamp.
- [KUMA supported event sources](https://support.kaspersky.com/kuma/4.0/en-US/255782.htm) — MikroTik Syslog source listing. This does not validate the generated wire format.
