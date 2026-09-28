# MikroTik RouterOS Syslog

Produces the remote syslog stream of one MikroTik RouterOS edge router: Winbox logins and logouts of six administrators, generic mangle-rule and item edits, DHCP lease assignments for 40 LAN clients, and internet UDP packets logged by an input-chain rule. Each record is ECS JSON carrying the RouterOS message and a constructed BSD-syslog line in `event.original`.

## Event Types

Shares measured over the five 73-hour `anomaly_mode: false` calibration captures (39,799 records).

| Action | Message | Share | Category |
| --- | --- | ---: | --- |
| `firewall_log` | `input: in:ether1 out:(none), src-mac ..., proto UDP, <src>:<port>-><dst>:<port>, len <n>` | 85.65% | Network |
| `dhcp_assigned` | `defconf assigned <ip> for <MAC> <host>` | 3.64% | Network |
| `dhcp_deassigned` | `defconf deassigned <ip> for <MAC> <host>` | 3.44% | Network |
| `login` | `user <u> logged in from <ip> via winbox` | 1.98% | Authentication |
| `logout` | `user <u> logged out from <ip> via winbox` | 1.98% | Authentication |
| `mangle_rule_changed` | `mangle rule changed by <u>` | 1.29% | Configuration |
| `mangle_rule_added` | `mangle rule added by <u>` | 0.62% | Configuration |
| `mangle_rule_removed` | `mangle rule removed by <u>` | 0.56% | Configuration |
| `mangle_rule_moved` | `mangle rule moved by <u>` | 0.51% | Configuration |
| `item_added` | `item added by <u>` | 0.33% | Configuration |

About 2,600 records per day. Rates are synthetic workload choices, not measured production frequencies:

- **Firewall packets** - unsolicited UDP probes of the WAN address (DNS, NTP, SNMP, IKE, SSDP, SIP), random sources, exponential gaps with short repeat bursts. The rule uses `action=log`, which records the packet and passes it to the next rule, so no accept/drop outcome is claimed.
- **DHCP** - per client: joins (workstations and laptops follow a working-hours curve, phones, printers and cameras do not), a lognormal lease stay, then a deassignment.
- **Administrator sessions** - per user: session arrivals thinned by the working-hours curve, about 40% from the user's own external addresses (`203.0.113.0/24`), the rest from the user's internal workstation. A session carries zero to a dozen edits with lognormal gaps; a user may hold overlapping sessions and often reconnects from the same address minutes after logging out. Edit types are random, so background sessions - external ones included - contain partial add/move/change/remove sequences and complete ones from internal addresses. Temporary rules added in background are removed by later edits; at most eight exist at a time.

## Anomaly Chain

`anomaly_mode: true` is the default; `anomaly_mode: false` produces only the background above.

An administrator logs in via Winbox from an external address and, within one session, adds, moves, changes and removes a mangle rule, then logs out - a short remote change of packet marking/routing that leaves no rule behind.

1. `system,info,account` - `user <U> logged in from <external IP> via winbox`
2. `system,info` - `mangle rule added by <U>`
3. `system,info` - `mangle rule moved by <U>`
4. `system,info` - `mangle rule changed by <U>`
5. `system,info` - `mangle rule removed by <U>`
6. `system,info,account` - `user <U> logged out from <external IP> via winbox`

**Linking fields.** `user.name` joins the steps; `source.ip` joins login and logout. RouterOS edit messages carry no session, rule ID or client address, so the link from edits to the external session is by user and time only.

**Recurrence.** `anomaly_interval_hours` (default `24`, minimum `4`) is measured in event time. The first episode starts within the first min(interval, 24 h) of the run, its hour drawn from the working-hours curve squared; each later start is drawn in a window of min(interval / 4, 6 h) centred one interval after the previous actual start, with the same weighting, so episodes stay in busy hours. At intervals up to 8 h the window covers much of the clock. A lognormal delay (median one minute) follows each start. Missed episodes are not replayed.

**Variation.** Each episode picks a user other than the previous episode's, weighted like background sessions, and one of that user's external addresses - the same user/address pairs that appear in background sessions. Edit gaps, logout delay and the reconnect chance follow the background session model; the whole chain fits in 30 minutes (measured spans 311, 499 and 608 s at the default interval; 87 to 1,753 s at 12 h).

**Background guard.** Background never completes the chain: when a background `mangle rule removed` would finish an external login, add, move and change by the same user inside the 30-minute chain window, that edit is not logged, and the rule stays until a later ordinary remove. Complete add/move/change/remove sequences from internal addresses, and external sessions with any subset of the edits, remain in both modes.

**Detection idea.** Per user, an external Winbox login followed within 30 minutes by mangle add, move, change and remove.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `router_name` | `mt-edge-01` | Router identity in the syslog header and `observer.hostname` |
| `router_ip` | `10.30.0.1` | Management address in `observer.ip` |
| `wan_ip` | `192.0.2.10` | WAN address targeted by logged UDP packets |
| `wan_gateway_mac` | `02:00:5E:10:00:01` | Upstream gateway MAC in packet lines (`src-mac`) |
| `anomaly_mode` | `true` | Include recurring external-session mangle episodes |
| `anomaly_interval_hours` | `24` | Episode interval in hours, minimum 4 |

Administrators (user, weight, internal and external addresses) live in `samples/admins.json`; DHCP clients (IP, MAC, host name, device kind) in `samples/dhcp_clients.json`. Keep external addresses in `203.0.113.0/24` or adjust the detection idea accordingly.

### Output Parameters

The shipped `generator.yml` writes `output/events.json` and has no `${params.*}` or `${secrets.*}` placeholders. To send elsewhere, replace the output with placeholders and pass them at run time, for example:

```yaml
output:
  - opensearch:
      hosts: ["${params.opensearch_host}"]
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: mikrotik-routeros
```

## Usage

From the content-packs repository root, live:

```bash
eventum generate --path generators/network-mikrotik-routeros/generator.yml --id network-mikrotik-routeros --live-mode true
```

As a batch (add `start`/`end` to the `cron` input for a finite window; the second episode can start up to 51 hours after the run start plus its start delay, so use at least 52 hours to see two at the default interval):

```bash
eventum generate --path generators/network-mikrotik-routeros/generator.yml --id network-mikrotik-routeros --live-mode false --keep-order true
```

## Sample Output

A chain step from the final default-on capture:

```json
{"@timestamp": "2026-09-01T16:10:24+00:00", "ecs": {"version": "8.17.0"}, "event": {"kind": "event", "module": "mikrotik", "dataset": "mikrotik.routeros.syslog", "category": ["configuration"], "type": ["change"], "action": "mangle_rule_added", "original": "<134>Sep  1 16:10:24 mt-edge-01 system,info mangle rule added by admin"}, "message": "mangle rule added by admin", "observer": {"hostname": "mt-edge-01", "ip": "10.30.0.1", "vendor": "MikroTik", "product": "RouterOS", "type": "router"}, "log": {"syslog": {"priority": 134, "facility": {"code": 16, "name": "local0"}, "severity": {"code": 6, "name": "info"}}}, "mikrotik": {"topics": ["system", "info"]}, "user": {"name": "admin"}, "related": {"user": ["admin"]}}
```

## Limitations

- **Remote envelope not verified.** The manual shows local `/log print` lines and documents `remote-log-format=syslog` (BSD syslog, always UDP), facility, severity, `bsd-syslog` time format and `add-topics-string`. No complete remote frame from RouterOS 7 with this profile was found, so the PRI, header, hostname and topic placement in `event.original` are constructed from RFC 3164 and the manual. The router clock is modeled as UTC (PRI 134 = local0.info).
- **Removal message inferred.** `mangle rule removed by <user>` comes from a RouterOS 6.35rc record; its RouterOS 7 wording is assumed.
- **One service.** Only `via winbox` logins are modeled; login failures, SSH/WebFig/API sessions, and other rule types (filter, NAT) are out of scope.
- **Generic edits.** RouterOS logs no rule ID or change content, so which rule an edit touches is not visible, and packet logging is not tied to mangle changes.
- **ECS mapping** follows the vendor Elasticsearch guide's packet fields; the rest of the ECS envelope is a synthetic choice, not a published integration.
- **Rates** are synthetic.

## References

- [RouterOS Log manual](https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/log/) - local message examples, remote action properties, topics.
- [RouterOS Syslog with Elasticsearch](https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/log/syslog-with-elasticsearch/) - packet-line fields.
- [Common firewall matchers and actions](https://help.mikrotik.com/docs/spaces/ROS/pages/250708064/Common+Firewall+Matchers+and+Actions) - `action=log` passes the packet to the next rule.
- [RouterOS 6.35rc forum record](https://forum.mikrotik.com/t/v6-35rc-release-candidate-is-released-new-wireless-package/94918?page=5) - `mangle rule removed by` wording.
- [RFC 3164](https://www.rfc-editor.org/rfc/rfc3164) - BSD syslog PRI and timestamp.
