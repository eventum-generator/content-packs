# MikroTik RouterOS Syslog

Produces the remote syslog stream of one MikroTik RouterOS edge router: Winbox logins and logouts of six administrators, generic mangle-rule and item edits, DHCP lease assignments for 40 LAN clients, and internet UDP packets logged by an input-chain rule. Each record is ECS JSON carrying the RouterOS message and a constructed BSD-syslog line in `event.original`.

## Volume and Timing

About 2,600 records per day, all in UTC:

- **Administrator sessions** follow a working-hours curve, about 38 Winbox logins a day plus reconnects:

  | UTC hours | Sessions per hour |
  | --- | ---: |
  | 07-15 | 3.1 |
  | 06-07, 15-16 | 2.2 |
  | 05-06, 16-18 | 1.2 |
  | 18-22 | 0.65 |
  | 22-05 | 0.27 |

- **Logged internet UDP packets** arrive at about 107 an hour around the clock.
- **DHCP** lease records follow the office day for workstations and laptops and are spread over the day for other devices.

Daily and hourly counts vary by up to ±20%. Records of one session are seconds to minutes apart; about 1.5% of seconds hold two or three records.

## Event Types

Shares over six days of output with the default settings (`anomaly_mode: true`); the range shows how much the background shares vary between six-day windows.

| Action | Message | Share | Background range | Category |
| --- | --- | ---: | ---: | --- |
| `firewall_log` | `input: in:ether1 out:(none), src-mac ..., proto UDP, <src>:<port>-><dst>:<port>, len <n>` | 83.89% | 82.5-85.4% | Network |
| `dhcp_assigned` | `defconf assigned <ip> for <MAC> <host>` | 3.66% | 3.22-3.80% | Network |
| `dhcp_deassigned` | `defconf deassigned <ip> for <MAC> <host>` | 3.51% | 3.08-3.63% | Network |
| `login` | `user <u> logged in from <ip> via winbox` | 2.01% | 1.85-2.27% | Authentication |
| `logout` | `user <u> logged out from <ip> via winbox` | 2.01% | 1.85-2.27% | Authentication |
| `mangle_rule_changed` | `mangle rule changed by <u>` | 1.57% | 1.10-2.04% | Configuration |
| `mangle_rule_added` | `mangle rule added by <u>` | 1.07% | 0.95-1.23% | Configuration |
| `mangle_rule_removed` | `mangle rule removed by <u>` | 1.04% | 0.93-1.21% | Configuration |
| `mangle_rule_moved` | `mangle rule moved by <u>` | 1.01% | 0.78-1.18% | Configuration |
| `item_added` | `item added by <u>` | 0.23% | 0.17-0.39% | Configuration |

With `anomaly_mode: true` each episode adds its own records, so the mangle-edit shares are slightly higher than in background alone.

Rates are synthetic workload choices, not measured production frequencies:

- **Firewall packets** - unsolicited UDP probes of the WAN address (DNS, NTP, SNMP, IKE, SSDP, SIP) from random sources; a prober sends one to five packets to one port in quick succession. The rule uses `action=log`, which records the packet and passes it to the next rule, so no accept/drop outcome is claimed.
- **DHCP** - per client: joins (workstations and laptops follow the working-hours curve, phones, printers and cameras do not), a lognormal lease stay, then a deassignment.
- **Administrator sessions** - six users weighted by activity; about 40% of sessions come from the user's own external addresses (`203.0.113.0/24`), the rest from the user's internal workstation. About 65% of sessions edit; 60% of those start with work on one mangle rule (added and moved into place, then changed, sometimes removed again as a test rule; added and taken back; or an earlier temporary rule moved, changed and removed as clean-up), followed by a geometric number of random edits with lognormal gaps. The more temporary rules exist, the more likely a random edit removes one (clean-up), and a remove with no temporary rule left is logged as a change, so the number of temporary rules stays small without a hard limit. A user may hold overlapping sessions and reconnects from the same address minutes after 30% of logouts.

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

**Placement.** An episode is an extra session on top of the background: no background session is replaced, cancelled or moved, so background session counts, hours and per-user activity stay as they are.

**Recurrence.** `anomaly_interval_hours` (default `24`, minimum `4`) is measured in event time. The first episode starts within the first min(interval, 24 h) of the run, its hour drawn from the working-hours curve squared (plus a small floor); each later start is drawn in a window of min(interval / 4, 6 h) centred one interval after the previous actual start, with the same weighting, so episodes stay in busy hours. At intervals up to 8 h the window covers much of the clock. Missed episodes are not replayed.

**Variation.** Each episode picks a user other than the previous episode's, weighted like background sessions, and one of that user's external addresses - the same user/address pairs that appear in background sessions. Edit gaps, logout delay and the reconnect chance follow the background session model; the whole chain fits in 30 minutes; login to remove typically takes about 5 minutes, 90% under 11, rarely up to about 28.

**No chain in background.** Background never completes the chain: when a background `mangle rule removed` would finish an external login, add, move and change by the same user inside the 30-minute chain window, that record is logged as another edit of the same user (change, move, add or item add) at the same time, and the rule stays until a later ordinary remove. Complete add/move/change/remove sequences from internal addresses, and external sessions with any subset of the edits, remain in both modes.

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

The patterns start at midnight of the current day and never end. For a finite batch, set `start` and `end` in all six files under `patterns/` to the same range, with `start` at 00:00 UTC so the hour bands stay in place (for example `start: "2026-09-01T00:00:00Z"` and `end: "+7d"`); the second episode can start up to 51 hours after the run start, so use at least 52 hours to see two at the default interval. Then run:

```bash
eventum generate --path generators/network-mikrotik-routeros/generator.yml --id network-mikrotik-routeros --live-mode false --keep-order true
```

Performance: 14 days (about 36,000 records) in about 8.6 s on one core, roughly 4,200 records per second including start-up.

## Sample Output

The final step of an episode (`anomaly_mode: true`):

```json
{"@timestamp": "2026-09-01T08:49:09+00:00", "ecs": {"version": "8.17.0"}, "event": {"kind": "event", "module": "mikrotik", "dataset": "mikrotik.routeros.syslog", "category": ["configuration"], "type": ["change"], "action": "mangle_rule_removed", "original": "<134>Sep  1 08:49:09 mt-edge-01 system,info mangle rule removed by netops"}, "message": "mangle rule removed by netops", "observer": {"hostname": "mt-edge-01", "ip": "10.30.0.1", "vendor": "MikroTik", "product": "RouterOS", "type": "router"}, "log": {"syslog": {"priority": 134, "facility": {"code": 16, "name": "local0"}, "severity": {"code": 6, "name": "info"}}}, "mikrotik": {"topics": ["system", "info"]}, "user": {"name": "netops"}, "related": {"user": ["netops"]}}
```

## Limitations

- **Remote envelope not verified.** The manual shows local `/log print` lines and documents `remote-log-format=syslog` (BSD syslog, always UDP), facility, severity, `bsd-syslog` time format and `add-topics-string`. No complete remote frame from RouterOS 7 with this profile was found, so the PRI, header, hostname and topic placement in `event.original` are constructed from RFC 3164 and the manual. The router clock is modeled as UTC (PRI 134 = local0.info).
- **DHCP assignment message inferred.** The manual shows `defconf deassigned <ip> for <MAC> <host>`; the `assigned` form is assumed by symmetry.
- **Removal message inferred.** `mangle rule removed by <user>` comes from a RouterOS 6.35rc record; its RouterOS 7 wording is assumed.
- **One service.** Only `via winbox` logins are modeled; login failures, SSH/WebFig/API sessions, and other rule types (filter, NAT) are out of scope.
- **Generic edits.** RouterOS logs no rule ID or change content, so which rule an edit touches is not visible, and packet logging is not tied to mangle changes.
- **ECS mapping** follows the vendor Elasticsearch guide's packet fields; the rest of the ECS envelope is a synthetic choice, not a published integration.
- **Record spacing.** Consecutive records of one administrator session are seconds to minutes apart; about 1.5% of seconds hold two or three records.
- **Chain parts in default output.** With `anomaly_mode: true` each episode adds its own records, so counts of the chain parts (an external login followed by mangle edits, add/move/change/remove sequences of one user) are about one per episode higher than in background alone; at short intervals this excess grows with the number of episodes.
- **Rates** are synthetic.

## References

- [RouterOS Log manual](https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/log/) - local message examples, remote action properties, topics.
- [RouterOS Syslog with Elasticsearch](https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/log/syslog-with-elasticsearch/) - packet-line fields.
- [Common firewall matchers and actions](https://help.mikrotik.com/docs/spaces/ROS/pages/250708064/Common+Firewall+Matchers+and+Actions) - `action=log` passes the packet to the next rule.
- [RouterOS 6.35rc forum record](https://forum.mikrotik.com/t/v6-35rc-release-candidate-is-released-new-wireless-package/94918?page=5) - `mangle rule removed by` wording.
- [RFC 3164](https://www.rfc-editor.org/rfc/rfc3164) - BSD syslog PRI and timestamp.
