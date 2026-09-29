# pfSense Firewall and IPsec Generator

Produces the remote syslog stream of one pfSense CE 2.9.0 firewall with eight site-to-site IPsec tunnels: `filterlog` packet records for LAN passes, WAN default-deny blocks and traffic arriving through the tunnels on `enc0`, and `charon` records for Phase 1 identity lookups, failed and successful negotiations, CHILD_SA closures and IKE_SA deletions. Each record is ECS JSON carrying the native message and a complete RFC 5424 syslog line in `event.original`.

## Event Types

Shares are for background (`anomaly_mode: false`).

| Action | Native record | Share | Category |
| --- | --- | ---: | --- |
| `pass` | `filterlog` LAN pass, rule 115 | 52.34% | Network |
| `block` | `filterlog` WAN default deny, rule 5 | 25.44% | Network |
| `pass` | `filterlog` IPsec (`enc0`) pass, rule 146 | 20.27% | Network |
| `ipsec-peer-lookup` | `charon` `looking for pre-shared key peer configs matching ...` | 0.53% | Network |
| `ipsec-ike-established` | `charon` `IKE_SA ... established between ...` | 0.30% | Network |
| `ipsec-child-established` | `charon` `CHILD_SA ... established with SPIs ...` | 0.30% | Network |
| `ipsec-child-closed` | `charon` `closing CHILD_SA ... with SPIs ...` | 0.29% | Network |
| `ipsec-ike-deleting` | `charon` `deleting IKE_SA ... between ...` | 0.29% | Network |
| `ipsec-peer-not-found` | `charon` `no peer config found` | 0.23% | Network |

About 12,900 records per day. Rates are synthetic workload choices, not measured production frequencies:

- **LAN** - workstation DNS and HTTPS passes (`igb1.12`, rule tracker `1690001001`).
- **WAN** - unsolicited internet connection attempts to the WAN address hitting the default deny rule (`igb0`, tracker `1000000103`, rule 5 / subrule 16777216). A scanner sends one to four probes (65/18/10/7%) back to back, about 25 s apart on average.
- **Tunnels** - per site an independent lifecycle: a negotiation attempt, IKE_SA and CHILD_SA establishment, a lognormal lifetime (median 2.5 h), closure and deletion (idle, DPD or reauthentication), and a lognormal pause (median 1 h) before the next attempt. Some attempts offer a wrong Phase 1 identity (`vpn-ext` or the branch firewall FQDN, more often in office hours, when peers are being reconfigured); each fails with `no peer config found` and is retried within seconds to minutes with the same identity until it is corrected or the peer gives up. Repeated failures of one peer and failures followed by a successful negotiation are ordinary.
- **enc0 traffic** - while a site's CHILD_SA is up, hosts of its subnet (`10.200.<k>.0/24`) reach internal servers on DNS, Kerberos, LDAP, RPC, HTTPS, SMB, RDP and WinRM (IPsec tab rule tracker `ipsec_pass_rule_tracker`), at a rate proportional to the site weight. Administrative ports carry about a quarter of that traffic, from every site host to every server offering them; an administrative connection is followed in 40% of cases by one or two further management sessions from the same host to the same server within a minute or two.

Every `enc0` pass requires an active CHILD_SA of its site; closing and deleting records carry the native IDs, SPIs and selectors of the established SA. No tunnel is assumed to be up at the start of a run; each site first negotiates within the first hour. A pass record means that a packet matched a pass rule, not that a connection or authentication succeeded.

## Volume and Timing

- **LAN and `enc0` traffic** - about 9,600 records a day: 3,200 spread evenly plus 6,400 on a daily curve (beta, a = 4.25, b = 4.75) peaking at 10:00-12:00 of the generator timezone (UTC by default), each day's count varying by up to 10%. The hourly rate runs from about 133 at night to 750 at the peak. While a site's CHILD_SA is up, a record of this traffic is an `enc0` pass of site k with probability 0.0545 × weight_k, otherwise a LAN pass, so LAN traffic absorbs the variation in the number of tunnels up.
- **WAN probes** - 143 an hour around the clock, each hour's count varying by up to 20%.

`charon` records, follow-up management sessions and episode steps take the place of LAN, `enc0` or WAN records at their time, so they do not add to the volume. Records of the same moment - a lookup and its `no peer config found`, or IKE_SA and CHILD_SA - are 4-5 s apart in median and at most about a minute apart at night.

## Anomaly Chain

`anomaly_mode: true` is the default; `anomaly_mode: false` produces only the background above.

A branch peer repeatedly offers a wrong Phase 1 identity, then the configured one; the tunnel comes up and a host behind it opens an SMB, RDP or WinRM session to an internal server - a peer being reconfigured until it connects, immediately followed by administrative access through the new tunnel.

1. `charon` - `<N> looking for pre-shared key peer configs matching <WAN>...<peer>[<wrong ID>]`, then `<N> no peer config found` - three to five times with background retry gaps
2. `charon` - `<N> looking for ... <peer>[<peer>]`, `<conK|N> IKE_SA conK[N] established between ...`, `<conK|N> CHILD_SA conK{M} established with SPIs ... and TS 10.20.0.0/16|/0 === 10.200.K.0/24|/0`
3. `filterlog` - an `enc0` pass from a host `10.200.K.x` to a server on 445, 3389 or 5985

The tunnel then lives and closes like any background tunnel (CHILD_SA closure and IKE_SA deletion with the same IDs and SPIs), and the administrative pass may be followed by background management sessions like any other.

**Volume.** The record count is the same in both modes: an episode's records take the place of about ten records of whatever kind would have come at those moments. Background schedules are not paused or shifted.

**Linking fields.** The peer address (`source.ip` of lookups and IKE_SA, `...<peer>[` in the message) identifies the site. A failure line carries only the IKE_SA unique ID `<N>` of its lookup. IKE and CHILD lines carry `<conK|N>`; the CHILD_SA traffic selector names the site subnet, which joins the `enc0` source address. The mapping peer - connection - subnet is tunnel configuration, not part of any single record.

**Recurrence.** `anomaly_interval_hours` (default `24`, minimum `4`) is measured in event time. The first episode starts within the first min(interval, 24 h) of the run, its hour weighted by the squared hourly LAN and `enc0` rate (relative to the peak, plus a floor of 0.02); each later start is drawn in a window of min(interval / 4, 6 h) centred one interval after the previous actual start, with the same weighting, so episodes stay in busy hours. At intervals up to 8 h the window covers much of the clock. The episode is the next reconnection of a site whose tunnel is down, so it starts when that site would have reconnected anyway, a random delay after the drawn start: a site due to reconnect within 30 minutes of that start, or, when none has reconnected 20 minutes after it, the down site next due, which then reconnects within a few minutes, earlier than it otherwise would. At a 4 h interval the delay is 22 min in median, under 28 min for 90% of episodes and up to about 45 min (the delay has no hard upper bound); 49% of episodes are such early reconnections. Missed episodes are not replayed.

**Variation.** Each episode picks a site other than the previous episode's among those whose tunnel is down and due to reconnect within 30 minutes of the start, weighted like background traffic (after 20 minutes without one, the down site that reconnects first); the wrong identity is one the site offers in background; the port, server and host are drawn like a background administrative pass (port by background weight, a server offering it, a host of the site), so every server, port and host - server pair of an episode also occurs in background traffic. Failure count, retry gaps and traffic gaps follow the background distributions; the chain spans about 71 to 211 s from the first lookup to the administrative pass at the default interval (57 to 273 s at 8 h).

**Background without the chain.** Background never completes the chain: a background administrative-port pass that would finish three wrong-identity lookups and an IKE_SA of the same site inside the 15-minute chain window appears instead, at the same time and from the same host, as a pass to a non-administrative port and server drawn by the background non-administrative flow weights, so non-administrative traffic keeps its usual mix around chain prefixes. This holds for the whole window, also after an episode's own pass, so each episode completes the chain exactly once; no record is missing or delayed. Wrong-identity failure runs, failures followed by an established tunnel, and administrative traffic after an established tunnel remain in both modes.

**Detection idea.** Per site, at least three `no peer config found` failures after lookups with a non-configured identity, then an established IKE_SA and an administrative-port pass through `enc0` from the site subnet, all within 15 minutes.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include recurring identity-mismatch tunnel episodes |
| `anomaly_interval_hours` | `24` | Episode interval in hours, minimum 4 |
| `hostname` | `fw01.corp.example` | Firewall host name in the syslog header, `host.name` and `observer.name` |
| `wan_ip` | `203.0.113.1` | WAN address: local IKE endpoint and target of blocked probes |
| `ipsec_pass_rule_tracker` | `1534283903` | Tracker of the logged IPsec-tab pass rule |

Sites (connection name, peer address, subnet, hosts, weight, alternative identity) live in `samples/sites.json`, internal servers (address, ports, weight) in `samples/servers.json`. Keep peers in `198.51.100.0/24` and subnets in `10.200.<k>.0/24` with `con<k>` naming, or adjust the detection accordingly.

### Output Parameters

The shipped `generator.yml` writes `output/events.json` and has no `${params.*}` or `${secrets.*}` placeholders. To send elsewhere, replace the output with placeholders and pass them at run time, for example:

```yaml
output:
  - opensearch:
      hosts: ["${params.opensearch_host}"]
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: pfsense
```

A real pfSense collector needs **Firewall Events** and **VPN Events** enabled under Remote Syslog Contents, the optional **syslog (RFC 5424)** log format (BSD is the default), logging enabled on the LAN and IPsec pass rules (pfSense logs default blocks but not passes), and the IPsec log levels IKE SA, IKE Child SA and Configuration Backend set to Diag, others to Control.

## Usage

From the content-packs repository root, live:

```bash
eventum generate --path generators/network-pfsense/generator.yml --id network-pfsense --live-mode true
```

`patterns/office-floor.yml` and `patterns/office-peak.yml` set the LAN and `enc0` curve, `patterns/wan.yml` the WAN probe rate. The patterns start at midnight of the current day and never end. For a finite batch, set `start` and `end` in the three files under `patterns/` (for example `start: "2026-09-01T00:00:00Z"`, `end: "+7d"`); the second episode can start up to 51 hours after the run start plus its start delay, so use at least 52 hours to see two at the default interval:

```bash
eventum generate --path generators/network-pfsense/generator.yml --id network-pfsense --live-mode false --keep-order true
```

## Sample Output

A chain step (the IKE_SA of the first episode) of a default run:

```json
{"@timestamp": "2026-09-01T10:19:59.653536+00:00", "data_stream": {"dataset": "pfsense.log", "namespace": "default", "type": "logs"}, "destination": {"ip": "203.0.113.1"}, "ecs": {"version": "8.17.0"}, "event": {"action": "ipsec-ike-established", "category": ["network"], "dataset": "pfsense.log", "kind": "event", "original": "\u003c30\u003e1 2026-09-01T10:19:59.653536+00:00 fw01.corp.example charon 18610 - - 10[IKE] \u003ccon2|803\u003e IKE_SA con2[803] established between 203.0.113.1[203.0.113.1]...198.51.100.2[198.51.100.2]", "type": ["info"]}, "host": {"name": "fw01.corp.example"}, "log": {"syslog": {"priority": 30}}, "message": "10[IKE] \u003ccon2|803\u003e IKE_SA con2[803] established between 203.0.113.1[203.0.113.1]...198.51.100.2[198.51.100.2]", "observer": {"name": "fw01.corp.example", "product": "pfSense", "type": "firewall", "vendor": "Netgate", "version": "2.9.0"}, "process": {"name": "charon", "pid": 18610}, "related": {"ip": ["198.51.100.2", "203.0.113.1"]}, "source": {"ip": "198.51.100.2"}, "syslog": {"facility": {"code": 3}, "priority": 30, "severity": {"code": 6}}}
```

## Limitations

- **Selected profile only.** IPv4 TCP SYN and UDP DNS records, IKEv1 PSK site-to-site tunnels and default `enc0` filtering. IPv6, ICMP, DHCP, NAT translation, OpenVPN, administrator logins and the full IKE exchange (proposals, NAT-T, DPD, rekeying messages) are not modeled.
- **No complete CE 2.9.0 capture.** The `filterlog` grammar and log settings come from current Netgate documentation; the `charon` bodies from Netgate's IPsec troubleshooting examples (edited for brevity by Netgate) and older real pfSense `charon` records with `<conn|id>` context. Close and delete bodies follow upstream strongSwan 5.9.14 source, not the exact library build bundled with CE 2.9.0. Live SIEM/parser compatibility is not verified.
- **Synthetic counters.** CHILD_SA byte counters include traffic and replies that `filterlog` does not log, so they cannot be derived from the logged packets.
- **Tunnel churn.** Real site-to-site tunnels usually rekey without going down; the down periods here stand for idle, DPD and reauthentication teardowns and give the negotiation records a realistic volume.
- **Episode site choice** is limited to sites whose tunnel is down and about to reconnect, which the per-site lifecycles make roughly independent of site weight. The episode is that site's reconnection; in about half of the episodes it comes before the site's pause would end, shortening that pause by up to its remaining length.
- **ECS mapping** of `charon` records (`source.ip` / `destination.ip` on lookup and IKE_SA lines) is derived from the message text; Elastic's pfSense IPsec pipeline does not extract these fields.
- **Record spacing.** Records of the same moment (a lookup and its failure, IKE_SA and CHILD_SA, CHILD_SA closure and IKE_SA deletion) are median 4-5 s apart, 90% within 20 s, at most about 70 s at night, where real `charon` writes them within milliseconds. Probes of one WAN scanner are about 25 s apart on average.
- **Rates** are synthetic.

## Performance

About 4,700 records per second on one core: a 14-day default run (182,844 records) takes 39 s.

## References

- [pfSense CE release versions](https://docs.netgate.com/pfsense/en/latest/releases/versions.html), [raw filter log format](https://docs.netgate.com/pfsense/en/latest/monitoring/logs/raw-filter-format.html), [firewall log and default deny example](https://docs.netgate.com/pfsense/en/latest/monitoring/logs/firewall.html) - `filterlog` CSV grammar and default deny tracker.
- [IPsec troubleshooting](https://docs.netgate.com/pfsense/en/latest/troubleshooting/ipsec-logs.html) - `charon` lookup, `no peer config found`, IKE_SA and CHILD_SA bodies, diagnostic log levels.
- [Log settings](https://docs.netgate.com/pfsense/en/latest/monitoring/logs/settings.html), [remote logging](https://docs.netgate.com/pfsense/en/latest/monitoring/logs/remote.html) - RFC 5424 format with microsecond timestamps, Firewall/VPN event forwarding.
- [IPsec advanced settings](https://docs.netgate.com/pfsense/en/latest/vpn/ipsec/advanced.html), [IPsec firewall rules](https://docs.netgate.com/pfsense/en/latest/vpn/ipsec/firewall-rules.html) - `enc0` filtering and IPsec-tab pass rules.
- [pfSense redmine #11761](https://redmine.pfsense.org/issues/11761) - real `charon` records with `<conn|id>` context.
- [Elastic pfSense integration fixture](https://github.com/elastic/integrations/blob/main/packages/pfsense/data_stream/log/_dev/test/pipeline/test-pfsense-syslog.log) and [IPsec pipeline](https://github.com/elastic/integrations/blob/main/packages/pfsense/data_stream/log/elasticsearch/ingest_pipeline/ipsec.yml) - RFC 5424 `filterlog` records, IPsec field extraction.
- strongSwan 5.9.14 [quick_delete.c](https://github.com/strongswan/strongswan/blob/5.9.14/src/libcharon/sa/ikev1/tasks/quick_delete.c) and [isakmp_delete.c](https://github.com/strongswan/strongswan/blob/5.9.14/src/libcharon/sa/ikev1/tasks/isakmp_delete.c) - CHILD_SA closing and IKE_SA deleting bodies.
- pfSense [filterlog print-ip.c](https://github.com/pfsense/FreeBSD-ports/blob/devel/sysutils/filterlog/files/print-ip.c) - UDP length includes the 8-byte header (69-byte packet, UDP length 49).
