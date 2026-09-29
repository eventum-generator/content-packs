# Cisco Catalyst 9800 wireless client state syslog

Synthetic client-state records of one Cisco Catalyst 9800 wireless controller, using the named-client, no-channel message examples published in the Cisco Catalyst 9800 IOS XE 17.11 documentation. The pack preserves controller console/buffer-format text in `event.original` and supplies a declared ECS mapping. It models client associations and address learning, not authentication results.

## Event Types

| Native mnemonic | Meaning | Share of records | ECS category/type |
| --- | --- | --- | --- |
| `CLIENT_MOVED_TO_RUN_STATE` | Client enters RUN on the named AP | 31.7% | `network` / `connection`, `start` |
| `CLIENT_IP_UPDATED` | RUN client's address list gains a learned address on the same AP | 36.6% | `network` / `connection`, `info` |
| `CLIENT_MOVED_TO_DELETE_STATE` | RUN client is deleted from its current AP | 31.7% | `network` / `connection`, `end` |

Shares are the same in both modes.

## Clients and Volume

One controller serves 600 fixed named stations across 30 pre-existing APs on 10 floors, three APs per floor. The `presence` field of the inventory splits them into 540 office stations, carried by employees, and 60 always-on devices (phones left on chargers, scanners, sensors) spread over all floors. Times of day below are UTC, the controller's clock.

Office stations follow a working day. Each employee comes in on about 9 of 10 days, arrives around 08:45 (standard deviation about 35 minutes, between 07:00 and 11:00) and leaves about 9 hours later (6.5 to 11.5 hours); during the day the station associates, roams and reconnects, and its last association ends when the employee leaves. Always-on devices stay associated around the clock apart from short sleep/wake gaps. As a result about 50 stations are associated at night (42-60 on the hour between 20:00 and 07:00); the count climbs from 07:00, holds at about 410 (370-440) between 10:00 and 16:00, falls to about 65 in the 19:00 hour and is back at the night level from 20:00.

The controller logs about 24,300 records a day (plus or minus 3% from day to day), following the same curve:

| Hours (UTC) | Records per hour | Associated stations (hourly mean) |
| --- | --- | --- |
| 20:00-07:00 | about 435 | 50 |
| 07:00-08:00 | about 595 | 62 |
| 08:00-09:00 | about 1,510 | 190 |
| 09:00-10:00 | about 2,050 | 370 |
| 10:00-16:00 | about 1,800 | 410 |
| 16:00-17:00 | about 1,710 | 375 |
| 17:00-18:00 | about 1,385 | 270 |
| 18:00-19:00 | about 840 | 135 |
| 19:00-20:00 | about 530 | 64 |

Records come at irregular intervals: about 2 seconds apart on average in working hours (median 1.4 s, 90th percentile 4.6 s) and about 8 seconds apart at night (median 5.7 s, 90th percentile 19 s).

Each station follows its own lifecycle: absence, RUN on one AP of its floor, address learning, DELETE from the same AP with the same addresses, then absence again. Sessions mix a lognormal body (35-minute median for office stations, 15 minutes for always-on devices, at most 12 hours) with a 12% short tail of about 10 seconds to 3 minutes, which stands for sleep/wake, band steering and re-authentication; the only same-client session in the Cisco examples lasts 130 seconds. Absences mix a lognormal body (10-minute median for office stations, 3 minutes for always-on devices, at most 8 hours) with a 12% quick-reconnect tail of about 1..60 seconds. The resulting median session is about 28 minutes for office stations and 12.5 minutes for always-on devices; the median absence within a working day is about 8 minutes, and 2.5 minutes for always-on devices. Tails start at a small offset and fade out below it, so no length has a hard floor. Each association picks the station's home AP with 50% probability and each other AP on its floor with 25%. At the first record some stations are already associated, so the stream starts in steady state and a station's first record may be its DELETE.

Address learning follows the 17.11 examples. Both RUN examples carry one IPv4 address. In the open-authentication example, the same client's IP update comes 645 ms after RUN and lists the IPv4 address followed by a new link-local address; its DELETE two minutes later lists link-local first, two global IPv6 addresses, and IPv4 last. The 802.1X RUN and IP-update examples belong to different clients. Accordingly, RUN carries the station's IPv4 address, IP updates append in learning order, and DELETE lists link-local, then global IPv6, then IPv4. An IP update adds the IPv6 link-local address shortly after RUN, and dual-stack stations add a global IPv6 address with a second update seconds later. Counting both updates, an IP update comes a median 2.2 seconds after RUN in working hours and about 7.5 seconds at night; the 90th percentile is 14 seconds, and the longest delays reach about 1 minute in working hours and about 3 minutes at night. The inventory holds 350 IPv4 plus link-local stations (including slot 0), 150 dual-stack stations, 50 IPv4-only stations that emit no IP update, and 50 IPv6-only stations; slot 0 is IPv4 plus link-local or IPv6-only, depending on `suspicious_ip`. Cisco shows no IPv6-only RUN record, so starting those at the link-local address and adding the global address by update is a synthetic assumption. About half of the link-local addresses are modified EUI-64 derived from the MAC, as in the 802.1X example; the rest use random interface identifiers, as in the open-authentication example. Slot 0 always derives EUI-64 from the configured MAC. Mid-session renumbering, DHCP renewal to a new lease and roaming without DELETE are not modeled.

## Source Profile

The selected text follows the 17.11 configuration guide's `%CLIENT_ORCH_LOG-7-...` examples: source timestamp, `Chassis 1 R0/0`, `wncd`, username, dotted MAC, space-separated IP values, AP and SSID. `wireless client syslog-detailed` enables these detailed messages. If forwarding to a syslog server, its filter must include severity 7, for example `logging trap debugging`; an informational filter excludes them. This pack uses synchronized UTC source time, millisecond datetime timestamps with timezone display, and disabled native sequence numbering. The documented timestamp options include `service timestamps log datetime msec show-timezone`.

`event.original` is the source console/buffer record, not a fabricated RFC3164/5424 UDP/TCP envelope. There is no native PRI, hostname, transport peer or message sequence in this selected variant. `host.name` is configured controller context, and the minimal `agent` fields identify a synthetic Eventum reader. They do not describe a tested live collector. All times are rendered in UTC whatever time zone the generator runs in. The native timestamp omits a year, so the full year in `@timestamp` comes from the simulation/collector context.

`client.ip` and `client.address` carry one primary address: the IPv4 address when present, otherwise the first global IPv6 address, otherwise the link-local address. The complete list is retained in `related.ip` and `cisco_wlc.client_ips`. `cisco_wlc.client_mac` and native text retain dotted Cisco notation, while ECS `client.mac` uses uppercase hyphen-separated octets. `log.level` is `debugging`, the Cisco keyword for severity 7. `cisco_wlc.client_state` and ECS actions/types are derived from the mnemonic. Neither the RUN message nor its username proves an AAA outcome, authentication method or malicious activity.

## Anomaly Chain

`anomaly_mode` defaults to `true`. The first episode starts within the first `anomaly_interval_hours` (default 24 hours), and within the first 24 hours for longer intervals, at an hour drawn in proportion to the hourly record volume. Each later episode starts within a window of min(interval / 4, 6 hours) centred one interval after the actual start of the previous one: 21-27 hours apart at the default interval. Within that window the start is weighted by the square of the hourly volume plus a small floor, so episodes fall mostly in working hours; at short intervals the window regularly reaches the night, and night episodes are carried by always-on devices, the only stations present then. Missed episodes are never made up, and at most one episode runs at a time.

An episode is a station's own next association after an ordinary absence. The station makes three associations on AP-A, AP-B and AP-C of its floor, and each RUN is followed by the station's normal address learning. The first two associations take their lengths from the same short-session tail as ordinary traffic, and each reassociation takes its delay from the ordinary quick-reconnect tail. The third association continues as an ordinary session and ends with an ordinary DELETE, followed by the station's ordinary absence. In an episode the two short associations last 1-165 seconds (most 20-110 s), the reconnects 0-45 seconds, and RUN-A to the IP update on AP-C takes 57-285 seconds. The same MAC, username and SSID link the episode. Episodes use the stations that learn one address by update (IPv4 plus link-local, IPv6-only), preferring stations that have not yet taken part, and rotate the order of the floor's three APs. An office station takes part only while its working day has at least 30 more minutes to run. There are no fabricated native session IDs or emitted episode/mode markers.

Set `anomaly_mode: false` for ordinary traffic only. Short sessions and quick reconnects are frequent in both modes: about 14% of sessions last under 3 minutes and about 11% of absences under 20 seconds, and every action, station and station-AP pair of the episodes also occurs in ordinary traffic. A detection can group by native MAC plus SSID and look for RUN on three distinct APs, each earlier association closed by DELETE, where the IP update on the third AP comes within 400 seconds of the first RUN. Ordinary traffic reaches three distinct APs within 400 seconds about seven times a day, but then the station logs no IP update in that association and keeps only its RUN address until DELETE, so the complete shape occurs only in episodes. With `anomaly_mode: true` each episode adds its own two short associations, so counts of short sessions and quick reconnects are about two per episode higher. The pattern signals rapid reassociation or instability. It does not establish seamless roaming, an authentication failure, a deauthentication attack, an AP outage, a cloned client or an intrusion.

## Parameters

### Event Parameters

Edit `event.template.params` in a local configuration copy.

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include periodic rapid three-AP episodes alongside ordinary traffic; must be a YAML boolean |
| `anomaly_interval_hours` | `24` | Recurrence in hours, numeric 6..8760, measured from the actual start of the previous episode |
| `controller_name` | `wlc9800-01.corp.example` | Controller identity supplied as source context |
| `ssid` | `corp-wifi` | Shared WLAN SSID; selected ASCII subset, 1..32 characters, without parentheses or newlines |
| `suspicious_user` | `visitor01` | Inventory slot 0 username, used by ordinary traffic in both modes and eligible for episodes like any other station; 1..64 letters/digits or `._@+-` |
| `suspicious_mac` | `02aa.bbcc.ddee` | Inventory slot 0 dotted MAC, unique, nonzero and unicast; source text is lowercase, ECS notation is normalized, and the slot's link-local address is derived from it |
| `suspicious_ip` | `192.0.2.91` | Inventory slot 0 primary address; IPv4 gives an IPv4 plus link-local station, IPv6 an IPv6-only station |

The legacy `suspicious_*` names do not reserve an anomaly-only actor. The configured MAC and address must not collide with other inventory rows, including their derived or sampled link-local and global IPv6 addresses. Multicast, unspecified, loopback, link-local, reserved, IPv4 zero-network and IPv4 last-octet 0/255 addresses are rejected before any record is written. The station inventory is `samples/clients.json`, with the `presence` class of each station. The files in `patterns/` set the volume per hour of day; together they match the record rate of those 540 office stations and 60 always-on devices, so a changed inventory size or class mix needs a matching change of their `ratio` values.

### Output Parameters

The shipped output writes `output/events.json` with the JSON formatter and requires no endpoint or secrets. To target another output plugin in a local copy, use `${params.siem_host}` and `${secrets.siem_token}` where that plugin requires them. Those are replacement patterns, not required parameters of this file-output configuration.

## Usage

From the content-packs repository root, live (about 7 records a minute at night and 30 in working hours):

```bash
eventum generate --path generators/network-cisco-wlc-9800/generator.yml --id cisco-wlc-9800 --live-mode true
```

The files in `patterns/` set the volume per hour of day; each starts at midnight of the current day and never ends. For a finite batch, set the same `start` and `end` in every file, with `start` at midnight UTC so the hours stay in place (for example `start: "2026-09-01T00:00:00Z"`, `end: "+4d"`), and generate as fast as possible:

```bash
eventum generate --path generators/network-cisco-wlc-9800/generator.yml --id cisco-wlc-9800 --live-mode false --keep-order true
```

`--keep-order true` keeps records in chronological order in the output file. The second episode can start up to 51 hours after the start of the window at the default interval, so use at least 52 hours to see two.

## Performance

About 2,400 records per second in batch mode; 14 days (340,000 records) take about 2.5 minutes.

## Sample Output

An IP update on AP-C that completes an episode, copied unchanged from a default-mode run. Controller and reader context is synthetic enrichment.

```json
{
  "@timestamp": "2026-09-01T12:36:55.168+00:00",
  "agent": {
    "name": "synthetic-wlc-reader",
    "type": "eventum"
  },
  "cisco_wlc": {
    "ap_name": "AP-Floor7-C",
    "chassis": "1 R0/0",
    "client_ips": [
      "10.20.30.115",
      "fe80::5eff:fe10:254"
    ],
    "client_mac": "0200.5e10.0254",
    "client_state": "ip_update",
    "ssid": "corp-wifi"
  },
  "client": {
    "address": "10.20.30.115",
    "ip": "10.20.30.115",
    "mac": "02-00-5E-10-02-54"
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "ip-update",
    "category": [
      "network"
    ],
    "code": "CLIENT_IP_UPDATED",
    "kind": "event",
    "original": "Sep  1 12:36:55.168 UTC: %CLIENT_ORCH_LOG-7-CLIENT_IP_UPDATED: Chassis 1 R0/0: wncd: Username (employee-596), MAC: 0200.5e10.0254, IP 10.20.30.115 fe80::5eff:fe10:254 IP address updated, associated to AP (AP-Floor7-C) with SSID (corp-wifi)",
    "provider": "CLIENT_ORCH_LOG",
    "severity": 7,
    "timezone": "+00:00",
    "type": [
      "connection",
      "info"
    ]
  },
  "host": {
    "name": "wlc9800-01.corp.example"
  },
  "log": {
    "level": "debugging"
  },
  "process": {
    "name": "wncd"
  },
  "related": {
    "ip": [
      "10.20.30.115",
      "fe80::5eff:fe10:254"
    ],
    "user": [
      "employee-596"
    ]
  },
  "user": {
    "name": "employee-596"
  }
}
```

## Coverage and Limits

All eleven source elements in the chosen guide examples are represented: timestamp, facility, severity, mnemonic, chassis, process, username, MAC, complete address list, AP and SSID. This covers the selected elements, not all possible source values or a complete same-version unredacted wire capture. Address lists hold one to three addresses; the seven-address list of the 802.1X example is not reproduced, and the list order is a single rule fitted to the one same-client example sequence. The documented open-auth/null usernames and temporary username gaps following AP reconnect are omitted by the named-client subset.

The 17.11 configuration-guide RUN example has no channel suffix. The 17.12 system-message catalog adds `on channel (...)`; this generator deliberately preserves the published 17.11 example variant. The exact 17.11 system-message catalog could not be retrieved, so no claim is made that every 17.11 build emits this exact variant. Published MAC/IP values are redacted, so this pack supplies synthetic complete values; no unredacted capture from a live controller was available to compare byte for byte, and parsing by a live collector or normalizer is untested.

The maintained Elastic Aironet package's compatibility list describes AireOS, although its tests also contain another IOS-XE class, severity 6 `CLIENT_ADDED_TO_RUN_STATE`, with different fields. Those records and the package's SISF normalized sample are not references for these three severity 7 classes. Compatibility with AireOS-oriented Elastic/KUMA normalizers or Smart Monitor parsers has not been tested. AP connectivity, WLAN policy, packet forwarding, radio/channel details, session/authentication IDs, AAA decisions and delete reasons are outside this selected output.

Session, absence, attendance and address-learning distributions are synthetic choices, not measured production workload. Every day is a working day: there are no weekends or holidays, the working day is fixed to the controller's UTC clock, and the record rate steps from hour to hour rather than changing smoothly within an hour. The controller logs its records one at a time, about 2 seconds apart in working hours and 8 seconds at night. Consequently the IP update follows its RUN after seconds (median 2.2 s in working hours, 7.5 s at night, at most about 3 minutes) rather than the sub-second delay of the Cisco example, and the length of very short sessions and reconnects follows the spacing of neighbouring records, so some are shorter or longer than their nominal range, most of all at night. About seven times a day an ordinary association has no IP update although its station normally learns an address, whenever it is the station's third distinct AP within 400 seconds. Ordinary stations and the last episode's final association may remain associated at the end of a finite window.

## References

- [Cisco Catalyst 9800 IOS XE 17.11 detailed client-state syslogs and forwarding configuration](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/17-11/config-guide/b_wl_17_eleven_cg/m_syslog_server.html)
- [Cisco IOS XE 17 system-message guide index](https://www.cisco.com/c/en/us/support/ios-nx-os-software/ios-xe-17/products-system-message-guides-list.html)
- [Cisco 17.12 system-message catalog, contrasting RUN channel variant](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/17_xe/syslogs/17-12-x/b-system-message-guide-17-12-x.html)
- [Cisco system-message timestamp, sequence and severity settings](https://www.cisco.com/c/en/us/td/docs/routers/access/wireless/software/guide/SysMsgLogging.html)
- [ECS 8.17 client fields and MAC notation](https://www.elastic.co/guide/en/ecs/8.17/ecs-client.html)
- [ECS 8.17 event.category allowed values and expected event.type](https://www.elastic.co/guide/en/ecs/8.17/ecs-allowed-values-event-category.html)
- [Pinned Elastic Aironet compatibility documentation](https://github.com/elastic/integrations/blob/78fd455d22cdb74bd2a8e53249c25cc060f06010/packages/cisco_aironet/docs/README.md)
- [Pinned Elastic Aironet native fixtures, different IOS-XE message class](https://github.com/elastic/integrations/blob/78fd455d22cdb74bd2a8e53249c25cc060f06010/packages/cisco_aironet/data_stream/log/_dev/test/pipeline/test-aironet-messages.log)
- [KUMA 4.2 source catalog](https://support.kaspersky.ru/kuma/4.2/255782)
