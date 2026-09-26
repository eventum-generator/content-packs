# Cisco Catalyst 9800 wireless client state syslog

Synthetic client-state records using the named-client, no-channel message examples published in Cisco Catalyst 9800 IOS XE 17.11 documentation. The pack preserves controller console/buffer-format text in `event.original` and supplies a declared ECS mapping. It models client associations and address learning, not authentication results.

## Event Types

| Native mnemonic | Meaning | Share of records | ECS category/type |
| --- | --- | --- | --- |
| `CLIENT_MOVED_TO_RUN_STATE` | Client enters RUN on the named AP | 31.5-31.8% | `network` / `connection`, `start` |
| `CLIENT_IP_UPDATED` | RUN client's address list gains a learned address on the same AP | 36.5-37.0% | `network` / `connection`, `info` |
| `CLIENT_MOVED_TO_DELETE_STATE` | RUN client is deleted from its current AP | 31.5-31.7% | `network` / `connection`, `end` |

Shares are the range measured over the five final 97-hour validation runs described under Usage, in both modes.

One controller serves 48 fixed named stations across 12 pre-existing APs, three per floor. Each station follows its own lifecycle: absence, RUN on one AP of its floor, address learning, DELETE from the same AP with the same addresses, then absence again. Sessions mix a lognormal body (35-minute median, at most 12 hours) with a 12% short tail of about 10 seconds to 3 minutes, which stands for sleep/wake, band steering and re-authentication; the only same-client session in the Cisco examples lasts 130 seconds. Absences mix a lognormal body (10-minute median, at most 8 hours) with a 12% quick-reconnect tail of about 1..60 seconds. Tails start at a small offset and fade out below it, so no length has a hard floor. Each association picks the station's home AP with 50% probability and each other AP on its floor with 25%. At the first input timestamp some stations are already associated, so the stream starts in steady state and a station's first record may be its DELETE.

Address learning follows the 17.11 examples. Both RUN examples carry one IPv4 address. In the open-authentication example, the same client's IP update comes 645 ms after RUN and lists the IPv4 address followed by a new link-local address; its DELETE two minutes later lists link-local first, two global IPv6 addresses, and IPv4 last. The 802.1X RUN and IP-update examples belong to different clients. Accordingly, RUN carries the station's IPv4 address, IP updates append in learning order, and DELETE lists link-local, then global IPv6, then IPv4. An IP update 5 ms..3 s later adds the IPv6 link-local address, and dual-stack stations add a global IPv6 address with a second update 0.5..15 s later. A session that ends before learning completes deletes the client with the addresses learned so far. Besides slot 0, the inventory holds 27 IPv4 plus link-local stations, 12 dual-stack stations, 4 IPv4-only stations that emit no IP update, and 4 IPv6-only stations; slot 0 is IPv4 plus link-local or IPv6-only, depending on `suspicious_ip`. Cisco shows no IPv6-only RUN record, so starting those at the link-local address and adding the global address by update is a synthetic assumption. About half of the link-local addresses are modified EUI-64 derived from the MAC, as in the 802.1X example; the rest use random interface identifiers, as in the open-authentication example. Slot 0 always derives EUI-64 from the configured MAC. Mid-session renumbering, DHCP renewal to a new lease and roaming without DELETE are not modeled.

The input ticks every second (`* * * * * *`, `count: 1`). A tick produces a record only when some station's next step is due, and other ticks are dropped. The record rate therefore varies: final runs measured 3,186-3,283 records a day, 82-197 per hour, and 21-45 concurrently associated stations with a median of 35-36, never zero. Each record carries its scheduled millisecond and is never later than the input tick that emits it. After an input gap longer than one minute, overdue stations get fresh schedules instead of a backdated burst.

## Source Profile

The selected text follows the 17.11 configuration guide's `%CLIENT_ORCH_LOG-7-...` examples: source timestamp, `Chassis 1 R0/0`, `wncd`, username, dotted MAC, space-separated IP values, AP and SSID. `wireless client syslog-detailed` enables these detailed messages. If forwarding to a syslog server, its filter must include severity 7, for example `logging trap debugging`; an informational filter excludes them. This pack uses synchronized UTC source time, millisecond datetime timestamps with timezone display, and disabled native sequence numbering. The documented timestamp options include `service timestamps log datetime msec show-timezone`.

`event.original` is the source console/buffer record, not a fabricated RFC3164/5424 UDP/TCP envelope. There is no native PRI, hostname, transport peer or message sequence in this selected variant. `host.name` is configured controller context, and the minimal `agent` fields identify a synthetic Eventum reader. They do not describe a tested live collector. Input instants are converted to UTC before native and ECS rendering, so a non-UTC `--timezone` changes nothing in the output; the custom validation runs used `--timezone Europe/Moscow`. The native timestamp omits a year, so the full year in `@timestamp` comes from the simulation/collector context.

`client.ip` and `client.address` carry one primary address: the IPv4 address when present, otherwise the first global IPv6 address, otherwise the link-local address. The complete list is retained in `related.ip` and `cisco_wlc.client_ips`. `cisco_wlc.client_mac` and native text retain dotted Cisco notation, while ECS `client.mac` uses uppercase hyphen-separated octets. `log.level` is `debugging`, the Cisco keyword for severity 7. `cisco_wlc.client_state` and ECS actions/types are derived from the mnemonic. Neither the RUN message nor its username proves an AAA outcome, authentication method or malicious activity.

## Anomaly Chain

`anomaly_mode` defaults to `true`. An episode is due every `anomaly_interval_hours`, default 24 hours, with the first due time one interval after the first input timestamp. It starts on the first input tick at or after the due time, once the selected station has finished address learning, any current association of it is at least three minutes old, and any last DELETE of it is at least 90 seconds old. Measured starts came 0-1 seconds after the due tick, or up to 76 seconds later while waiting for those conditions. The next episode is due one interval after the actual start. When the input has a gap, one episode starts at the first tick after the gap and the next follows one interval later; no overdue episodes are queued. Each episode selects the next station from the same 48-station inventory and rotates the order of its floor's three APs. There are no fabricated native session IDs or emitted episode/mode markers.

If the station is associated, the controller first logs DELETE with its actual current AP and complete address list. The station then makes three associations on AP-A, AP-B and AP-C. Each RUN is followed by the station's normal address learning. The first two associations take their lengths from the same short-session tail as ordinary traffic, limited to 100 seconds, and each reassociation takes its delay from the ordinary quick-reconnect tail, limited to 30 seconds. The third association continues as an ordinary session and ends with an ordinary DELETE. The final paired runs measured short associations of 12.9-89.8 seconds, reconnects of 2.1-27.4 seconds and 55-148 seconds from RUN-A to RUN-C; additional independent runs reached 186 seconds from RUN-A to RUN-C. The same MAC, username and SSID link the episode. At most one episode exists at a time.

Set `anomaly_mode: false` for ordinary traffic only. Short sessions and quick reconnects are frequent in both modes: about 13% (12.8-13.9% across measured runs) of sessions last under 3 minutes and 12.1-12.6% of absences under 20 seconds, with the same low quantiles and minima in paired runs. A single short session or quick reconnect therefore identifies an episode with 1.5-2.4% precision in the default 24-hour run, 3.0-4.2% in the 12-hour run and 5.6-8.8% in the 6-hour runs. A detection can group by native MAC plus SSID and look for three consecutive associations on three distinct APs, where the first two last at most two minutes and each reassociation comes within one minute. Ordinary traffic may repeat quick reconnects, but after two such short associations on two APs it returns to one of those two APs, so this exact shape occurs only in episodes. A looser predicate, any three distinct-AP RUNs of one MAC within 15 minutes, matched 4-9 times per run outside episodes in both modes. The pattern signals rapid reassociation or instability. It does not establish seamless roaming, an authentication failure, a deauthentication attack, an AP outage, a cloned client or an intrusion.

Every episode record, including the leading and closing DELETEs, matches an ordinary record with the same action, MAC, AP and address list, both in the same run and in the paired false-mode run. The configured slot-0 station takes part in ordinary traffic in both modes. In paired true and false runs, the event mix, concurrent-station counts, per-station record spacing, same-mnemonic run lengths, hourly counts, and the shares, low quantiles and minima of short sessions and quick reconnects differ by no more than between two independent false-mode runs.

## Parameters

### Event Parameters

Edit `event.template.params` in a local configuration copy.

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include periodic rapid three-AP episodes alongside ordinary traffic; must be a YAML boolean |
| `anomaly_interval_hours` | `24` | Recurrence in hours, numeric 6..8760, measured from the actual start of the previous episode |
| `controller_name` | `wlc9800-01.corp.example` | Controller identity supplied as source context |
| `ssid` | `corp-wifi` | Shared WLAN SSID; selected ASCII subset, 1..32 characters, without parentheses or newlines |
| `suspicious_user` | `visitor01` | Inventory slot 0 username, used by ordinary traffic in both modes and the first episode; 1..64 letters/digits or `._@+-` |
| `suspicious_mac` | `02aa.bbcc.ddee` | Inventory slot 0 dotted MAC, unique, nonzero and unicast; source text is lowercase, ECS notation is normalized, and the slot's link-local address is derived from it |
| `suspicious_ip` | `192.0.2.91` | Inventory slot 0 primary address; IPv4 gives an IPv4 plus link-local station, IPv6 an IPv6-only station |

The legacy `suspicious_*` names do not reserve an anomaly-only actor. The configured MAC and address must not collide with other inventory rows, including their derived or sampled link-local and global IPv6 addresses. Multicast, unspecified, loopback, link-local, reserved, IPv4 zero-network and IPv4 last-octet 0/255 addresses are rejected. Parameter guards run before any event is emitted. Inventories are intentionally finite; changing their size or the input rate requires adapting the model and validation.

### Output Parameters

The shipped output writes `output/events.json` with the JSON formatter and requires no endpoint or secrets. To target another output plugin in a local copy, use `${params.siem_host}` and `${secrets.siem_token}` where that plugin requires them. Those are replacement patterns, not required parameters of this file-output configuration.

## Usage

```bash
# Live mode (about two records per minute)
eventum generate \
  --path generators/network-cisco-wlc-9800/generator.yml \
  --id cisco-wlc-9800 \
  --live-mode true
```

For a finite batch run, add a window to `input[0].cron` in a local copy of `generator.yml` without changing the expression or count, then generate as fast as possible:

```yaml
start: '2026-09-25T00:00:00+00:00'
end: '2026-09-29T01:15:00+00:00'
```

```bash
eventum generate \
  --path generators/network-cisco-wlc-9800/generator.yml \
  --id cisco-wlc-9800 \
  --live-mode false \
  --keep-order true
```

`--keep-order true` keeps records in chronological order in the output file.

With that 97-hour-15-minute window, the final validation runs wrote 12,909-13,305 records each. Default enabled/disabled runs contained 4/0 episodes, custom 12-hour enabled/disabled runs 8/0, and the minimum 6-hour enabled run 16; every episode's final association was closed by DELETE inside the window. Custom runs changed controller identity, quoted ASCII SSID, username, MAC and the configured address to IPv6. A separate run with a 35-hour input gap and a 6-hour interval produced one episode right after the gap and the next one 6 hours later. Native state checks, paired ordinary overlap and paired statistics passed. Seven native/ECS-consistent mutations, a catch-up variant of the template run over the gap and the superseded lockstep captures were rejected, and fifteen parameter-guard cases stopped before the first event with a diagnostic.

## Sample Output

Actual record 3129 of the final default-enabled run: the DELETE that ends the first episode's association with AP-A. Native source text is copied unchanged from that capture. Controller/reader context is synthetic enrichment.

```json
{
  "@timestamp": "2026-09-26T00:01:22.207+00:00",
  "agent": {
    "name": "synthetic-wlc-reader",
    "type": "eventum"
  },
  "cisco_wlc": {
    "ap_name": "AP-Floor1-A",
    "chassis": "1 R0/0",
    "client_ips": [
      "fe80::aa:bbff:fecc:ddee",
      "192.0.2.91"
    ],
    "client_mac": "02aa.bbcc.ddee",
    "client_state": "delete",
    "ssid": "corp-wifi"
  },
  "client": {
    "address": "192.0.2.91",
    "ip": "192.0.2.91",
    "mac": "02-AA-BB-CC-DD-EE"
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "delete",
    "category": [
      "network"
    ],
    "code": "CLIENT_MOVED_TO_DELETE_STATE",
    "kind": "event",
    "original": "Sep 26 00:01:22.207 UTC: %CLIENT_ORCH_LOG-7-CLIENT_MOVED_TO_DELETE_STATE: Chassis 1 R0/0: wncd: Username (visitor01), MAC: 02aa.bbcc.ddee, IP fe80::aa:bbff:fecc:ddee 192.0.2.91 disconnected from AP (AP-Floor1-A) with SSID (corp-wifi)",
    "provider": "CLIENT_ORCH_LOG",
    "severity": 7,
    "timezone": "+00:00",
    "type": [
      "connection",
      "end"
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
      "fe80::aa:bbff:fecc:ddee",
      "192.0.2.91"
    ],
    "user": [
      "visitor01"
    ]
  },
  "user": {
    "name": "visitor01"
  }
}
```

## Coverage and Limits

All eleven source elements in the chosen guide examples are represented: timestamp, facility, severity, mnemonic, chassis, process, username, MAC, complete address list, AP and SSID. This 11/11 accounting covers the selected elements, not all possible source values or a complete same-version unredacted wire fixture. Address lists hold one to three addresses; the seven-address list of the 802.1X example is not reproduced, and the list order is a single rule fitted to the one same-client example sequence. The documented open-auth/null usernames and temporary username gaps following AP reconnect are omitted by the named-client subset.

The 17.11 configuration-guide RUN example has no channel suffix. The 17.12 system-message catalog adds `on channel (...)`; this generator deliberately preserves the published 17.11 example variant. The exact 17.11 system catalog could not be inspected after a bounded search: browser size caps and direct HTTP403 prevented retrieval. No claim is made that every 17.11 build emits this exact variant. Published MAC/IP values are redacted, so this pack supplies synthetic complete values and does not assert byte parity with a live capture. Native wire evidence and live collector/normalizer parsing remain `BLOCKED_RAW_EVIDENCE`.

The maintained Elastic Aironet package's compatibility list describes AireOS, although its tests also contain another IOS-XE class, severity 6 `CLIENT_ADDED_TO_RUN_STATE`, with different fields. Those records and the package's SISF normalized sample are not references for these three severity 7 classes. Compatibility with AireOS-oriented Elastic/KUMA normalizers or Smart Monitor parsers has not been tested. AP connectivity, WLAN policy, packet forwarding, radio/channel details, session/authentication IDs, AAA decisions and delete reasons are outside this selected output. Session, absence and address-learning distributions are synthetic training choices, not measured production workload; rates are stationary, with no working-day cycle.

State consists of 48 finite station records, fixed sample/AP sets, scalar cursors and timestamps, and at most one active episode. Nothing grows with run length. Ordinary stations, and the last episode's final association, may legitimately remain associated at the end of a finite window.

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
