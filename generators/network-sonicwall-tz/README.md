# SonicWall TZ SonicOS Traffic and CFS Logs

SonicOS 6.5.4 default Syslog traffic and Content Filtering Service (CFS) records based on SonicWall's complete published examples. Eventum emits ECS JSON and preserves the native line in `event.original`.

## Event types

| SonicOS `m` | Action | Approximate background frequency | ECS category |
| --- | --- | --- | --- |
| `97` | Website accessed, CFS category Not Rated | 75% | network, web |
| `537` | Connection closed | 20% | network, web |
| `14` | Website access denied by CFS | 5% | network, web |

Weights and the one-record-per-second rate are synthetic demo settings, not measured SonicOS traffic frequencies. This pack uses SonicOS's **default key-value Syslog format**. SonicOS ArcSight CEF output is a separate format and is not generated here.

## Anomaly Chain

After 60 routine records, a client receives three CFS denials for a site in the `Gambling` category. The same source then has a CFS observation for an alternate, `Not Rated` destination at the same URL path, followed by a connection-close record for that second flow. Correlate the five events by `source.ip`, time, `url.path`, and, for the final pair, source port and destination IP. A rule can surface a burst of CFS denials followed by traffic to an unrated alternate host.

The alternate host is a synthetic hypothesis for a policy-evasion investigation. The logs do not prove the two hosts are related, that content was retrieved, or that CFS was bypassed. The `m=97` record's `fw_action="NA"` is retained; it is an access observation, not labeled an explicit firewall Allow decision.

`anomaly_mode: true` is the default. Set it to `false` for background traffic only. Sort by `@timestamp` when checking the chain; output lines can be reordered by concurrent generation.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`.

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Enable the CFS denial and alternate-host chain. |
| `anomaly_interval_events` | `60` | Routine records between chains. |
| `firewall_ip` | `10.20.30.1` | SonicWall firewall address in the log. |
| `firewall_serial` | `02DEADBEEF01` | Synthetic appliance serial. |
| `target_source_ip` | `10.20.30.77` | Chain client address. |
| `blocked_ip` | `203.0.113.40` | CFS-denied destination. |
| `blocked_domain` | `betting.example` | CFS-denied hostname. |
| `alternate_ip` | `203.0.113.41` | Later unrated destination. |
| `alternate_domain` | `alternate.example` | Later unrated hostname. |

### Output Parameters

The shipped file output needs no overrides. Replace `output.file` with another output plugin and use top-level `${params.*}` or `${secrets.*}` substitutions for destination settings when needed.

## Usage

From the content-packs repository:

```bash
eventum generate --path generators/network-sonicwall-tz/generator.yml --id sonicwall --live-mode false
eventum generate --path generators/network-sonicwall-tz/generator.yml --id sonicwall --live-mode true
```

Output: `generators/network-sonicwall-tz/output/events.json`. Extract `event.original` if a collector expects default SonicOS Syslog lines.

## Sample output

Copied from an actual anomaly-mode run:

```json
{
  "@timestamp": "2026-09-25T13:59:03+00:00",
  "destination": {
    "ip": "203.0.113.40",
    "port": 80
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "website_denied",
    "category": [
      "network",
      "web"
    ],
    "code": "14",
    "dataset": "sonicwall.sonicos",
    "kind": "event",
    "original": "Sep 25 13:59:03 10.20.30.1 id=firewall sn=02DEADBEEF01 time=\"2026-09-25 13:59:03\" fw=10.20.30.1 pri=3 c=4 m=14 msg=\"Web site access denied\" app=9 n=61 src=10.20.30.77:51000:X0 dst=203.0.113.40:80:X1 srcMac=02:00:00:00:00:77 dstMac=02:00:00:00:01:01 proto=tcp/http dstname=betting.example arg=/offers code=11 Category=\"Gambling\" rule=\"9 (LAN->WAN)\" fw_action=\"drop\"",
    "type": [
      "denied"
    ]
  },
  "network": {
    "transport": "tcp"
  },
  "observer": {
    "ip": "10.20.30.1",
    "product": "SonicOS",
    "vendor": "SonicWall"
  },
  "related": {
    "ip": [
      "10.20.30.77",
      "203.0.113.40"
    ]
  },
  "rule": {
    "name": "9 (LAN->WAN)"
  },
  "sonicwall": {
    "sonicos": {
      "category": "Gambling",
      "firewall_action": "drop",
      "log_number": 61,
      "serial": "02DEADBEEF01"
    }
  },
  "source": {
    "ip": "10.20.30.77",
    "port": 51000
  },
  "url": {
    "domain": "betting.example",
    "path": "/offers"
  }
}
```

## Scope and validation

The three raw templates retain every positional and key-value field in the selected `m=14`, `m=97`, and `m=537` examples in the SonicOS 6.5.4 guide. Variable values, including addresses, domains, ports, times, and `n`, are synthetic. Both modes were generated and parsed as JSON; the five-step chain appears only in anomaly mode.

The selected SonicOS guide covers generic SonicOS appliances, rather than a TZ-specific capture. KUMA 4.2 lists Sonicwall TZ key-value Syslog for SonicOS 7.3 and CEF Syslog for 6.5/7.3. This pack's default key-value lines follow a SonicOS 6.5.4 vendor sample; compatibility with KUMA's specified TZ normalizer or a 7.3 device was not tested and should not be inferred from that table.

## References

- [SonicOS 6.5.4 Log Events Reference Guide, default Syslog examples](https://www.sonicwall.com/techdocs/pdf/sonicos-6-5-4-log-events-reference-guide.pdf)
- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)
