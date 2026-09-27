# Ideco NGFW Novum Syslog Generator

Generates Syslog messages of one Ideco NGFW Novum (v22) that publishes a PPTP VPN to remote users and faces ordinary internet noise. Three services are modeled: `traffic-journal` (firewall flows), `ideco-vpn-authd` (VPN authorizations) and `fail2ban` (`Found`, `Ban`, `Unban`). Each native line is kept in `event.original` inside an ECS JSON envelope. The format follows the [v22 Syslog guide](https://docs.ideco.ru/pdf/v22/ru-ngfw-settings-services-syslog.pdf); CEF is not modeled.

## Event Types

Shares measured over 240-hour default runs (`anomaly_mode` true / false, about 205,000 records each).

| Service and action | `event.action` | Share on / off | Category |
|---|---|---:|---|
| `traffic-journal` `result:accept` | `traffic_accept` | 72.8% / 72.8% | network |
| `traffic-journal` `result:drop` | `traffic_drop` | 25.1% / 25.1% | network |
| `fail2ban` `INFO [jail] Found` | `fail2ban_found` | 1.21% / 1.16% | intrusion_detection |
| `ideco-vpn-authd` `... is authorized as user ...` | `vpn_authorized` | 0.72% / 0.74% | authentication |
| `fail2ban` `NOTICE [jail] Ban` | `fail2ban_ban` | 0.09% / 0.09% | intrusion_detection |
| `fail2ban` `NOTICE [jail] Unban` | `fail2ban_unban` | 0.09% / 0.09% | intrusion_detection |

Background processes are independent and random, weighted by hour of day (UTC):

- **VPN users** (60 by default, each with one or two home addresses and a skewed activity weight) log in about 2.5 times a day. A login opens a PPTP control connection to the NGFW (`inp`, port 1723), may fail a few times (each failure is a `utm-vpn-authd` `Found`), then succeeds; the session then produces flows from its `10.128.0.x` tunnel address to internal servers. A user who fails four or more times gives up and sometimes returns later; six failures within 15 minutes get the address banned.
- **Brute-force campaigns** from about 40 internet addresses target `utm-vpn-authd`, `utm-ssh` or `utm-web-interface`, with per-address jail preferences; long campaigns end in a ban.
- **Administrators** occasionally mistype the password of the administrative web interface from LAN workstations.
- **Traffic**: LAN clients browsing the internet and resolving names on the NGFW, and internet scans of NGFW ports.

fail2ban is applied consistently: six `Found` for one address and jail within 900 s produce `Ban`, a banned address produces no attempts in that jail, and `Unban` follows 2700 s later (plus a few seconds).

## Anomaly Chain

A VPN password is guessed: one VPN user's address fails at least four VPN authorizations and then authorizes as that user.

| Step | Record | Linking fields |
|---|---|---|
| 1 | `traffic-journal` `accept`, `table:inp`, `dst_port:1723` from the user's address | `source.ip` |
| 2-5 (or 2-6) | 4 or 5 `fail2ban` `INFO [utm-vpn-authd] Found <address>` | `source.ip`, jail |
| 6 | `ideco-vpn-authd` `Subnet 10.128.0.x/32 is authorized as user '<user>'. Connection made from '<address>'` | `source.ip`, `user.name` |
| then | VPN session flows from the tunnel address to internal servers | tunnel IP |

The whole chain lasts 30 seconds to about 5 minutes, below the six-failure ban threshold. Failures use the same gap law as ordinary users.

- **Recurrence:** the first episode starts at a random time within the first min(interval, 24 hours) of the run, with its hour drawn from the VPN login hour-of-day curve. Each later episode is due `anomaly_interval_hours` (default 24, minimum 1) after the actual start of the previous one. It starts at a random time in a window of min(interval / 4, 6 hours) centred on the due time, weighted by the squared login curve plus a small floor. Gaps therefore stay within the interval plus or minus half that window. Measured over 240 hours: 21.0-26.9 hours between default episodes and 7.1-8.9 hours with an 8-hour interval. Missed episodes are not caught up.
- **Episode hours:** because the window is centred on the due time and weighted towards busy hours, daily episodes stay in the hours when users log in. In the measured default run, all 10 episodes started between 08:00 and 20:00 UTC and none at night; in a second run all 10 started between 07:38 and 10:20 UTC. Within one run the daily start times usually span about 5.5 h, so a run covers busy hours but not the full login curve. At intervals of 8 hours or less, the start necessarily moves around the clock: with an 8-hour interval, 10 of 31 episodes started between 00:00 and 07:00 UTC, against 6% of ordinary logins.
- **Variation:** the user is drawn with the background user weights, never the previous episode's user and never a user whose address has a VPN failure in the last 15 minutes or an active ban; one of that user's own home addresses is used. The number of failures (4 or 5), their gaps, the tunnel address and the session flows vary per episode.
- **Separability:** every user, address, user/address pair, jail and action of the chain also occurs in the background of both modes, including failure runs, successes after one to three failures and failure runs of four or more without success. Only the full order is absent from the background: if an ordinary login would succeed while its address already has four VPN failures in the last 900 s, that attempt fails instead (same time, same address). Attempts from an address that already has four VPN failures in the last 900 s are less frequent than attempts just after that window, for both user and attacker addresses: such an address is one or two failures away from a ban, after which it stays silent. This comes from fail2ban, not from the anomaly.
- **Detection idea:** an `ideco-vpn-authd` authorization from an address with at least four `utm-vpn-authd` `Found` records in the preceding 15 minutes.

`anomaly_mode` defaults to `true`. With `false`, the generator emits the background only and never the complete chain.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
|---|---|---|
| `anomaly_mode` | `true` | Include recurring VPN password-guessing episodes; `false` emits background only |
| `anomaly_interval_hours` | `24` | Hours from one episode start to the next due time, 1 to 8760 |
| `ngfw_host` | `ideco-ngfw` | Hostname in the Syslog header |
| `ngfw_ip` | `10.50.0.1` | NGFW address, destination of `inp` traffic |
| `vpn_user_count` | `60` | Number of VPN users, 10 to 200 |
| `vpn_type` | `pptp` | Value of `type` in VPN authorization messages |

Addresses use documentation ranges (`198.51.100.0/24`, `203.0.113.0/24`, `192.0.2.0/24`) and RFC 1918 networks. Zone names (`LAN`, `WAN`, `NGFW`, `VPN`, `SERVERS`), rule IDs and security profile names are examples of one deployment, not vendor defaults.

### Output Parameters

The shipped configuration writes `output/events.json` and needs no parameters or secrets. To send events elsewhere, replace the `output` block with another output plugin and put its endpoints and credentials into `${params.*}` and `${secrets.*}` placeholders.

## Usage

Live mode, one tick per second:

```bash
eventum generate --path generators/network-ideco-ngfw/generator.yml --id ideco-ngfw --live-mode true
```

Batch mode: set `input[0].cron.start` and `input[0].cron.end` in `generator.yml` (for example 240 hours for about ten default episodes), then run:

```bash
eventum generate --path generators/network-ideco-ngfw/generator.yml --id ideco-ngfw --live-mode false
```

## Sample Output

The final record of the first episode in a 240-hour default run (synthetic, not a vendor capture):

```json
{"@timestamp": "2026-09-01T19:20:09+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "vpn_authorized", "category": ["authentication", "network"], "dataset": "ideco.ngfw_syslog", "kind": "event", "original": "2026-09-01T19:20:09+00:00 ideco-ngfw ideco-vpn-authd - - - Subnet 10.128.0.87/32 is authorized as user \u0027v.zaitsev\u0027. Connection made from \u0027203.0.113.72\u0027, type \u0027pptp\u0027", "outcome": "success", "type": ["start", "allowed"]}, "ideco": {"ngfw": {"fields": {"connected_from": "203.0.113.72", "subnet": "10.128.0.87/32", "type": "pptp", "user": "v.zaitsev"}, "service": "ideco-vpn-authd"}}, "message": "Subnet 10.128.0.87/32 is authorized as user \u0027v.zaitsev\u0027. Connection made from \u0027203.0.113.72\u0027, type \u0027pptp\u0027", "observer": {"hostname": "ideco-ngfw", "ip": "10.50.0.1", "product": "NGFW Novum", "vendor": "Ideco"}, "process": {"name": "ideco-vpn-authd"}, "related": {"ip": ["203.0.113.72", "10.128.0.87"], "user": ["v.zaitsev"]}, "source": {"ip": "203.0.113.72"}, "user": {"name": "v.zaitsev"}}
```

## Limitations

- **Traffic line:** the guide's `traffic-journal` example is cut off after `ips_pro`. The generator emits 19 of the 39 documented keys in a plausible order; NAT, user, location, cluster and VCE keys are omitted. The complete serialization cannot be confirmed against a vendor capture. The `flow_id` value format is not documented; a random 16-digit number is used.
- **fail2ban:** the guide shows a complete `Found` line and the `NOTICE [jail] Ban <ip>` body, described as the record of a block or an unblock; the `Unban` wording is inferred from it and from fail2ban. The 6 failures / 15 minutes / 45 minutes thresholds come from the [v21 guide](https://docs.ideco.ru/pdf/v21/ru-ngfw-settings-server-management-additionally.pdf) and are fixed in the generator. Ban durations are therefore nearly constant (2700 s plus a few seconds), as in fail2ban; this fixed hold is native fail2ban behaviour, identical with and without the anomaly, and a statistical check may report it as a regularity.
- **VPN:** only the documented successful authorization message is produced; failed VPN authorizations are visible only through `fail2ban` `Found`. The guide documents the `pptp` type only. VPN disconnections are not modeled.
- One record per second at most; ordinary traffic is thinned to about 0.25 records per second so that multi-day runs stay small. Timestamps are UTC, and Syslog transport framing is not modeled.

## References

- [Ideco NGFW Novum v22: Syslog](https://docs.ideco.ru/pdf/v22/ru-ngfw-settings-services-syslog.pdf) - Syslog header, `traffic-journal` keys, `ideco-vpn-authd` and `fail2ban` messages, jail list
- [Ideco NGFW v21: additional server settings](https://docs.ideco.ru/pdf/v21/ru-ngfw-settings-server-management-additionally.pdf) - fail2ban thresholds
- No Elastic integration exists for Ideco NGFW; the ECS mapping is inferred.
