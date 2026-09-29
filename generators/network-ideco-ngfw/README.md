# Ideco NGFW Novum Syslog Generator

Generates Syslog messages of one Ideco NGFW Novum (v22) that publishes a PPTP VPN to remote users and faces ordinary internet noise. Three services are modeled: `traffic-journal` (firewall flows), `ideco-vpn-authd` (VPN authorizations) and `fail2ban` (`Found`, `Ban`, `Unban`). Each native line is kept in `event.original` inside an ECS JSON envelope. The format follows the [v22 Syslog guide](https://docs.ideco.ru/pdf/v22/ru-ngfw-settings-services-syslog.pdf); CEF is not modeled.

## Event Types

Shares of a 7-day default run (`anomaly_mode` true / false, about 188,000 records each).

| Service and action | `event.action` | Share on / off | Category |
|---|---|---:|---|
| `traffic-journal` `result:accept` | `traffic_accept` | 79.04% / 78.99% | network |
| `traffic-journal` `result:drop` | `traffic_drop` | 16.50% / 16.43% | network |
| `ideco-vpn-authd` `... is authorized as user ...` | `vpn_authorized` | 3.31% / 3.34% | authentication |
| `fail2ban` `INFO [jail] Found` | `fail2ban_found` | 0.99% / 1.06% | intrusion_detection |
| `fail2ban` `NOTICE [jail] Ban` | `fail2ban_ban` | 0.08% / 0.09% | intrusion_detection |
| `fail2ban` `NOTICE [jail] Unban` | `fail2ban_unban` | 0.08% / 0.09% | intrusion_detection |

The activity is independent and random:

- **VPN users** (300 by default, each with one home address and an activity weight between 0.7 and 2.5) log in about three times a day. A login opens a PPTP control connection to the NGFW (`inp`, port 1723), may fail (each failure is a `utm-vpn-authd` `Found`), then authorizes; the session then produces a few flows (median 6, about 90 s apart) from its `10.128.0-3.x` tunnel address to internal servers. 96.9% of ordinary logins succeed at once, 2.5% after one failure and 0.6% after two. About 1% of logins, more on some days than others, use a stale saved password and fail three to eight times: after three failures the user types the right password, after more the user gives up and in 60% of cases returns later (median 40 minutes), usually succeeding at once. About 4% of logins see at least one failure, and 7-10% of VPN authorization attempts fail.
- **Brute-force campaigns**: about 40 a day from 40 internet addresses against `utm-vpn-authd`, `utm-ssh` or `utm-web-interface`, each address with its own jail preferences; a campaign makes about five attempts in median, a few seconds apart, and long campaigns end in a ban.
- **Administrators** mistype the password of the administrative web interface (`utm-web-interface`) about six times a day, one to four failures from one of three LAN workstations.
- **Traffic**: LAN clients browsing the internet (7% dropped) and resolving names or time on the NGFW, and internet connections to NGFW ports, half of them from the brute-force addresses.

fail2ban is applied consistently: six `Found` for one address and jail within 900 s produce `Ban`, a banned address produces no attempts in that jail, and `Unban` follows 2700 s later (plus a few seconds).

## Volume and Timing

About 27,000 records a day, on UTC hour-of-day curves:

| UTC hours | LAN traffic per hour | VPN logins per hour |
|---|---:|---:|
| 21:00-06:00 | 296 | 4 |
| 06:00-07:00, 18:00-21:00 | 593 | 21 |
| 07:00-08:00, 17:00-18:00 | 1,037 | 51 |
| 08:00-17:00 | 1,432 | 76 |

Internet traffic to the NGFW adds 250 records an hour around the clock (each hour's count varying by up to 10%); the daily LAN and VPN counts vary by up to 3%. Failures, authorizations, session flows and fail2ban records take the place of LAN or internet traffic records at their time, so they do not add to the volume. Records of one login or ban are seconds apart: a `Ban` follows the sixth `Found` 3 s later in median and at most about 30 s later.

## Anomaly Chain

A VPN password is guessed: one VPN user's address fails at least four VPN authorizations and then authorizes as that user.

| Step | Record | Linking fields |
|---|---|---|
| 1 | `traffic-journal` `accept`, `table:inp`, `dst_port:1723` from the user's home address | `source.ip` |
| 2-5 (or 2-6) | 4 or 5 `fail2ban` `INFO [utm-vpn-authd] Found <address>` | `source.ip`, jail |
| 6 | `ideco-vpn-authd` `Subnet 10.128.x.y/32 is authorized as user '<user>'. Connection made from '<address>'` | `source.ip`, `user.name` |
| then | VPN session flows from the tunnel address to internal servers | tunnel IP |

The chain lasts about half a minute to three minutes, below the six-failure ban threshold. Failure gaps and session flows follow the same laws as ordinary logins.

- **Recurrence:** the first episode starts at a random time within the first min(interval, 24 hours) of the data, its hour drawn from the VPN login curve. Each later episode is due `anomaly_interval_hours` (default 24, minimum 1) after the actual start of the previous one and starts in a window of min(interval / 4, 6 hours) centred on the due time, weighted by the squared login curve plus a small floor, so daily episodes fall in busy hours. At intervals of 8 hours or less, episodes move around the clock. Missed episodes are not caught up.
- **Variation:** the user is drawn with the ordinary user weights, never the previous episode's user and never a user whose address has a VPN failure in the last 15 minutes or an active ban. The number of failures (4 or 5), their gaps, the tunnel address and the session flows vary per episode.
- **Episode records:** an episode is one additional login of the chosen user. Its records take the place of LAN or internet traffic records at their moments; the user's own logins and all other activity keep their times.
- **Background without the chain:** every user, address, user/address pair, jail and action of the chain also occurs in ordinary data, including failure runs of four or more without success and successes after one to three failures. Only the full order is absent: when a returning user's address already has four VPN failures in the last 15 minutes, that attempt fails once more instead of authorizing, at the same time and from the same address (a few times a week).
- **Detection idea:** an `ideco-vpn-authd` authorization from an address with at least four `utm-vpn-authd` `Found` records in the preceding 15 minutes.

`anomaly_mode` defaults to `true`. With `false`, the generator emits ordinary activity only and never the complete chain.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
|---|---|---|
| `anomaly_mode` | `true` | Include recurring VPN password-guessing episodes; `false` emits ordinary activity only |
| `anomaly_interval_hours` | `24` | Hours from one episode start to the next due time, 1 to 8760 |
| `ngfw_host` | `ideco-ngfw` | Hostname in the Syslog header |
| `ngfw_ip` | `10.50.0.1` | NGFW address, destination of `inp` traffic |
| `vpn_user_count` | `300` | Number of VPN users taken from `samples/vpn_users.csv`, 100 to 500 |
| `vpn_type` | `pptp` | Value of `type` in VPN authorization messages |

VPN users and their home addresses live in `samples/vpn_users.csv` (500 rows). Home addresses are in the `198.18.0.0/15` benchmarking range, internet addresses in documentation ranges (`198.51.100.0/24`, `203.0.113.0/24`, `192.0.2.0/24`), internal ones in RFC 1918 networks. Zone names (`LAN`, `WAN`, `NGFW`, `VPN`, `SERVERS`), rule IDs and security profile names are examples of one deployment, not vendor defaults.

### Output Parameters

The shipped configuration writes `output/events.json` and needs no parameters or secrets. To send events elsewhere, replace the `output` block with another output plugin and put its endpoints and credentials into `${params.*}` and `${secrets.*}` placeholders.

## Usage

From the content-packs repository root, live:

```bash
eventum generate --path generators/network-ideco-ngfw/generator.yml --id ideco-ngfw --live-mode true
```

The files under `patterns/` set the hour-of-day curves: `lan-*.yml` for LAN traffic, `vpn-*.yml` for VPN logins and administrator sessions, `wan.yml` for internet traffic. They start at midnight of the current day and never end. For a finite batch, set `start` and `end` in all nine files (for example `start: "2026-09-01T00:00:00Z"`, `end: "+7d"`); the second episode can start up to 51 hours after the start, so use at least 52 hours to see two at the default interval:

```bash
eventum generate --path generators/network-ideco-ngfw/generator.yml --id ideco-ngfw --live-mode false --keep-order true
```

## Sample Output

The final record of the first episode in a 7-day default run (synthetic, not a vendor capture):

```json
{"@timestamp": "2026-09-01T11:26:00+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "vpn_authorized", "category": ["authentication", "network"], "dataset": "ideco.ngfw_syslog", "kind": "event", "original": "2026-09-01T11:26:00+00:00 ideco-ngfw ideco-vpn-authd - - - Subnet 10.128.0.68/32 is authorized as user \u0027p.vlasov\u0027. Connection made from \u0027198.19.71.123\u0027, type \u0027pptp\u0027", "outcome": "success", "type": ["start", "allowed"]}, "ideco": {"ngfw": {"fields": {"connected_from": "198.19.71.123", "subnet": "10.128.0.68/32", "type": "pptp", "user": "p.vlasov"}, "service": "ideco-vpn-authd"}}, "message": "Subnet 10.128.0.68/32 is authorized as user \u0027p.vlasov\u0027. Connection made from \u0027198.19.71.123\u0027, type \u0027pptp\u0027", "observer": {"hostname": "ideco-ngfw", "ip": "10.50.0.1", "product": "NGFW Novum", "vendor": "Ideco"}, "process": {"name": "ideco-vpn-authd"}, "related": {"ip": ["198.19.71.123", "10.128.0.68"], "user": ["p.vlasov"]}, "source": {"ip": "198.19.71.123"}, "user": {"name": "p.vlasov"}}
```

## Limitations

- **Traffic line:** the guide's `traffic-journal` example is cut off after `ips_pro`. The generator emits 19 of the 39 documented keys in a plausible order; NAT, user, location, cluster and VCE keys are omitted. The complete serialization cannot be confirmed against a vendor capture. The `flow_id` value format is not documented; a random 16-digit number is used.
- **fail2ban:** the guide shows a complete `Found` line and the `NOTICE [jail] Ban <ip>` body, described as the record of a block or an unblock; the `Unban` wording is inferred from it and from fail2ban. The 6 failures / 15 minutes / 45 minutes thresholds come from the [v21 guide](https://docs.ideco.ru/pdf/v21/ru-ngfw-settings-server-management-additionally.pdf) and apply to every jail, so ban durations are nearly constant (2700 s plus a few seconds).
- **VPN:** only the documented successful authorization message is produced; failed VPN authorizations are visible only through `fail2ban` `Found`. The guide documents the `pptp` type only. VPN disconnections are not modeled.
- **Record spacing:** records of one login, campaign or ban are seconds apart (the first failure or authorization follows the control connection 5 s later in median and up to about a minute at night; a `Ban` follows the sixth `Found` 3 s later in median), where a real NGFW writes a ban within milliseconds of the failure that triggers it. Timestamps have whole-second precision and are UTC; Syslog transport framing is not modeled.
- **Episodes:** with `anomaly_mode: true` each episode adds its own records, so counts of four- and five-failure VPN runs, of authorizations after failures and of VPN control connections are about one per episode higher than with `false`.
- **Rates** and failure shares are synthetic.

## Performance

About 2,400 records per second on one core: a 14-day default run (about 376,000 records) takes about 2.5 minutes.

## References

- [Ideco NGFW Novum v22: Syslog](https://docs.ideco.ru/pdf/v22/ru-ngfw-settings-services-syslog.pdf) - Syslog header, `traffic-journal` keys, `ideco-vpn-authd` and `fail2ban` messages, jail list
- [Ideco NGFW v21: additional server settings](https://docs.ideco.ru/pdf/v21/ru-ngfw-settings-server-management-additionally.pdf) - fail2ban thresholds
- No Elastic integration exists for Ideco NGFW; the ECS mapping is inferred.
