# S-Terra Gate VPN Gateway

Generates the `vpnsvc` log of one S-Terra Gate 4.1 remote-access VPN gateway as ECS JSON, for training SIEM content on Russian certified IPsec VPN telemetry. `event.original` holds the syslog line as S-Terra Gate writes it to `/var/log/cspvpngate.log` or sends it to a syslog server: BSD timestamp, host, `vpnsvc:`, the eight-digit MSG ID, the optional `<n:m>` IKE session and the message body built from the vendor template for that MSG ID. The surrounding JSON maps the template parameters to ECS and `s_terra.vpn_gate.*`. About 60 S-Terra Client users connect from eight office NAT addresses and four mobile-carrier NAT addresses.

## Event Types

Shares measured on the final default capture (78 h, `anomaly_mode: true`, 5,339 records).

| MSG ID | Vendor name | Message | Level | Share | Category |
|---|---|---|---|---:|---|
| `1000001A` | `MSG_ID_IKE_DELETION_RECV` | Received deletion for IPSec / ISAKMP connection | INFO | 27.76% (1482) | Network |
| `00100119` | `MSG_ID_LP_HOST_CONNECTED` | IPSec connection established | NOTICE | 14.09% (752) | Network |
| `0010011D` | `MSG_ID_LP_CONNECTION_CLOSED` | IPSec connection closed | NOTICE | 13.95% (745) | Network |
| `10000005` | `MSG_ID_IKE_SA_CREATED` | ISAKMP connection created | INFO | 13.94% (744) | Network |
| `10002001` | `MSG_ID_IKE_IKECFG_ASSIGNED` | IKECFG address assigned | INFO | 13.94% (744) | Network |
| `10000006` | `MSG_ID_IKE_SA_CLOSED` | ISAKMP connection closed | INFO | 13.80% (737) | Network |
| `0010011C` | `MSG_ID_LP_INCOMING_CONNECTION_FAILURE` | Incoming connection failed | ERR | 2.53% (135) | Network, Authentication |

A session is: ISAKMP connection created, IKECFG address assigned, one IPsec connection to the office network (`10.20.0.0/16`) or, for the five administrators, often one to the management network (`10.0.10.0/24`) and sometimes both; at the end the client deletes each IPsec connection and then the ISAKMP connection, and the gateway logs each closure. ISAKMP and IPsec connection numbers come from one gateway counter; exchange numbers in `<n:m>` grow per ISAKMP connection.

## Background Model

Each one-second tick emits at most one record: the earliest due line, otherwise nothing. Connection attempts arrive as one merged Poisson stream (0.003 per second) scaled by a Moscow-time office-hours factor (08:00-19:00 1.6, 19:00-23:00 0.7, night 0.25). Each arrival picks a user by a fixed random per-user weight (log-normal), so users act independently.

- A user connects from the office NAT address 80% of the time, otherwise from a mobile-carrier address; the NAT source port is random per attempt series.
- Each user has a fixed random failure propensity (log-normal, median 5%, at most 40%). A failing attempt is repeated 1-4 times (gaps log-normal, median 35 s); 75% of such series end in a session, the rest are given up.
- About twice a day a site-wide problem makes two or more users behind one office address fail 1-3 times each within minutes; 60% of them connect later.
- Session length is log-normal (median 90 min, at most 10 h); sessions of one user may overlap.
- Administrators open the management tunnel in 40% of their sessions.

Over 78 h an `anomaly_mode: false` capture holds 110-171 failures, 15-58 management tunnels, 17-28 failures for a second identity at one address within 45 minutes, 22-39 IPsec connections from an address where two identities failed in the preceding 45 minutes, and 2-5 management tunnels after a failure of one identity at the same address.

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the generator emits the background only and the complete chain never occurs.

Sequence, all from one office address P:

1. `0010011C Incoming connection failed` for identity A (1-3 times).
2. `0010011C Incoming connection failed` for another identity B (1-3 times).
3. `10000005 ISAKMP connection created`, `10002001 IKECFG address assigned` and `00100119 IPSec connection established` with `Filter IPsec:Protect:RA-MAP:20:MGMT-NET` for administrator identity C; in half of the episodes an office tunnel follows.

Linking fields: `source.ip` in all steps; `user.name` (the IKE identity) differs between steps 1 and 2; `s_terra.vpn_gate.isakmp_connection_id` and `<n:m>` link the step 3 lines. A and B are users behind P, C is an administrator whose office address is P.

Recurrence: an episode becomes due every `anomaly_interval_hours` of source time (default 24, minimum 2), first one interval after generation starts. After it is due it starts with a per-second probability proportional to the office-hours factor (mean delay 56 minutes during office hours, longer in the evening and at night). The next due time counts from the actual start, so a late episode never causes catch-up. Episodes in the final captures spanned 205-343 s at the default interval (2 episodes in 78 h, 29 h apart) and 71-807 s at 6 h (10 episodes, 6.2-11.8 h apart).

Variation: C differs from the previous episode's administrator and P from the previous address; A, B and C are picked with the background per-user weights; failure counts and gaps between failures follow the background retry law, but A and B almost always give up after failing (about 70% of background failure series continue to a later success). C's session lasts as long as a background session and ends with the same deletions and closures, so the management tunnel is visibly closed.

Detection idea: failed IKE authentication for two different identities from one address, followed within 45 minutes by a management-network tunnel from that address (identity guessing followed by administrative access). Each fragment occurs in background: repeated failures, failures of several identities at one address, successful tunnels after them, and management tunnels after a single failure. Only the complete sequence is kept out of the background: an ordinary management tunnel from an address where two different identities failed in the last 3,600 s is opened to the office network instead.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
|---|---|---|
| `anomaly_mode` | `true` | Add periodic episodes to the background |
| `anomaly_interval_hours` | `24` | Episode interval in source hours, 2-8760 |
| `gateway_host` | `vpn-gw-01` | Syslog host name and `observer.hostname` |
| `user_domain` | `contoso.example` | Domain of the USER_FQDN IKE identities |

### Output Parameters

The shipped config writes `output/events.json` with the `json` formatter and needs no `${params.*}` or `${secrets.*}`. To send events elsewhere, replace the `output` section and put destination settings behind top-level placeholders, for example:

```yaml
output:
  - opensearch:
      hosts:
        - ${params.opensearch_host}
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: s-terra-gate
```

A collector that parses S-Terra syslog needs `event.original` rather than the surrounding JSON.

## Usage

Live mode:

```bash
eventum generate --path generators/vpn-s-terra-gate/generator.yml --id s-terra-gate --live-mode true
```

Batch mode needs a bounded input: add `start` and `end` to the `cron` input, then run:

```bash
eventum generate --path generators/vpn-s-terra-gate/generator.yml --id s-terra-gate --live-mode false
```

## Limitations

- Message bodies follow the S-Terra Gate 4.1 event catalog templates; one raw line (`00100119`) from a gateway log confirms the frame. No raw example of the other MSG IDs was found.
- The catalog does not list values for the SA deletion reason of `0010011D`; `deleted by peer` is a placeholder. The optional stage and reason of `0010011C` are omitted rather than invented. Subnet notation in the traffic selector, the `RA-MAP` crypto-map names and `proxy ARP enabled` for every IKECFG address are assumptions.
- Only INFO-and-above lines of a remote-access concentrator are generated: no DEBUG exchange details, no site-to-site peers, no re-keying, no DPD or lifetime expiry, no RADIUS/XAUTH, certificate or KERNEL filter messages. Every session ends with client deletions.
- The syslog clock is UTC and the line carries no year or time zone, as in the BSD format. The office-hours curve assumes Moscow time; there is no weekday/weekend difference. One record per second at most.
- The first episode is due one interval after generation starts, so its hour depends on the start time. Rates, user counts, addresses and behavior are training assumptions, not measured production volume. No Elastic integration exists for this source, so the ECS mapping is an assumption. Compatibility with SIEM normalizers for S-Terra is not tested.
- The published raw line has two spaces between the host name and `vpnsvc:`; the pack writes one.

## Sample Output

The management tunnel that completes the first episode, copied byte for byte from the final default capture (line 1773; the failures for two identities are lines 1768-1770, the ISAKMP connection line 1771, the closures lines 1885-1890):

```json
{"@timestamp": "2026-09-22T00:49:58+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "ipsec-connection-established", "category": ["network"], "code": "00100119", "dataset": "s_terra.vpn_gate", "kind": "event", "module": "s_terra", "original": "Sep 22 00:49:58 vpn-gw-01 vpnsvc: 00100119 \u003c8801:2\u003e IPSec connection 8802 established, traffic selector 10.99.1.76-\u003e10.0.10.0/24, peer 198.51.100.14:12933, id \"n.komarova@contoso.example\", Filter IPsec:Protect:RA-MAP:20:MGMT-NET, IPsecAction IPsecAction:RA-MAP:20, IKERule IKERule:RA-MAP:10", "outcome": "success", "type": ["start", "connection"]}, "log": {"level": "notice"}, "observer": {"hostname": "vpn-gw-01", "product": "S-Terra Gate", "type": "vpn", "vendor": "S-Terra", "version": "4.1"}, "process": {"name": "vpnsvc"}, "related": {"ip": ["198.51.100.14", "10.99.1.76"], "user": ["n.komarova@contoso.example"]}, "s_terra": {"vpn_gate": {"filter": "IPsec:Protect:RA-MAP:20:MGMT-NET", "ike_id": "n.komarova@contoso.example", "ike_rule": "IKERule:RA-MAP:10", "ipsec_action": "IPsecAction:RA-MAP:20", "ipsec_connection_id": 8802, "isakmp_connection_id": 8801, "msg_id": "00100119", "msg_name": "MSG_ID_LP_HOST_CONNECTED", "section": "LP", "session_id": "\u003c8801:2\u003e", "severity": "NOTICE", "traffic_selector": "10.99.1.76-\u003e10.0.10.0/24"}}, "source": {"ip": "198.51.100.14", "port": 12933}, "user": {"name": "n.komarova@contoso.example"}}
```

## References

- [S-Terra Gate 4.1: logged event catalog](https://doc.s-terra.ru/rh_output/4.1/Gate/output/mergedProjects/Syslog/%D0%A1%D0%BF%D0%B8%D1%81%D0%BE%D0%BA_%D0%BF%D1%80%D0%BE%D1%82%D0%BE%D0%BA%D0%BE%D0%BB%D0%B8%D1%80%D1%83%D0%B5%D0%BC%D1%8B%D1%85_%D1%81%D0%BE%D0%B1%D1%8B%D1%82%D0%B8%D0%B9.htm): MSG IDs, levels, message templates and parameters.
- [S-Terra Gate 4.1: log_mgr set](https://doc.s-terra.ru/rh_output/4.1/Gate/output/mergedProjects/Syslog/log_mgr_set.htm): syslog client, facility and log levels.
- [How to troubleshoot domestic IPsec VPN, part 1 (Habr)](https://habr.com/ru/articles/514996/): raw `cspvpngate.log` line with the syslog frame.
- [Elastic ECS field reference](https://www.elastic.co/docs/reference/ecs/ecs-field-reference)
