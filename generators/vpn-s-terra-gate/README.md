# S-Terra Gate VPN Gateway

Generates the `vpnsvc` log of one S-Terra Gate 4.1 remote-access VPN gateway as ECS JSON, for training SIEM content on Russian certified IPsec VPN telemetry. `event.original` holds the syslog line as S-Terra Gate writes it to `/var/log/cspvpngate.log` or sends it to a syslog server: BSD timestamp, host, `vpnsvc:`, the eight-digit MSG ID, the optional `<n:m>` IKE session and the message body built from the vendor template for that MSG ID. The surrounding JSON maps the template parameters to ECS and `s_terra.vpn_gate.*`. About 2,000 S-Terra Client users in 40 branch offices connect from their office NAT address or from mobile-carrier NAT pools.

## Event Types

Shares measured on a 96-hour default output (`anomaly_mode: true`, 159,138 records, about 39,800 per day).

| MSG ID | Vendor name | Message | Level | Share | Category |
|---|---|---|---|---:|---|
| `1000001A` | `MSG_ID_IKE_DELETION_RECV` | Received deletion for IPSec / ISAKMP connection | INFO | 28.11% (44,736) | Network |
| `00100119` | `MSG_ID_LP_HOST_CONNECTED` | IPSec connection established | NOTICE | 14.20% (22,597) | Network |
| `0010011D` | `MSG_ID_LP_CONNECTION_CLOSED` | IPSec connection closed | NOTICE | 14.12% (22,478) | Network |
| `10000005` | `MSG_ID_IKE_SA_CREATED` | ISAKMP connection created | INFO | 14.06% (22,378) | Network |
| `10002001` | `MSG_ID_IKE_IKECFG_ASSIGNED` | IKECFG address assigned | INFO | 14.06% (22,378) | Network |
| `10000006` | `MSG_ID_IKE_SA_CLOSED` | ISAKMP connection closed | INFO | 13.99% (22,258) | Network |
| `0010011C` | `MSG_ID_LP_INCOMING_CONNECTION_FAILURE` | Incoming connection failed | ERR | 1.45% (2,313) | Network, Authentication |

A session is: ISAKMP connection created, IKECFG address assigned, one IPsec connection to the office network (`10.20.0.0/16`) or, for the 20 administrators, usually one to the management network (`10.0.10.0/24`) and sometimes both; at the end the client deletes each IPsec connection and then the ISAKMP connection, and the gateway logs each closure. The opening lines of a session are 0-3 s apart. ISAKMP and IPsec connection numbers come from one gateway counter; exchange numbers in `<n:m>` grow per ISAKMP connection. IKECFG addresses come from `10.99.0.0/21` and are never held by two open sessions at once.

## Volume and Behavior

Volume follows Moscow office hours (UTC+3); the syslog clock is UTC. Lines per second by Moscow hour:

| Moscow time | Lines/s |
|---|---:|
| 00:00-07:00 | 0.12 |
| 07:00-08:00, 20:00-21:00 | 0.38 |
| 08:00-09:00, 18:00-19:00 | 0.55 |
| 09:00-18:00 | 0.80 |
| 19:00-20:00 | 0.45 |
| 21:00-22:00 | 0.30 |
| 22:00-23:00 | 0.22 |
| 23:00-24:00 | 0.16 |

The daily volume varies by about 3%. About 5,600 sessions start per day and up to about 900 are open at once in office hours.

- Each user has a fixed activity level: busier users connect more often and hold shorter sessions (median about 40-150 minutes, at most 8 hours). A user has at most one attempt or session at a time.
- A user connects from the office NAT address 80% of the time, otherwise from one address of their mobile carrier's pool; the NAT source port is random per attempt and not reused while the attempt is open.
- Each user has a fixed failure propensity (median 4%). 5.4% of connection attempts fail: once in 45% of failing attempts, twice in 30%, three times in 15%, four times in 10% (gaps median 35 s); 75% of them end in a session, the rest are given up.
- One or two times a day a site-wide problem makes two or more users behind one office address fail 1-3 times each within minutes; 60% of them connect later.
- Administrators open the management tunnel in 80% of their sessions, half of those together with the office tunnel.

Per day ordinary traffic holds about 60-75 failures of a second identity at an address within 45 minutes of another identity's failure, about 250-280 tunnels opened from an address where two identities failed in the preceding 45 minutes, and about 25 management tunnels after one identity's failure at the same address.

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the output holds ordinary traffic only and the complete chain never occurs.

Sequence, all from one branch office address P within 45 minutes:

1. `0010011C Incoming connection failed` for identity A (1-4 times).
2. `0010011C Incoming connection failed` for another identity B (1-4 times).
3. `10000005 ISAKMP connection created`, `10002001 IKECFG address assigned` and `00100119 IPSec connection established` with `Filter IPsec:Protect:RA-MAP:20:MGMT-NET` for administrator identity C; in half of the episodes an office tunnel follows.

Linking fields: `source.ip` in all steps; `user.name` (the IKE identity) differs between steps 1 and 2; `s_terra.vpn_gate.isakmp_connection_id` and `<n:m>` link the step 3 lines. A and B are users of the branch behind P, C is an administrator of that branch.

Recurrence: the first episode starts within min(`anomaly_interval_hours`, 24 h) of the start of the output, at an hour drawn from the volume curve. Each later episode is due `anomaly_interval_hours` after the actual start of the previous one (default 24, minimum 2) and starts within a window of min(interval / 4, 6 h) centred on the due time, at an hour weighted towards office hours. A late episode never causes catch-up; rarely, when no suitable users are free, an episode is not written and the next one follows an interval later. An episode usually spans 1-29 minutes from A's first failure to C's tunnel (median 6, at most 40); B's first failure follows A's last one after 7 s to 6 minutes (median 1), and C's tunnel follows B's last failure after 26 s to 23 minutes (median 3).

Variation: C differs from the previous episode's administrator and P from the previous address. C and the branch are picked by the ordinary activity levels among administrators who are not connected at that moment; A and B are picked among the busier users of the branch who are not connected, so each of them connects from P at least a few times a day. Failure counts, gaps and the chance of a later successful session for A and B follow the ordinary failure law; C's session lasts as long as an ordinary administrator session and ends with the same deletions and closures, so the management tunnel is visibly closed.

Detection idea: failed IKE authentication for two different identities from one address, followed within 45 minutes by a management-network tunnel from that address (identity guessing followed by administrative access). Each fragment occurs in ordinary traffic: repeated failures, failures of several identities at one address, successful tunnels after them, and management tunnels after a single failure. Only the complete sequence is kept out of ordinary traffic: an administrator's management tunnel from an address where two different identities failed in the preceding 45 minutes is opened to the office network instead (a few times in four days).

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
|---|---|---|
| `anomaly_mode` | `true` | Add periodic episodes to ordinary traffic |
| `anomaly_interval_hours` | `24` | Episode interval in source hours, 2-8760 |
| `gateway_host` | `vpn-gw-01` | Syslog host name and `observer.hostname` |
| `user_domain` | `contoso.example` | Domain of the USER_FQDN IKE identities |

### Samples

The estate lives in `samples/` and can be edited:

| File | Columns | Content |
|---|---|---|
| `users.csv` | `login`, `site`, `role` | 2,000 IKE identities (local part), their branch office and role (`user` or `admin`) |
| `sites.csv` | `site`, `address` | 40 branch offices and their NAT addresses |
| `carriers.csv` | `carrier`, `address` | NAT addresses of four mobile carriers |

Every branch with administrators needs several ordinary users besides them. The volume curve is set in `patterns/`: each file adds lines per second for a range of the day.

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

In live mode a record reaches the output after its own timestamp: under a minute in office hours, up to about 4 minutes at night and up to about 9 minutes around midnight Moscow time. Timestamps stay in order; live detection rules should look back at least 10 minutes.

Batch mode needs a finite window: in every file under `patterns/` set `oscillator.start` to the first day of the window at midnight and `oscillator.end` to its end instead of `never`, then run:

```bash
eventum generate --path generators/vpn-s-terra-gate/generator.yml --id s-terra-gate --live-mode false
```

Performance: about 3,300 events/s in batch mode (14 days, 556,608 lines, in 168 s).

## Limitations

- Message bodies follow the S-Terra Gate 4.1 event catalog templates; one raw line (`00100119`) from a gateway log confirms the frame. No raw example of the other MSG IDs was found.
- The catalog does not list values for the SA deletion reason of `0010011D`; `deleted by peer` is a placeholder. The optional stage and reason of `0010011C` are omitted rather than invented. Subnet notation in the traffic selector, the `RA-MAP` crypto-map names and `proxy ARP enabled` for every IKECFG address are assumptions.
- Only INFO-and-above lines of a remote-access concentrator are generated: no DEBUG exchange details, no site-to-site peers, no re-keying, no DPD or lifetime expiry, no RADIUS/XAUTH, certificate or KERNEL filter messages. Every session ends with client deletions.
- The line carries no year or time zone, as in the BSD format. The office-hours curve assumes Moscow time; there is no weekday/weekend difference.
- With `anomaly_mode: true` each episode adds its own records, so counts of the chain parts (failures of two identities at one address, management tunnels after failures) are about one per episode higher than with `false`.
- Rates, user counts, addresses and behavior are training assumptions, not measured production volume. No Elastic integration exists for this source, so the ECS mapping is an assumption. Compatibility with SIEM normalizers for S-Terra is not tested.
- The published raw line has two spaces between the host name and `vpnsvc:`; the pack writes one.

## Sample Output

The management tunnel that completes the first episode of the 96-hour default output (line 2895; the failures of the two identities are lines 2786-2839 and 2719-2739, the ISAKMP connection and IKECFG lines 2893-2894):

```json
{"@timestamp": "2026-09-21T04:50:33+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "ipsec-connection-established", "category": ["network"], "code": "00100119", "dataset": "s_terra.vpn_gate", "kind": "event", "module": "s_terra", "original": "Sep 21 04:50:33 vpn-gw-01 vpnsvc: 00100119 \u003c5504:2\u003e IPSec connection 5505 established, traffic selector 10.99.2.39-\u003e10.0.10.0/24, peer 203.0.113.177:52883, id \"n.efimov@contoso.example\", Filter IPsec:Protect:RA-MAP:20:MGMT-NET, IPsecAction IPsecAction:RA-MAP:20, IKERule IKERule:RA-MAP:10", "outcome": "success", "type": ["start", "connection"]}, "log": {"level": "notice"}, "observer": {"hostname": "vpn-gw-01", "product": "S-Terra Gate", "type": "vpn", "vendor": "S-Terra", "version": "4.1"}, "process": {"name": "vpnsvc"}, "related": {"ip": ["203.0.113.177", "10.99.2.39"], "user": ["n.efimov@contoso.example"]}, "s_terra": {"vpn_gate": {"filter": "IPsec:Protect:RA-MAP:20:MGMT-NET", "ike_id": "n.efimov@contoso.example", "ike_rule": "IKERule:RA-MAP:10", "ipsec_action": "IPsecAction:RA-MAP:20", "ipsec_connection_id": 5505, "isakmp_connection_id": 5504, "msg_id": "00100119", "msg_name": "MSG_ID_LP_HOST_CONNECTED", "section": "LP", "session_id": "\u003c5504:2\u003e", "severity": "NOTICE", "traffic_selector": "10.99.2.39-\u003e10.0.10.0/24"}}, "source": {"ip": "203.0.113.177", "port": 52883}, "user": {"name": "n.efimov@contoso.example"}}
```

## References

- [S-Terra Gate 4.1: logged event catalog](https://doc.s-terra.ru/rh_output/4.1/Gate/output/mergedProjects/Syslog/%D0%A1%D0%BF%D0%B8%D1%81%D0%BE%D0%BA_%D0%BF%D1%80%D0%BE%D1%82%D0%BE%D0%BA%D0%BE%D0%BB%D0%B8%D1%80%D1%83%D0%B5%D0%BC%D1%8B%D1%85_%D1%81%D0%BE%D0%B1%D1%8B%D1%82%D0%B8%D0%B9.htm): MSG IDs, levels, message templates and parameters.
- [S-Terra Gate 4.1: log_mgr set](https://doc.s-terra.ru/rh_output/4.1/Gate/output/mergedProjects/Syslog/log_mgr_set.htm): syslog client, facility and log levels.
- [How to troubleshoot domestic IPsec VPN, part 1 (Habr)](https://habr.com/ru/articles/514996/): raw `cspvpngate.log` line with the syslog frame.
- [Elastic ECS field reference](https://www.elastic.co/docs/reference/ecs/ecs-field-reference)
