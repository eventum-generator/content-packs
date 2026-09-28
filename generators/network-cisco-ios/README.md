# Cisco IOS Syslog

Generates remote syslog from one Cisco IOS router as the Elastic Cisco IOS integration stores it: ACL decisions, SSH logins, configuration commands and changes, and interface line-protocol changes. It is intended for SIEM content that correlates access-list changes with administrator logins.

The profile is a router that sends to a TCP syslog collector with the default `local7` facility, message counters (`service sequence-numbers`), UTC timestamps with milliseconds and year (`service timestamps log datetime msec year`), logged ACEs, SSH login logging (`login on-failure log`, `login on-success log`) and configuration logging (`archive log config` / `notify syslog`). `event.original` has the frame of the Elastic sample event, `<PRI>count: Mon dd yyyy HH:MM:SS.mmm: %FACILITY-SEVERITY-MNEMONIC: text`. The other fields are the ones the integration's ingest pipeline produces for each message: ACL records carry the access list, the five-tuple, `event.action` `deny`/`allow` and a Community ID; `LOGIN_SUCCESS` carries the user, source address and port 22; `LOGIN_FAILED`, `CFGLOG_LOGGEDCMD`, `CONFIG_I` and `UPDOWN` are not parsed further by the pipeline and carry only `message`.

The network model: `OUTSIDE_IN` (the `acl_name` parameter) permits the server services in `samples/services.json` and ends with a logged deny (ACE 100), so client applications that try the management servers `10.50.2.15`-`10.50.2.19` on 443 are denied. Administrators occasionally insert a temporary `host`-to-`host` permit ahead of ACE 100 and remove it later with `no <sequence>`. `EDGE_FILTER` denies unsolicited internet connections to the outside address `192.0.2.10`.

## Event Types

Shares measured in a 73-hour default capture with `anomaly_mode: true` (42,510 events).

| Message | Category | Content | Share |
| --- | --- | --- | ---: |
| `%SEC-6-IPACCESSLOGP` `OUTSIDE_IN` permitted | network | Client connection to a permitted service, or to a management server while a temporary permit exists | 80.03% |
| `%SEC-6-IPACCESSLOGP` `EDGE_FILTER` denied | network | Internet probe of the outside address | 12.58% |
| `%SEC-6-IPACCESSLOGP` `OUTSIDE_IN` denied | network | Management-server retries and connections to closed ports | 6.44% |
| `%SEC_LOGIN-5-LOGIN_SUCCESS` | network | SSH login of an administrator or the config backup account | 0.34% |
| `%PARSER-5-CFGLOG_LOGGEDCMD` | network | Logged configuration command | 0.27% |
| `%SYS-5-CONFIG_I` | network | Configuration change from a vty session | 0.15% |
| `%SEC_LOGIN-4-LOGIN_FAILED` | network | Failed SSH login | 0.15% |
| `%LINEPROTO-5-UPDOWN` | network | Interface line protocol down or up | 0.05% |

`event.category` is `network` for every message, as the pipeline sets it. Rates are synthetic, not measured Cisco production frequencies. Background activity is a set of independent random processes: business connections that follow a UTC working-hours curve, per-pair retries of management servers, internet probes in short bursts, sessions of six administrators (`samples/admins.json`) with random arrival times, mistyped passwords (one to five failures, sometimes giving up), configuration commands, temporary permits held for a lognormal time (median 45 minutes) and removed by any administrator, a config backup account (`oxidized`) that polls at random intervals and sometimes fails three times in a row, and occasional interface flaps. An ACL decision always follows the current rule set. Source ports are random; the same first-packet record is not repeated for one ACL, action and five-tuple inside the five-minute log interval.

## Anomaly Chain

With `anomaly_mode: true` (default) an episode repeats every `anomaly_interval_hours` (default 24, minimum 4). One administrator workstation is used throughout:

1. `OUTSIDE_IN` denies the workstation's connection to its management server on 443.
2. Three to five `LOGIN_FAILED` for the workstation owner's account from that address, then `LOGIN_SUCCESS`.
3. `CFGLOG_LOGGEDCMD` records `ip access-list extended OUTSIDE_IN` and `<seq> permit tcp host <workstation> host <server> eq 443 log`; `CONFIG_I` follows from the same address.
4. `OUTSIDE_IN` permits the workstation's connection to that server on 443.

Linking fields: the workstation address (`source.ip` of the flows, `[Source: ]` in the login messages, the address in `CONFIG_I`), the server (`destination.ip`) and the ACE text. The whole chain takes a few minutes and always completes within 30 minutes of the denied connection. The permit is later removed like any temporary permit: an administrator logs in, logs `no <seq>`, `CONFIG_I` follows, and later connections of the pair are denied again.

Recurrence: the first episode starts within the first min(interval, 24 h) of the run, at an hour weighted by the square of the administrator activity curve. Each later episode starts in a window of min(interval / 4, 6 h) centred one interval after the previous actual start, weighted the same way, plus a random delay of about a minute. Missed episodes are not replayed. At intervals of 8 hours or less the start times necessarily cover night hours. The workstation differs from the previous episode's and is chosen with the background session weights; the failure count, gaps between steps, ACE sequence number and removal follow the background distributions.

Every action, address, account, workstation-to-server pair and account-to-address pair of the chain also occurs in ordinary background, in both modes: denied retries to the same server, typo failures and give-ups, the backup account's failure runs, self-granted and other temporary permits, and permitted connections while those exist. Only the complete ordered sequence within 30 minutes is kept out of the background: if a background permitted connection would complete it, that connection is not logged. Detection idea: per source address, a denied connection to a server on 443, at least three failed logins and a successful login, a configuration change, and a permitted connection to the same server within 30 minutes.

Set `anomaly_mode: false` for background only; that mode never contains the complete chain.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `router_ip` | `10.30.0.1` | Router address; the collector peer in `log.source.address` |
| `acl_name` | `OUTSIDE_IN` | Name of the edited ACL protecting the servers |
| `anomaly_mode` | `true` | Include the anomaly chain; `false` emits background only |
| `anomaly_interval_hours` | `24` | Hours between episode starts, 4 to 8760 |

Administrators, clients, services and restricted pairs come from `samples/admins.json`, `samples/clients.json`, `samples/services.json` and `samples/restricted.json`. An administrator entry has `user`, `ip` (workstation), `weight` (session rate) and `target` (a management server the workstation retries on 443).

### Output Parameters

The shipped output writes JSON lines to `output/events.json`. Replace the `output` section, for example with an `opensearch` or `tcp` output, to send events elsewhere; the configuration has no `${params.*}` or `${secrets.*}` placeholders.

## Usage

Live, one tick per second:

```bash
eventum generate --path generators/network-cisco-ios/generator.yml --id network-cisco-ios --live-mode true
```

Finite sample mode: add `start` and `end` to the `cron` input (for example `start: "2026-09-25T00:00:00+00:00"` and `end: "2026-09-28T01:00:00+00:00"`, which contains at least two default episodes), then run:

```bash
eventum generate --path generators/network-cisco-ios/generator.yml --id network-cisco-ios --live-mode false --keep-order true
```

## Sample Output

The permit command of an episode, a line from a real default run:

```json
{"@timestamp": "2026-09-25T11:37:42.893Z", "agent": {"ephemeral_id": "960a0fda-a7b7-4362-9018-34b1d0d119c4", "id": "f00ff835-626e-4a18-a8a2-0bb3ebb7503f", "name": "syslog-collector", "type": "filebeat", "version": "8.17.0"}, "cisco": {"ios": {"facility": "PARSER", "message_count": 1827406}}, "data_stream": {"dataset": "cisco_ios.log", "namespace": "default", "type": "logs"}, "ecs": {"version": "8.17.0"}, "elastic_agent": {"id": "f00ff835-626e-4a18-a8a2-0bb3ebb7503f", "snapshot": false, "version": "8.17.0"}, "event": {"agent_id_status": "verified", "category": ["network"], "code": "CFGLOG_LOGGEDCMD", "dataset": "cisco_ios.log", "ingested": "2026-09-25T11:37:43Z", "original": "<189>1827406: Sep 25 2026 11:37:42.893: %PARSER-5-CFGLOG_LOGGEDCMD: User:admin  logged command:90 permit tcp host 10.30.1.31 host 10.50.2.16 eq 443 log", "provider": "firewall", "sequence": 1827406, "severity": 5, "timezone": "+00:00", "type": ["info"]}, "input": {"type": "tcp"}, "log": {"level": "notification", "source": {"address": "10.30.0.1:29659"}, "syslog": {"priority": 189}}, "message": "User:admin  logged command:90 permit tcp host 10.30.1.31 host 10.50.2.16 eq 443 log", "observer": {"product": "IOS", "type": "router", "vendor": "Cisco"}, "tags": ["preserve_original_event", "cisco-ios", "forwarded"]}
```

## Limitations

- Only first-packet `IPACCESSLOGP` records are produced; five-minute aggregated counts, `IPACCESSLOGRL` rate-limit summaries and other protocols are not modeled. At most one message is emitted per second.
- The message counter skips random values to stand for messages outside the modeled families (for example SSH or logout messages).
- Collector metadata (`agent`, `elastic_agent`, `data_stream`, `log.source.address`, `event.ingested` truncated to seconds) is synthetic, patterned on the Elastic sample event. Output was checked against the pipeline source, not by running the pipeline.
- The `CONFIG_I` user/vty/address form comes from the Elastic sample and a device capture without an IOS version; full raw parity with one IOS release is not established.
- Command records name the user but not the session; joining them to a login is time-based.

## References

- [Elastic Cisco IOS sample event](https://github.com/elastic/integrations/blob/main/packages/cisco_ios/data_stream/log/sample_event.json), [ingest pipeline](https://github.com/elastic/integrations/blob/main/packages/cisco_ios/data_stream/log/elasticsearch/ingest_pipeline/default.yml) and [raw test records](https://github.com/elastic/integrations/blob/main/packages/cisco_ios/data_stream/log/_dev/test/pipeline/test-cisco-ios.log)
- [Cisco IOS system message logging](https://www.cisco.com/c/en/us/td/docs/routers/access/wireless/software/guide/SysMsgLogging.html): message format, sequence numbers, `local7`
- [Cisco IOS ACL logging](https://sec.cloudapps.cisco.com/security/center/resources/access_control_list_logging.html): `IPACCESSLOGP` first-packet and five-minute behavior
- [Cisco IOS 15SY IP access list sequence numbering](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_data_acl/configuration/15-sy/sec-data-acl-15-sy-book/sec-acl-seq-num-persistent.html): inserting and removing numbered entries
- [Cisco IOS/IOS XE Common Criteria guide](https://www.cisco.com/c/dam/en_us/solutions/industries/government/security_certification/pdfs/catalyst-3850-catalyst-6500-agd.pdf): `SEC_LOGIN`, `PARSER` and `SYS` message bodies
- [Cisco configuration change notification and logging](https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/system-management/system-management/m_cm-config-logger-0.html): `CFGLOG_LOGGEDCMD`
- [Cisco IOS 15SY embedded management components](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipv6_nman/configuration/15-sy/ip6n-15-sy-book/ip6-emb-mgmt.html): `logging host ... transport tcp`
