# Cisco IOS Syslog

Generates ECS-compatible remote syslog from one Cisco IOS router, modeled on the IOS 15SY message format and the Elastic Cisco IOS log integration. Native messages cover IPv4 ACL decisions, SSH logins, configuration commands, configuration changes, and line-protocol state.

The profile assumes TCP syslog collection, the default `local7` facility, numbered messages, UTC timestamps with milliseconds, ACL entries with `log`, and configuration-change notifications enabled with `archive log config` / `notify syslog`. In `OUTSIDE_IN`, a sequence-100 logged deny blocks the controlled flow until a sequence-50 permit is inserted before it; the other modeled flows match separate pre-existing ACEs. `event.original` uses the `<PRI>sequence: device timestamp: %FACILITY-SEVERITY-MNEMONIC: text` form from the [Elastic sample event](https://github.com/elastic/integrations/blob/main/packages/cisco_ios/data_stream/log/sample_event.json); the transport peer is recorded separately in `log.source.address`. The input emits one event every five seconds.

Reference field coverage: **35/35 leaf fields** in the Elastic sample event. This is output-shape coverage, not a claim that every value or every IOS message family is modeled.

## Event Types

| Native message | Meaning | Routine selection weight |
| --- | --- | ---: |
| `%SEC-6-IPACCESSLOGP` | Logged TCP ACL decision | 96.8% |
| `%SEC_LOGIN-5-LOGIN_SUCCESS` | Successful SSH login | 1.0% |
| `%SEC_LOGIN-4-LOGIN_FAILED` | Failed SSH login | 0.8% |
| `%PARSER-5-CFGLOG_LOGGEDCMD` | Configuration command notification | 0.8% |
| `%SYS-5-CONFIG_I` | Configuration changed | 0.5% |
| `%LINEPROTO-5-UPDOWN` | Interface line-protocol transition | 0.1% |

These are synthetic selection weights for a router with ACL logging, not measured Cisco production frequencies. ACL permit/deny is determined by the selected flow, ACL, and current rule state. A flow is not randomly permitted and denied under the same unchanged ACL. Routine source ports vary so repeated `1 packet` records represent distinct flows. The pack does not simulate IOS five-minute ACL packet aggregation or rate-limit summaries.

## Anomaly Chain

The default `anomaly_mode: true` produces one intrusion sequence after 720 routine events (about one hour at the shipped rate):

1. `OUTSIDE_IN` denies TCP from `10.99.2.41:55222` to `10.50.2.15:443`.
2. Three `%SEC_LOGIN-4-LOGIN_FAILED` records for `admin` from `10.99.2.41` are followed by `%SEC_LOGIN-5-LOGIN_SUCCESS` from the same IP.
3. `%PARSER-5-CFGLOG_LOGGEDCMD` records entering `OUTSIDE_IN` and inserting `50 permit tcp host 10.99.2.41 host 10.50.2.15 eq 443 log` before the existing sequence-100 logged deny.
4. `%SYS-5-CONFIG_I` records the change; the previously denied flow is then permitted by `OUTSIDE_IN`.

The nine records span 40 seconds. Correlate on router, login user and remote IP, command text, ACL name, and the source/destination tuple before and after the change. A parser command record identifies the user but does not carry the management client's IP or a session ID; joining it to the login is a time-based inference, not a native IOS session link.

Both modes also contain a one-time ordinary ACL maintenance test after 360 routine events: `admin` temporarily inserts the same sequence-50 permit, tests the flow, re-enters the ACL, removes the permit, and sees it denied again. Failed-login bursts are absent from this maintenance sequence. Thus `admin`, the IPs, command, permit record, and deny record each appear in background; a detection must correlate the suspicious order and timing. After the anomalous change, the ACL remains open, as it would on the device until another change removes it.

Set `event.template.params.anomaly_mode: false` for background only. It still produces logins, failures, configuration commands, ACL decisions, and the ordinary maintenance test, but never the failed-login-to-permit sequence.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `router_name`, `router_ip` | `edge-ios-01`, `10.30.0.1` | Single router identity |
| `normal_user`, `normal_source_ip` | `netops`, `10.30.1.24` | Routine operator and management address |
| `anomaly_user`, `anomaly_source_ip` | `admin`, `10.99.2.41` | User and remote address shared by the intrusion sequence |
| `anomaly_target_ip`, `acl_name` | `10.50.2.15`, `OUTSIDE_IN` | Protected target and edited ACL |
| `maintenance_after_events` | `360` | Routine events before the one-time maintenance test |
| `anomaly_interval_events` | `720` | Routine events before the one-time intrusion sequence |
| `anomaly_mode` | `true` | Include the intrusion sequence; `false` emits background only |

Keep `maintenance_after_events` lower than `anomaly_interval_events` when changing both. Event counts include ordinary selections, not events inserted by the maintenance or intrusion sequences.

### Output Parameters

The shipped configuration writes to `output/events.json` locally. It has no top-level `${params.*}` or `${secrets.*}` placeholders. Change `output.file.path` or the output plugin when sending data to a SIEM.

## Usage

From the content-packs repository root, run live at one event every five seconds:

```bash
eventum generate --path generators/network-cisco-ios/generator.yml --id network-cisco-ios --live-mode true --keep-order true
```

For a bounded accelerated sample run, use:

```bash
timeout 2 eventum generate --path generators/network-cisco-ios/generator.yml --id network-cisco-ios-sample --live-mode false --keep-order true
```

The sample command ends with exit code 124 when `timeout` stops the otherwise unbounded cron source. Increase the timeout if fewer than 737 events are produced on your machine; the complete anomaly follows 720 routine events and eight maintenance events.

## Sample Output

A complete `CFGLOG_LOGGEDCMD` event from the intrusion sequence in a real enabled-mode run:

```json
{
  "@timestamp": "2026-09-25T17:40:25+00:00",
  "agent": {
    "ephemeral_id": "c0ffee00-1111-4444-8888-123456789abc",
    "id": "c0ffee00-1111-4444-8888-123456789abc",
    "name": "syslog-collector",
    "type": "filebeat",
    "version": "8.17.0"
  },
  "cisco": {
    "ios": {
      "access_list": "OUTSIDE_IN",
      "command": "50 permit tcp host 10.99.2.41 host 10.50.2.15 eq 443 log",
      "facility": "PARSER",
      "message_count": 100735
    }
  },
  "data_stream": {
    "dataset": "cisco_ios.log",
    "namespace": "default",
    "type": "logs"
  },
  "ecs": {
    "version": "8.17.0"
  },
  "elastic_agent": {
    "id": "c0ffee00-1111-4444-8888-123456789abc",
    "snapshot": false,
    "version": "8.17.0"
  },
  "event": {
    "action": "configuration-command",
    "agent_id_status": "verified",
    "category": [
      "configuration"
    ],
    "code": "CFGLOG_LOGGEDCMD",
    "dataset": "cisco_ios.log",
    "ingested": "2026-09-25T17:40:25+00:00",
    "kind": "event",
    "original": "<189>100735: Sep 25 2026 17:40:25.000 UTC: %PARSER-5-CFGLOG_LOGGEDCMD: User:admin  logged command:50 permit tcp host 10.99.2.41 host 10.50.2.15 eq 443 log",
    "provider": "firewall",
    "sequence": 100735,
    "severity": 5,
    "timezone": "+00:00",
    "type": [
      "change"
    ]
  },
  "input": {
    "type": "tcp"
  },
  "log": {
    "level": "notification",
    "source": {
      "address": "10.30.0.1:49152"
    },
    "syslog": {
      "priority": 189
    }
  },
  "message": "User:admin  logged command:50 permit tcp host 10.99.2.41 host 10.50.2.15 eq 443 log",
  "observer": {
    "hostname": "edge-ios-01",
    "ip": "10.30.0.1",
    "product": "IOS",
    "type": "router",
    "vendor": "Cisco"
  },
  "related": {
    "user": [
      "admin"
    ]
  },
  "tags": [
    "preserve_original_event",
    "cisco-ios",
    "forwarded"
  ],
  "user": {
    "name": "admin"
  }
}
```

## References and Limits

- [Cisco IOS Release 15SY Embedded Syslog Manager guide](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/esm/configuration/15-sy/esm-15-sy-book.pdf): remote TCP syslog transport.
- [Cisco IOS system message logging](https://www.cisco.com/c/en/us/td/docs/routers/access/wireless/software/guide/SysMsgLogging.html): sequence/timestamp format and default `local7` facility.
- [Cisco IOS ACL logging](https://sec.cloudapps.cisco.com/security/center/resources/access_control_list_logging.html): `IPACCESSLOGP` text, first-packet records, and five-minute aggregation.
- [Cisco IOS named ACL configuration](https://www.cisco.com/c/en/us/support/docs/security/ios-firewall/23602-confaccesslists.html): `ip access-list extended`, `permit tcp`, and `no permit` syntax.
- [Cisco IOS 15SY ACL sequence numbering](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_data_acl/configuration/15-sy/sec-data-acl-15-sy-book/sec-acl-seq-num-persistent.html): insert an ACE before a later deny.
- [Cisco IOS/IOS XE Common Criteria audit examples](https://www.cisco.com/c/dam/en_us/solutions/industries/government/security_certification/pdfs/catalyst-3850-catalyst-6500-agd.pdf): `SEC_LOGIN`, `PARSER`, `SYS`, and ACL message bodies. Examples include an IOS 15.1(2)SY3 Catalyst 6500.
- [Cisco configuration-change notification](https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/system-management/system-management/m_cm-config-logger-0.html): `archive log config` / `notify syslog` prerequisites and `CFGLOG_LOGGEDCMD` example.
- [Elastic Cisco IOS raw test records](https://github.com/elastic/integrations/blob/main/packages/cisco_ios/data_stream/log/_dev/test/pipeline/test-cisco-ios.log) and [sample event](https://github.com/elastic/integrations/blob/main/packages/cisco_ios/data_stream/log/sample_event.json): native framing and normalized field shape.

A `CFGLOG_LOGGEDCMD` record proves that a command was logged, not that the command succeeded. The template therefore omits `event.outcome` for parser and configuration notifications. Collector and ECS metadata are synthetic, based on the Elastic example. No real device, collector, or traffic is contacted.
