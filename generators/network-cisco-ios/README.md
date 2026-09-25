# Cisco IOS Syslog

Produces ECS-compatible Cisco IOS remote syslog with numbered native `%FACILITY-SEVERITY-MNEMONIC` messages, ACL decisions, login results and configuration records.

Reference field coverage: **35/35 fields in the [Elastic Cisco IOS sample event](https://github.com/elastic/integrations/blob/main/packages/cisco_ios/data_stream/log/sample_event.json). The reference is a configuration event; the pack also models ACL and login fields from the integration test lines.**

## Event Types

| Native message | Meaning | Routine weight |
| --- | --- | ---: |
| `%SEC-6-IPACCESSLOGP` | ACL denied | 55% |
| `%SEC-6-IPACCESSLOGP` | ACL permitted | 30% |
| `%SEC_LOGIN-5-LOGIN_SUCCESS` | Administrator login | 8% |
| `%SYS-5-CONFIG_I` | Configuration changed | 4% |
| `%LINEPROTO-5-UPDOWN` | Interface line state | 3% |
| `%SEC_LOGIN-4-LOGIN_FAILED`, `%PARSER-5-CFGLOG_LOGGEDCMD` | Failed login and logged commands | Anomaly only |

Routine percentages are configured selection weights, not measured vendor frequencies. One reusable Jinja template covers the FSM states; the source-specific native records are emitted alongside normalized ECS fields. The `event.sequence` and device counters are bounded.

## Anomaly Chain

Three `%SEC_LOGIN-4-LOGIN_FAILED` messages for `admin` from `10.99.2.41` are followed by `%SEC_LOGIN-5-LOGIN_SUCCESS` on the same router. With IOS configuration command logging enabled, `%PARSER-5-CFGLOG_LOGGEDCMD` records entry into ACL `OUTSIDE_IN` and a permit for TCP from that IP to `10.50.2.15:443`. `%SYS-5-CONFIG_I` follows, then `%SEC-6-IPACCESSLOGP` permits the matching flow. Correlate by router, user, source IP, ACL name and the logged command text. Rules can detect failed-to-successful admin login, an ACL permit for the login source, and the first permitted flow after that change. Command detail requires `archive log config` with `notify syslog` on a real IOS device.

`anomaly_mode: true` is the default. Set `event.template.params.anomaly_mode: false` to generate routine background only. The anomaly identities and targeted objects do not appear in background mode.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `router_name`, `router_ip` | `edge-ios-01`, `10.30.0.1` | Single router identity |
| `normal_user`, `normal_source_ip` | `netops`, `10.30.1.24` | Routine administrator |
| `anomaly_user`, `anomaly_source_ip` | `admin`, `10.99.2.41` | Chain administrator and source |
| `anomaly_target_ip`, `acl_name` | `10.50.2.15`, `OUTSIDE_IN` | Permitted target and ACL |
| `anomaly_interval_events` | `250` | Routine events between chains; counter is bounded |
| `anomaly_mode` | `true` | Include chain; `false` emits background only |

### Output Parameters

The shipped configuration writes `output/events.json` locally and needs no `${params.*}` or `${secrets.*}` overrides. Change `output.file.path` or replace the output plugin when connecting to a SIEM.

## Usage

From the content-packs repository root:

```bash
eventum generate --path generators/network-cisco-ios/generator.yml --id network-cisco-ios --live-mode true
```

Adjust the cron expression and count in `generator.yml` for a different event rate.

## Sample Output

Copied from a real enabled-mode generator run:

```json
{
  "@timestamp": "2026-09-25T14:29:44+00:00",
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
      "command": "permit tcp host 10.99.2.41 host 10.50.2.15 eq 443 log",
      "facility": "PARSER",
      "message_count": 109544,
      "sequence": "109544"
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
    "ingested": "2026-09-25T14:29:44+00:00",
    "kind": "event",
    "original": "Sep 25 14:29:44 edge-ios-01 109544: Sep 25 14:29:44.000: %PARSER-5-CFGLOG_LOGGEDCMD: User:admin logged command:permit tcp host 10.99.2.41 host 10.50.2.15 eq 443 log",
    "outcome": "success",
    "provider": "firewall",
    "sequence": 109544,
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
      "address": "10.30.0.1:514"
    },
    "syslog": {
      "priority": 189
    }
  },
  "message": "User:admin logged command:permit tcp host 10.99.2.41 host 10.50.2.15 eq 443 log",
  "observer": {
    "hostname": "edge-ios-01",
    "ip": "10.30.0.1",
    "product": "IOS",
    "type": "router",
    "vendor": "Cisco"
  },
  "related": {
    "ip": [
      "10.99.2.41",
      "10.50.2.15"
    ],
    "user": [
      "admin"
    ]
  },
  "source": {
    "ip": "10.99.2.41"
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

- [Elastic Cisco IOS raw syslog tests](https://github.com/elastic/integrations/blob/main/packages/cisco_ios/data_stream/log/_dev/test/pipeline/test-cisco-ios.log): envelope, ACL and successful-login examples.
- [Cisco IOS configuration change logging](https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/system-management/system-management/m_cm-config-logger-0.html): `%PARSER-5-CFGLOG_LOGGEDCMD` and `notify syslog`.
- [Cisco IOS system message guide](https://www.cisco.com/c/en/us/td/docs/ios/15_0sy/system/messages/15sysmg.pdf): SEC_LOGIN and SYS message formats.
- [KUMA 4.0 supported sources](https://support.kaspersky.com/kuma/4.0/en-US/255782.htm): IOS normalizer.

ACL decision records require ACL logging; command records require configuration change notification. The pack represents a device configured to emit both. A login and a later command with the same user/IP are correlated evidence, not an authenticated session ID.
