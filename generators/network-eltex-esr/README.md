# Eltex ESR Router Syslog

Generates ECS-compatible JSON for Eltex ESR-series service routers running software 1.40. `event.original` is a complete RFC 5424 remote syslog record, and `message` is the documented native `%GROUP-SEVERITY-MNEMONIC: text` body. The source is the [Eltex ESR 1.40 syslog reference](https://eltex.ru/storage/upload_center/files/53/ESR-Series_Syslog_reference_1.40.pdf). This pack uses ESR router messages; it does not reuse MES switch message codes.

No dedicated Elastic ESR integration sample and fields catalog was found. The reference map covers **58/58 selected fields**: all ten parts of the ESR remote syslog format and 48 documented parameter slots across the selected message types. Native values appear in the original line and their parsed ECS or `eltex.esr.*` counterparts. Actual ESR installations can configure different facilities and program names; this synthetic example uses `login` for AAA as in the reference, group-derived names for other subsystems, authpriv facility 10 for account/system events, and local0 facility 16 for security traffic.

## Event Types

| Native message | Generated action | Routine weight |
| --- | --- | ---: |
| `%FIREWALL-I-LOG` zone-pair permit | `firewall_permitted` | 62% |
| `%FIREWALL-I-LOG` zone-pair deny | `firewall_denied` | 20% |
| `%NAT-I-LOG` SNAT translation | `snat_translation` | 15% |
| `%IPS-I-INFO` signature drop | `ips_drop` | 1.5% |
| `%AAA-I-SSH` / `%AAA-LOCAL-I-SESSION` | Normal SSH session with open and close | 1% trigger, then three linked events |
| `%AAA-I-SSH` failed password | `ssh_password_failed` | 0.5% |

Twelve generated actions use one reusable Jinja template across the FSM states.

These are routine FSM selection weights, not measured vendor frequencies. At the default one event per two seconds, a production-like router produces mostly firewall decisions and NAT records, with less frequent IPS and administrator activity. The linked normal sessions and anomaly sequences add events to the output. Firewall/NAT traffic chooses coherent addresses, ports and interfaces from `samples/flows.json`; all records have one router identity and a bounded, increasing syslog sequence number. Firewall, NAT and IPS logging must be enabled on a real router to see those message families.

## Anomaly Chain

With `anomaly_mode: true`, after every 1,000 routine events the FSM emits this ordered sequence on the same ESR:

1. Three `%AAA-I-SSH` failed passwords for `admin` from `10.99.4.33`, followed by an accepted password and an `%AAA-LOCAL-I-SESSION` opened record.
2. `%USER-I-INFO` reports that `admin` changed the privilege-15 enable password.
3. `%USER-I-ADD` creates `svc_remote_NNN`; `%USER-I-INFO` changes that user's privilege from 5 to 14.
4. `%TIME-I-INFO` reports that `admin` changed system time, then `%AAA-I-SSH` accepts the new service account from the same unusual source.

Rules can separately detect repeated SSH failure then success from one address, a high-privilege password change after that login, new account creation followed by a privilege increase, and a new privileged account's first SSH access. The `USER` creation and privilege messages do not name the actor; only the surrounding `USER` enable-password and `TIME` messages identify `admin`. Correlation is by router, time, and account name, not proof of who executed those two account actions. Sort by `@timestamp` or `eltex.esr.sequence_number` when inspecting local sample output; asynchronous file writes may move a few adjacent lines.

Set `anomaly_mode: false` under `event.template.params` to emit only routine firewall, NAT, IPS and administrator traffic. It produces no `svc_remote_NNN` account, unusual source address, enable-password change, privilege increase or system-time change.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `router_name`, `router_ip` | `esr-edge-01`, `10.50.0.1` | One ESR router identity |
| `normal_user`, `normal_source_ip` | `netops`, `10.50.1.25` | Routine SSH administrator |
| `unusual_user`, `unusual_source_ip` | `admin`, `10.99.4.33` | Anomaly SSH identity and source |
| `service_user_prefix` | `svc_remote_` | Prefix for distinct anomaly-created accounts |
| `anomaly_interval_events` | `1000` | Routine events between chains; bounds the counter |
| `anomaly_mode` | `true` | Enable or disable the complete anomaly sequence |

### Output Parameters

The shipped configuration writes `output/events.json` under the generator directory and declares no top-level `${params.*}` or `${secrets.*}` overrides. Change `output.file.path` for another local destination, or replace the output plugin to send events to a SIEM.

## Usage

Run from the content-packs repository root:

```bash
eventum generate --path generators/network-eltex-esr/generator.yml --id esr --live-mode true
```

Change the cron expression or count in `generator.yml` to adjust the rate.

## Sample Output

This record was copied from an enabled-mode generator run:

```json
{"@timestamp": "2026-09-25T11:16:11+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "user_privilege_changed", "category": ["iam"], "dataset": "eltex.esr.syslog", "kind": "event", "module": "eltex", "original": "<86>1 2026-09-25T11:16:11+00:00 esr-edge-01 user - - - 1026: %USER-I-INFO: Privilege level of user svc_remote_001 was changed from 5 to 14", "outcome": "success", "type": ["change"]}, "message": "%USER-I-INFO: Privilege level of user svc_remote_001 was changed from 5 to 14", "log": {"level": "info", "syslog": {"priority": 86, "facility": {"code": 10}, "severity": {"code": 6}, "appname": "user", "version": "1"}}, "observer": {"hostname": "esr-edge-01", "ip": "10.50.0.1", "name": "esr-edge-01", "product": "ESR", "type": "router", "vendor": "Eltex"}, "eltex": {"esr": {"group": "USER", "mnemonic": "INFO", "severity_code": "I", "sequence_number": 1026, "details": {"privilege": {"new": 14, "old": 5}}}}, "user": {"target": {"name": "svc_remote_001"}}}
```

## Reference and Limits

- [Eltex ESR-series Syslog Reference, software 1.40](https://eltex.ru/storage/upload_center/files/53/ESR-Series_Syslog_reference_1.40.pdf): RFC 5424 envelope and native AAA, USER, TIME, firewall, NAT and IPS patterns.
- [Eltex ESR-Series quick guide](https://eltex.ru/storage/upload_center/files/35/ESR-Series_Quick_guide_1.18.1_en.pdf): external syslog collection recommendations and security logging context. The generator's message codes follow the newer 1.40 reference.
- [Elastic ECS field reference](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html): normalized field names.

The RFC 5424 program names and facilities outside the documented `login` example are synthetic configuration choices. The sequence number is bounded at 2,147,483,647. The generator does not imply that the syslog line alone proves which SSH session caused a user-change event, and it does not model a device-wide configuration commit for the account changes.
