# Eltex ESR Router Syslog

Generates selected Eltex ESR-series software 1.40 remote syslog records as ECS JSON. `event.original` holds the RFC 5424 frame and `message` the documented `%GROUP-SEVERITY-MNEMONIC: text` body. The source is one router with local SSH administrators and a small fixed IPv4 traffic inventory. ESR router codes are distinct from the MES switch source.

## Event Types

| Native message / generated action | Ordinary behavior | Category |
|---|---|---|
| `%FIREWALL-I-LOG` / `firewall_permitted` | Logged fixed permitted rule | Network |
| `%FIREWALL-I-LOG` / `firewall_denied` | Logged fixed denied rule | Network |
| `%NAT-I-LOG` / `snat_translation` | SNAT of permitted IPv4 traffic | Network |
| `%IPS-I-INFO` / `ips_drop` | Selected native ICMP drop signature | Intrusion detection |
| `%AAA-I-SSH` / `ssh_password_failed` | Isolated failed attempt followed by success | Authentication |
| `%AAA-I-SSH` / `ssh_password_accepted` | Existing administrator or applied temporary account | Authentication |
| `%AAA-LOCAL-I-SESSION` / `session_opened` | Open after accepted SSH authentication | Authentication |
| `%AAA-LOCAL-I-SESSION` / `session_closed` | Close the existing selected session | Authentication |
| `%USER-I-ADD` / `user_created` | Create the currently absent temporary alias | IAM |
| `%USER-I-ADD` / `user_removed` | Remove the currently existing temporary alias | IAM |
| `%USER-I-INFO` / `user_privilege_changed` | Existing default privilege 1 changes to 14 | IAM |
| `%USER-I-INFO` / `enable_password_changed` | Privilege15 enable-password maintenance | IAM/configuration |
| `%SYS-W-EVENT` / `configuration_applied` | Apply the pending configuration | Configuration |
| `%TIME-I-INFO` / `system_time_changed` | Administrator clock maintenance | Configuration |

One stateful renderer shares the native envelope across fourteen actions. All actions, both administrators/IPs and all three temporary aliases occur outside the dense sequence in both modes. No emitted field labels an episode.

The input emits one record every ten seconds, 8640 records/day. Network-only slots choose permit/deny/SNAT/IPS with weights 620:200:150:15. Administrative workflows replace some slots. These rates and the maintenance-intensive account rotation are selected training assumptions, not vendor production measurements. Four fictional flow records retain addresses, ports, interfaces and NAT mappings. Rules 10/20/30 permit and 40 denies throughout capture. NAT/IPS selections use permitted candidates; no unchanged matching rule randomly switches its action. Firewall, NAT and IPS logging must be enabled on a real router.

## Anomaly Chain

`anomaly_mode` defaults to `true`. An episode becomes eligible every 24 source hours, first after one interval:

1. The second existing administrator makes three failed password attempts, then authenticates and opens an SSH session from the same address/port.
2. That administrator changes the privilege 15 enable password. A currently absent temporary alias is created at the documented default privilege 1, then changed to 14.
3. `%SYS-W-EVENT` reports successful application of the pending configuration. `%TIME-I-INFO` identifies the administrator who changes system time.
4. The applied temporary account authenticates from the same IP with a different TCP source port, opens and closes its session, then the administrator session closes.

Fourteen core records span **130 seconds**. The next due time starts at the actual first failure, without catch-up bursts. An existing temporary account is visibly removed and that deletion applied before another episode starts. Ordinary removal of an injected account becomes eligible one hour after creation. Queued workflows finish before another begins, so eligibility may wait.

The three-name pool rotates independently for ordinary creation and episodes. A name can be reused after visible removal/application. Fresh SSH source ports and router/time/native sequence distinguish its observed incarnations. The source publishes no native user UUID or SSH session identifier here, so none is invented. Accepted/open/close context is modeled consistently, but the session-only lines do not themselves contain a remote address.

Detection ideas: three failed passwords followed by success for the same account/source; enable-password maintenance and a new privilege 14 account in one short router window; first SSH use after visible account creation/application. USER create/privilege/remove bodies name only the target, so the surrounding administrator session supports contextual correlation, not proof of the command actor. The time-change body contains no old/new clock values. It does not establish clock rollback or evasion, and the selected source clock remains UTC and ordered.

`anomaly_mode: false` retains the same accounts, IPs, actions and alias family. Ordinary maintenance creates/applies an account and tests SSH at default privilege 1, raises its privilege in a later hourly session, uses it separately, and eventually removes/applies the deletion. Enable-password/time maintenance occurs in another short session. The complete three-failure/privileged-new-account sequence is absent. Every ordinary alias is actually created and authenticated, rather than appearing only as a cleanup target.

## Source Profile and Limits

Both existing administrators have privilege 15 and configured local-password SSH rights. The selected lockout policy is the documented default five-attempt threshold and 300-second lock duration; isolated ordinary failure resets on success and an episode stops at three failures. Every candidate user/privilege change becomes usable only after its visible application. Service SSH closes before administrator logout/removal. State retains one temporary account, at most two live session contexts, one queue capped at fourteen actions, two modulo 3 cursors and scalar clocks/counters. A finite run may leave one existing account awaiting future cleanup; no final invisible reset is fabricated.

The source's CLI `commit` must be confirmed within 600 seconds or the configuration rolls back. This profile **assumes timely confirmation outside the selected message subset**. The syslog catalog's CLI commit/confirm patterns literally contain `console`; an exact SSH command-input form was not established. The generator omits those CLI records rather than changing that literal and presenting it as a captured SSH format. `Configuration is applied` therefore does not itself prove permanent confirmation. The sampled ordering of USER changes before application is a selected lifecycle model, not a captured complete device trace.

The vendor reference has a complete remote AAA-LOCAL example and field-complete selected body patterns. All ten selected remote-frame slots and the session access/user slots are represented; other message bodies preserve their documented parameters. This is format-slot coverage, not a 58/58 realism score or a full live-wire comparison. No matching maintained Elastic ESR sample was established.

Sequence numbers are enabled in the selected profile and bounded at 2147483647. AAA program `login`/authpriv comes from the vendor example. Group-derived programs/local0 for other families are explicitly inferred selected bindings, without a complete native multi-family capture proving them. UTC second precision, immediate normalization and global sequence allocation are configuration/collector assumptions. Native `%SYS-W-EVENT` severity is warning even for successful application. ICMP IPS suffixes 2048/0 are preserved privately, with no TCP/UDP ECS-port or unproved ICMP-type interpretation.

IPv6, console/Telnet, public-key authentication, AAA backends, password-expiry events, configuration rollback/timer records and complete traffic/session lifecycles are outside this subset. Exact full native capture, subsystem facility bindings and live SIEM-parser parity remain unverified.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
|---|---|---|
| `router_name` | `esr-edge-01` | One router hostname |
| `router_ip` | `10.50.0.1` | Selected management destination |
| `normal_user` | `netops` | Existing privilege 15 administrator |
| `normal_source_ip` | `10.50.1.25` | First administrator client |
| `unusual_user` | `admin` | Second existing administrator, also ordinary |
| `unusual_source_ip` | `10.99.4.33` | Second client, also ordinary |
| `service_user_prefix` | `svc_remote_` | Three fixed aliases with 001/002/003 suffixes |
| `anomaly_mode` | `true` | Periodic episodes mixed with background |
| `anomaly_interval_hours` | `24` | Finite value from 6 to 8760 hours |

Names use ASCII letters, digits, underscore/hyphen, start with a letter and have at most 31 characters including suffixes. Administrators and generated aliases must be distinct. Router hostname is an ASCII label up to 64 characters; management/client addresses are IPv4. Traffic/rule mappings in `samples/flows.json` are a separate fixed inventory. Keep its permitted and denied candidates consistent. Keep count 1/ten-second cadence for documented episode timing.

### Output Parameters

The shipped generator writes `output/events.json` and requires no top-level `${params.*}` or `${secrets.*}` values. Change the file path or replace the output plugin to send this selected normalized JSON to a SIEM. Exact native parsing still requires a real source capture.

## Usage

From the content-packs repository root:

```bash
uv run --project ../eventum eventum generate --path generators/network-eltex-esr/generator.yml --id esr --live-mode true
```

For a finite batch, copy the config beside the original, set ISO 8601 cron `start`/`end`, then run that path with `--live-mode false --keep-order true -vv`. Batch mode alone does not bound an open-ended input. For example, 2026-09-26T00:00:00Z to 2026-09-29T04:20:00Z covers 76h20 and three daily sequences. Custom input with Moscow offsets still produces source UTC. Check nonempty output and error logs as well as exit status. Serialize Eventum/Node validation with `flock -x /tmp/eventum-generator-heavy.lock`.

## Validation

An independent native/state checker verified five fresh finite outputs, all generation exit 0 and no error log:

| Capture | Hours | Records | Complete sequences | Create/remove |
|---|---:|---:|---:|---|
| Default on |76h20|27481|3|16/15|
| Default off |76h20|27481|0|13/12|
| Custom on, 12h interval |76h20|27481|6|19/18|
| Custom off |76h20|27481|0|13/12|
| Minimum 6h interval |100h20|36121|16|33/32|

All 14 actions and all three actual ordinary creation/authentication identities occur outside episodes, with zero policy contradictions, at most two sessions and one valid existing tail account. Checks cover native bodies/frame, UTC/source cadence, candidate application, before-state privilege/deletion, matching SSH lifecycles, simultaneous source-port distinction and recurrence. Native-consistent negative captures reject wrong old privilege, SSH before application, removal of an absent alias and identical live TCP tuples.

The unmodified original 388238b model was separately generated for 80 minutes: 2401 records had 2360 one-second gaps and 40 sixty-one-second gaps, not steady two-second cadence. Two old chains created accounts without removals/application, opened administrator sessions without closing them, and accepted service authentication without open/close. Intermediate fixes that still produced static alias discrimination were rejected; only the fresh final snapshot above is reviewed.

## Sample Output

The complete privilege-change record below was copied from the first final default-enabled episode. Its USER body has no command actor:

```json
{
  "@timestamp": "2026-09-27T00:01:10+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "user_privilege_changed",
    "category": [
      "iam"
    ],
    "dataset": "eltex.esr.syslog",
    "kind": "event",
    "module": "eltex",
    "original": "<134>1 2026-09-27T00:01:10+00:00 esr-edge-01 user - - - 8648: %USER-I-INFO: Privilege level of user svc_remote_001 was changed from 1 to 14",
    "outcome": "success",
    "type": [
      "change"
    ]
  },
  "message": "%USER-I-INFO: Privilege level of user svc_remote_001 was changed from 1 to 14",
  "log": {
    "level": "info",
    "syslog": {
      "priority": 134,
      "facility": {
        "code": 16
      },
      "severity": {
        "code": 6
      },
      "appname": "user",
      "version": "1"
    }
  },
  "observer": {
    "hostname": "esr-edge-01",
    "ip": [
      "10.50.0.1"
    ],
    "name": "esr-edge-01",
    "product": "ESR",
    "type": "router",
    "vendor": "Eltex"
  },
  "eltex": {
    "esr": {
      "group": "USER",
      "mnemonic": "INFO",
      "severity_code": "I",
      "sequence_number": 8648,
      "details": {
        "privilege": {
          "new": 14,
          "old": 1
        }
      }
    }
  },
  "user": {
    "target": {
      "name": "svc_remote_001"
    }
  },
  "related": {
    "user": [
      "svc_remote_001"
    ]
  }
}
```

## References

- [Eltex ESR 1.40 Syslog Reference](https://docs.eltex-co.ru/download/attachments/52497571/ESR-Series_Syslog_reference_1.40.pdf?api=v2): remote envelope, native selected message bodies and optional sequence/timestamp controls.
- [Eltex ESR 1.40 CLI Reference](https://docs.eltex-co.ru/download/attachments/52497571/ESR-Series_CLI_1.40.pdf?api=v2): local user default privilege, configuration/confirmation, administrative privilege requirements and lockout defaults.
- [Elastic ECS field reference](https://www.elastic.co/docs/reference/ecs/ecs-field-reference): normalized field names; no dedicated ESR integration parity is claimed.
