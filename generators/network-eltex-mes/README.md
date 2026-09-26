# Eltex MES Switch Syslog

Generates ECS JSON carrying selected MES5324 syslog **message bodies** in `event.original` and `message`. Bodies follow the official [MES23xx/MES33xx/MES35xx/MES5324 message catalog](https://eltex.ru/storage/upload_center/files/46/MES23xx_MES33xx_MES35xx_MES5324_Log_reference.pdf). The catalog has no firmware identifier. Configuration and hardware assumptions use the same-family [4.0.27.3 operation manual](https://eltex.ru/storage/upload_center/files/60/MES_Series_user_manual_4.0.27.3.pdf). This is not an exact 4.0.27.3 live capture or a full syslog transport generator. Eltex ESR routing logs are a separate product stream.

## Source Profile

One MES5324 has eight selected `te1/0/*` interfaces initially up, four dual-rate target ports initially configured for 10G, and 52 pre-existing MAC entries. Forty-eight endpoints share four downstream ports; four selected endpoints use distinct target ports. The primary target is configurable. Existing VLAN membership and dual-rate optics/peers permitting 1G and 10G are explicit inventory assumptions. No MAC move, interface creation or VLAN creation is implied.

HTTPS management with local-user-table authentication is enabled. Both configured users are existing administrators authorized for the selected maintenance operations. AAA login and link logging, MAC-change notifications and an informational-or-more-detailed exported logging threshold are assumed enabled. Local file logging is enabled and export aggregation is disabled. The selected local password lockout threshold is five consecutive failures. Ordinary isolated failures are followed by success, and episodes contain only three failures before success. The profile needs no account unlock event.

There are two configured syslog destinations: an unchanged retained collector, modeled as `10.40.0.20` in the default inventory, and the configurable auxiliary receiver `syslog_server_ip`. Only the auxiliary receiver is removed and visibly re-added. Continued delivery to the retained collector is therefore coherent. The generator emits neither collector framing nor the retained destination as a native event field. Keep those destinations distinct when changing the scenario.

The stream selects FDB learning/clearing notifications amid unlogged endpoint traffic and maintenance. It tracks each selected entry's presence, but does not implement packet traffic, exact MAC aging deadlines, SNMP batching or all entries on a live switch. Background removals represent selected aging/clearing transitions; learn events require an absent entry and an up port. An endpoint held during port maintenance cannot be relearned before that port's visible Up and restoration. Initial state and unobserved traffic are scenario assumptions, not reconstructed vendor history.

## Event Types

| Native class | Meaning in this profile |
|---|---|
| `BRG_MACNTFY-I-MAC_CHANGED` | Learn an absent selected MAC or remove a present entry |
| `AAA-W-REJECT` | Reject HTTPS local-user-table authentication |
| `AAA-I-CONNECT` | Accept that authentication and open the selected session |
| `AAA-I-DISCONNECT` | Terminate the existing same-user/source session |
| `LINK-N-PortConfRecover` | Report a configured speed of 1G or 10G |
| `LINK-W-Down` / `LINK-W-Up` | Change the selected interface's current link state |
| `SYSLOG-N-CLEARLOGGINGFILE` | Clear the local logging file |
| `SYSLOG-N-NOSYSLOGSERVER` | Remove the existing auxiliary receiver |
| `SYSLOG-N-NEWSYSLOGSERVER` | Re-add that absent receiver |

Ten native classes use one stateful template. All occur in both modes. Every 30 minutes, ordinary maintenance rotates among port maintenance, file clearing, auxiliary-receiver maintenance and one failed-then-successful login. Both administrators and all four targets also participate in ordinary work. Port maintenance visibly restores speed/link/MAC before disconnecting; auxiliary-receiver maintenance re-adds its destination two minutes after deletion. These routines do not combine three failures, port disruption, file clearing and receiver deletion into the complete episode.

One record every 30 seconds gives 120 records/hour or 2,880 records/day for a half-open day. The sixth cron field is seconds. Cadence, ordinary maintenance intervals, target rotation and traffic selection are synthetic workload choices, not measured Eltex production frequencies.

## Anomaly Chain

`anomaly_mode: true` is the default. The first episode becomes eligible after `anomaly_interval_hours`, default 24 hours. Adjacent episodes alternate administrator/source tuples and rotate the four existing MAC/port targets. Native classes have no session or campaign identifier; no invented ID, mode tag or actor is appended to configuration messages.

1. Three HTTPS authentication rejections for one existing administrator/source occur 30 seconds apart, followed by acceptance.
2. The same switch reports target speed 1G, then that port Down and its present MAC Removed.
3. The local logging file is cleared, the auxiliary receiver is removed, and the accepted session disconnects. Ten records span four minutes 30 seconds.
4. Fifteen minutes after receiver deletion, the other administrator opens a new session. Speed 10G, Up, MAC learning, auxiliary-receiver addition and disconnect are visible in order. Receiver addition occurs 17 minutes after deletion. Recovery completes 21 minutes 30 seconds after the first rejection.

An absent target MAC is first visibly learned on an up port, so an episode can start up to one tick late. The next due time is measured from the actual first rejection. Ordinary administration is postponed during the recovery hold and near the next due time, avoiding overlapping selected sessions and preventing a due episode from starving. Missed episodes are not replayed in a catch-up burst. A finite run can end inside an ordinary trace or episode; it does not silently reset state at the tail.

Detection can correlate repeated failures and success by native user/source/destination, then speed/link/MAC and logging operations by switch, port and time. `PortConfRecover` is documented as a configured-speed change result. Its name is not treated as a recovery command, and its body proves neither who changed it nor why the link subsequently went down. Actorless configuration lines support temporal/device correlation, not attribution to the preceding user. Clearing a local file does not erase already exported records, and deleting an auxiliary receiver does not establish complete audit suppression.

`anomaly_mode: false` removes the combined rapid sequence. Both modes retain the same actors, ports, MACs, VLANs, 1G/10G values, file clearing and receiver removal/addition. Recurring episodes reuse physical inventory plausibly rather than inventing new native identities.

State is bounded: 52 inventory/presence slots, eight link slots, four speed slots, one selected session, one held target, one recovery context, a pending plan of at most ten records and scalar schedule/cursor values. Completed episodes and historical sessions are not retained.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
|---|---|---|
| `switch_name`, `switch_ip` | `mes-access-01`, `10.40.0.11` | Synthetic switch inventory |
| `normal_user`, `normal_source_ip` | `netops`, `10.40.1.25` | First existing administrator/source, active in both modes |
| `unusual_user`, `unusual_source_ip` | `admin`, `10.99.4.21` | Second existing administrator/source, active in both modes |
| `target_port`, `target_mac`, `target_vlan` | `te1/0/5`, `e0:d9:e3:2c:19:b0`, `20` | First of four maintenance/episode target tuples |
| `syslog_server_ip` | `10.40.0.12` | Auxiliary receiver, separate from the retained collector |
| `anomaly_interval_hours` | `24` | Positive finite hours between actual starts; values below 6 clamp to 6 |
| `anomaly_mode` | `true` | Include periodic combined episodes; false emits ordinary activity |

Keep count one and the shipped 30-second cadence for documented timing. Fractional hours begin on the first tick at or after their due time, with an additional tick if target-MAC preparation is needed. Usernames and switch names must be nonempty ASCII labels without whitespace, commas, quotes, backslashes or newlines. Use distinct administrator names/source tuples. Supply valid IPv4, MAC and VLAN values. The primary target must be a valid distinct `te1/0/1..24` port, separate from fixed `te1/0/1..4` and `te1/0/6..8`, and its MAC must not duplicate another sample. VLAN must already exist and be allowed on that port. The 52 rows in `samples/endpoints.json` are fixed profile inventory; changing its cardinality or target ordering requires adapting the model. Sample `02:*` addresses are synthetic locally administered MACs; the primary default reproduces the vendor's illustrative MAC.

### Output Parameters

The local file output requires no credentials or top-level substitutions. Change `output.file.path`, or replace the output plugin for your SIEM. A collector requiring the native message body must receive `event.original`, rather than the outer ECS JSON.

## Usage

From the content-packs repository root:

```bash
flock -x /tmp/eventum-generator-heavy.lock uv run --project ../eventum eventum generate --path generators/network-eltex-mes/generator.yml --id mes --live-mode true --keep-order true
```

For a finite 48-hour-and-30-minute batch covering two default episodes and their recovery:

```bash
uv run --project ../eventum python - <<'PYCONFIG'
from pathlib import Path
import yaml
root = Path('generators/network-eltex-mes')
config = yaml.safe_load((root / 'generator.yml').read_text())
config['input'][0]['cron'].update(
    start='2026-09-25T00:00:00+00:00',
    end='2026-09-27T00:30:00+00:00',
)
(root / '.finite.yml').write_text(yaml.safe_dump(config, sort_keys=False))
PYCONFIG
flock -x /tmp/eventum-generator-heavy.lock uv run --project ../eventum eventum generate --path generators/network-eltex-mes/.finite.yml --id mes-finite --live-mode false --keep-order true
rm generators/network-eltex-mes/.finite.yml
```

The finite command exits normally and writes 5,821 records. ECS timestamps are normalized to UTC, including a Europe/Moscow CLI/input. Native bodies contain no time field; the outer timestamp is the synthetic event clock, not a fabricated source timestamp or transport header.

## Sample Output

The following synthetic event is copied exactly from the final default-on capture. It is not a live vendor capture:

```json
{
  "@timestamp": "2026-09-26T00:02:00+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "eltex": {
    "mes": {
      "component": "LINK",
      "details": {
        "interface": {
          "speed": "1G"
        }
      },
      "mnemonic": "PortConfRecover",
      "severity_code": "N"
    }
  },
  "event": {
    "action": "interface_speed_changed",
    "category": [
      "configuration",
      "network"
    ],
    "dataset": "eltex.mes.syslog",
    "kind": "event",
    "module": "eltex",
    "original": "LINK-N-PortConfRecover: Port te1/0/5 configured to speed 1G",
    "outcome": "unknown",
    "type": [
      "change"
    ]
  },
  "interface": {
    "name": "te1/0/5"
  },
  "log": {
    "level": "notice"
  },
  "message": "LINK-N-PortConfRecover: Port te1/0/5 configured to speed 1G",
  "observer": {
    "hostname": "mes-access-01",
    "ip": [
      "10.40.0.11"
    ],
    "model": "MES5324",
    "name": "mes-access-01",
    "product": "MES",
    "type": "switch",
    "vendor": "Eltex"
  }
}
```

## Validation and Evidence Limits

Four final finite 96h30 runs emitted 11,581 records each. Default 24-hour recurrence yielded four complete episodes and recoveries; custom 12-hour recurrence yielded eight. Both disabled captures contained zero full episodes. Custom parameters changed switch, both users/IPs, target MAC/port/VLAN and auxiliary receiver, with +03 input normalized to UTC. Streaming checks covered documented body grammar, punctuation/severity, native-to-ECS fields, session/FDB/link/speed/receiver state, lockout threshold, source-time cadence and recovery, actor/target variation and ordinary action overlap.

The actual original 69,481-record trace demonstrates the prior cron burst error, redundant FDB transitions, repeated receiver deletion without addition, repeated port-down/speed states and unclosed selected sessions. The corrected traces pass those checks. Mutations changing both native and normalized MAC state or receiver action together are rejected by lifecycle checks, independently of field equality.

Catalog examples establish complete AAA, speed, Down/Up, MAC removal and local-file/receiver message bodies. Learning uses the catalog's lowercase `learnt` parameter value; a complete native learning example was not found. The Up entry calls severity Informational while its complete example uses `LINK-W-Up`; this profile preserves the example's W prefix. The catalog is unversioned, while the 4.0.27.3 manual supports configuration/hardware assumptions only. Exact installed-build bytes, learning capitalization in a live record, full correlated capture, wire transport envelope and live SIEM parsing remain **BLOCKED_RAW_EVIDENCE**. A bounded search inspected the official catalog, current same-family download/manual and older 4.0.22 manual; it does not certify full native parity. Fifteen selected body identity/parameter fields are represented, which is field coverage rather than a realism score. No dedicated maintained Elastic MES sample was available. `observer.model`, inventory, parsed details and ECS outcomes are synthetic normalization; actorless events retain `event.outcome: unknown`.
