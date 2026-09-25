# Carbon Black EDR Event Forwarder JSON

Synthetic Carbon Black EDR (formerly CB Response) endpoint events for SIEM process and network correlation.

## Event types

| Native type | Behavior | Approximate frequency with anomaly mode | ECS category/type |
| --- | --- | --- | --- |
| `ingress.event.procstart` (`event_type: proc`) | Process creation | 41% | `process` / `start` |
| `ingress.event.netconn` | Outbound TCP connection | 41% | `network` / `connection` |
| `ingress.event.childproc` | Child process creation | <1% | `process` / `start` |
| `ingress.event.regmod` | Registry value written | 6% | `registry` / `change` |
| `ingress.event.filemod` | File last-write change | 12% | `file` / `change` |

The generator models one EDR server and four routine endpoint sensors. The anomaly uses a fifth sensor. Each source event is JSON under `carbon_black.edr`; its raw JSON record is retained in `event.original`. The outer document adds ECS fields for SIEM use.

## Anomaly Chain

With `anomaly_mode: true` (the default), a Word process on `WS-FIN-01` creates PowerShell. That process starts with a hidden script, writes a `Run` registry value, modifies an AppData file and opens an outbound TCP connection. These are five distinct vendor-documented endpoint event types. The `childproc.child_process_guid` equals the later events' `process_guid`; the `childproc.process_guid` equals `procstart.parent_process_guid`. All five retain the same `sensor_id`, host and process MD5. A rule can correlate those keys over a short window and distinguish the sequence from ordinary process starts and network traffic. Sort by `@timestamp` when inspecting a batch, since output line order can differ from event time.

With `anomaly_mode: false`, the fifth sensor and the linked `childproc` series disappear. The four routine sensors continue producing process starts, connections, independent registry setting writes and temporary-file updates. A rule therefore needs the shared process and sensor identifiers plus the sequence, not the presence of a single event type.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
| --- | --- | --- |
| `cb_server` | `cb-01.example.test` | EDR server name in the native record |
| `link_base` | `https://cb-01.example.test` | Base URL for native sensor and process links |
| `anomaly_mode` | `true` | Include the correlated five-event chain |
| `anomaly_interval_events` | `60` | Routine process starts between chains |
| `chain_host` | `WS-FIN-01` | Hostname for the correlated series |
| `chain_sensor_id` | `7` | Sensor ID for the correlated series |
| `chain_user` | `alice@example.test` | User context of the process |
| `chain_local_ip` | `10.20.30.77` | Source address of the final connection |

### Output Parameters

The supplied config writes ECS JSON Lines to `output/events.json`; it defines no top-level `params` or `secrets`. To send it elsewhere, replace `output.file` with the desired output plugin and define that plugin's `${params.*}` and `${secrets.*}` values. Forward `event.original` if the receiver expects the unwrapped Event Forwarder JSON record.

## Usage

Run from the content-packs repository root:

```bash
eventum generate --path generators/security-carbon-black-edr-event-forwarder/generator.yml --id cb-edr --live-mode false
eventum generate --path generators/security-carbon-black-edr-event-forwarder/generator.yml --id cb-edr-live --live-mode true
```

Set `anomaly_mode: false` in `generator.yml` for background-only output.

## Sample output event

This registry event was copied from an anomaly-mode run:

```json
{
  "@timestamp": "2026-09-25T14:38:32+00:00",
  "carbon_black": {
    "edr": {
      "action": "writeval",
      "actiontype": 2,
      "cb_server": "cb-01.example.test",
      "computer_name": "WS-FIN-01",
      "event_type": "regmod",
      "link_process": "https://cb-01.example.test/#analyze/00000007-0000-3830-a545-1e222047f361/1",
      "link_sensor": "https://cb-01.example.test/#/host/7",
      "md5": "E3F7D643F0133A6BCB598EAD3B4F1C76",
      "path": "\\registry\\user\\s-1-5-21-1000-1000-1000-1001\\software\\microsoft\\windows\\currentversion\\run\\updater",
      "pid": 5442,
      "process_guid": "00000007-0000-3830-a545-1e222047f361",
      "sensor_id": 7,
      "timestamp": 1790347112,
      "type": "ingress.event.regmod"
    }
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "ingress.event.regmod",
    "category": [
      "registry"
    ],
    "dataset": "carbon_black_edr.event_forwarder",
    "kind": "event",
    "original": "{\"action\": \"writeval\", \"actiontype\": 2, \"cb_server\": \"cb-01.example.test\", \"computer_name\": \"WS-FIN-01\", \"event_type\": \"regmod\", \"link_process\": \"https://cb-01.example.test/#analyze/00000007-0000-3830-a545-1e222047f361/1\", \"link_sensor\": \"https://cb-01.example.test/#/host/7\", \"md5\": \"E3F7D643F0133A6BCB598EAD3B4F1C76\", \"path\": \"\\\\registry\\\\user\\\\s-1-5-21-1000-1000-1000-1001\\\\software\\\\microsoft\\\\windows\\\\currentversion\\\\run\\\\updater\", \"pid\": 5442, \"process_guid\": \"00000007-0000-3830-a545-1e222047f361\", \"sensor_id\": 7, \"timestamp\": 1790347112, \"type\": \"ingress.event.regmod\"}",
    "type": [
      "change"
    ]
  },
  "host": {
    "name": "WS-FIN-01"
  },
  "observer": {
    "name": "cb-01.example.test",
    "product": "EDR",
    "vendor": "Carbon Black"
  },
  "process": {
    "entity_id": "00000007-0000-3830-a545-1e222047f361",
    "executable": "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe",
    "pid": 5442
  },
  "registry": {
    "path": "\\registry\\user\\s-1-5-21-1000-1000-1000-1001\\software\\microsoft\\windows\\currentversion\\run\\updater"
  },
  "related": {
    "hosts": [
      "WS-FIN-01"
    ],
    "user": [
      "alice@example.test"
    ]
  },
  "user": {
    "name": "alice@example.test"
  }
}
```

## Format and coverage

All 84 native field positions across the five complete JSON examples in the [Carbon Black EDR Event Forwarder schema](https://developer.carbonblack.com/reference/enterprise-response/connectors/event-forwarder/event-schema/) are represented: 14/14 `childproc`, 20/20 `procstart`, 14/14 `regmod`, 16/16 `filemod` and 20/20 `netconn`. Values, field types and cross-event identifiers follow those examples. The scope excludes other endpoint event types, alerts, LEEF output, proxy-specific `netconn` fields and transport headers. The vendor schema does not pin these examples to a current EDR release, so this is a profile of the documented Event Forwarder JSON, not a claim of compatibility with every EDR version.

**KUMA compatibility:** The KUMA 4.2 Carbon Black EDR entry names a Syslog-CEF normalizer. This pack emits the Event Forwarder's native JSON stream, which that CEF normalizer cannot parse. Configure a JSON ingestion path for this pack. Carbon Black states that CEF output is available through its native rsyslog templates, not through Event Forwarder; this generator does not synthesize that separate CEF stream.

## References

- [Carbon Black EDR Event Forwarder data formats](https://developer.carbonblack.com/reference/enterprise-response/connectors/event-forwarder/event-schema/) - complete native JSON examples and field meanings.
- [Broadcom: EDR Syslog CEF output](https://knowledge.broadcom.com/external/article/285764) - CEF is a separate native rsyslog export, not Event Forwarder output.
- [KUMA 4.2 supported data sources](https://support.kaspersky.ru/kuma/4.2/255782) - Carbon Black EDR Syslog-CEF normalizer entry.
