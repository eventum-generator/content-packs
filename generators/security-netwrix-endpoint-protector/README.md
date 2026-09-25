# Netwrix Endpoint Protector Device Control SIEM export

Synthetic Endpoint Protector 5.9.4 Device Control SIEM message bodies in Netwrix's documented Standard format. This pack models one Device Control stream with the `Exclude Headers` export option, not a complete syslog wire frame.

## Event types

| Native event | Approximate share with anomaly mode | ECS category | Meaning |
| --- | ---: | --- | --- |
| `Connected` | 32.9% | `host` | USB device connected to an endpoint |
| `File Read` | 23.7% | `file` | File read from the device |
| `File Write` | 10.5% | `file` | File written to the device |
| `Disconnected` | 32.9% | `host` | USB device disconnected |

The template uses FSM mode and emits one event per simulated second. A 24-session background cycle contains 18 single-file reads and six single-file writes; every session starts with `Connected` and ends with `Disconnected`. Default anomaly mode then adds one four-event session. Frequencies and timing are synthetic, not measured Endpoint Protector production rates.

## Anomaly Chain

With `anomaly_mode: true` (the default), `sorlov` on `FIN-WS-07` connects USB serial `USB-8F12A7C9`, writes `payroll-q3.csv`, writes `customer-export.zip` one second later, and disconnects. The four events share `Client User`, `Client Computer`, `IP Address`, `MAC Address`, and `Device Serial`. A detection rule can group by endpoint, user, and device serial, sort by `@timestamp`, and alert on two `File Write` events within three seconds of one connection. Do not use output row order as the event clock.

Routine sessions also include individual writes of those same two files by the same user, computer, and USB serial. A single event type, actor, device, or filename therefore does not distinguish the modes. With `anomaly_mode: false`, all four native event types remain, but each connection contains at most one file operation and there are no two-write clusters within a three-second window. This sequence is a detection exercise, not proof of data theft; the native export does not state whether a transfer was authorized.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Add a two-write session; `false` emits only single-operation background sessions |
| `epp_server` | `epp-01` | Endpoint Protector server in `observer.name` |
| `routine_sessions_before_chain` | `24` | Background sessions between anomaly sessions |
| `suspect_user` | `sorlov` | User in the two-write session and some background sessions |
| `suspect_computer` | `FIN-WS-07` | Endpoint in the two-write session and some background sessions |
| `suspect_client_ip` | `10.50.4.77` | Endpoint IP in the two-write session and some background sessions |
| `suspect_device_serial` | `USB-8F12A7C9` | USB serial shared by anomaly and some background sessions |

### Output Parameters

No top-level `${params.*}` or `${secrets.*}` are required. Output defaults to `output/events.json`; edit the file output section to deliver elsewhere.

## Usage

From the content-packs repository:

```bash
eventum generate --path generators/security-netwrix-endpoint-protector/generator.yml --id epp --live-mode false
```

For continuous generation, use `--live-mode true`. Set `event.template.params.anomaly_mode` to `false` for background only. The file output is overwritten when a run starts.

## Sample output

This complete JSON event was copied from an anomaly-mode run:

```json
{
  "@timestamp": "2026-09-25T14:52:11+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "endpoint_protector": {
    "device_control": {
      "device_serial": "USB-8F12A7C9",
      "fields": {
        "Client Computer": "FIN-WS-07",
        "Client User": "sorlov",
        "Date/Time(Client UTC)": "2026-09-25T14:52:11Z",
        "Date/Time(Client)": "2026-09-25 14:52:11",
        "Date/Time(Server UTC)": "2026-09-25T14:52:11Z",
        "Date/Time(Server)": "2026-09-25 14:52:11",
        "Device": "USB Mass Storage Device",
        "Device PID": "5581",
        "Device Serial": "USB-8F12A7C9",
        "Device Type": "USB Storage",
        "Device VID": "0781",
        "EPP Client Version": "5.9.4",
        "Event Name": "File Write",
        "File Hash": "415290769594460e2e485922904f345d",
        "File Name": "E:/exports/customer-export.zip",
        "File Size": "43122688",
        "File Type": "ZIP",
        "IP Address": "10.50.4.77",
        "Justification": "",
        "Log ID": "3d0eb4c025494f1293a9f667f33f3f19",
        "MAC Address": "02-1A-11-42-27-77",
        "OS": "Windows 11 Enterprise",
        "Repository Type": "",
        "Serial Number": "WS-SN-2077",
        "Shadow Exists": "No",
        "Time Interval": ""
      }
    }
  },
  "event": {
    "action": "file_write",
    "category": [
      "file"
    ],
    "dataset": "endpoint_protector.device_control",
    "id": "3d0eb4c025494f1293a9f667f33f3f19",
    "kind": "event",
    "module": "endpoint_protector",
    "original": "Device Control – File Write: [Log ID] 3d0eb4c025494f1293a9f667f33f3f19 | [Event Name] File Write | [Client Computer] FIN-WS-07 | [IP Address] 10.50.4.77 | [MAC Address] 02-1A-11-42-27-77 | [Serial Number] WS-SN-2077 | [OS] Windows 11 Enterprise | [Client User] sorlov | [Device Type] USB Storage | [Device] USB Mass Storage Device | [Device VID] 0781 | [Device PID] 5581 | [Device Serial] USB-8F12A7C9 | [EPP Client Version] 5.9.4 | [File Name] E:/exports/customer-export.zip | [File Hash] 415290769594460e2e485922904f345d | [File Type] ZIP | [File Size] 43122688 | [Justification]  | [Time Interval]  | [Date/Time(Server)] 2026-09-25 14:52:11 | [Date/Time(Client)] 2026-09-25 14:52:11 | [Date/Time(Server UTC)] 2026-09-25T14:52:11Z | [Date/Time(Client UTC)] 2026-09-25T14:52:11Z | [Shadow Exists] No | [Repository Type] ",
    "outcome": "success",
    "type": [
      "change"
    ]
  },
  "file": {
    "extension": "zip",
    "path": "E:/exports/customer-export.zip",
    "size": 43122688
  },
  "host": {
    "ip": [
      "10.50.4.77"
    ],
    "name": "FIN-WS-07"
  },
  "message": "Device Control – File Write",
  "observer": {
    "name": "epp-01",
    "product": "Endpoint Protector",
    "vendor": "Netwrix",
    "version": "5.9.4"
  },
  "related": {
    "hosts": [
      "FIN-WS-07",
      "epp-01"
    ],
    "ip": [
      "10.50.4.77"
    ],
    "user": [
      "sorlov"
    ]
  },
  "source": {
    "ip": "10.50.4.77"
  },
  "user": {
    "name": "sorlov"
  }
}
```

## Format and coverage

The official Standard format defines `log_type: [field_name] value | ...`. `event.original` is a synthetic composition of that message body, using Netwrix's `Device Control – <event>` names and all 26 documented Device Control columns in order. `endpoint_protector.device_control.fields` retains those exact names and gives 26/26 field coverage. Empty columns are preserved. `host.name` is the endpoint; `observer.name` is the Endpoint Protector server. The generated `Log ID`, file values, timestamps, and complete line are synthetic, not copied from a vendor-captured record. Native timestamp-value formatting is not specified by the reference and may differ on a real appliance.

The first-party reference identifies this Standard format as available since 5.9.4. Netwrix documents `Exclude Headers` for SIEM export, which is the modeled body-only setting. The complete syslog header, alternate export formats, and KUMA 4.2's generic Endpoint Protector 5.9 regexp normalizer were not tested; parser compatibility is not claimed. Event classes and field availability also depend on the SIEM policy and Endpoint Protector configuration.

## References

- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)
- [Netwrix Endpoint Protector: SIEM Integration, Standard format and 5.9.4 fields](https://docs.netwrix.com/docs/endpointprotector/admin/appliance)
- [Netwrix Endpoint Protector: Device Control event catalog](https://docs.netwrix.com/docs/endpointprotector/admin/systempar)
- [Netwrix Endpoint Protector: SIEM setup and Exclude Headers](https://docs.netwrix.com/docs/endpointprotector/kb/administration-security-and-monitoring/set_up_a_siem_integration)
