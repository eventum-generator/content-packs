# Carbon Black EDR Event Forwarder

Legacy Event Forwarder ingress events, preserved as JSON in `event.original` and normalized following the Elastic `carbonblack_edr.log` pipeline. The selected stream describes application processes on ten workstations and two automation servers.

## Event types

About 9,840 records/day combine continuous server activity with human activity concentrated between 08:00 and 18:00 UTC. The fleet, accounts and application paths are synthetic. Rates and shares are workload assumptions.

| Native type | Activity | Approximate background share |
| --- | --- | ---: |
| ingress.event.procstart | Process starts | 6.1% |
| ingress.event.procend | Process exits | 6.1% |
| ingress.event.regmod | Temporary registry value written or deleted | 3.0% |
| ingress.event.filemod | Temporary file written or deleted | 10.2% |
| ingress.event.netconn | Outbound application connection | 74.6% |

Each host runs short application sessions. Process identifiers, hashes, paths and parent references remain stable throughout a session. The process GUID encodes the sensor, process ID and Windows FILETIME creation time. A process may write a temporary registry value, write a temporary file and make outbound HTTPS connections. Sessions end after about 10–20 minutes, removing their temporary objects before the process exit. One ordinary process per host is represented at a time; parent processes predate the capture.

## Anomaly Chain

With `anomaly_mode: true`, one workstation process starts, writes a registry value, writes a file and connects to an external application address within ten minutes. Host and process GUID join the four records. Each action, workstation, account and application also appears in ordinary activity. The same temporary-object cleanup applies to ordinary and episode processes.

The first episode starts within `min(interval, 24 hours)`, weighted toward office hours. Later starts lie within half of `min(interval/4, 6 hours)` around the preceding actual start plus the interval, with stronger daytime weighting. Workstations rotate between episodes. The default interval is 24 hours. Ordinary sessions continue during episodes; missed historical episodes are not replayed.

With `anomaly_mode: false`, the complete four-step sequence is absent. Registry and file changes, external connections and process starts remain ordinary activities. The correlated sequence describes observable application behavior; it does not establish malicious code execution or persistence.

## Parameters

Edit `event.template.params` in `generator.yml`.

| Parameter | Default | Meaning |
| --- | --- | --- |
| `cb_server` | `cb-01.example.test` | EDR server name |
| `link_base` | `https://cb-01.example.test/` | Console base URL for process and sensor links |
| `anomaly_mode` | `true` | Include recurring correlated process activity |
| `anomaly_interval_hours` | `24` | Episode interval in hours, from 2 to 8760 |

Host identities and application paths are in `samples/`. All shipped values are synthetic; no secrets are needed.

## Usage

From the content-packs root:

```bash
eventum generate --path generators/security-carbon-black-edr-event-forwarder/generator.yml --id carbonblack --live-mode true --keep-order true
```

For a finite batch, copy the directory and set every `patterns/*.yml` oscillator start/end to UTC midnight boundaries. Run that copy with `--live-mode false --keep-order true`. Output defaults to `output/events.json`. Pattern ratios control volume and office-hour ranges control the human schedule.

## Source fidelity and limitations

The profile follows the open-source legacy protobuf message processor. It covers procstart/procend, regmod, filemod and netconn ingress events; childproc, watchlist hits, threat intelligence and binary metadata are omitted. Executable hashes are stable synthetic values, not hashes of actual binaries. Parent processes are references rather than a complete process tree.

The ECS projection follows selected Elastic pipeline mappings. Native fields remain under `carbonblack.edr`; ingress events do not automatically gain ECS host, process, user or source/destination objects. Process start/end retain their native action without invented ECS categories. Registry and network fields follow the selected pipeline transformations. Compatibility with a live forwarder and downstream parser has not been exercised.

## Sample output

One complete synthetic normalized event:

```json
{"@timestamp": "2026-09-21T00:00:33.394736+00:00", "carbonblack": {"edr": {"command_line": "\"c:\\program files\\Fabrikam\\update.exe\"", "computer_name": "SRV-OPS-01", "event_type": "proc", "expect_followon_w_md5": false, "filtering_known_dlls": false, "link_parent": "https://cb-01.example.test/#analyze/0000001f-0000-05dc-01dd-494b758411e0/1", "link_process": "https://cb-01.example.test/#analyze/0000001f-0000-07d4-01dd-495c390ce1e0/0", "link_sensor": "https://cb-01.example.test/#/host/31", "md5": "90A22F0022EB9B544F2731AA76C9C3C3", "parent_create_time": 1789941633, "parent_guid": "0000001f-0000-05dc-01dd-494b758411e0", "parent_md5": "CC528C115378F7E5EB404837962C2206", "parent_path": "c:\\windows\\explorer.exe", "parent_pid": 1500, "parent_process_guid": "0000001f-0000-05dc-01dd-494b758411e0", "path": "c:\\program files\\Fabrikam\\update.exe", "pid": 2004, "process_guid": "0000001f-0000-07d4-01dd-495c390ce1e0", "process_path": "c:\\program files\\Fabrikam\\update.exe", "sensor_id": 31, "sha256": "357DA3610A6743839006711F24AB657BAEBF808A58EFE5761F742A4F9A75F2AD", "timestamp": 1789948833.394736, "username": "svc-monitor1@example.test"}}, "ecs": {"version": "8.11.0"}, "event": {"action": "ingress.event.procstart", "dataset": "carbonblack_edr.log", "kind": "event", "original": "{\"cb_server\": \"cb-01.example.test\", \"command_line\": \"\\\"c:\\\\program files\\\\Fabrikam\\\\update.exe\\\"\", \"computer_name\": \"SRV-OPS-01\", \"event_type\": \"proc\", \"expect_followon_w_md5\": false, \"filtering_known_dlls\": false, \"link_parent\": \"https://cb-01.example.test/#analyze/0000001f-0000-05dc-01dd-494b758411e0/1\", \"link_process\": \"https://cb-01.example.test/#analyze/0000001f-0000-07d4-01dd-495c390ce1e0/0\", \"link_sensor\": \"https://cb-01.example.test/#/host/31\", \"md5\": \"90A22F0022EB9B544F2731AA76C9C3C3\", \"parent_create_time\": 1789941633.394736, \"parent_guid\": \"0000001f-0000-05dc-01dd-494b758411e0\", \"parent_md5\": \"CC528C115378F7E5EB404837962C2206\", \"parent_path\": \"c:\\\\windows\\\\explorer.exe\", \"parent_pid\": 1500, \"parent_process_guid\": \"0000001f-0000-05dc-01dd-494b758411e0\", \"path\": \"c:\\\\program files\\\\Fabrikam\\\\update.exe\", \"pid\": 2004, \"process_guid\": \"0000001f-0000-07d4-01dd-495c390ce1e0\", \"process_path\": \"c:\\\\program files\\\\Fabrikam\\\\update.exe\", \"sensor_id\": 31, \"sha256\": \"357DA3610A6743839006711F24AB657BAEBF808A58EFE5761F742A4F9A75F2AD\", \"timestamp\": 1789948833.394736, \"type\": \"ingress.event.procstart\", \"username\": \"svc-monitor1@example.test\"}"}, "observer": {"name": "cb-01.example.test", "product": "Carbon Black EDR", "type": "edr", "vendor": "VMWare"}, "tags": ["carbonblack_edr-log", "forwarded", "preserve_original_event"]}
```

## References

- [Carbon Black Event Forwarder legacy processor](https://github.com/carbonblack/cb-event-forwarder/blob/develop/pkg/protobufmessageprocessor/legacy_pb_message_processor.go)
- [Process GUID conversion](https://github.com/carbonblack/cb-event-forwarder/blob/develop/pkg/utils/utils.go)
- [Sensor event protobuf](https://github.com/carbonblack/cb-event-forwarder/blob/develop/pkg/sensorevents/sensor_events.proto)
- [Elastic Carbon Black EDR ingest pipeline](https://github.com/elastic/integrations/blob/main/packages/carbonblack_edr/data_stream/log/elasticsearch/ingest_pipeline/default.yml)
