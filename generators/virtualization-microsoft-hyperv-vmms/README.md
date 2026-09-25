# Microsoft Hyper-V VMMS checkpoint events

Synthetic Windows Event XML from `Microsoft-Windows-Hyper-V-VMMS-Admin` for checkpoint and background disk merge failures. The format and three IDs follow a published Event Viewer XML example.

## Event Types

| Action | Baseline frequency | Category |
| --- | ---: | --- |
| `18014` - Checkpoint operation cancelled | 45% baseline | host |
| `18012` - Checkpoint operation failed | 40% baseline | host |
| `19100` - Background disk merge failed | 15% baseline | host |

Baseline percentages are synthetic weights, not measured vendor frequencies.

## Anomaly Chain

Event 18014 (cancelled), 18012 (failed), and 19100 (disk merge failed) recur for VM `APP-02` on one Hyper-V host. Correlate by `hyperv.vm.id`, host and a short time window after sorting by `@timestamp`; file line order is not guaranteed. This is a storage or backup fault pattern, not evidence of malicious activity. The VMMS record runs as SYSTEM and does not identify the operator.

`anomaly_mode` defaults to `true`. Set `event.template.params.anomaly_mode: false` for background activity only.

## Parameters

### Event Parameters

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include the correlated VM fault burst |
| `host_name` | `hyperv-02.example.test` | VMMS host |
| `affected_vm_name` | `APP-02` | VM in the fault burst |
| `affected_vm_id` | `8F233F6C-28E0-44B7-8A16-C57D0D72DB61` | Stable affected VM GUID |

### Output Parameters

The shipped config writes `output/events.json` and needs no connection parameters or secrets. To send to a SIEM, replace the file output in a local copy and add `${params.siem_host}` and `${secrets.siem_token}` for the selected output plugin where applicable.

## Usage

```bash
eventum generate --path generators/virtualization-microsoft-hyperv-vmms/generator.yml --id hyperv --live-mode false
eventum generate --path generators/virtualization-microsoft-hyperv-vmms/generator.yml --id hyperv --live-mode true
```

## Sample Output

This event was copied from an `anomaly_mode: true` generator run.

```json
{
  "@timestamp": "2026-09-25T12:52:43+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "disk-merge-failed",
    "category": [
      "host"
    ],
    "code": "19100",
    "kind": "event",
    "original": "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Microsoft-Windows-Hyper-V-VMMS\" Guid=\"{6066f867-7ca1-4418-85fd-36e3f9c0600c}\"/><EventID>19100</EventID><Version>0</Version><Level>2</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime=\"2026-09-25T12:52:43.000000Z\"/><EventRecordID>50048</EventRecordID><Correlation/><Execution ProcessID=\"2748\" ThreadID=\"1160\"/><Channel>Microsoft-Windows-Hyper-V-VMMS-Admin</Channel><Computer>hyperv-02.example.test</Computer><Security UserID=\"S-1-5-18\"/></System><UserData><VmlEventLog xmlns=\"http://www.microsoft.com/Windows/Virtualization/Events\"><VmName>APP-02</VmName><VmId>8F233F6C-28E0-44B7-8A16-C57D0D72DB61</VmId><ErrorMessage>%%2147942432</ErrorMessage><ErrorCode>0x80070020</ErrorCode></VmlEventLog></UserData></Event>",
    "outcome": "failure",
    "type": [
      "error"
    ]
  },
  "host": {
    "name": "hyperv-02.example.test"
  },
  "hyperv": {
    "error_code": "0x80070020",
    "vm": {
      "id": "8F233F6C-28E0-44B7-8A16-C57D0D72DB61",
      "name": "APP-02"
    }
  },
  "message": "'APP-02' background disk merge failed to complete: The process cannot access the file because it is being used by another process. (0x80070020). (Virtual machine ID 8F233F6C-28E0-44B7-8A16-C57D0D72DB61)",
  "related": {
    "hosts": [
      "hyperv-02.example.test"
    ]
  },
  "winlog": {
    "channel": "Microsoft-Windows-Hyper-V-VMMS-Admin",
    "provider_name": "Microsoft-Windows-Hyper-V-VMMS",
    "record_id": 50048,
    "user": {
      "identifier": "S-1-5-18"
    }
  }
}
```

## Coverage and Limits

The baseline represents isolated VMMS Admin errors on different VMs, not all healthy Hyper-V activity. The three-event XML shape is taken from one Microsoft-hosted user example for Windows Server 2022/2025; it is not a complete VMMS event catalog. All selected XML fields are retained in `event.original` (18/18 across the 19100 variant); ECS extracts provider, channel, event ID, record ID, VM and error code. `Security UserID=S-1-5-18` means SYSTEM, not the human who initiated a checkpoint.

## References

- [Microsoft Q&A VMMS XML example](https://learn.microsoft.com/en-us/answers/questions/2203089/hyper-v-checkpoint-error)
- [KUMA 4.2 source catalog](https://support.kaspersky.ru/kuma/4.2/255782)
