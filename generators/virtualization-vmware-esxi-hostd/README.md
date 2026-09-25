# VMware ESXi hostd logs

Synthetic ESXi `hostd.log` lines following Broadcom examples of host maintenance tasks, maintenance mode events and API logins.

## Event Types

| Action | Baseline frequency | Category |
| --- | ---: | --- |
| `login` - Host API login | 55% baseline | authentication |
| `logout` - Host API logout | 45% baseline | authentication |
| `task-created` - Enter-maintenance task created | Chain only | configuration |
| `maintenance-begin` - Host begins entering maintenance | Chain only | configuration |
| `maintenance-started` - User-attributed maintenance starts | Chain only | configuration |
| `maintenance-entered` - Host enters maintenance | Chain only | configuration |
| `task-completed` - Enter-maintenance task succeeds | Chain only | configuration |

Baseline percentages are synthetic weights, not measured vendor frequencies.

## Anomaly Chain

A `HostSystem.enterMaintenanceMode` task is created by `vpxuser:CORP\svc-backup`, followed by host begin, user-attributed start, entered mode, and task completion with `Status success`. Correlate task creation and completion by task ID, operation ID and actor; correlate the two unattributed host-mode records by host and a short time window. Sort by `@timestamp` before applying the sequence; file line order is not guaranteed. Maintenance by a backup service account is a synthetic suspicious condition that still needs an approved change-window check.

`anomaly_mode` defaults to `true`. Set `event.template.params.anomaly_mode: false` for background activity only.

## Parameters

### Event Parameters

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include the maintenance-task sequence |
| `host_name` | `esx-04.example.test` | ESXi host |
| `datacenter_name` | `dc-east` | Datacenter in maintenance event |
| `maintenance_actor` | `vpxuser:CORP\svc-backup` | Actor in the maintenance task |

### Output Parameters

The shipped config writes `output/events.json` and needs no connection parameters or secrets. To send to a SIEM, replace the file output in a local copy and add `${params.siem_host}` and `${secrets.siem_token}` for the selected output plugin where applicable.

## Usage

```bash
eventum generate --path generators/virtualization-vmware-esxi-hostd/generator.yml --id esxi --live-mode false
eventum generate --path generators/virtualization-vmware-esxi-hostd/generator.yml --id esxi --live-mode true
```

## Sample Output

This event was copied from an `anomaly_mode: true` generator run.

```json
{
  "@timestamp": "2026-09-25T12:58:44+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "task-created",
    "category": [
      "configuration"
    ],
    "kind": "event",
    "original": "2026-09-25T12:58:44.000Z In(166) Hostd[2101270]: [Originator@6876 sub=Vimsvc.TaskManager opID=a51bb486-3b41-42eb-a394-22ac9e452c6f-6a-a-615a sid=8c327895 user=vpxuser:CORP\\svc-backup] Task Created : haTask-ha-host-vim.HostSystem.enterMaintenanceMode-17044002",
    "type": [
      "change"
    ]
  },
  "host": {
    "name": "esx-04.example.test"
  },
  "log": {
    "file": {
      "path": "/var/run/log/hostd.log"
    },
    "level": "info"
  },
  "process": {
    "name": "Hostd",
    "pid": 2101270
  },
  "related": {
    "user": [
      "vpxuser:CORP\\svc-backup"
    ]
  },
  "vmware": {
    "esxi": {
      "actor": "vpxuser:CORP\\svc-backup",
      "message": "Task Created : haTask-ha-host-vim.HostSystem.enterMaintenanceMode-17044002",
      "operation_id": "a51bb486-3b41-42eb-a394-22ac9e452c6f-6a-a-615a",
      "session_id": "8c327895",
      "subsystem": "Vimsvc.TaskManager",
      "task_id": "haTask-ha-host-vim.HostSystem.enterMaintenanceMode-17044002"
    }
  }
}
```

## Coverage and Limits

Broadcom examples establish 11 selected raw fields, all preserved in `event.original`: timestamp, level, process/PID, Originator, subsystem, operation ID, session ID, user where present, event key or task ID, message, and completion status. Numeric `Event N` values are event keys, not stable semantic event IDs, so detection uses message/action. The chosen login example is from ESXi 8.0.2, while KUMA 4.2 lists ESXi syslog normalizers through 7.0; direct compatibility with those normalizers is unverified. `event.original` is a local hostd line, so a remote syslog collector may add an outer header.

## References

- [Broadcom maintenance event samples](https://knowledge.broadcom.com/external/article/428259/how-to-confirm-when-esx-host-was-placed.html)
- [Broadcom hostd task samples](https://knowledge.broadcom.com/external/article/424736/vsan-cluster-shutdown-wizard-fails-at-st.html)
- [Broadcom hostd login samples](https://knowledge.broadcom.com/external/article/393891/esxi-host-events-log-flooded-with-user.html)
- [KUMA 4.2 source catalog](https://support.kaspersky.ru/kuma/4.2/255782)
