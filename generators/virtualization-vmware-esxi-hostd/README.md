# VMware ESXi hostd

VMware ESXi 8 hostd authentication and VM task messages, preserved in `event.original` with a synthetic ECS JSON wrapper. The profile represents one host, four administrators and two API automation clients.

## Event types

| Action | Approximate share | Category |
|---|---:|---|
| `login` | 48.44% | Authentication |
| `logout` | 48.44% | Authentication |
| `auth-failed` | 1.18% | Authentication |
| `vm-snapshot-request` | 0.71% | Configuration |
| `task-completed` | 0.97% | Configuration |
| `vm-poweroff-request` | 0.13% | Configuration |
| `vm-poweron-request` | 0.13% | Configuration |

## Activity

About 3,300 records per day. Automated API clients operate throughout the day. Administrator activity is concentrated at 08:00-18:00 UTC with a small overnight share. Most records describe successful logins and logouts. Password mistakes are uncommon, with single mistakes more frequent than two or three retries. Accounts make at most four consecutive failed attempts before success, so account lockouts are outside this profile. Occasional VM snapshots and planned power cycles use the same client population.

## Anomaly Chain

For one user and source address: three rejected passwords, a successful login, then a VM power-off request within 30 minutes. Each action and user/address pair also appears in ordinary activity. With `anomaly_mode: false`, this complete ordered sequence is absent. With `true`, each episode adds one complete sequence. Subsequent episodes use a different administrator and VM. Ordinary sessions continue independently. Powered-off VMs are restored after approximately 5-15 minutes in either mode.

The first episode starts within the smaller of the configured interval and 24 hours, favouring working hours. Later starts are drawn around the previous actual start plus the interval, within half a window of `min(interval / 4, 6 hours)` on either side. Working hours are favoured within that window. The next available record time can add a short delay. Missed episodes do not accumulate.

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `anomaly_mode` | `true` | Include recurring complete chains. |
| `anomaly_interval_hours` | `24` | Recurrence interval, 2-8760 hours. |
| `host_name` | `esx-04.example.test` | ESXi host name. |

## Usage

```bash
eventum generate --path generators/virtualization-vmware-esxi-hostd/generator.yml --id esxi-hostd --live-mode true
```

For a finite batch, set `oscillator.start` and `oscillator.end` in each `patterns/*.yml` file to the same UTC date range, starting at midnight, then run:

```bash
eventum generate --path generators/virtualization-vmware-esxi-hostd/generator.yml --id esxi-hostd --live-mode false --keep-order true
```

Results are written to `output/events.json`. Set the template parameters in `generator.yml` before starting. Performance: approximately 1,400 events/second in a four-day batch on the development machine.

## Sample output

```json
{"@timestamp": "2026-09-21T00:02:39.760Z", "ecs": {"version": "8.17.0"}, "event": {"action": "login", "category": ["authentication"], "kind": "event", "original": "2026-09-21T00:02:39.760Z In(166) Hostd[2103838]: [Originator@6876 sub=Vimsvc.ha-eventmgr opID=esxui-e3e6-d1bf sid=7926f1f1] Event 6549 : User svc-backup@10.20.2.32 logged in as pyvmomi Python/3.8.18 (VMkernel; 8.0.2; x86_64)", "outcome": "success", "type": ["start"]}, "host": {"name": "esx-04.example.test"}, "log": {"file": {"path": "/var/run/log/hostd.log"}, "level": "info"}, "process": {"name": "Hostd", "pid": 2103838}, "related": {"ip": ["10.20.2.32"], "user": ["svc-backup"]}, "source": {"ip": "10.20.2.32"}, "user": {"name": "svc-backup"}, "vmware": {"esxi": {"client_agent": "pyvmomi Python/3.8.18 (VMkernel; 8.0.2; x86_64)", "message": "Event 6549 : User svc-backup@10.20.2.32 logged in as pyvmomi Python/3.8.18 (VMkernel; 8.0.2; x86_64)", "subsystem": "Vimsvc.ha-eventmgr"}}}
```

## Limitations

- The ECS wrapper and `vmware.esxi` fields are this pack's mapping, not the output of a vendor collector or Elastic integration. Client addresses on task records are inferred from the associated synthetic session.
- The selected hostd lines omit PAM diagnostics, companion authentication messages, snapshot cleanup, VM state transitions and most hostd subsystems. Full native-file and live parser compatibility have not been established.
- Related records are seconds apart, sometimes longer, rather than the millisecond spacing common in native logs. Session counts, message shares and VM activity are synthetic.
- Episodes add their own authentication and VM task records, increasing those counts. Each complete chain describes only the selected user/address sequence, not all possible suspicious activity.

## References

- [Broadcom: ESXi API login and logout messages](https://knowledge.broadcom.com/external/article/393891/esxi-host-events-log-flooded-with-user.html)
- [Broadcom: rejected password message and session identifier](https://knowledge.broadcom.com/external/article/323622)
- [Broadcom: VM power-off task](https://knowledge.broadcom.com/external/article/397721)
- [Broadcom: VM power-on task](https://knowledge.broadcom.com/external/article/416006/a-general-system-error-occurred-while-tr.html)
- [Broadcom: snapshot task](https://knowledge.broadcom.com/external/article/318905)
- [Broadcom: Task Completed message](https://knowledge.broadcom.com/external/article/424736/vsan-cluster-shutdown-wizard-fails-at-st.html)

No matching Elastic ESXi integration is asserted for this custom wrapper.
