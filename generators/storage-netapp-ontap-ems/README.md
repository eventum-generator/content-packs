# NetApp ONTAP EMS syslog

Synthetic ONTAP 9.12.1 Event Management System (EMS) notifications in the documented `legacy-netapp` syslog format. This pack models authentication failures, account lockout, and successful ZAPI Snapshot creation. It does not model ONTAP `audit.log` or file-access audit events.

## Event types

| EMS event name | Approximate share with anomaly mode | ECS category | Meaning |
| --- | ---: | --- | --- |
| `zapi.snapshot.success` | 82.5% | `file` | Asynchronous ZAPI Snapshot created |
| `security.invalid.login` | 15% | `authentication` | Failed SSH authentication |
| `useradmin.lockedout.user` | 2.5% | `authentication` | Account locked after failed attempts |

The template uses FSM mode and emits one event per five simulated minutes. The source is one ONTAP node (`cluster1-01`) with stable cluster and user identifiers. With anomaly mode disabled, the first two types remain at about 91.7% and 8.3%; lockout events are absent.

## Anomaly Chain

With `anomaly_mode: true` (the default), every 36 routine notifications are followed by three `security.invalid.login` messages for `admin` over SSH and one `useradmin.lockedout.user` message for the same account. The sequence assumes `security.passwd.lockout.numtries=3`. A detection can group by `host.name` and `user.name`, sort by `@timestamp`, and alert when three failures precede a lockout within 20 minutes. File row order is not the detection clock. With `anomaly_mode: false`, only routine Snapshot successes and isolated failures for `alice` are produced; no `admin` chain is scheduled.

The EMS catalog contains both failure and lockout messages but does not expose a client IP in these messages. The pack therefore does not invent `source.ip`. A lockout can also result from other authentication activity; the sequence here is a synthetic scenario, not proof of a single attacking host.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include the linked failure-to-lockout sequence; `false` produces background only |
| `node_name` | `cluster1-01` | ONTAP node in the syslog header |
| `vserver` | `cluster1` | Vserver in failed-login messages |
| `snapshot_volume` | `vol_data` | Volume in ZAPI Snapshot messages |
| `target_user` | `admin` | Account in the anomaly sequence |
| `incidental_user` | `alice` | Account with isolated background failures |
| `lockout_attempts` | `3` | Lockout threshold reflected in the EMS message |

### Output Parameters

No top-level `${params.*}` or `${secrets.*}` are required. Output defaults to `output/events.json`; edit the file output section to point Eventum at another destination.

## Usage

From the content-packs repository:

```bash
eventum generate --path generators/storage-netapp-ontap-ems/generator.yml --id ontap --live-mode false
```

For continuous generation, use `--live-mode true`. Set `event.template.params.anomaly_mode` to `false` for background only. The file output is overwritten when a run starts.

## Sample output

This JSON event was copied from an anomaly-mode run, not handwritten:

```json
{
  "@timestamp": "2026-09-25T15:00:39+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "useradmin.lockedout.user",
    "category": [
      "authentication"
    ],
    "kind": "event",
    "original": "<11>Sep 25 15:00:39 [cluster1-01:useradmin.lockedout.user:error]: User 'admin' is locked out of the appliance for failing authentication '3' times.",
    "outcome": "failure",
    "type": [
      "denied"
    ]
  },
  "host": {
    "name": "cluster1-01"
  },
  "log": {
    "syslog": {
      "facility": {
        "code": 1,
        "name": "user"
      },
      "priority": 11,
      "severity": {
        "code": 3,
        "name": "error"
      }
    }
  },
  "netapp": {
    "ems": {
      "message": "User 'admin' is locked out of the appliance for failing authentication '3' times.",
      "name": "useradmin.lockedout.user",
      "severity": "error"
    }
  },
  "related": {
    "user": [
      "admin"
    ]
  },
  "user": {
    "name": "admin"
  }
}
```

## Format and coverage

`event.original` is synthetically assembled from NetApp's documented ONTAP 9.12.1 `legacy-netapp` header grammar and the 9.12.1 EMS catalog's exact event names, severities, messages, and placeholders. It is not a captured vendor line. The modeled raw-format parts are all present: PRI, RFC 3164 timestamp, node name, EMS event name, EMS severity, and message (6/6). The selected `user` facility gives priorities 9, 11, and 13 according to the severity; it is a scenario choice, not a claim about every installation's facility. NetApp also offers RFC 5424, which this pack does not emit.

Configure an EMS destination and event filter that forwards these event names. Forwarding, enabled severities, hostname overrides, facility selection, and account lockout policy vary by deployment. KUMA 4.2 lists ONTAP 9.12 syslog normalization, but this synthetic pack has not been tested against that normalizer. No Elastic `sample_event.json` was used because the ONTAP vendor's EMS wire format is the reference for this pack.

## References

- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)
- [ONTAP 9.12.1 EMS syslog destination and message format](https://docs.netapp.com/us-en/ontap-cli-9121/event-notification-destination-create.html)
- [ONTAP 9.12.1 invalid login EMS message](https://docs.netapp.com/us-en/ontap-ems-9121/security-invalid-events.html)
- [ONTAP 9.12.1 lockout EMS message](https://docs.netapp.com/us-en/ontap-ems-9121/useradmin-lockedout-events.html)
- [ONTAP 9.12.1 ZAPI Snapshot success EMS message](https://docs.netapp.com/us-en/ontap-ems-9121/pdfs/fullsite-sidebar/ONTAP_9_12_1_EMS_reference.pdf)
- [NetApp EMS forwarding and filters](https://kb.netapp.com/on-prem/ontap/Ontap_OS/OS-KBs/Event_forwarding_to_a_Syslog_server)
