# Proxmox VE access and pveam logs

Synthetic native lines from `/var/log/pveproxy/access.log` and `/var/log/pveam.log`, modeled on Proxmox source code and user-submitted Proxmox 7.x log examples.

## Event Types

| Action | Baseline frequency | Category |
| --- | ---: | --- |
| `api-read` - VM status or configuration GET | 88% of routine access picks | web |
| `ticket-issued` - Ticket endpoint HTTP 200 | 12% of routine access picks; chain | authentication |
| `ticket-denied` - Ticket endpoint HTTP 401 | Chain only | authentication |
| `vm-stop-request` - VM stop API HTTP 200 | Chain only | host |
| `pveam-start` - Update started | Scheduled baseline cycle | package |
| `pveam-download` - Signature file download requested | Scheduled baseline cycle | package |
| `pveam-finished` - Signature file download HTTP 200 | Scheduled baseline cycle | package |
| `pveam-download-data` - Data file download requested | Scheduled baseline cycle | package |
| `pveam-finished-data` - Data file download HTTP 200 | Scheduled baseline cycle | package |
| `pveam-signature` - Good signature recorded | Scheduled baseline cycle | package |
| `pveam-success` - Update successful | Scheduled baseline cycle | package |

Baseline percentages are synthetic weights, not measured vendor frequencies.

## Anomaly Chain

Three HTTP 401 responses for `POST /api2/json/access/ticket` from `192.0.2.91`, then HTTP 200 for the same endpoint, then an authenticated `POST /api2/json/nodes/pve-01/qemu/103/status/stop` from that IP as `ops@pam`. Correlate ticket attempts by source IP and time, then use the authenticated username on the stop request. The ticket endpoint does not expose a username in `access.log`, and HTTP 200 on the stop endpoint means request acceptance, not proven VM shutdown. Sort by `@timestamp` before applying the sequence; file line order is not guaranteed. Failed ticket requests can also be benign renewal failures.

`anomaly_mode` defaults to `true`. Set `event.template.params.anomaly_mode: false` for background activity only.

## Parameters

### Event Parameters

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include the API ticket and VM stop sequence |
| `node_name` | `pve-01` | Proxmox node in API paths |
| `suspect_ip` | `192.0.2.91` | Source IP in the sequence |
| `suspect_user` | `ops@pam` | Authenticated API user on the stop request |
| `target_vmid` | `103` | VM ID in the stop request |

### Output Parameters

The shipped config writes `output/events.json` and needs no connection parameters or secrets. To send to a SIEM, replace the file output in a local copy and add `${params.siem_host}` and `${secrets.siem_token}` for the selected output plugin where applicable.

## Usage

```bash
eventum generate --path generators/virtualization-proxmox-ve/generator.yml --id proxmox --live-mode false
eventum generate --path generators/virtualization-proxmox-ve/generator.yml --id proxmox --live-mode true
```

## Sample Output

This event was copied from an `anomaly_mode: true` generator run.

```json
{
  "@timestamp": "2026-09-25T12:59:19+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "vm-stop-request",
    "category": [
      "host"
    ],
    "kind": "event",
    "original": "::ffff:192.0.2.91 - ops@pam [25/Sep/2026:12:59:19 +0000] \"POST /api2/json/nodes/pve-01/qemu/103/status/stop HTTP/1.1\" 200 121",
    "outcome": "success",
    "type": [
      "change"
    ]
  },
  "host": {
    "name": "pve-01"
  },
  "http": {
    "request": {
      "method": "POST"
    },
    "response": {
      "body": {
        "bytes": 121
      },
      "status_code": 200
    }
  },
  "log": {
    "file": {
      "path": "/var/log/pveproxy/access.log"
    }
  },
  "proxmox": {
    "access": {
      "username": "ops@pam"
    }
  },
  "related": {
    "ip": [
      "192.0.2.91"
    ],
    "user": [
      "ops@pam"
    ]
  },
  "source": {
    "ip": "192.0.2.91"
  },
  "url": {
    "path": "/api2/json/nodes/pve-01/qemu/103/status/stop"
  },
  "user": {
    "name": "ops@pam"
  }
}
```

## Coverage and Limits

The seven pveam line forms and timestamps follow the Proxmox implementation and a 2022 user-submitted Proxmox 7.x log; pveproxy access examples are user-submitted logs on the Proxmox forum. Current Proxmox source uses newer catalog versions and a different signature verifier, so this pack is pinned to the 7.x-style pveam variant. KUMA 4.2 lists Proxmox 7.2-3 and file collection; test other versions with the target parser. Access lines preserve client, identity, user, timestamp, request, status and size; pveam lines preserve local timestamp and message (10/10 selected raw fields). The pveam timestamp has no timezone; output assumes the host is UTC.

## References

- [Proxmox pveproxy source](https://github.com/proxmox/pve-manager/blob/master/PVE/Service/pveproxy.pm)
- [Proxmox pveam source](https://github.com/proxmox/pve-manager/blob/master/PVE/APLInfo.pm)
- [Proxmox forum access examples](https://forum.proxmox.com/threads/unexpected-authentication-failure-in-syslog.133011/)
- [Proxmox forum pveam 7.x sample](https://forum.proxmox.com/threads/pveam-update-failed-gpgv-bad-signature.108652/)
- [KUMA 4.2 source catalog](https://support.kaspersky.ru/kuma/4.2/255782)
