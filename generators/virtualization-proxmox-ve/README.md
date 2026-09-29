# Proxmox VE access and pveam logs

Synthetic Proxmox VE 7.x API proxy and appliance index update records, preserved in `event.original` with an ECS JSON wrapper. The profile represents one node, twelve VMs, six administrators, two automation accounts and an API-token monitor.

## Event types

About 12,240 records per day. Administrator requests concentrate at 08:00-18:00 UTC with a low overnight share. Automation and monitoring continue throughout the day. Normal sessions include ticket authentication and renewal, cluster/node/VM reads, occasional planned power changes and later restoration. The daily appliance index update starts between 01:00 and 06:00 UTC.

| Action | Approximate share | Category |
| --- | ---: | --- |
| `api-read` | 94.83% | API request |
| `ticket-issued` | 4.64% | Authentication |
| `ticket-denied` | 0.14% | Authentication |
| `vm-start-request` | 0.11% | VM operation |
| `vm-stop-request` | 0.06% | VM operation |
| `pveam-signature-verification` | 0.05% | Appliance index update |
| `vm-shutdown-request` | 0.05% | VM operation |
| `pveam-download-start` | 0.03% | Appliance index update |
| `pveam-download-finished` | 0.03% | Appliance index update |
| `vm-reboot-request` | 0.03% | VM operation |
| `pveam-update-successful` | 0.02% | Appliance index update |
| `pveam-update-start` | 0.01% | Appliance index update |

Password mistakes are uncommon and single mistakes are more frequent than repeated mistakes. Response sizes, session lengths and request rates are synthetic.

## Anomaly Chain

One automation-client address receives three HTTP 401 responses from `POST /api2/json/access/ticket`, then a 200 response from that endpoint and a successful `POST /api2/json/nodes/<node>/qemu/<vmid>/status/stop` within 30 minutes. Zero to four reads can occur before the stop. Correlate by `source.ip`; ticket requests have no authenticated username in the native log. `user.name` identifies the account on subsequent requests.

The first sequence starts within the smaller of 24 hours and the configured interval. Subsequent starts are centered on the previous actual start plus the interval, with a window width of `min(interval / 4, 6 hours)`. The two automation clients run around the clock, so episode hours are uniformly weighted. Consecutive episodes use different clients and VMs. Existing ordinary sessions continue independently. The stopped VM is restored using the same schedule as ordinary power changes, usually within minutes to an hour and occasionally longer.

`anomaly_mode: false` retains the individual request types and clients without the complete sequence. Enabling it adds one correlated sequence per episode. HTTP 200 on a power endpoint means the task was queued, not that the VM completed the operation. The synthetic scenario assumes the queued power requests succeed; task-status responses are outside this profile.

## Parameters

| Parameter | Default | Meaning |
| --- | --- | --- |
| `node_name` | `pve-01` | Node name in native API paths and ECS host fields |
| `anomaly_mode` | `true` | Include correlated authentication and stop requests |
| `anomaly_interval_hours` | `24` | Recurrence interval, from 6 to 8760 hours |

Edit these under `event.template.params` in `generator.yml`. The file output needs no credentials.

## Usage

```bash
eventum generate --path generators/virtualization-proxmox-ve/generator.yml --id proxmox --live-mode true
```

For a finite batch, set the same explicit UTC start/end dates in every `patterns/*.yml` oscillator, starting at midnight, then run:

```bash
eventum generate --path generators/virtualization-proxmox-ve/generator.yml --id proxmox-batch --live-mode false --keep-order true
```

Output is `output/events.json` relative to the generator directory. Replace the output block to send to a SIEM. Performance: about 2,290 events/second for a four-day batch on the development machine.

## Sample output

```json
{"@timestamp": "2026-09-01T03:13:28+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "vm-stop-request", "category": ["host"], "kind": "event", "original": "::ffff:10.20.1.22 - backup-ops@pve [01/09/2026:03:13:28 +0000] \"POST /api2/json/nodes/pve-01/qemu/101/status/stop HTTP/1.1\" 200 76", "outcome": "success", "type": ["change"]}, "host": {"name": "pve-01"}, "http": {"request": {"method": "POST"}, "response": {"body": {"bytes": 76}, "status_code": 200}, "version": "1.1"}, "log": {"file": {"path": "/var/log/pveproxy/access.log"}}, "proxmox": {"access": {"username": "backup-ops@pve"}}, "related": {"ip": ["10.20.1.22"], "user": ["backup-ops@pve"]}, "source": {"ip": "10.20.1.22"}, "url": {"path": "/api2/json/nodes/pve-01/qemu/101/status/stop"}, "user": {"name": "backup-ops@pve"}}
```

## Coverage and limits

- Native access records follow `<client> - <user> [%d/%m/%Y:%H:%M:%S %z] "<request line>" <status> <bytes>`. IPv4 clients appear as IPv4-mapped IPv6 addresses. The 13-byte HTTP 401 body corresponds to the older JSON error response. Releases from 2025 can include a larger error body. Read and ticket response sizes are illustrative; power-task response sizes include the corresponding UPID length.
- The selected source profile is Proxmox VE 7.x. Its appliance update uses `aplinfo-pve-7.dat`, the TurnKey index and `gpgv`; newer releases use different files and verification tools. Update failures are omitted. The host clock is UTC.
- Web console and websocket traffic, API-token creation, failed-login user names from pvedaemon, task-status polling, and cluster operations are omitted. Related appliance update messages are seconds apart rather than milliseconds. Native timestamps have one-second precision.
- ECS fields and action names are enrichment. They do not appear in the native lines. A failed new ticket request does not invalidate another existing ticket from the same client.

## References

- [pve-http-server `AnyEvent.pm` (access log format, 3 s delay on 401)](https://git.proxmox.com/?p=pve-http-server.git;a=blob;f=src/PVE/APIServer/AnyEvent.pm;hb=HEAD)
- [pve-http-server `Formatter/Standard.pm` (JSON error body)](https://git.proxmox.com/?p=pve-http-server.git;a=blob;f=src/PVE/APIServer/Formatter/Standard.pm;hb=HEAD)
- [pve-access-control `AccessControl.pm` (ticket endpoint)](https://github.com/proxmox/pve-access-control/blob/master/src/PVE/API2/AccessControl.pm)
- [pve-manager `APLInfo.pm` (pveam log)](https://github.com/proxmox/pve-manager/blob/master/PVE/APLInfo.pm)
- [pve-manager `pve-daily-update.timer`](https://github.com/proxmox/pve-manager/blob/master/services/pve-daily-update.timer)
- [Proxmox VE API authentication](https://pve.proxmox.com/wiki/Proxmox_VE_API#Authentication)
- [Proxmox forum: access log 401 line](https://forum.proxmox.com/threads/unexpected-authentication-failure-in-syslog.133011/)
- [Proxmox forum: pveam 7.x update log](https://forum.proxmox.com/threads/pveam-update-failed-gpgv-bad-signature.108652/)
