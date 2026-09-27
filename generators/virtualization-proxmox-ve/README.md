# Proxmox VE access and pveam logs

Synthetic Proxmox VE 7.x lines from the API proxy log `/var/log/pveproxy/access.log` and the appliance index update log `/var/log/pveam.log`, wrapped in ECS JSON, for testing detections of API login abuse and VM power changes on a Proxmox node.

Nine API clients run independent random sessions: ticket logins with occasional mistyped passwords and give-ups, ticket renewals, GUI/API reads, and VM start, stop, shutdown and reboot requests against twelve VMs whose power state is tracked. A monitoring API token polls without tickets. The daily `pveam` index update runs between 01:00 and 06:00 host time.

## Event Types

Shares are measured on a 120-hour `anomaly_mode: true` capture (27,231 events, four episodes).

| Action | Share | Category |
| --- | ---: | --- |
| `api-read` - authenticated `GET` of cluster, node or VM data | 94.59% | web |
| `ticket-issued` - `POST /api2/json/access/ticket`, HTTP 200 (login or renewal) | 3.19% | authentication |
| `ticket-denied` - `POST /api2/json/access/ticket`, HTTP 401 | 0.75% | authentication |
| `vm-start-request` - `POST .../qemu/<vmid>/status/start` | 0.52% | host |
| `vm-shutdown-request` - `POST .../qemu/<vmid>/status/shutdown` | 0.29% | host |
| `vm-stop-request` - `POST .../qemu/<vmid>/status/stop` | 0.24% | host |
| `vm-reboot-request` - `POST .../qemu/<vmid>/status/reboot` | 0.11% | host |
| `pveam-signature-verification` - gpgv output lines | 0.11% | package |
| `pveam-download-start` - `start download <url>` | 0.07% | package |
| `pveam-download-finished` - `download finished: 200 OK` | 0.07% | package |
| `pveam-update-successful` - `update successful` (per index source) | 0.04% | package |
| `pveam-update-start` - `starting update` | 0.02% | package |

Rates, session lengths and response sizes are synthetic; Proxmox publishes no frequency data.

## Anomaly Chain

One client address sends three `POST /api2/json/access/ticket` requests answered with HTTP 401, then one answered with HTTP 200, and then, as that client's user, zero to four reads followed by `POST /api2/json/nodes/<node>/qemu/<vmid>/status/stop` on a running VM. The session then continues like any other: reads and ticket renewals until it ends or a renewal fails. The stopped VM is started again later by any power-capable user who is logged in, which appears as `vm-start-request`.

- **Linking fields:** `source.ip` across all steps; `user.name` on the stop request (ticket requests log `-` as the user, because pveproxy fills the user field only after authentication); the VM id in `url.path`.
- **Timing:** gaps between attempts, requests and renewals and the session length come from the same model as ordinary sessions; measured spans from the first denial to the stop were 37-279 seconds.
- **Recurrence:** `anomaly_interval_hours` (default 24, minimum 6, maximum 8760). The first episode is due one interval after the generator starts. At each due time the episode starts after a random delay of up to `min(30 min, interval / 8)`, and waits for an idle power-capable client whose own next login is more than an hour away. The next due time is one interval after the actual start; missed episodes are not replayed.
- **Variation:** each episode uses a client and a running VM different from the previous episode's. All six power-capable clients and all twelve VMs also appear in ordinary traffic.
- **Background overlap:** ordinary traffic in both modes contains one to five denied logins by the same address seconds to minutes apart (about seven runs of three or more per day), logins that give up, renewal failures, successful logins followed by power requests, and stop requests by every chain user. Only the full ordered sequence is kept out of the background: an ordinary stop that would complete it within 30 minutes is replaced by a read.
- **Detection idea:** per `source.ip`, three or more HTTP 401 ticket responses followed by an HTTP 200 ticket response and a VM stop within 30 minutes. Sort by `@timestamp` first. A 401 on the ticket endpoint can also be an expired-ticket renewal, and HTTP 200 on the stop endpoint means that the task was queued, not that the VM halted.

`anomaly_mode` defaults to `true`. With `anomaly_mode: false` the generator produces only the background described above, with no complete chain.

## Parameters

### Event Parameters

| Name | Default | Description |
| --- | --- | --- |
| `node_name` | `pve-01` | Node name in API paths, task UPIDs and `host.name` |
| `anomaly_mode` | `true` | Add recurring anomaly chain episodes to the background |
| `anomaly_interval_hours` | `24` | Hours between episode due times (6-8760) |

### Output Parameters

The shipped config writes `output/events.json` and needs no connection parameters or secrets. To send events to a SIEM, replace the file output in a local copy and reference placeholders such as `${params.opensearch_host}` and `${secrets.opensearch_password}` in the chosen output plugin.

## Usage

```bash
eventum generate --path generators/virtualization-proxmox-ve/generator.yml --id proxmox --live-mode false
eventum generate --path generators/virtualization-proxmox-ve/generator.yml --id proxmox --live-mode true
```

Live mode emits one event at most per second. For a finite batch, add `start` and `end` to the `cron` input.

## Sample Output

The stop request of an episode, copied from the final `anomaly_mode: true` capture:

```json
{"@timestamp": "2026-09-21T00:06:36+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "vm-stop-request", "category": ["host"], "kind": "event", "original": "::ffff:10.20.1.22 - backup-ops@pve [21/09/2026:00:06:36 +0000] \"POST /api2/json/nodes/pve-01/qemu/110/status/stop HTTP/1.1\" 200 76", "outcome": "success", "type": ["change"]}, "host": {"name": "pve-01"}, "http": {"request": {"method": "POST"}, "response": {"body": {"bytes": 76}, "status_code": 200}, "version": "1.1"}, "log": {"file": {"path": "/var/log/pveproxy/access.log"}}, "proxmox": {"access": {"username": "backup-ops@pve"}}, "related": {"ip": ["10.20.1.22"], "user": ["backup-ops@pve"]}, "source": {"ip": "10.20.1.22"}, "url": {"path": "/api2/json/nodes/pve-01/qemu/110/status/stop"}, "user": {"name": "backup-ops@pve"}}
```

## Coverage and Limits

- **Access log.** Lines follow `log_request` in pve-http-server: `<client> - <user> [%d/%m/%Y:%H:%M:%S %z] "<request line>" <status> <bytes>`, with IPv4 clients shown as `::ffff:a.b.c.d`. The 401 body size of 13 bytes (`{"data":null}`) matches a 2023 forum capture; pve-http-server added an error message to JSON error bodies in January 2025, so newer releases log a larger size. Stop, start, shutdown and reboot sizes are the exact length of the returned task UPID. Ticket and read sizes are synthetic.
- **Not modeled.** Web GUI password logins through `/api2/extjs/access/ticket` (logged as HTTP 200 even when they fail), API token creation, console and websocket traffic, the pvedaemon syslog lines that name the user of a failed login, and task-status polling after power requests. One node, twelve VMs, no cluster.
- **pveam.** The 17-line update sequence follows `APLInfo.pm` and a 2022 Proxmox 7.x user log: both index sources (`aplinfo-pve-7.dat`, then TurnKey), gpgv output, one `update successful` per source. Failures are not modeled. Current releases use `sqv` and newer index files, so this part is pinned to 7.x. pveam timestamps have no zone; the generator assumes the host clock is UTC.
- **Timing.** Timestamps have one-second resolution like the native lines. The generator emits at most one event per one-second input tick; events due close together, such as the 17 lines of one pveam update, are written on consecutive ticks but keep their own timestamps, so output order and timestamps stay consistent.
- **Mapping.** ECS fields repeat values from the native line only; `event.action` names are this pack's labels.

## References

- [pve-http-server `AnyEvent.pm` (access log format, 3 s delay on 401)](https://git.proxmox.com/?p=pve-http-server.git;a=blob;f=src/PVE/APIServer/AnyEvent.pm;hb=HEAD)
- [pve-http-server `Formatter/Standard.pm` (JSON error body)](https://git.proxmox.com/?p=pve-http-server.git;a=blob;f=src/PVE/APIServer/Formatter/Standard.pm;hb=HEAD)
- [pve-access-control `AccessControl.pm` (ticket endpoint)](https://github.com/proxmox/pve-access-control/blob/master/src/PVE/API2/AccessControl.pm)
- [pve-manager `APLInfo.pm` (pveam log)](https://github.com/proxmox/pve-manager/blob/master/PVE/APLInfo.pm)
- [pve-manager `pve-daily-update.timer`](https://github.com/proxmox/pve-manager/blob/master/services/pve-daily-update.timer)
- [Proxmox VE API authentication](https://pve.proxmox.com/wiki/Proxmox_VE_API#Authentication)
- [Proxmox forum: access log 401 line](https://forum.proxmox.com/threads/unexpected-authentication-failure-in-syslog.133011/)
- [Proxmox forum: pveam 7.x update log](https://forum.proxmox.com/threads/pveam-update-failed-gpgv-bad-signature.108652/)
