# VMware vCenter vpxd Events

Generates VMware vCenter Server 8.0 `vpxd` events forwarded over remote syslog (RFC 5424, UDP) and indexed by Elastic Agent's VMware vSphere integration (`vsphere.log`). `event.original` holds the native syslog line; the other fields are what the integration's ingest pipeline derives from it plus the collector metadata Elastic Agent adds.

One vCenter (`vcsa01.lab.example`) manages one datacenter with twelve VMs on three ESXi hosts. Four service accounts call the vSphere API around the clock: a monitoring poller, a metrics collector, an orchestration account and a backup account. Eight staff accounts (four administrators, two helpdesk operators, two developers) log in during the working day, sometimes after mistyping the password, power-cycle VMs, change their CPU or memory in short maintenance windows, and grant or remove temporary permissions.

## Volume and Timing

About 8,100 records per day, ±3% from day to day. Service accounts produce about 7,900 of them at a flat rate; staff produce about 220, following a UTC working-day curve:

| UTC hours | Share of staff activity |
|---|---:|
| 07-17 | 90% |
| 06-07, 17-19 | 6% |
| 19-06 (on-call work, even rate) | 4% |

Service accounts log in and out every few seconds to minutes: the monitoring poller about 2,300 times a day, the metrics collector about 970, the orchestration account about 390 and the backup account about 200. Staff members log in about 3-17 times a day each (administrators most). A staff session lasts a median 10-12 minutes (90th percentile about 30 minutes); a monitoring poller session a median 14 s, a metrics collector session about 2 minutes, a backup session about 10 minutes.

Records of one session follow each other seconds to minutes apart: wrong passwords a median 12 s apart, the first operation a median 1 minute after login, maintenance steps 30-45 s apart. The syslog header trails the event's `createdTime` by a median 0.5 ms (rarely up to 2.5 s); `event.ingested` is 0.2-30 s later and in whole seconds.

## Event Types Covered

Shares over four days of a default run (`anomaly_mode: true`); the last column shows the same share in four-day runs without anomalies.

| Native class | Share | Background | ECS fields from the pipeline | Meaning |
|---|---:|---:|---|---|
| `vim.event.UserLoginSessionEvent` | 49.26% | 49.15-49.35% | `event.action: login`, `event.outcome: success`, `user.*`, `source.ip`, `user_agent.*` | API session opened |
| `vim.event.UserLogoutSessionEvent` | 49.24% | 49.15-49.35% | as login, plus `event.start`/`end`/`duration`, `vsphere.log.api.invocations` | Session closed: login time and number of API calls |
| `vim.event.VmPoweredOffEvent` | 0.55% | 0.50-0.65% | — | VM powered off |
| `vim.event.VmPoweredOnEvent` | 0.55% | 0.50-0.65% | — | The same VM powered on again |
| `vim.event.VmReconfiguredEvent` | 0.17% | 0.15-0.21% | — | `numCPU` or `memoryMB` changed while the VM is off |
| `vim.event.EventEx` (failed SSO login) | 0.11% | 0.05-0.09% | `event.outcome: failure`, `user.name`, `source.ip` (no `event.action`) | Wrong password for a staff account |
| `vim.event.PermissionAddedEvent` | 0.08% | 0.07-0.11% | — | Temporary permission created |
| `vim.event.PermissionRemovedEvent` | 0.04% | 0.03-0.05% | — | Expired permission removed |

For VM and permission events the vSphere pipeline only splits the syslog envelope, so the acting account, VM and principal are in `message` and `event.original`, not in `user.*` or `event.action`.

- Failed logins: 7% of staff sessions start with one to five wrong passwords, each extra failure rarer than the previous one (45 : 15 : 6 : 3 : 1); 12% of those end without a login. That is 5-10% of staff login attempts; service accounts never fail. Runs of three or more failures before a login happen a few times a week.
- VM work: administrators and operators power-cycle any VM or run maintenance (power off, change `numCPU` or `memoryMB` one step on the 1-16 CPU or 2-64 GB ladder, power on); developers power-cycle test and batch VMs; the orchestration account occasionally recycles a batch VM. Every VM powered off is powered on again in the same session.
- Permissions: administrators grant roles `ReadOnly` (30%), `VirtualMachinePowerUser` (25%), `Admin` (25%), `VirtualMachineUser` (15%) and `ResourcePoolAdministrator` (5%) to eight principals on the datacenter, two clusters, three folders or two VMs, about six grants a day (one or two of them `Admin`). Grants are temporary: after a median 36 hours (2 hours to 14 days) an administrator removes the expired permission in a later session. There is at most one permission per principal and entity.

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the generator writes only the background described above and never the complete chain.

Sequence for one administrator account within 30 minutes (typically 1-8 minutes from the first failure to the grant):

1. Three to five failed SSO logins for the administrator's name from the administrator's own address (`vim.event.EventEx`, `Failed login <name> from <ip> ... in SSO`), seconds apart.
2. A successful login of that administrator from the same address (`UserLoginSessionEvent`).
3. As the first operation of that session, a `PermissionAddedEvent` by the same administrator granting role `Admin` to a principal on an inventory object.

The session may continue with further ordinary operations and ends with a logout, like any administrator session.

Linking fields: the user name (`user.name` on the authentication records; the first bracket of `message` on the permission record, `DOMAIN\name`), `source.ip`, and the principal, entity and role in the permission message.

Volume: episodes do not change the event volume or the hour curve; an episode's five to ten records take the place of as many ordinary records out of about 8,100 a day. The episode is a normal session of an administrator who has no session open at that moment; that administrator's own sessions before and after it keep their usual timing.

Restoration: the episode's `Admin` grant is temporary like every other grant and is removed by an administrator after the same lease (median 36 hours); a grant made near the end of a run can still be in place when it ends.

Recurrence: `anomaly_interval_hours` (default 24, minimum 6, maximum 8760), counted in event time. The first episode starts within the first min(interval, 24 h). Each later episode is due one interval after the actual previous start and starts at a random time in a window of w = min(interval / 4, 6 h) centred on the due time. Start times in both cases are weighted by the square of the staff hour curve plus a small floor, so episodes fall mostly into office hours; missed time is never caught up. Consecutive starts are 21-27 h apart at the default interval. At intervals of 8 h or less the start times necessarily cover the whole clock, including night hours.

Variation: the administrator is drawn with the same weights as background activity among administrators with no session open, never the previous episode's; the principal is never the previous episode's principal; the number of failures (3-5) follows the tail of the background failure law.

Background overlap: every element occurs in ordinary traffic in both modes: failed logins of every administrator from their own address, runs of three or more failures followed by a login, and `Admin` grants by all four administrators (one or two a day). Only the full sequence is absent from background. With `anomaly_mode: true` each episode adds its own run of failures, login and `Admin` grant, so these counts are about one per episode higher than in background alone.

Detection idea: three or more failed SSO logins for one account, then a successful login of that account from the same address, then a permission with role `Admin` created by that account, all within 30 minutes.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Name | Default | Description |
|---|---|---|
| `anomaly_mode` | `true` | Emit recurring anomaly episodes; `false` gives background only |
| `anomaly_interval_hours` | `24` | Interval between episodes in event time (6-8760) |
| `vcenter_host` | `vcsa01.lab.example` | vCenter hostname in the syslog header (`host.name`) |
| `vcenter_ip` | `10.40.0.10` | Address the syslog datagrams come from (`log.source.address`) |
| `datacenter` | `DC-East` | Datacenter name in VM and permission messages |
| `sso_domain` | `VSPHERE.LOCAL` | SSO domain of all accounts and principals |
| `collector_name` | `log-collector-01.lab.example` | Elastic Agent host (`agent.name`, `host.hostname`) |
| `collector_ip` | `10.40.0.50` | Elastic Agent host address |
| `collector_mac` | `00-50-56-A1-7B-10` | Elastic Agent host MAC address |
| `collector_host_id` | `3f0b6c1e2d9a4c7f8e5b1a2d3c4e5f60` | Elastic Agent host id |
| `agent_id` | `5096d7cc-1e4b-4959-abea-7355be2913a7` | Elastic Agent id |
| `agent_ephemeral_id` | `c4a1df82-7a9c-4a3e-8546-6d7cc04538e6` | Elastic Agent ephemeral id |
| `agent_version` | `8.17.0` | Elastic Agent version |

Accounts and their addresses, VMs, principals and permission entities are in `samples/users.json`, `samples/vms.json`, `samples/principals.json` and `samples/entities.json`.

### Output Parameters

The shipped `generator.yml` writes `output/events.json`. To deliver elsewhere, replace the file output with another output plugin and put endpoint settings in top-level `${params.*}` placeholders and credentials in `${secrets.*}`, for example `hosts: ["${params.opensearch_host}"]` and `password: ${secrets.opensearch_password}`.

## Usage

Live generation at the configured rate:

```bash
eventum generate --path generators/virtualization-vmware/generator.yml --id vmware --live-mode true
```

Batch generation: set `start` and `end` of the `oscillator` in all four `patterns/*.yml` files to the same range, with `start` at 00:00 UTC so the hour bands stay in place (for example `start: "2026-09-01T00:00:00Z"` and `end: "2026-09-05T00:00:00Z"`), then run:

```bash
eventum generate --path generators/virtualization-vmware/generator.yml --id vmware --live-mode false --keep-order true
```

The volume is the sum of the `time_patterns` files under `patterns/`: `automation` (service accounts, 00-24 UTC) and the three staff files `staff-night` (00-24), `staff-extended` (06-19) and `staff-office` (07-17). To change the volume, scale the `ratio` of the files; episode start hours follow the shipped staff curve even if you reshape the files.

Performance: about 3,900 events per second in batch mode on one core.

## Sample Output

The first failed login and the `Admin` grant of the first episode of a default run:

```json
{"@timestamp": "2026-09-01T11:00:13.646Z", "agent": {"ephemeral_id": "c4a1df82-7a9c-4a3e-8546-6d7cc04538e6", "id": "5096d7cc-1e4b-4959-abea-7355be2913a7", "name": "log-collector-01.lab.example", "type": "filebeat", "version": "8.17.0"}, "client": {"ip": "10.40.3.22"}, "data_stream": {"dataset": "vsphere.log", "namespace": "default", "type": "logs"}, "ecs": {"version": "8.11.0"}, "elastic_agent": {"id": "5096d7cc-1e4b-4959-abea-7355be2913a7", "snapshot": false, "version": "8.17.0"}, "event": {"agent_id_status": "verified", "category": ["authentication"], "dataset": "vsphere.log", "id": "674988", "ingested": "2026-09-01T11:00:14Z", "kind": "event", "original": "\u003c14\u003e1 2026-09-01T11:00:13.646579+00:00 vcsa01.lab.example vpxd 36683 - -  Event [674988] [1-1] [2026-09-01T11:00:13.646479Z] [vim.event.EventEx] [info] [ops.petrova] [] [674988] [Failed login ops.petrova from 10.40.3.22 at 09/01/2026 11:00:13 GMT in SSO]", "outcome": "failure", "timezone": "+00:00", "type": ["info"]}, "host": {"architecture": "x86_64", "containerized": false, "hostname": "log-collector-01.lab.example", "id": "3f0b6c1e2d9a4c7f8e5b1a2d3c4e5f60", "ip": ["10.40.0.50"], "mac": ["00-50-56-A1-7B-10"], "name": "vcsa01.lab.example", "os": {"codename": "jammy", "family": "debian", "kernel": "5.15.0-122-generic", "name": "Ubuntu", "platform": "ubuntu", "type": "linux", "version": "22.04.5 LTS (Jammy Jellyfish)"}}, "input": {"type": "udp"}, "log": {"level": "info", "logger": "vim.event.EventEx", "source": {"address": "10.40.0.10:59236"}, "syslog": {"facility": {"code": 1, "name": "User"}, "priority": 14, "severity": {"code": 6, "name": "Informational"}}}, "message": "[ops.petrova] [] [674988] [Failed login ops.petrova from 10.40.3.22 at 09/01/2026 11:00:13 GMT in SSO]", "process": {"name": "vpxd", "pid": 36683}, "related": {"ip": ["10.40.3.22"]}, "source": {"ip": "10.40.3.22"}, "tags": ["preserve_original_event", "vmware-sphere"], "user": {"name": "ops.petrova"}}
{"@timestamp": "2026-09-01T11:06:41.733Z", "agent": {"ephemeral_id": "c4a1df82-7a9c-4a3e-8546-6d7cc04538e6", "id": "5096d7cc-1e4b-4959-abea-7355be2913a7", "name": "log-collector-01.lab.example", "type": "filebeat", "version": "8.17.0"}, "data_stream": {"dataset": "vsphere.log", "namespace": "default", "type": "logs"}, "ecs": {"version": "8.11.0"}, "elastic_agent": {"id": "5096d7cc-1e4b-4959-abea-7355be2913a7", "snapshot": false, "version": "8.17.0"}, "event": {"agent_id_status": "verified", "dataset": "vsphere.log", "id": "675058", "ingested": "2026-09-01T11:06:43Z", "kind": "event", "original": "\u003c14\u003e1 2026-09-01T11:06:41.733321+00:00 vcsa01.lab.example vpxd 36683 - -  Event [675058] [1-1] [2026-09-01T11:06:41.73214Z] [vim.event.PermissionAddedEvent] [info] [VSPHERE.LOCAL\\ops.petrova] [DC-East] [675058] [Permission created for VSPHERE.LOCAL\\contractor.lee on Cluster-Dev, role is Admin, propagation is Enabled]", "timezone": "+00:00"}, "host": {"architecture": "x86_64", "containerized": false, "hostname": "log-collector-01.lab.example", "id": "3f0b6c1e2d9a4c7f8e5b1a2d3c4e5f60", "ip": ["10.40.0.50"], "mac": ["00-50-56-A1-7B-10"], "name": "vcsa01.lab.example", "os": {"codename": "jammy", "family": "debian", "kernel": "5.15.0-122-generic", "name": "Ubuntu", "platform": "ubuntu", "type": "linux", "version": "22.04.5 LTS (Jammy Jellyfish)"}}, "input": {"type": "udp"}, "log": {"level": "info", "logger": "vim.event.PermissionAddedEvent", "source": {"address": "10.40.0.10:59236"}, "syslog": {"facility": {"code": 1, "name": "User"}, "priority": 14, "severity": {"code": 6, "name": "Informational"}}}, "message": "[VSPHERE.LOCAL\\ops.petrova] [DC-East] [675058] [Permission created for VSPHERE.LOCAL\\contractor.lee on Cluster-Dev, role is Admin, propagation is Enabled]", "process": {"name": "vpxd", "pid": 36683}, "tags": ["preserve_original_event", "vmware-sphere"]}
```

## Limitations

- Only eight vpxd event classes are present. A real vCenter also logs tasks, alarms, host and cluster events, `PermissionUpdatedEvent`, `BadUsernameSessionEvent` and many more; native event keys skip values as if those events were there, but the events themselves are absent.
- Authentication records (login, logout, failed SSO login) follow the Elastic vSphere integration fixtures field for field. No raw vpxd syslog line of a VM power, reconfiguration or permission event was available: those messages use the vCenter event catalog wording (`Permission created for ... role is ..., propagation is ...`, `Permission rule removed for ...`, `... is powered on/off`, `Reconfigured ...`), and the entity bracket carries the datacenter name.
- The reconfiguration message lists the changed setting on one line (`Modified: config.hardware.numCPU: 2 -> 4;`); vCenter writes the change list over several lines with `Added:` and `Deleted:` sections, and only CPU and memory changes appear.
- Role names are the internal vCenter names (`Admin`, `ReadOnly`, `VirtualMachinePowerUser`, ...), not the labels the vSphere Client shows.
- Every account connects with user agent `Go-http-client/1.1`; there are no vSphere Client browser sessions, PowerCLI or other client software, and every account uses one fixed address.
- Records of one session are seconds apart rather than milliseconds: a monitoring poller session that lasts well under a second on a real vCenter here lasts a median 14 s, and its logout `event.duration` reflects that.
- `chainId` equals the event key for logins and permissions; for VM events it points to a preceding key that stands for the task event, which is not included.
- `agent`, `elastic_agent`, `host.*` (except `host.name`), `log.source.address` and `event.agent_id_status` describe a synthetic Elastic Agent collector; the vpxd process id and the UDP source port stay the same for a whole run.
- The hour curve is in UTC and repeats every day: there is no weekly cycle, so weekends look like weekdays.
- With `anomaly_mode: true` each episode adds its own run of three to five failed logins, a login and an `Admin` grant, so runs of three or more failures before a login are about one a day more frequent than the few a week of background, and `Admin` grants rise from one or two a day to two or three. A 6-hour interval makes these about four times higher.

## References

- [Elastic VMware vSphere integration: `vsphere.log` ingest pipelines, fields, sample event and test fixtures](https://github.com/elastic/integrations/tree/main/packages/vsphere/data_stream/log)
- [vCenter Server 8.0 Update 2 event catalog](https://github.com/lamw/vcenter-event-mapping/blob/master/vsphere-8.0u2.md)
- [VMware vSphere event message catalog (`event.vmsg`)](https://github.com/akutz/simdk/blob/master/ws/src/main/webapp/catalog/en/event.vmsg)
- [govmomi vCenter simulator event templates](https://github.com/vmware/govmomi/blob/v0.46.3/simulator/esx/event_manager.go)
- [Broadcom KB 422164: reconfiguration events with `Modified:` settings](https://knowledge.broadcom.com/external/article/422164)
