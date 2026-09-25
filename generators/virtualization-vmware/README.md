# VMware vSphere vCenter Event Log Generator

Produces ECS JSON for vCenter `vpxd` events forwarded through syslog. The stream models one vCenter with a ten-VM routine inventory. Each event preserves a vCenter-style syslog record in `event.original` and exposes the event class, key, actor, client IP when logged, and VM or permission target for SIEM correlation.

## Event Types

| vCenter class | Event | Routine frequency | Category |
|---|---|---:|---|
| `UserLoginSessionEvent` | Successful login | 38% | Authentication |
| `UserLogoutSessionEvent` | Logout | 32% | Authentication |
| `VmPoweredOnEvent` | VM powered on | 15% | Host |
| `VmPoweredOffEvent` | VM powered off | 10% | Host |
| `VmReconfiguredEvent` | VM reconfigured | 5% | Configuration |
| `EventEx` | Failed SSO login | Chain only | Authentication |
| `PermissionAddedEvent` | Administrator permission added | Chain only | IAM |

These routine weights are synthetic defaults, not measured production rates. One emitting template handles the common `vpxd` syslog envelope; FSM states provide the correlation. With `anomaly_mode: true`, an eight-event chain follows every 250 routine events.

## Anomaly Chain

Four failed SSO logins for different principals arrive from `10.99.6.44`, followed by a successful `VSPHERE.LOCAL\Administrator` login from the same address. The actor grants the `Administrator` role on `DC-East` to `VSPHERE.LOCAL\svc_backup`, reconfigures `prod-db-01`, and powers that VM off. The class names, event key shape, and login log syntax follow the vCenter/Elastic references. Free-text descriptions of the permission and VM changes are synthetic, because vCenter's `fullFormattedMessage` is not a fixed wire format.

Detection ideas: multiple failed SSO logins from one IP followed by an Administrator session; an Administrator permission grant after that session; a permission grant followed by a production VM reconfiguration and power-off by the same actor. Join the login events on `source.ip`, the later events on `user.name` and time, and the VM events on `vsphere.event.vm.id`. The numeric `event.id` increases across the single vCenter stream. With `anomaly_mode: false`, none of the failed-login, permission-grant, attacker-IP, or `prod-db-01` steps is emitted.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
|---|---|---|
| `vcenter_host` | `vcsa01.lab.example` | vCenter hostname |
| `vcenter_ip` | `10.40.0.10` | vCenter address and syslog sender |
| `vcenter_mac` | `00-50-56-A1-3F-2C` | Synthetic host MAC |
| `vcenter_id` | `7c49a8e2c6244517b5572cfd43e91a0a` | Stable host ID |
| `datacenter` | `DC-East` | Datacenter in vCenter events |
| `domain` | `VSPHERE.LOCAL` | SSO domain |
| `agent_id` | `5096d7cc-1e4b-4959-abea-7355be2913a7` | Stable collector ID |
| `agent_ephemeral_id` | `c4a1df82-7a9c-4a3e-8546-6d7cc04538e6` | Collector session ID |
| `agent_version` | `8.17.0` | Filebeat version in ECS envelope |
| `attack_ip` | `10.99.6.44` | Source of the correlated login attempts |
| `attack_user` | `Administrator` | SSO account that logs in |
| `granted_principal` | `VSPHERE.LOCAL\svc_backup` | Recipient of Administrator permission |
| `critical_vm` | `prod-db-01` | VM reconfigured and powered off |
| `anomaly_mode` | `true` | Emit the chain; `false` emits only routine events |
| `ecs_version` | `8.11.0` | ECS version in output |

Routine users and VM inventory are in `samples/users.json` and `samples/vms.json`.

### Output Parameters

The shipped generator writes `output/events.json` and needs no output parameters or secrets. To send events to OpenSearch, replace the output block and provide these substitutions:

```yaml
output:
  - opensearch:
      hosts:
        - ${params.opensearch_host}
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: ${params.opensearch_index}
```

| Placeholder | Purpose |
|---|---|
| `${params.opensearch_host}` | OpenSearch URL |
| `${params.opensearch_user}` | User name |
| `${secrets.opensearch_password}` | Password from the Eventum keyring |
| `${params.opensearch_index}` | Target index |

## Usage

Run from the content-packs repository root:

```bash
# Bounded batch sample
timeout 2 eventum generate --path generators/virtualization-vmware/generator.yml --id vsphere --live-mode false

# Live stream, five events per second
eventum generate --path generators/virtualization-vmware/generator.yml --id vsphere --live-mode true
```

Set `anomaly_mode: false` in `generator.yml` for background-only generation. Batch sample mode continues until interrupted; the timeout bounds its output.

## Sample Output

This complete permission event was copied from an anomaly-enabled generator run:

```json
{"@timestamp": "2026-09-25T10:42:40+00:00", "agent": {"ephemeral_id": "c4a1df82-7a9c-4a3e-8546-6d7cc04538e6", "id": "5096d7cc-1e4b-4959-abea-7355be2913a7", "name": "vcsa01.lab.example", "type": "filebeat", "version": "8.17.0"}, "data_stream": {"dataset": "vsphere.log", "namespace": "default", "type": "logs"}, "ecs": {"version": "8.11.0"}, "elastic_agent": {"id": "5096d7cc-1e4b-4959-abea-7355be2913a7", "snapshot": false, "version": "8.17.0"}, "event": {"action": "permission-added", "agent_id_status": "verified", "category": ["iam"], "dataset": "vsphere.log", "id": "576047", "ingested": "2026-09-25T10:42:40+00:00", "kind": "event", "original": "\u003c14\u003e1 2026-09-25T10:42:40+00:00 vcsa01.lab.example vpxd 58650 - -  Event [576047] [1-1] [2026-09-25T10:42:40.000000Z] [vim.event.PermissionAddedEvent] [info] [VSPHERE.LOCAL\\Administrator] [DC-East] [576047] [Permission added for VSPHERE.LOCAL\\svc_backup on DC-East with role Administrator by VSPHERE.LOCAL\\Administrator]", "outcome": "success", "timezone": "+00:00", "type": ["change"]}, "host": {"architecture": "x86_64", "containerized": false, "hostname": "vcsa01.lab.example", "id": "7c49a8e2c6244517b5572cfd43e91a0a", "ip": ["10.40.0.10"], "mac": ["00-50-56-A1-3F-2C"], "name": "vcsa01.lab.example", "os": {"family": "linux", "kernel": "5.10.0", "name": "VMware Photon OS", "platform": "photon", "type": "linux", "version": "5.0"}}, "input": {"type": "udp"}, "log": {"level": "info", "logger": "vim.event.PermissionAddedEvent", "source": {"address": "10.40.0.10:59146"}, "syslog": {"priority": 14}}, "message": "Permission added for VSPHERE.LOCAL\\svc_backup on DC-East with role Administrator by VSPHERE.LOCAL\\Administrator", "process": {"name": "vpxd", "pid": 58650}, "related": {"user": ["Administrator", "svc_backup"]}, "tags": ["preserve_original_event", "vmware-sphere"], "user": {"domain": "VSPHERE.LOCAL", "name": "Administrator"}, "vsphere": {"event": {"class": "vim.event.PermissionAddedEvent", "created_time": "2026-09-25T10:42:40.000000Z", "key": 576047, "permission": {"entity": "DC-East", "principal": "VSPHERE.LOCAL\\svc_backup", "role": "Administrator"}, "user_name": "VSPHERE.LOCAL\\Administrator"}}}
```

## References and Scope

The [Elastic vSphere integration](https://www.elastic.co/docs/reference/integrations/vsphere) collects remote syslog and supplies the [`vsphere.log` sample event](https://github.com/elastic/integrations/blob/main/packages/vsphere/data_stream/log/sample_event.json), [raw fixture](https://github.com/elastic/integrations/blob/main/packages/vsphere/data_stream/log/_dev/test/pipeline/test-format-common.log), and [ingest pipeline](https://github.com/elastic/integrations/blob/main/packages/vsphere/data_stream/log/elasticsearch/ingest_pipeline/default.yml). The raw fixture provides the `vpxd` `Event [key]` envelope and login/failed-login examples. Broadcom documents [base event fields](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.event.Event.html), [login sessions](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.event.UserLoginSessionEvent.html), [permission changes](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.event.PermissionAddedEvent.html), and [VM reconfiguration](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.event.VmReconfiguredEvent.html).

Validation covered 38 of 39 leaf fields in Elastic's `vsphere.log` sample event. The omitted `host.os.codename` belongs to Elastic's test-container host metadata and has no appropriate Photon OS value. The generator models vCenter `vpxd` events; ESXi hostd/vmkernel, appliance-management audit, and metrics are separate streams.
