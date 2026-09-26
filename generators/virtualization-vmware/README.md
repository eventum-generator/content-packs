# VMware vCenter vpxd Events

ECS JSON with an embedded RFC5424 `event.original` for a selected vCenter remote-syslog event stream. Models nine existing SSO identities and eleven VMs, including stateful sessions, temporary permissions, configured CBT changes and power transitions. This profile excludes ESXi hostd, SOAP responses, metrics, tasks and additional SSO service logs.

## Generation Modes

- **Background logs:** `anomaly_mode: false`. Completed administrative and service workflows with isolated failed SSO retries.
- **Contains anomaly:** `anomaly_mode: true` (default). The same background plus recurring authentication, privilege and VM-change chains. `anomaly_interval_hours: 24` by default.

Both modes use the same identities, peers, VM inventory and eight event classes. The configured `attack_user`, `attack_ip`, `granted_principal` and `critical_vm` also participate in ordinary activity. No event contains an episode flag or an incident identifier. Detect the sequence of actions and timing, rather than matching a reserved username or IP.

## Event Types

| Native class | ECS action | Category | Meaning |
|---|---|---|---|
| `UserLoginSessionEvent` | `login` | authentication | Accepted login and stored start/peer |
| `UserLogoutSessionEvent` | `logout` | authentication | Logout of the same current session, stored login time and API call count |
| `EventEx` | `login` | authentication | Failed SSO login, informational syslog severity as in the maintained fixture |
| `PermissionAddedEvent` | `permission-added` | iam | Authorized temporary propagated Administrator permission on the selected datacenter |
| `PermissionRemovedEvent` | `permission-removed` | iam | Removal of that existing direct permission |
| `VmReconfiguredEvent` | `vm-reconfigured` | configuration | Actual transition of the modeled configured `changeTrackingEnabled` flag |
| `VmPoweredOffEvent` | `vm-powered-off` | host | Powered-on VM becomes powered-off |
| `VmPoweredOnEvent` | `vm-powered-on` | host | Powered-off VM becomes powered-on |

At each free workflow boundary, background weights are 55 for a query session, 15 for a CBT disable/enable session, 15 for a power-off/on session, 10 for grant/use/revoke maintenance and 5 for an isolated failed SSO attempt followed by a successful retry. These are workflow weights, not event percentages. Workflows produce 2, 4, 4, 12 and 3 records respectively.

Temporary-permission maintenance includes the recipient's CBT disable, power-off, CBT restore and power-on before another authorized administrator revokes the grant. Ordinary failed SSO attempts are globally separated by at least 15 minutes. Every completed workflow releases its session and restores its changes.

## Periodic Anomaly Chain

Times are offsets from the episode's actual start. One record is emitted per minute.

| Minute | Visible behavior |
|---|---|
| 0–3 | Four distinct existing usernames fail SSO from the same peer |
| 4 | An existing administrator logs in successfully |
| 5–6 | That administrator grants the existing backup principal Administrator on the datacenter, then logs out |
| 7–10 | Recipient logs in, changes configured CBT `true -> false`, powers off the same VM, then logs out |
| 11–14 | Ordinary monitor login/logout activity |
| 15–19 | A different authorized administrator logs in, restores configured CBT, powers on the VM, revokes the permission and logs out |

The next due time is the previous episode's actual start plus `anomaly_interval_hours`. The first due time is one interval after the first source timestamp. The scheduler waits for the current ordinary workflow to finish and for 15 minutes of quiet after any prior failed SSO attempt. The conservative extra delay is at most 27 minutes at the default cadence. There is no catch-up burst. The selected interval is clamped to 1–8760 hours. Administrators, responders and VM targets rotate between episodes.

A detection can correlate four failed identities from one peer within five minutes, an accepted administrator login, a permission grant, and that recipient's CBT change plus power-off within ten minutes. Use observed usernames, authentication peers, principal/entity, VM name and time windows. The stream does not expose native session IDs for these operations and does not prove password compromise or process attribution.

`changeTrackingEnabled` is a **configured flag**. All selected VMs start with `capability.changeTrackingSupported=true`. The API specifies that a changed flag becomes effective at a later power-on, resume, snapshot operation or migration. This chain restores the flag before power-on. It therefore does not establish an effective CBT reset, backup failure or a measured runtime outage.

## Source and State Boundaries

Initial inventory: eleven powered-on VMs with configured CBT enabled, nine existing identities, no active sessions and no temporary direct grant. Five identities have an existing propagated Administrator baseline. Other ordinary query sessions are assumed to have inherited read-only access without an existing direct grant on the selected datacenter. The extra unlogged API invocation included in each session's call count is synthetic. Its success and returned inventory are not claimed.

The model retains nine user contexts, eleven current VM states, at most nine sessions, one temporary grant, one workflow of at most sixteen queued records and scalar scheduling counters. There is no growing event/session history. The validation captures reached at most one concurrent session. Finite input may stop inside a valid session or recovery workflow.

Native `key` increases within this uninterrupted synthetic vCenter stream. `chainId` equals the operation's key in this selected subset. It is not a campaign key. `vsphere.event.*` is a profile normalization of visible message fields and documented operation semantics, not a serialized SOAP Event object. API-only session IDs, VM MoRefs, credential ownership and non-authentication client IPs are not fabricated.

Native `createdTime` uses input time converted to UTC. The selected syslog header is 300 microseconds later, `@timestamp` is that header truncated to milliseconds, and `event.ingested` is input time plus 200 milliseconds. These fixed latencies and the vpxd PID are synthetic context. Authentication peer addresses are included only in login, logout and failed SSO messages.

## Reference Coverage and Limits

Login, logout and failed SSO envelopes/messages follow the pinned Elastic vSphere common-log fixtures. Login and logout ECS normalization retains all 30/30 and 34/34 reference leaves. Failed SSO retains 17/17 reference leaves and adds inferred authentication classification. Arrays count as one leaf. These figures describe field presence in the selected fixtures, not complete product coverage or live parser certification.

The other message templates are supported by Broadcom API event semantics and the Broadcom/VMware govmomi v0.46.3 simulator catalog. Broadcom KB422164 supplies the CBT-change message body for vCenter 7.x/8.x. The selected reconfiguration body omits additional Added/Deleted extraConfig sections. Permission message wording is explicitly synthetic: no matching complete vendor wire capture was found in the bounded search. Role, propagation and individual-principal semantics follow the API, while their exact English syslog rendering is not established.

`agent`, `elastic_agent`, `host`, `data_stream`, UDP source port and collector metadata are synthetic deployment enrichment. `related.*` arrays and added `vsphere.event.*` fields describe this profile. There is no verified collector status or claim of an identical live vCenter 8.x wire stream. JSON ordering, native fractional precision and all possible VMware event classes are outside the reviewed subset.

## Parameters

### Event Parameters

Configured under `event.template.params`. No secrets are required.

| Parameter | Default | Meaning |
|---|---|---|
| `vcenter_host` | `vcsa01.lab.example` | Synthetic vCenter hostname |
| `vcenter_ip` | `10.40.0.10` | Synthetic vCenter/collector source address |
| `vcenter_mac` | `00-50-56-A1-3F-2C` | Synthetic host MAC |
| `vcenter_id` | `7c49a8e2c6244517b5572cfd43e91a0a` | Synthetic host identifier |
| `datacenter` | `DC-East` | Existing datacenter receiving the temporary grant |
| `domain` | `VSPHERE.LOCAL` | SSO domain for ordinary inventory and configured administrator |
| `agent_id` | `5096d7cc-1e4b-4959-abea-7355be2913a7` | Synthetic collector identifier |
| `agent_ephemeral_id` | `c4a1df82-7a9c-4a3e-8546-6d7cc04538e6` | Synthetic collector lifetime identifier |
| `agent_version` | `8.17.0` | Synthetic Filebeat/Elastic Agent version |
| `attack_ip` | `10.99.6.44` | Shared existing administrator peer, also used in background |
| `attack_user` | `Administrator` | Existing administrator short name replacing the default inventory administrator |
| `granted_principal` | `VSPHERE.LOCAL\svc_backup` | Full existing individual principal, including domain; replaces the ordinary backup identity |
| `critical_vm` | `prod-db-01` | VM name replacing the first ordinary inventory entry; also used in background |
| `anomaly_mode` | `true` | Enable recurring anomaly chains over background |
| `ecs_version` | `8.11.0` | ECS metadata version |
| `anomaly_interval_hours` | `24` | Desired start-to-start interval, clamped to 1–8760 hours |

Keep all nine resolved full usernames distinct and all eleven VM names distinct. `attack_user` is a short name. `granted_principal` is the exact full `DOMAIN\name` identity and may use a different domain. Replace deployment values coherently. This review covers the shipped sample inventory and the documented custom profile, not arbitrary inventory shapes or invalid-parameter handling.

### Output Parameters

The `file` output writes newline-delimited JSON to `output/events.json`, using `write_mode: overwrite` and `formatter.format: json`. Change the existing output plugin configuration to choose another path or destination. The output has no `${params.*}` or `${secrets.*}` placeholders.

## Usage

From a content-packs checkout beside the Eventum source checkout:

```bash
# Live generation, default background plus periodic anomalies.
uv run --project ../eventum eventum generate \
  --path generators/virtualization-vmware/generator.yml \
  --id vmware --live-mode true --keep-order true

# Batch generation. Add finite input bounds before running.
uv run --project ../eventum eventum generate \
  --path generators/virtualization-vmware/generator.yml \
  --id vmware --live-mode false --keep-order true
```

For a reproducible finite interval, add these values to the existing cron input, keeping its `expression: '* * * * * 0'` and `count: 1`:

```yaml
start: '2026-09-26T00:00:00Z'
end: '2026-09-29T04:20:00Z'
```

This interval provides 76 hours 20 minutes at one event per minute and includes multiple daily episodes after scheduler delays. Set `event.template.params.anomaly_mode: false` for background only. Set `anomaly_interval_hours: 12` for twelve-hour recurrence. Keep ordered source timestamps for the stateful model.

## Validation

Five final finite captures were replayed against native envelope, UTC, causal session/call-count, permission lifecycle, configured CBT/power state and behavioral-chain checks. An independent reviewer also checked current state and ordinary recipient operations.

| Capture | Rows | Detected chains | Completed recoveries |
|---|---:|---:|---:|
| Default, 76h20, enabled | 4581 | 3 | 3 |
| Default, 76h20, background | 4581 | 0 | 0 |
| Custom deployment/12h interval, enabled | 4581 | 6 | 6 |
| Same custom deployment, background | 4581 | 0 | 0 |
| Minimum 1h interval, 20h20 | 1221 | 19 | 18 |

The stress capture ends inside the nineteenth recovery after configured CBT has been restored. Its remaining power-on, revoke and logout are beyond the finite horizon. Both background captures contain all eight native classes, all nine identities and all eleven VM targets, including the configured recipient's reconfiguration and power operations. Five coherent negative captures reject an existing duplicate grant, wrong recipient principal, redundant power transition, wrong old CBT value and logout without a current login.

The original implementation was run in both modes for twenty minutes. It produced 6005 records per mode, 846/842 logouts without an observed login, and 777/801 redundant VM power transitions. In enabled mode the chain repeated every 51–52 seconds and granted an already-present permission 22 times without revocation. Final validation uses the revised source, not those historical captures.

## Sample Output

One complete event copied from the final default-enabled capture:

```json
{
  "@timestamp": "2026-09-27T00:19:00.000Z",
  "agent": {
    "ephemeral_id": "c4a1df82-7a9c-4a3e-8546-6d7cc04538e6",
    "id": "5096d7cc-1e4b-4959-abea-7355be2913a7",
    "name": "vcsa01.lab.example",
    "type": "filebeat",
    "version": "8.17.0"
  },
  "data_stream": {
    "dataset": "vsphere.log",
    "namespace": "default",
    "type": "logs"
  },
  "ecs": {
    "version": "8.11.0"
  },
  "elastic_agent": {
    "id": "5096d7cc-1e4b-4959-abea-7355be2913a7",
    "snapshot": false,
    "version": "8.17.0"
  },
  "event": {
    "action": "vm-reconfigured",
    "category": [
      "configuration"
    ],
    "dataset": "vsphere.log",
    "id": "577251",
    "ingested": "2026-09-27T00:19:00.200Z",
    "kind": "event",
    "original": "<14>1 2026-09-27T00:19:00.000300+00:00 vcsa01.lab.example vpxd 58650 - -  Event [577251] [1-1] [2026-09-27T00:19:00.000000Z] [vim.event.VmReconfiguredEvent] [info] [VSPHERE.LOCAL\\svc_backup] [DC-East] [577251] [Reconfigured prod-db-01 on esxi01.lab.example in DC-East.\n  Modified:\n  config.changeTrackingEnabled: true -> false;]",
    "outcome": "success",
    "timezone": "+00:00",
    "type": [
      "change"
    ]
  },
  "host": {
    "architecture": "x86_64",
    "containerized": false,
    "hostname": "vcsa01.lab.example",
    "id": "7c49a8e2c6244517b5572cfd43e91a0a",
    "ip": [
      "10.40.0.10"
    ],
    "mac": [
      "00-50-56-A1-3F-2C"
    ],
    "name": "vcsa01.lab.example",
    "os": {
      "family": "linux",
      "name": "VMware Photon OS",
      "platform": "photon",
      "type": "linux"
    }
  },
  "input": {
    "type": "udp"
  },
  "log": {
    "level": "info",
    "logger": "vim.event.VmReconfiguredEvent",
    "source": {
      "address": "10.40.0.10:59146"
    },
    "syslog": {
      "facility": {
        "code": 1,
        "name": "User"
      },
      "priority": 14,
      "severity": {
        "code": 6,
        "name": "Informational"
      }
    }
  },
  "message": "[VSPHERE.LOCAL\\svc_backup] [DC-East] [577251] [Reconfigured prod-db-01 on esxi01.lab.example in DC-East.\n  Modified:\n  config.changeTrackingEnabled: true -> false;]",
  "process": {
    "name": "vpxd",
    "pid": 58650
  },
  "related": {
    "user": [
      "svc_backup"
    ]
  },
  "tags": [
    "preserve_original_event",
    "vmware-sphere"
  ],
  "user": {
    "domain": "VSPHERE.LOCAL",
    "name": "svc_backup"
  },
  "vsphere": {
    "event": {
      "chain_id": 577251,
      "class": "vim.event.VmReconfiguredEvent",
      "configuration": {
        "change_tracking_enabled": {
          "new": false,
          "old": true
        }
      },
      "created_time": "2026-09-27T00:19:00.000000Z",
      "host": {
        "name": "esxi01.lab.example"
      },
      "key": 577251,
      "user_name": "VSPHERE.LOCAL\\svc_backup",
      "vm": {
        "name": "prod-db-01"
      }
    }
  }
}
```

## References

- [Broadcom Event base fields](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.event.Event.html)
- [Broadcom login](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.event.UserLoginSessionEvent.html) and [logout](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.event.UserLogoutSessionEvent.html) semantics
- [AuthorizationManager permission lifecycle](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.AuthorizationManager.html)
- [PermissionAddedEvent](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.event.PermissionAddedEvent.html) and [PermissionRemovedEvent](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.event.PermissionRemovedEvent.html)
- [VirtualMachineConfigSpec, changeTrackingEnabled precondition and activation](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.vm.ConfigSpec.html)
- [Broadcom KB422164, vCenter CBT-change message examples](https://knowledge.broadcom.com/external/article/422164/cbt-reset-observed-on-vm-due-to-backup-a.html)
- [Broadcom KB432327, vCenter auditing classes](https://knowledge.broadcom.com/external/article/432327/auditing-user-operations-in-vcenter-using.html)
- [VMware/Broadcom govmomi v0.46.3 event catalog](https://github.com/vmware/govmomi/blob/v0.46.3/simulator/esx/event_manager.go)
- [Pinned Elastic vSphere common-log raw fixtures](https://github.com/elastic/integrations/blob/78fd455d22cdb74bd2a8e53249c25cc060f06010/packages/vsphere/data_stream/log/_dev/test/pipeline/test-format-common.log) and [normalized expectations](https://github.com/elastic/integrations/blob/78fd455d22cdb74bd2a8e53249c25cc060f06010/packages/vsphere/data_stream/log/_dev/test/pipeline/test-format-common.log-expected.json)
