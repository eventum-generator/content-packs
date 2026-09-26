# Falco Runtime Alerts

Synthetic Falco syscall alerts from five Kubernetes node sensors and 50 persistent application containers. The selected source profile is Falco **0.45.0**, stable rules **5.2.0**, JSON file output with explicitly configured extra fields. It covers three standard rules, not Kubernetes audit-plugin events or Sysdig Secure incidents.

## Source Profile

The tagged rules require engine >=0.57.0 and container extractor >=0.4.0; Falco 0.45.0 reports engine 0.65.0 and uses libs 0.26.0. Container/Kubernetes extraction and API-server DNS resolution are assumed available. The synthetic Ubuntu-based application images contain `/usr/bin/bash`, `/usr/bin/python3.10` and `/usr/bin/curl`, run as root, and have writable executables. None of the namespaces/images is on these rules' Kubernetes/maintenance allowlists. The script names are ordinary local maintenance programs, not Ansible/Chef/Qualys exceptions.

The selected Falco configuration disables suggested appended text and enables these fields. The suffix is identical in both modes:

```yaml
json_output: true
json_include_output_property: true
json_include_output_fields_property: true
json_include_tags_property: true
json_include_message_property: false
time_format_iso_8601: true
append_output:
  - match:
      source: syscall
    suggested_output: false
    extra_output: "container_id=%container.id container_name=%container.name"
    extra_fields:
      - container.image.repository
      - container.image.tag
      - k8s.ns.name
      - k8s.pod.name
      - proc.pid
      - proc.ppid
      - proc.pid.ts
      - proc.ppid.ts
      - evt.category
  - match:
      rule: Read sensitive file untrusted
    extra_fields:
      - fd.type
      - fd.typechar
      - fd.num
      - evt.is_open_read
      - evt.rawres
      - evt.failed
  - match:
      rule: Contact K8S API Server From Container
    extra_fields:
      - fd.lip
      - fd.rip
      - fd.sip
      - fd.sip.name
      - fd.typechar
```

Standard rule output supplies the remaining fields, including shell `exe_flags`, sensitive-read ancestor names, and API connection/port/protocol fields. `proc.pid` and `proc.ppid` are host PIDs, not invented Kubernetes user identities. `proc.pid.ts`/`proc.ppid.ts` are integer epoch nanoseconds. Read alerts represent successful read-mode opens of `/etc/shadow` with a nonnegative real FD. API alerts represent `connect` attempts to the DNS-identified API service; they do not establish HTTP success, token authorization, transferred data or compromise.

Complete older native JSON examples exist for all three classes: maintained Elastic 2024 fixtures and Falco's official 2021 API example. The current tagged rules/engine/field sources specify the selected output. **BLOCKED_RAW_EVIDENCE:** exact Falco 0.45.0/rules 5.2.0 full native records with this `append_output`, a coherent full process trace and a live parser run were not obtained. Older records are format evidence, not current-version capture parity. Synthetic runtime topology, process creation/exit, command selection and traffic distribution are modeling assumptions.

## Event Types

| Native rule | Syscall / condition | Priority | Ordinary selection | ECS category/type |
|---|---|---|---|---|
| Terminal shell in container | `execve`, bash, nonzero tty, container-entrypoint parent | Notice | Weight6; also emitted when the current shell expires | process/start |
| Read sensitive file untrusted | `openat`, read mode, valid FD, nontrusted Python | Warning | Weight3 | file/access |
| Contact K8S API Server From Container | `connect`, IPv4, API DNS name, nonallowlisted container | Notice | Weight1; every sixth eligible pod visit requests this class | network/connection |

One selected alert is emitted per minute, with 0..999 ms source jitter. An ordinary pod is eligible at most once per 10 minutes. Shell lifetime and eligibility override the weights, so they are not output percentages. The reviewed default on run produced 3771 shell, 408 read and 402 API alerts in 4581 rows. All three classes, both command variants, all 50 containers and their common root actors occur in ordinary activity in both modes. These are background **alerts**, including permitted maintenance that triggers the selected rules.

Native `event.original` is a complete JSON object with UTC/nanosecond time, the exact tagged standard output plus selected suffix, lexicographically sorted tags/keys, and unchanged native field types. The outer event follows the pinned Elastic Falco integration's relevant ECS mappings with field preservation. Native event-time nanoseconds become normalized milliseconds. Native process-start nanoseconds are preserved, while outer ECS `process.start`/`process.parent.start` are explicitly converted to UTC ISO dates instead of copying ns directly into date fields. This is a documented normalization correction, not exact pipeline-output parity. The normalized fields omit the ancestor-name/exec-flag keys unconditionally removed by that pipeline; the complete native fields remain in `event.original`. Agent/host/ingest/file metadata, including `event.agent_id_status: verified`, are explicitly supplied synthetic collector context. That status does not demonstrate live collector verification. Whole UTF-8 lines accumulate separately for each sensor; rotation resets the next complete line to offset 0 at 100 MiB. No source sequence or outcome is invented.

## Anomaly Chain

`anomaly_mode` defaults to `true`. Every 12 hours, after the selected target is eligible, one container emits:

1. A new interactive bash shell with native PID/start and a permitted `containerd-shim` parent.
2. After 60 seconds, a new Python child of that observed shell opens `/etc/shadow` for reading.
3. After another 60 seconds, a new curl child of the same shell attempts a connection to the Kubernetes API service.

Join by sensor/container/pod, `proc.ppid`→the observed shell's `proc.pid`, matching `proc.ppid.ts`→`proc.pid.ts`, and the inherited tty. A complete episode spans 120 seconds. Detection can correlate interactive entry, sensitive-file access and unexpected API contact inside that window. It does not identify the Kubernetes user who invoked exec.

Targets rotate by 11 slots over the 50-container inventory. Shell/child PIDs are newly allocated per sensor and command variants/tty/ephemeral ports vary from the same pools used by ordinary alerts. The next due time is measured from the actual first shell, with no catch-up bursts. Minute ticks and the target's 10 minute cooldown can postpone an episode by up to about 11 minutes. `anomaly_mode: false` retains all constituent rules/signatures but its per-pod cooldown prevents a complete short-window chain.

The source is a selected-alert subset: existing ordinary terminal parents may predate the finite capture, and Python/curl creation plus all process exits are unlogged. A current shell remains live for at most 30 minutes; replacing it models its prior unlogged exit. Persistent shim contexts are exec-point parents, not a claim that every shell is the container init process. No container recreation or exit alert is fabricated. State is bounded by 50 inventory/shell/cooldown/visit slots, five PID counters/collector offsets, one pending three-record trace and scalar cursors. PID allocation skips live parent contexts; it uses the same 100000..2000000 range in both modes.

## Reference Field Coverage

Exact path coverage uses the pinned maintained Elastic sample and native fixtures. Dictionary leaves count as fields; primitive arrays count once, without array indices. Generated paths are the union per matching rule. `event.original` is one ECS leaf; its parsed native fields have a separate denominator. Counts measure presence, not equal values/types, live parsing or current-version raw parity.

| Reference | Covered / denominator | Coverage |
|---|---:|---:|
| ECS maintained sample | 78/78 | 100.00% |
| native embedded maintained sample | 20/20 | 100.00% |
| native fixture union: Read sensitive file untrusted | 30/74 | 40.54% |
| native fixture union: Terminal shell in container | 23/25 | 92.00% |
| native official2021 API example | 11/12 | 91.67% |

The maintained ECS sample and its embedded native record omit no paths. The broader read fixture union intentionally exercises optional parser fields beyond the selected output profile. The exact omitted paths are:

- **native fixture union: Read sensitive file untrusted**: `output_fields.container.ip`, `output_fields.container.mounts`, `output_fields.container.privileged`, `output_fields.container.type`, `output_fields.evt.num`, `output_fields.evt.res`, `output_fields.evt.time`, `output_fields.fd.cip`, `output_fields.fd.cip.name`, `output_fields.fd.cport`, `output_fields.fd.directory`, `output_fields.fd.filename`, `output_fields.fd.ino`, `output_fields.fd.lip`, `output_fields.fd.lip.name`, `output_fields.fd.lport`, `output_fields.fd.rip`, `output_fields.fd.rip.name`, `output_fields.fd.rport`, `output_fields.fd.sip`, `output_fields.fd.sip.name`, `output_fields.fd.sport`, `output_fields.group.gid`, `output_fields.group.name`, `output_fields.k8s.pod.ip`, `output_fields.k8s.pod.labels`, `output_fields.k8s.pod.uid`, `output_fields.proc.args`, `output_fields.proc.cmdnargs`, `output_fields.proc.cwd`, `output_fields.proc.duration`, `output_fields.proc.env`, `output_fields.proc.is_sid_leader`, `output_fields.proc.is_vpgid_leader`, `output_fields.proc.pexepath`, `output_fields.proc.ppid.duration`, `output_fields.proc.pvpid`, `output_fields.proc.sid`, `output_fields.proc.sid.exepath`, `output_fields.proc.sname`, `output_fields.proc.vpgid`, `output_fields.proc.vpgid.exepath`, `output_fields.proc.vpgid.name`, `output_fields.proc.vpid`.
- **native fixture union: Terminal shell in container**: `output_fields.evt.time`, `uuid`.
- **native official2021 API example**: `output_fields.evt.time`.

`uuid` is present in the maintained parser fixture but is not emitted by the selected tagged Falco0.45.0 formatter; no external producer/Sidekick UUID is invented. `output_fields.evt.time` is a legacy prefix alias; this profile emits `evt.time.iso8601`. `evt.res` is optional string result enrichment; read success is represented by native `evt.rawres`/`evt.failed`, while no result is inferred for API attempts. `evt.num` is an unconfigured source sequence, so no synthetic sequence is invented. Extra container runtime/IP/privilege/mounts and Kubernetes UID/labels/pod-IP fields are not requested by the selected append_output or supplied by a confirmed extractor capture. Socket address/name/port fields in file-open parser cases are not represented as network connections; the actual selected API class supplies its documented tuple. Additional process/group/argument/environment/session/namespace-PID/lifetime/executable fields are optional append_output enrichments, not observed from these selected alerts. No fake value fills them. The full omitted-path list above includes those fields rather than inflating coverage by excluding parser cases. The official2021 API example has no current-engine envelope/field contract; its only missing alias is handled the same way.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
|---|---|---|
| `anomaly_mode` | `true` | Enable periodic complete episodes; false retains ordinary alerts |
| `anomaly_interval_hours` | `12` | Finite interval in hours, minimum 1; smaller values clamp to 1 |
| `api_server_ip` | `10.96.0.1` | IPv4 address of the selected API DNS service, used in both modes |
| `agent_version` | `8.13.3` | Synthetic Elastic Agent version |
| `ecs_version` | `8.17.0` | ECS version |
| `data_stream_namespace` | `lab-k8s` | Data-stream namespace |
| `log_path` | `/var/log/falco/events.log` | Synthetic collector source-file path |

The persistent50-container/five-node inventory is in `samples/pods.csv`. Keep exactly 50 rows, IPv4 pod/service addresses and distinct sensor/container contexts when editing it.

### Output Parameters

The shipped configuration writes JSON lines to `output/events.json` and needs no secrets or output placeholders. To use a backend output, replace the file block with that plugin's configuration and supply its `${params.*}`/`${secrets.*}` values through the CLI.

## Usage

From the content-packs repository, run live generation:

```bash
flock -x /tmp/eventum-generator-heavy.lock uv run --project ../eventum eventum generate --path generators/security-falco/generator.yml --id falco --live-mode true --keep-order true
```

For a finite batch, copy `generator.yml` beside the original as `finite.yml`, set `input[0].cron.start` to `2026-09-01T00:00:00+03:00` and `end` to `2026-09-02T00:20:00+03:00`, then run:

```bash
flock -x /tmp/eventum-generator-heavy.lock uv run --project ../eventum eventum generate --path generators/security-falco/finite.yml --id falco-batch --live-mode false --keep-order true
```

This 24h20 window contains 1461 input ticks and two complete default episodes, allowing cooldown postponement. Source output is UTC even when the input bounds have another offset. Set `anomaly_mode: false` in the copy for ordinary alerts only. Hour/day scheduling is source-time simulation in batch mode; the batch does not wait 24 hours. Keep `--keep-order true` for this stateful chronological output; the asynchronous writer otherwise may emit batches in completion order.

## Sample Output

Complete synthetic event copied from the reviewed default run, row 723. It is not a captured vendor record:

```json
{
  "@timestamp": "2026-09-01T09:02:00.573+00:00",
  "agent": {
    "ephemeral_id": "ef48dd34-7392-4eea-a6c2-0db179650001",
    "id": "ef48dd34-7392-4eea-a6c2-0db179650001",
    "name": "elastic-agent-worker-01",
    "type": "filebeat",
    "version": "8.13.3"
  },
  "container": {
    "id": "a4c8e0200001",
    "name": "payments-app"
  },
  "data_stream": {
    "dataset": "falco.alerts",
    "namespace": "lab-k8s",
    "type": "logs"
  },
  "ecs": {
    "version": "8.17.0"
  },
  "elastic_agent": {
    "id": "ef48dd34-7392-4eea-a6c2-0db179650001",
    "snapshot": false,
    "version": "8.13.3"
  },
  "event": {
    "agent_id_status": "verified",
    "category": [
      "file"
    ],
    "dataset": "falco.alerts",
    "ingested": "2026-09-01T09:02:00.573+00:00",
    "kind": "alert",
    "original": "{\"hostname\":\"worker-01\",\"output\":\"2026-09-01T09:02:00.573000000+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=containerd-shim ggparent=containerd gggparent=systemd evt_type=openat user=root user_uid=0 user_loginuid=-1 process=python3 proc_exepath=/usr/bin/python3.10 parent=bash command=python3 /opt/maintenance/check_shadow.py terminal=34819 container_id=a4c8e0200001 container_name=payments-app\",\"output_fields\":{\"container.id\":\"a4c8e0200001\",\"container.image.repository\":\"registry.example.test/payments/app\",\"container.image.tag\":\"2.4.1\",\"container.name\":\"payments-app\",\"evt.category\":\"file\",\"evt.failed\":false,\"evt.is_open_read\":true,\"evt.rawres\":9,\"evt.time.iso8601\":1788253320573000000,\"evt.type\":\"openat\",\"fd.name\":\"/etc/shadow\",\"fd.num\":9,\"fd.type\":\"file\",\"fd.typechar\":\"f\",\"k8s.ns.name\":\"payments\",\"k8s.pod.name\":\"payments-app-7df86c5d4-01\",\"proc.aname[2]\":\"containerd-shim\",\"proc.aname[3]\":\"containerd\",\"proc.aname[4]\":\"systemd\",\"proc.cmdline\":\"python3 /opt/maintenance/check_shadow.py\",\"proc.exepath\":\"/usr/bin/python3.10\",\"proc.name\":\"python3\",\"proc.pid\":100480,\"proc.pid.ts\":1788253320553000000,\"proc.pname\":\"bash\",\"proc.ppid\":100479,\"proc.ppid.ts\":1788253260553000000,\"proc.tty\":34819,\"user.loginuid\":-1,\"user.name\":\"root\",\"user.uid\":0},\"priority\":\"Warning\",\"rule\":\"Read sensitive file untrusted\",\"source\":\"syscall\",\"tags\":[\"T1555\",\"container\",\"filesystem\",\"host\",\"maturity_stable\",\"mitre_credential_access\"],\"time\":\"2026-09-01T09:02:00.573000000Z\"}",
    "provider": "syscall",
    "severity": 47,
    "timezone": "+00:00",
    "type": [
      "access"
    ]
  },
  "falco": {
    "hostname": "worker-01",
    "output": "2026-09-01T09:02:00.573000000+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=containerd-shim ggparent=containerd gggparent=systemd evt_type=openat user=root user_uid=0 user_loginuid=-1 process=python3 proc_exepath=/usr/bin/python3.10 parent=bash command=python3 /opt/maintenance/check_shadow.py terminal=34819 container_id=a4c8e0200001 container_name=payments-app",
    "output_fields": {
      "container": {
        "id": "a4c8e0200001",
        "image": {
          "repository": "registry.example.test/payments/app",
          "tag": "2.4.1"
        },
        "name": "payments-app"
      },
      "evt": {
        "category": "file",
        "failed": false,
        "is_open_read": true,
        "rawres": 9,
        "time": {
          "iso8601": 1788253320573
        },
        "type": "openat"
      },
      "fd": {
        "name": "/etc/shadow",
        "num": 9,
        "type": "file",
        "typechar": "f"
      },
      "k8s": {
        "ns": {
          "name": "payments"
        },
        "pod": {
          "name": "payments-app-7df86c5d4-01"
        }
      },
      "proc": {
        "cmdline": "python3 /opt/maintenance/check_shadow.py",
        "exepath": "/usr/bin/python3.10",
        "name": "python3",
        "pid": {
          "ts": 1788253320553000000
        },
        "pname": "bash",
        "ppid": {
          "ts": 1788253260553000000
        },
        "tty": 34819
      },
      "process": {
        "parent": {
          "pid": 100479
        },
        "pid": 100480
      },
      "user": {
        "loginuid": -1,
        "name": "root",
        "uid": "0"
      }
    },
    "priority": "Warning",
    "rule": "Read sensitive file untrusted",
    "source": "syscall",
    "tags": [
      "T1555",
      "container",
      "filesystem",
      "host",
      "maturity_stable",
      "mitre_credential_access"
    ],
    "time": "2026-09-01T09:02:00.573000000Z"
  },
  "falco.container.mounts": null,
  "file": {
    "path": "/etc/shadow",
    "type": "file"
  },
  "host": {
    "architecture": "x86_64",
    "containerized": true,
    "hostname": "worker-01",
    "id": "ef48dd34-7392-4eea-a6c2-0db179650001",
    "ip": [
      "10.20.0.11"
    ],
    "mac": [
      "02-42-ac-14-00-01"
    ],
    "name": "worker-01",
    "os": {
      "codename": "jammy",
      "family": "debian",
      "kernel": "5.15.0-91-generic",
      "name": "Ubuntu",
      "platform": "ubuntu",
      "type": "linux",
      "version": "22.04"
    }
  },
  "input": {
    "type": "log"
  },
  "log": {
    "file": {
      "path": "/var/log/falco/events.log"
    },
    "offset": 171724
  },
  "message": "Read sensitive file untrusted",
  "observer": {
    "hostname": "worker-01",
    "product": "falco",
    "type": "sensor",
    "vendor": "sysdig"
  },
  "orchestrator": {
    "namespace": "payments",
    "resource": {
      "name": "payments-app-7df86c5d4-01",
      "type": "pod"
    }
  },
  "process": {
    "command_line": "python3 /opt/maintenance/check_shadow.py",
    "executable": "/usr/bin/python3.10",
    "name": "python3",
    "parent": {
      "name": "bash",
      "pid": 100479,
      "start": "2026-09-01T09:01:00.553+00:00"
    },
    "pid": 100480,
    "start": "2026-09-01T09:02:00.553+00:00",
    "user": {
      "id": "0",
      "name": "root"
    }
  },
  "related": {
    "hosts": [
      "worker-01"
    ]
  },
  "rule": {
    "name": "Read sensitive file untrusted"
  },
  "tags": [
    "preserve_original_event",
    "preserve_falco_fields"
  ],
  "threat.technique.id": [
    "T1555"
  ]
}
```

## References

- [Falco JSON output channels](https://falco.org/docs/concepts/outputs/channels/) and [output formatting / append_output](https://falco.org/docs/concepts/outputs/formatting/).
- [Tagged Falco0.45.0 JSON formatter](https://github.com/falcosecurity/falco/blob/0.45.0/userspace/engine/formats.cpp) and [configuration](https://github.com/falcosecurity/falco/blob/0.45.0/falco.yaml).
- [Stable rules5.2.0](https://github.com/falcosecurity/rules/blob/falco-rules-5.2.0/rules/falco_rules.yaml), including required engine/container plugin versions, the three exact outputs and their conditions.
- [Supported fields](https://falco.org/docs/reference/rules/supported-fields/) and tagged [libs0.26.0 process fields](https://github.com/falcosecurity/libs/blob/0.26.0/userspace/libsinsp/sinsp_filtercheck_thread.cpp) and [syscall field types](https://github.com/falcosecurity/libs/blob/0.26.0/userspace/libsinsp/sinsp_filtercheck_evt.cpp).
- [Official older full API JSON example](https://falco.org/blog/falcosidekick-response-engine-part-9-fission/) and [source issue #2476](https://github.com/falcosecurity/falco/issues/2476).
- Pinned Elastic Falco integration [native fixtures](https://github.com/elastic/integrations/blob/c7fa9114e76abac8638ca66bb9088632731373bb/packages/falco/data_stream/alerts/_dev/test/pipeline/test-falco.log), [sample event](https://github.com/elastic/integrations/blob/c7fa9114e76abac8638ca66bb9088632731373bb/packages/falco/data_stream/alerts/sample_event.json) and [pipeline](https://github.com/elastic/integrations/blob/c7fa9114e76abac8638ca66bb9088632731373bb/packages/falco/data_stream/alerts/elasticsearch/ingest_pipeline/default.yml).
