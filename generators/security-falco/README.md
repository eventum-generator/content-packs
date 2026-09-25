# Falco alert generator

Generates Falco syscall alerts as ECS JSON, preserving a native Falco JSON alert in `event.original`. The fields follow the Elastic Falco `alerts` integration and Falco's documented JSON output and stable rules.

## Event Types

The `chain` picker repeats a 40-event cycle with `anomaly_mode: true`. These are demo weights for exercising correlation rules, not measured production frequencies. Background events are independent Falco alerts from different containers; they are not benign syscalls.

| Falco rule | Events per cycle | Frequency | Priority |
|---|---:|---:|---|
| Terminal shell in container | 27 | 67.5% | Notice |
| Read sensitive file untrusted | 11 | 27.5% | Warning |
| Contact K8S API Server From Container | 2 | 5% | Notice |

The pack uses three event templates through six chain aliases.

## Anomaly Chain

With `anomaly_mode: true`, every cycle contains a linked three-alert sequence on one fictional container:

1. A terminal shell starts in an application container.
2. A Python process under that shell reads `/etc/shadow`.
3. A `curl` process under the shell contacts the Kubernetes API service at `10.96.0.1:443`.

The alerts share `container.id`, `k8s.pod.name` and `k8s.ns.name` in Falco `output_fields`. A SIEM rule can join them by container ID within a short time window and require the sensitive file and API destination. The same pod and namespace help when correlating a shell alert with Kubernetes audit events. The sequence is suspicious, but the alerts alone do not establish who opened the shell. With `anomaly_mode: false`, the special positions emit independent background alerts; no Kubernetes API contact or linked three-step episode is generated.

The pool has 50 synthetic pods across five namespaces and five nodes. The `k8s.*` and image values in `output_fields` assume Falco's documented `append_output` enrichment is configured for those fields. Production rules and Falco versions can yield different field sets.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
|---|---|---|
| `anomaly_mode` | `true` | Set to `false` for independent background alerts only |
| `agent_version` | `8.13.3` | Synthetic Elastic Agent version |
| `ecs_version` | `8.17.0` | ECS version in the normalized event |
| `data_stream_namespace` | `lab-k8s` | Elastic data stream namespace |
| `log_path` | `/var/log/falco/events.log` | Simulated source log path |

### Output Parameters

The shipped configuration writes to `output/events.json` and requires no top-level `params` or `secrets`. To override that path, define a top-level parameter and substitute it in the output block:

```yaml
params:
  output_path: output/events.json
output:
  - file:
      path: ${params.output_path}
      write_mode: overwrite
      formatter:
        format: json
```

A backend output can use `${params.*}` for its address and `${secrets.*}` for credentials. Those substitutions are separate from `event.template.params`, which contains Jinja constants.

## Usage

Run from the content-packs root:

```bash
# Bounded sample mode; it runs continuously until stopped.
timeout 2 eventum generate --path generators/security-falco/generator.yml --id falco-sample --live-mode false

# Continuous 5 alerts/second stream.
eventum generate --path generators/security-falco/generator.yml --id falco-live --live-mode true
```

## Sample Output

This complete event was copied from a validation run's `output/events.json`:

```json
{
  "@timestamp": "2026-09-25T10:37:29+00:00",
  "agent": {
    "ephemeral_id": "ef48dd34-7392-4eea-a6c2-0db179650004",
    "id": "ef48dd34-7392-4eea-a6c2-0db179650004",
    "name": "elastic-agent-worker-04",
    "type": "filebeat",
    "version": "8.13.3"
  },
  "container": {
    "id": "a4c8e0200004",
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
    "id": "ef48dd34-7392-4eea-a6c2-0db179650004",
    "snapshot": false,
    "version": "8.13.3"
  },
  "event": {
    "agent_id_status": "verified",
    "category": [
      "process"
    ],
    "dataset": "falco.alerts",
    "ingested": "2026-09-25T10:37:29+00:00",
    "kind": "alert",
    "original": "{\"hostname\":\"worker-04\",\"output\":\"2026-09-25T10:37:29.000000000+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow evt_type=openat user=root user_uid=0 user_loginuid=-1 process=python3 proc_exepath=/usr/bin/python3 parent=bash command=python3 /tmp/check_users.py terminal=34816 container_id=a4c8e0200004 container_name=payments-app\",\"output_fields\":{\"container.id\":\"a4c8e0200004\",\"container.name\":\"payments-app\",\"container.image.repository\":\"registry.example.test/payments/app:2.4.1\",\"evt.time.iso8601\":1790332649000000000,\"evt.type\":\"openat\",\"k8s.ns.name\":\"payments\",\"k8s.pod.name\":\"payments-app-7df86c5d4-04\",\"proc.cmdline\":\"python3 /tmp/check_users.py\",\"proc.exepath\":\"/usr/bin/python3\",\"proc.name\":\"python3\",\"proc.pname\":\"bash\",\"proc.tty\":34816,\"user.loginuid\":-1,\"user.name\":\"root\",\"user.uid\":0,\"fd.name\":\"/etc/shadow\"},\"priority\":\"Warning\",\"rule\":\"Read sensitive file untrusted\",\"source\":\"syscall\",\"tags\":[\"T1555\",\"container\",\"filesystem\",\"host\",\"maturity_stable\",\"mitre_credential_access\"],\"time\":\"2026-09-25T10:37:29.000000000Z\"}",
    "provider": "syscall",
    "severity": 47,
    "timezone": "+00:00",
    "type": [
      "access"
    ]
  },
  "falco": {
    "hostname": "worker-04",
    "output": "2026-09-25T10:37:29.000000000+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow evt_type=openat user=root user_uid=0 user_loginuid=-1 process=python3 proc_exepath=/usr/bin/python3 parent=bash command=python3 /tmp/check_users.py terminal=34816 container_id=a4c8e0200004 container_name=payments-app",
    "output_fields": {
      "container": {
        "id": "a4c8e0200004",
        "image": {
          "repository": "registry.example.test/payments/app:2.4.1"
        },
        "name": "payments-app"
      },
      "evt": {
        "time": {
          "iso8601": 1790332649000
        },
        "type": "openat"
      },
      "fd": {
        "name": "/etc/shadow"
      },
      "k8s": {
        "ns": {
          "name": "payments"
        },
        "pod": {
          "name": "payments-app-7df86c5d4-04"
        }
      },
      "proc": {
        "cmdline": "python3 /tmp/check_users.py",
        "exepath": "/usr/bin/python3",
        "name": "python3",
        "pname": "bash",
        "tty": 34816
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
    "time": "2026-09-25T10:37:29.000000000Z"
  },
  "host": {
    "architecture": "x86_64",
    "containerized": true,
    "hostname": "worker-04",
    "id": "ef48dd34-7392-4eea-a6c2-0db179650004",
    "ip": [
      "10.20.0.14"
    ],
    "mac": [
      "02-42-ac-14-00-04"
    ],
    "name": "worker-04",
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
    "offset": 7118
  },
  "message": "Read sensitive file untrusted",
  "observer": {
    "hostname": "worker-04",
    "product": "falco",
    "type": "sensor",
    "vendor": "sysdig"
  },
  "process": {
    "command_line": "python3 /tmp/check_users.py",
    "executable": "/usr/bin/python3",
    "name": "python3",
    "parent": {
      "name": "bash"
    },
    "user": {
      "id": "0",
      "name": "root"
    }
  },
  "related": {
    "hosts": [
      "worker-04"
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

## Fidelity and References

The generator mirrors 77 of 78 leaf fields in Elastic's Falco sample event. It omits only `falco.container.mounts`, whose reference value is `null`. `agent`, `elastic_agent`, `host`, `input` and `log` represent synthetic collector enrichment; Falco itself emits the JSON preserved in `event.original`. The Falco rules are stable and enabled in the cited default rule catalog, but live alert volume depends on workload and local rule configuration.

- [Falco JSON output](https://falco.org/docs/concepts/outputs/channels/)
- [Falco default rules](https://falco.org/docs/reference/rules/default-rules/)
- [Falco `append_output` fields](https://falco.org/docs/concepts/outputs/formatting/)
- [Elastic Falco integration](https://www.elastic.co/docs/current/integrations/falco)
- [Elastic reference event](https://github.com/elastic/integrations/blob/main/packages/falco/data_stream/alerts/sample_event.json)
- [Elastic field mapping](https://github.com/elastic/integrations/blob/main/packages/falco/data_stream/alerts/fields/fields.yml)
