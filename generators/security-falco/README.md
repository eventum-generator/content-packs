# Falco Runtime Alerts

Synthetic Falco syscall alerts from 50 Kubernetes node sensors and 500 persistent application containers. The selected source profile is Falco **0.45.0**, stable rules **5.2.0**, JSON file output with explicitly configured extra fields. It covers three standard rules, not Kubernetes audit-plugin events or Sysdig Secure incidents.

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

Standard rule output supplies the remaining fields, including shell `exe_flags`, sensitive-read ancestor names, and API connection/port/protocol fields. `proc.pid` and `proc.ppid` are host PIDs, not invented Kubernetes user identities. `proc.pid.ts`/`proc.ppid.ts` are integer epoch nanoseconds. Read alerts represent successful read-mode opens of `/etc/shadow` with a nonnegative real FD. API alerts represent `connect` attempts to the DNS-identified API service by curl (`/version` or API discovery `/api`) from a session shell or from the application entrypoint `sh`; they do not establish HTTP success, token authorization, transferred data or compromise.

Complete older native JSON examples exist for all three classes: maintained Elastic 2024 fixtures and Falco's official 2021 API example. The current tagged rules/engine/field sources specify the selected output. **BLOCKED_RAW_EVIDENCE:** exact Falco 0.45.0/rules 5.2.0 full native records with this `append_output`, a coherent full process trace and a live parser run were not obtained. Older records are format evidence, not current-version capture parity. Synthetic runtime topology, process creation/exit, command selection and traffic distribution are modeling assumptions.

## Event Types

Shares are measured on the final default `anomaly_mode: true` run (6 days from a Thursday, weekend included, 62,555 alerts, 6 episodes).

| Native rule | Syscall / condition | Priority | Origin | Share | ECS category/type |
|---|---|---|---|---:|---|
| Terminal shell in container | `execve`, bash, nonzero tty, `containerd-shim` exec-point parent | Notice | Interactive exec session start | 14.4% | process/start |
| Read sensitive file untrusted | `openat`, read mode, valid FD, nontrusted Python | Warning | Child of a session shell | 36.6% | file/access |
| Contact K8S API Server From Container | `connect`, IPv4, API DNS name, nonallowlisted container | Notice | Child of a session shell (`/version` 26.8%, `/api` 3.1%) | 29.9% | network/connection |
| Contact K8S API Server From Container | same | Notice | Application entrypoint `sh`, tty 0 (`/version` 11.5%, `/api` 7.6%) | 19.1% | network/connection |

Background comes from two activities. Interactive exec sessions (3 of 7 new actions) hit a pod drawn by its activity weight: one fixed set of lognormal weights, so every run models the same busy and quiet pods. A session raises the shell alert, then its bash children raise shadow reads (55%) and API contacts (45%) at lognormal gaps until the session ends (lognormal duration, median 10 min, at most 4 h and 12 children). Several sessions of one pod may overlap; each gets the lowest free pts index of its pod as terminal (`34816` = pts/0, `34817` = pts/1, ...). Application entrypoint API contacts (4 of 7 new actions) hit a uniformly drawn pod. Per pod this is about 3.6 sessions and 4.8 entrypoint contacts a weekday on average, half that on Saturday and Sunday.

Ordinary traffic in both modes therefore contains repeated alerts of one pod within minutes, shell -> read and shell -> API lineage pairs, read -> API pairs of the same shell, and pod-level shell -> read -> API triples. These are background **alerts**, including permitted maintenance that triggers the selected rules.

Native `event.original` is a complete JSON object with UTC/nanosecond time, the exact tagged standard output plus selected suffix, lexicographically sorted tags/keys, and unchanged native field types. The outer event follows the pinned Elastic Falco integration's relevant ECS mappings with field preservation. Native event-time nanoseconds become normalized milliseconds. Native process-start nanoseconds are preserved, while outer ECS `process.start`/`process.parent.start` are explicitly converted to UTC ISO dates instead of copying ns directly into date fields. This is a documented normalization correction, not exact pipeline-output parity. The normalized fields omit the ancestor-name/exec-flag keys unconditionally removed by that pipeline; the complete native fields remain in `event.original`. Agent/host/ingest/file metadata, including `event.agent_id_status: verified`, are explicitly supplied synthetic collector context. That status does not demonstrate live collector verification. `event.ingested` trails the alert by a lognormal pipeline delay (median 1.8 s). Whole UTF-8 lines accumulate separately for each sensor; rotation resets the next complete line to offset 0 at 100 MiB. No source sequence or outcome is invented.

## Input and Rate

The input sets the alert rate; every input timestamp becomes exactly one alert, and no alert is dropped. The `time_patterns` files in `patterns/` stack uniform bands anchored at 00:00 UTC. Four files apply every day; the 15 files in `patterns/weekdays/` add the Monday-Friday part of the three daytime bands, one file per weekday and band with a one-week period anchored at that weekday's midnight:

| Band | Hours (UTC) | Weekday | Saturday, Sunday | Files |
|---|---|---:|---:|---|
| baseline | 00-24 | 120/h | 120/h | `baseline.yml` |
| daytime | 06-21 | +180/h | +63/h | `daytime.yml` + `weekdays/*-daytime.yml` |
| workday | 07-19 | +250/h | +87.5/h | `workday.yml` + `weekdays/*-workday.yml` |
| office | 08-18 | +400/h | +140/h | `office.yml` + `weekdays/*-office.yml` |

On a weekday the curve is 120 alerts/h at night (21-06), 300/h at 06 and 19-21, 550/h at 07 and 18, and 950/h in 08-18: about 12,600 alerts. On Saturday and Sunday the round-the-clock floor stays and the daytime bands drop to 35%, so the peak is 410/h and the day holds about 6,300 alerts, half a weekday (measured 0.47-0.52 across the final captures). Each band varies by ±10% per period. The event time is the input timestamp plus a random nanosecond remainder below one microsecond.

Each timestamp takes, in this order: the earliest due step of an anomaly episode; else the earliest due child of an open exec session; else a new background action (session start or entrypoint contact, see Event Types). A child is emitted at the first timestamp at or after its due time, so its gap is rounded up by part of one timestamp gap (on average 3.9 s in weekday office hours, 8.5 s in weekend office hours, 30 s at night).

**Episodes without drops.** An episode's shell takes the timestamp at which the episode is due; its read and API steps queue ahead of session children and take the first timestamps at or after their due times. An episode therefore replaces three background alerts: one background action fewer, or a due session child one timestamp later. It never pauses, re-phases or shifts the background processes.

## Anomaly Chain

`anomaly_mode` defaults to `true`; `false` emits the same background only, with no complete chain. One episode, all in one container:

1. A new interactive bash shell (`Terminal shell in container`) with a new host PID, the pod's `containerd-shim` parent and a terminal.
2. A Python child of that shell opens `/etc/shadow` for reading (`Read sensitive file untrusted`).
3. A curl child of the same shell queries API discovery `https://kubernetes.default.svc.cluster.local/api` (`Contact K8S API Server From Container`).

Linking fields: `container.id` (same pod and sensor), step 2/3 `proc.ppid` = step 1 `proc.pid`, `proc.ppid.ts` = step 1 `proc.pid.ts`, and the inherited `proc.tty`. Step gaps use the background child-gap distributions, conditioned on the whole chain ending six average timestamp gaps before the 300 s detection window closes (at most 280 s); measured spans were 35-269 s.

**Recurrence.** The first episode starts at a point of the first min(interval, 24 h) of the run, drawn from the background hour-of-day and weekday curve. Each next one is due `anomaly_interval_hours` after the actual start of the previous one, with no catch-up; its start is drawn from the window [due - w/2, due + w/2], w = min(interval / 4, 6 h), weighted by the squared curve (weekend level included) plus a 0.02 floor. While no pod qualifies (see below), a start is postponed in random 1-30 min steps; this happens only in the first hours of a run (in runs started at 00:00 UTC, up to 6-8 h on a weekday). In a 14-day default run from a Thursday (14 episodes, gaps 21.8-26.6 h), episode starts fell 0% / 0% / 100% / 0% into 00-06 / 06-12 / 12-18 / 18-24 UTC against 6.7% / 37% / 44% / 12% of background shells, and 29% on Saturday or Sunday against 17% of background shells: a 24 h interval cannot skip weekend days. Each run tends to stay near the hour of its first episode, because every start is drawn close to the previous start plus the interval, so the hour band differs between runs (other runs stayed in 06-12 or 14-17 UTC). With a 6 h interval (23 episodes in 6 days) they fell 22% / 26% / 26% / 26%.

**Variation.** The pod is drawn by the background session weights among the busy pods (weight at least 1.8: 109 of the 500 pods, holding 47% of all sessions), never repeating the previous episode's pod. Its own session background must already have shown, at least twice each, the terminal the new session gets, a shell command, a read command and an `/api` query by a session child; the episode reuses a shell and a read command from that history, drawn by their counts. Every pod|value pair of the chain therefore also occurs in ordinary traffic, and in any other run of the same pack. PIDs, process start offsets, FDs, ports and gaps are drawn from the same pools as background.

**Background guard.** A session child's API query that follows a shadow-read child of the same shell at most 300 s after that shell (compared on the millisecond `@timestamp` clock) queries `/version`; from 300 s on it queries `/api` at the ordinary 12%. The guard keeps event times, pod and lineage and changes only that final step's queried path, so the ordered shell -> read -> `/api` lineage within 300 s is the only episode-only pattern; no alert is dropped. In the 14-day default run the `/api` share of such queries by shell age was 0.000 up to 300 s, then 0.113 / 0.130 / 0.123 / 0.117 / 0.124 for 300-450 / 450-600 / 600-900 / 900-1200 / 1200-1800 s, while their counts per minute of span stay smooth across 300 s (1661 / 1836 in minutes 3-5, 1778 / 1741 in minutes 5-7).

**Detection idea.** Correlate per container: a terminal shell, then a sensitive-file read by its child, then API discovery by a child of the same shell, within 5 minutes. It does not identify the Kubernetes user who invoked exec.

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
| `anomaly_mode` | `true` | Enable recurring complete episodes; `false` keeps background alerts only |
| `anomaly_interval_hours` | `24` | Hours from the actual start of one episode to the due time of the next, 1 to 8760; other values fail validation |
| `api_server_ip` | `10.96.0.1` | IPv4 address of the selected API DNS service, used in both modes |
| `agent_version` | `8.13.3` | Synthetic Elastic Agent version |
| `ecs_version` | `8.17.0` | ECS version |
| `data_stream_namespace` | `lab-k8s` | Data-stream namespace |
| `log_path` | `/var/log/falco/events.log` | Synthetic collector source-file path |

The persistent 500-container/50-node inventory is in `samples/pods.csv`. Keep IPv4 pod addresses and distinct sensor/container contexts when editing it. The alert rate, hour curve and weekend level are set in `patterns/` (`multiplier.ratio` is alerts per period of a band: a day for the four daily files, one weekday for the files in `patterns/weekdays/`). The template holds a copy of the weekday hourly curve and the 0.35 weekend level that only places episode starts; keep them in step when changing the bands. The session/entrypoint mix, session shapes and the 300 s detection window are template constants.

### Output Parameters

The shipped configuration writes JSON lines to `output/events.json` and needs no secrets or output placeholders. To use a backend output, replace the file block with that plugin's configuration and supply its `${params.*}`/`${secrets.*}` values through the CLI.

## Usage

Live generation:

```bash
eventum generate --path generators/security-falco/generator.yml --id falco --live-mode true --keep-order true
```

For a finite batch, copy the generator directory and set `start` and `end` in every pattern file of the copy (the bands are placed relative to `start`). In the four `patterns/*.yml` files set `start` to a midnight UTC such as `"2026-09-17T00:00:00Z"`; in each `patterns/weekdays/*.yml` file set it to the first midnight of that file's weekday at or after it (`thu-*` 2026-09-17, `fri-*` 2026-09-18, `mon-*` 2026-09-21, ...), and remove from `generator.yml` a file whose start would fall at or after the end. Set every `end` to the same absolute end, such as `"2026-09-23T00:00:00Z"`. Then run:

```bash
eventum generate --path security-falco-batch/generator.yml --id falco-batch --live-mode false --keep-order true
```

Six days of source time with one weekend produce about 62,500 alerts and six default episodes. Set `anomaly_mode: false` in the copy for background only. Keep `--keep-order true`: output is stateful and chronological.

**Performance.** One core renders about 2,400 alerts/s: 14 days (149,588 alerts) took 62 s wall, six days (about 62,500 alerts) about 27 s of CPU.

## Limitations

- Source evidence: exact Falco 0.45.0/rules 5.2.0 native records with this `append_output`, a coherent full process trace and a live parser run were not obtained (see Source Profile).
- Only three rules are modeled; process exits, container lifecycle and all other rules are absent. Python/curl children and entrypoint `sh` are the only non-shell processes.
- Rates, the hour-of-day curve, session shapes and the `/version`/`/api` mix are modeling assumptions, not measured cluster statistics. Every weekday follows the same curve and both weekend days the same reduced one; holidays are not modeled.
- Session children and episode steps take the first timestamp at or after their due time, so their gaps are rounded up by part of one timestamp gap (on average 3.9 s in weekday office hours, 8.5 s in weekend office hours, 30 s at night).
- At the start of a run the first episode waits until some busy pod has background history for every chain value (6-8 h after a start at 00:00 UTC).
- Episode hours follow the squared curve, which favors office hours more than background does; a start drawn into the night can stay near night hours for several days. A 24 h interval also places episodes on weekend days, which then carry a larger share of episodes than of background shells (see Recurrence).
- Episode pods are weighted like background sessions but limited to the 109 busiest pods, so every chain value recurs in their ordinary traffic. Drawing from all 500 pods was tested and left out: with a 6 h interval one of 199 chain pod|value pairs was missing from one of seven background-only captures.

## Sample Output

The final step of the first episode from the final default run (row 5601), byte-exact. It is synthetic, not a captured vendor record:

```json
{"@timestamp": "2026-09-17T12:18:48.186+00:00", "agent": {"ephemeral_id": "ef48dd34-7392-4eea-a6c2-0db17965000d", "id": "ef48dd34-7392-4eea-a6c2-0db17965000d", "name": "elastic-agent-worker-13", "type": "filebeat", "version": "8.13.3"}, "container": {"id": "a4c8e020018a", "name": "webhooks-app"}, "data_stream": {"dataset": "falco.alerts", "namespace": "lab-k8s", "type": "logs"}, "destination": {"address": "10.96.0.1", "ip": "10.96.0.1", "port": 443}, "ecs": {"version": "8.17.0"}, "elastic_agent": {"id": "ef48dd34-7392-4eea-a6c2-0db17965000d", "snapshot": false, "version": "8.13.3"}, "event": {"agent_id_status": "verified", "category": ["network"], "dataset": "falco.alerts", "ingested": "2026-09-17T12:18:49.457+00:00", "kind": "alert", "original": "{\"hostname\":\"worker-13\",\"output\":\"2026-09-17T12:18:48.186051241+0000: Notice Unexpected connection to K8s API Server from container | connection=10.244.13.18:51597-\u003e10.96.0.1:443 lport=51597 rport=443 fd_type=ipv4 fd_proto=tcp evt_type=connect user=root user_uid=0 user_loginuid=-1 process=curl proc_exepath=/usr/bin/curl parent=bash command=curl -ks https://kubernetes.default.svc.cluster.local/api terminal=34816 container_id=a4c8e020018a container_name=webhooks-app\",\"output_fields\":{\"container.id\":\"a4c8e020018a\",\"container.image.repository\":\"registry.example.test/webhooks/app\",\"container.image.tag\":\"1.14.7\",\"container.name\":\"webhooks-app\",\"evt.category\":\"net\",\"evt.time.iso8601\":1789647528186051241,\"evt.type\":\"connect\",\"fd.l4proto\":\"tcp\",\"fd.lip\":\"10.244.13.18\",\"fd.lport\":51597,\"fd.name\":\"10.244.13.18:51597-\u003e10.96.0.1:443\",\"fd.rip\":\"10.96.0.1\",\"fd.rport\":443,\"fd.sip\":\"10.96.0.1\",\"fd.sip.name\":\"kubernetes.default.svc.cluster.local\",\"fd.type\":\"ipv4\",\"fd.typechar\":\"4\",\"k8s.ns.name\":\"webhooks\",\"k8s.pod.name\":\"webhooks-app-hpgsmv9l24-04\",\"proc.cmdline\":\"curl -ks https://kubernetes.default.svc.cluster.local/api\",\"proc.exepath\":\"/usr/bin/curl\",\"proc.name\":\"curl\",\"proc.pid\":220332,\"proc.pid.ts\":1789647528149592099,\"proc.pname\":\"bash\",\"proc.ppid\":220307,\"proc.ppid.ts\":1789647480110727812,\"proc.tty\":34816,\"user.loginuid\":-1,\"user.name\":\"root\",\"user.uid\":0},\"priority\":\"Notice\",\"rule\":\"Contact K8S API Server From Container\",\"source\":\"syscall\",\"tags\":[\"T1565\",\"container\",\"k8s\",\"maturity_stable\",\"mitre_discovery\",\"network\"],\"time\":\"2026-09-17T12:18:48.186051241Z\"}", "provider": "syscall", "severity": 47, "timezone": "+00:00", "type": ["connection"]}, "falco": {"hostname": "worker-13", "output": "2026-09-17T12:18:48.186051241+0000: Notice Unexpected connection to K8s API Server from container | connection=10.244.13.18:51597-\u003e10.96.0.1:443 lport=51597 rport=443 fd_type=ipv4 fd_proto=tcp evt_type=connect user=root user_uid=0 user_loginuid=-1 process=curl proc_exepath=/usr/bin/curl parent=bash command=curl -ks https://kubernetes.default.svc.cluster.local/api terminal=34816 container_id=a4c8e020018a container_name=webhooks-app", "output_fields": {"container": {"id": "a4c8e020018a", "image": {"repository": "registry.example.test/webhooks/app", "tag": "1.14.7"}, "name": "webhooks-app"}, "destination": {"ip": "10.96.0.1"}, "evt": {"category": "net", "time": {"iso8601": 1789647528186}, "type": "connect"}, "fd": {"l4proto": "tcp", "lport": 51597, "name": "10.244.13.18:51597-\u003e10.96.0.1:443", "rport": 443, "sip": {"name": "kubernetes.default.svc.cluster.local"}, "type": "ipv4", "typechar": "4"}, "k8s": {"ns": {"name": "webhooks"}, "pod": {"name": "webhooks-app-hpgsmv9l24-04"}}, "proc": {"cmdline": "curl -ks https://kubernetes.default.svc.cluster.local/api", "exepath": "/usr/bin/curl", "name": "curl", "pid": {"ts": 1789647528149592099}, "pname": "bash", "ppid": {"ts": 1789647480110727812}, "tty": 34816}, "process": {"parent": {"pid": 220307}, "pid": 220332}, "server": {"ip": "10.96.0.1"}, "source": {"ip": "10.244.13.18"}, "user": {"loginuid": -1, "name": "root", "uid": "0"}}, "priority": "Notice", "rule": "Contact K8S API Server From Container", "source": "syscall", "tags": ["T1565", "container", "k8s", "maturity_stable", "mitre_discovery", "network"], "time": "2026-09-17T12:18:48.186051241Z"}, "falco.container.mounts": null, "host": {"architecture": "x86_64", "containerized": true, "hostname": "worker-13", "id": "ef48dd34-7392-4eea-a6c2-0db17965000d", "ip": ["10.20.0.23"], "mac": ["02-42-ac-14-00-0d"], "name": "worker-13", "os": {"codename": "jammy", "family": "debian", "kernel": "5.15.0-91-generic", "name": "Ubuntu", "platform": "ubuntu", "type": "linux", "version": "22.04"}}, "input": {"type": "log"}, "log": {"file": {"path": "/var/log/falco/events.log"}, "offset": 271353}, "message": "Contact K8S API Server From Container", "observer": {"hostname": "worker-13", "product": "falco", "type": "sensor", "vendor": "sysdig"}, "orchestrator": {"namespace": "webhooks", "resource": {"name": "webhooks-app-hpgsmv9l24-04", "type": "pod"}}, "process": {"command_line": "curl -ks https://kubernetes.default.svc.cluster.local/api", "executable": "/usr/bin/curl", "name": "curl", "parent": {"name": "bash", "pid": 220307, "start": "2026-09-17T12:18:00.110+00:00"}, "pid": 220332, "start": "2026-09-17T12:18:48.149+00:00", "user": {"id": "0", "name": "root"}}, "related": {"hosts": ["worker-13"]}, "rule": {"name": "Contact K8S API Server From Container"}, "server": {"address": "10.96.0.1", "domain": "kubernetes.default.svc.cluster.local", "ip": "10.96.0.1"}, "source": {"address": "10.244.13.18", "ip": "10.244.13.18", "port": 51597}, "tags": ["preserve_original_event", "preserve_falco_fields"], "threat.technique.id": ["T1565"]}
```

## References

- [Falco JSON output channels](https://falco.org/docs/concepts/outputs/channels/) and [output formatting / append_output](https://falco.org/docs/concepts/outputs/formatting/).
- [Tagged Falco0.45.0 JSON formatter](https://github.com/falcosecurity/falco/blob/0.45.0/userspace/engine/formats.cpp) and [configuration](https://github.com/falcosecurity/falco/blob/0.45.0/falco.yaml).
- [Stable rules5.2.0](https://github.com/falcosecurity/rules/blob/falco-rules-5.2.0/rules/falco_rules.yaml), including required engine/container plugin versions, the three exact outputs and their conditions.
- [Supported fields](https://falco.org/docs/reference/rules/supported-fields/) and tagged [libs0.26.0 process fields](https://github.com/falcosecurity/libs/blob/0.26.0/userspace/libsinsp/sinsp_filtercheck_thread.cpp) and [syscall field types](https://github.com/falcosecurity/libs/blob/0.26.0/userspace/libsinsp/sinsp_filtercheck_evt.cpp).
- [Official older full API JSON example](https://falco.org/blog/falcosidekick-response-engine-part-9-fission/) and [source issue #2476](https://github.com/falcosecurity/falco/issues/2476).
- Pinned Elastic Falco integration [native fixtures](https://github.com/elastic/integrations/blob/c7fa9114e76abac8638ca66bb9088632731373bb/packages/falco/data_stream/alerts/_dev/test/pipeline/test-falco.log), [sample event](https://github.com/elastic/integrations/blob/c7fa9114e76abac8638ca66bb9088632731373bb/packages/falco/data_stream/alerts/sample_event.json) and [pipeline](https://github.com/elastic/integrations/blob/c7fa9114e76abac8638ca66bb9088632731373bb/packages/falco/data_stream/alerts/elasticsearch/ingest_pipeline/default.yml).
