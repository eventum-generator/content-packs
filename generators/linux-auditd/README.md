# Linux Auditd Event Log Generator

Produces realistic Linux audit events matching the output of **Auditbeat / Elastic Agent** with the auditd_manager integration. Events follow the Elastic Common Schema (ECS) and can be ingested directly into OpenSearch or Elasticsearch.

## Event Types Covered

| Record Type | event.action | Frequency | Category |
|-------------|-------------|-----------|----------|
| SYSCALL (execve) | `executed` | ~29% | process |
| SYSCALL (openat) | `opened-file` | ~23% | file |
| SYSCALL (connect) | `connected-to` | ~12% | network |
| USER_AUTH | `authenticated` | ~9% | authentication |
| CRED_ACQ | `acquired-credentials` | ~8% | authentication |
| CRED_DISP | `disposed-credentials` | ~8% | authentication |
| USER_LOGIN | `logged-in` | ~5% | authentication |
| USER_CMD | `ran-command` | ~3% | process |
| SERVICE_START | `started-service` | ~2% | process |
| SERVICE_STOP | `stopped-service` | ~2% | process |

## Realism Features

- **Weighted event distribution** matching a production Linux server with standard audit rules
- **Correlated authentication flow** — USER_AUTH → CRED_ACQ → USER_LOGIN → CRED_DISP using shared session pools
- **Correlated services** — SERVICE_START creates entries consumed by SERVICE_STOP
- **Monotonic sequence numbers** — sequential `event.sequence` across all events
- **Realistic user contexts** — root, regular users, service accounts (www-data, nginx, postgres) with correct UIDs
- **Multiple auth methods** — sshd (40%), sudo (30%), cron (15%), su (10%), login (5%)
- **Network connection targets** — external (40%), internal (40%), localhost (20%) with protocol-appropriate ports
- **File access patterns** — 20 realistic file paths (/etc/passwd, /etc/shadow, /var/log/*, config files)
- **Process trees** — 30 common Linux processes with correct parent-child relationships and arguments
- **Source IPs** — private IPs for internal access, public IPs for SSH brute-force
- **SELinux context** — unconfined/system_u contexts with realistic distribution
- **Failure simulation** — auth failures (15%), login failures (20%), execve non-zero exits (10%)

## Parameters

### Event Parameters

Edit the `params` section under `event.template` in `generator.yml`:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `hostname` | `web01` | Linux hostname |
| `fqdn_suffix` | `example.com` | Domain suffix appended to hostname |
| `os_kernel` | `6.1.0-27-amd64` | Kernel version string |
| `os_name` | `Debian GNU/Linux` | OS name |
| `os_platform` | `debian` | OS platform identifier |
| `os_version` | `12` | OS version |
| `agent_id` | `da084743-...` | Auditbeat agent ID |
| `agent_version` | `8.17.0` | Auditbeat version string |

## Usage

```bash
# Install Eventum
uv tool install eventum-generator

# Run the generator
eventum generate \
  --path generators/linux-auditd/generator.yml \
  --id auditd \
  --live-mode
```

### Adjusting Event Rate

Change the `count` in the input section:

```yaml
input:
  - cron:
      expression: "* * * * * *"
      count: 5    # 5 events/second (300/min, 18K/hour)
```

## Sample Output

### SYSCALL (execve) — Process Execution

```json
{
    "@timestamp": "2026-02-21T12:00:01.234567+00:00",
    "auditd": {
        "data": {
            "arch": "x86_64",
            "exit": "0",
            "success": "yes",
            "syscall": "execve",
            "tty": "pts0"
        },
        "message_type": "syscall",
        "result": "success",
        "session": "3",
        "summary": {
            "actor": { "primary": "jsmith", "secondary": "root" },
            "how": "/usr/bin/cat",
            "object": { "primary": "/usr/bin/cat", "type": "process" }
        }
    },
    "event": {
        "action": "executed",
        "category": ["process"],
        "kind": "event",
        "module": "auditd",
        "outcome": "success",
        "sequence": 1042,
        "type": ["start"]
    },
    "process": {
        "args": ["cat", "/etc/hostname"],
        "executable": "/usr/bin/cat",
        "name": "cat",
        "parent": { "executable": "/usr/bin/bash", "name": "bash", "pid": 10627 },
        "pid": 20240,
        "working_directory": "/home/jsmith"
    },
    "user": {
        "audit": { "id": "1000", "name": "jsmith" },
        "id": "0",
        "name": "root"
    },
    "service": { "type": "auditd" }
}
```

## File Structure

```
linux-auditd/
  generator.yml                              # Pipeline configuration
  README.md                                  # This file
  templates/
    syscall-execve.json.jinja                # Process execution (execve)
    syscall-open.json.jinja                  # File access (openat/open)
    syscall-connect.json.jinja               # Network connection (connect)
    user-auth.json.jinja                     # PAM authentication
    cred-acq.json.jinja                      # Credential acquisition (correlated)
    cred-disp.json.jinja                     # Credential disposal (correlated)
    user-login.json.jinja                    # User login (correlated)
    user-cmd.json.jinja                      # sudo command execution
    service-start.json.jinja                 # systemd service start
    service-stop.json.jinja                  # systemd service stop (correlated)
  samples/
    usernames.csv                            # 10 Linux user accounts with UIDs
    processes.json                           # 30 Linux processes with args/parents
    services.json                            # 12 systemd services
    file_paths.json                          # 20 monitored file paths with metadata
```

## References

- [Red Hat — Understanding Audit Log Files](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/security_guide/sec-understanding_audit_log_files)
- [Elastic Auditd Manager Integration](https://github.com/elastic/integrations/tree/main/packages/auditd_manager)
- [go-libaudit ECS Normalizations](https://github.com/elastic/go-libaudit/blob/main/aucoalesce/normalizations.yaml)
- [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html)
- [Auditbeat Reference](https://www.elastic.co/guide/en/beats/auditbeat/current/index.html)
