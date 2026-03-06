# Linux Syslog Generator

Produces realistic Linux syslog events in ECS-compatible JSON format, matching the output of Filebeat / Elastic Agent with the **System** integration (`system.syslog` dataset).

## Data Source

Linux syslog (`/var/log/syslog` on Debian/Ubuntu, `/var/log/messages` on RHEL/Rocky) — the central log facility collecting messages from SSH, sudo, cron, systemd, kernel, PAM, DHCP, Postfix, package management, and rsyslog itself.

## Event Types

| Template | Description | Weight |
|----------|-------------|--------|
| sshd-auth | SSH accepted/failed authentication | 150 |
| sshd-session | SSH session open/close/disconnect | 70 |
| sudo | sudo command execution and auth failures | 100 |
| su | su invocation success/failure | 20 |
| cron | Cron job execution | 120 |
| systemd-lifecycle | Service start/stop/failed | 150 |
| kernel-firewall | UFW BLOCK/ALLOW | 40 |
| kernel-generic | Filesystem, device, OOM, misc kernel | 65 |
| pam | PAM session/auth events | 50 |
| dhcp | DHCPACK/REQUEST/DISCOVER | 30 |
| postfix | SMTP delivery, connect/disconnect | 40 |
| package-mgmt | dpkg status changes | 30 |
| rsyslog | rsyslog internal + logrotate | 10 |

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `fqdn_suffix` | `example.com` | Domain suffix for hostnames |
| `agent_version` | `8.17.0` | Filebeat/Agent version string |
| `network_prefix` | `10.1` | First two octets of internal IP range |

## Usage

```bash
# Live mode (continuous generation)
eventum generate --path generators/linux-syslog/generator.yml --id syslog --live-mode

# Batch mode (generate and exit)
eventum generate --path generators/linux-syslog/generator.yml --id syslog --count 1000 --live-mode false
```

## Sample Output

```json
{
  "@timestamp": "2026-03-06T14:23:45.123456+00:00",
  "event": {
    "original": "<86>Mar  6 14:23:45 web-01 sshd[12345]: Accepted publickey for jsmith from 10.1.3.50 port 52341 ssh2",
    "dataset": "system.syslog",
    "module": "system",
    "kind": "event",
    "category": ["authentication"],
    "type": ["info"]
  },
  "message": "Accepted publickey for jsmith from 10.1.3.50 port 52341 ssh2",
  "host": {
    "hostname": "web-01",
    "ip": ["10.1.3.10"],
    "mac": ["00:50:56:8d:05:61"],
    "os": { "name": "Debian GNU/Linux", "version": "12", "kernel": "6.1.0-27-amd64", "platform": "debian" }
  },
  "process": { "name": "sshd", "pid": 12345 },
  "agent": { "type": "filebeat", "version": "8.17.0" },
  "log": { "file": { "path": "/var/log/syslog" }, "offset": 1000 },
  "data_stream": { "type": "logs", "dataset": "system.syslog", "namespace": "default" },
  "ecs": { "version": "8.11.0" }
}
```

## References

- [Elastic System Integration](https://docs.elastic.co/integrations/system)
- [RFC 3164 — BSD Syslog Protocol](https://datatracker.ietf.org/doc/html/rfc3164)
- [ECS Field Reference](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html)
