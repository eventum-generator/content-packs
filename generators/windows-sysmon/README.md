# Windows Sysmon Event Log Generator

Generates realistic [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) (System Monitor) events in ECS-compatible JSON format, matching the output of Winlogbeat / Elastic Agent for the `Microsoft-Windows-Sysmon/Operational` channel.

Simulates a well-tuned production endpoint running a SwiftOnSecurity-style Sysmon configuration (Events 7, 9, 10 disabled).

## Event Types

| Event ID | Description | Frequency | ECS Category |
|----------|-------------|-----------|--------------|
| 1 | Process Create | ~12% | process / start |
| 3 | Network Connection | ~8% | network / connection |
| 5 | Process Terminated | ~10% | process / end |
| 6 | Driver Loaded | <0.1% | driver / start |
| 8 | CreateRemoteThread | <0.1% | process / change |
| 11 | File Created | ~25% | file / creation |
| 12 | Registry Create/Delete | ~3% | registry / change |
| 13 | Registry Value Set | ~20% | registry / change |
| 15 | FileCreateStreamHash | ~2% | file / access |
| 17 | Named Pipe Created | ~0.5% | file / creation |
| 18 | Named Pipe Connected | ~0.5% | file / access |
| 22 | DNS Query | ~15% | network / dns |
| 23 | File Delete (Archived) | ~1.5% | file / deletion |
| 25 | Process Tampering | ~0.5% | process / change |
| 26 | File Delete (Logged) | ~1% | file / deletion |

## Realism Features

- **Process lifecycle correlation** — Event 1 (Process Create) stores processes in a shared pool; Event 5 (Process Terminated) consumes from the pool, maintaining consistent ProcessGuid, PID, Image, and User across the lifecycle
- **Process-to-activity linkage** — Events 3, 11, 12, 13, 22, 23, 26 reference active processes from the pool (non-consuming), so DNS queries, file operations, and network connections are attributed to realistic running processes
- **ECS field structure** — Full Elastic Common Schema compliance matching the `windows.sysmon_operational` data stream: `process.*`, `file.*`, `registry.*`, `dns.*`, `network.*`, `source.*`, `destination.*`, `related.*`
- **Sysmon-specific fields** — `winlog.event_data.*` includes IntegrityLevel, LogonGuid, LogonId, PE metadata, hash strings in `SHA1=...,MD5=...,SHA256=...,IMPHASH=...` format
- **Realistic process data** — 25 Windows processes with correct parent-child relationships, PE metadata (FileVersion, Description, Company, Product, OriginalFileName), integrity levels, and file hashes
- **DNS query responses** — 30 real-world DNS domains (Microsoft services, Google, certificate authorities, internal AD) with CNAME chains, resolved IPs, and success/NXDOMAIN distribution
- **Registry path diversity** — HKLM and HKU paths covering services, security policy, Explorer, Windows Defender, AppModel with correct event types (SetValue, CreateKey, DeleteKey)
- **120-host fleet** — each event is attributed to a random host from a pool of domain controllers, servers, and workstations with unique agent IDs
- **Per-host record IDs** — sequential `winlog.record_id` scoped per hostname
- **Per-host process pool** — process lifecycle correlation is tracked per host so create→terminate and process-to-activity linkages stay within the same machine
- **Process tampering realism** — Event 25 correctly attributes to browsers (Chrome, Edge, Firefox) which trigger benign tampering alerts

## Parameters

### Event Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `domain` | `CONTOSO` | NetBIOS domain name |
| `fqdn_suffix` | `contoso.local` | DNS domain suffix |
| `domain_sid` | `S-1-5-21-3457937927-...` | Domain SID prefix |
| `agent_version` | `8.17.0` | Agent version string |

### Host Pool

Host identity (`hostname`, `agent_id`, IP, MAC, role) is defined per-host in `samples/hosts.csv` (120 hosts). Each event randomly selects a host from the pool. Edit the CSV to customize the fleet.

## Usage

```bash
# Run the generator
eventum generate --path generators/windows-sysmon/generator.yml --id sysmon --live-mode
```

## Sample Output

### Event ID 1 — Process Create

```json
{
    "@timestamp": "2026-02-21T14:30:22.150000+00:00",
    "agent": {
        "ephemeral_id": "b8c4e2a1-3f5d-4e7a-9b1c-d3e5f7a9b1c3",
        "id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "name": "WORKSTATION01.contoso.local",
        "type": "winlogbeat",
        "version": "8.17.0"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "event": {
        "action": "Process creation",
        "category": ["process"],
        "code": "1",
        "created": "2026-02-21T14:30:22.150000+00:00",
        "kind": "event",
        "module": "sysmon",
        "provider": "Microsoft-Windows-Sysmon",
        "type": ["start"]
    },
    "host": {
        "name": "WORKSTATION01",
        "os": { "family": "windows", "type": "windows" }
    },
    "log": { "level": "information" },
    "process": {
        "args": ["C:\\Windows\\System32\\svchost.exe", "-k", "netsvcs", "-p"],
        "args_count": 4,
        "command_line": "C:\\Windows\\System32\\svchost.exe -k netsvcs -p",
        "entity_id": "{a23eae89-bd56-5903-0000-0010e9d95e00}",
        "executable": "C:\\Windows\\System32\\svchost.exe",
        "hash": {
            "md5": "774a62c08b8cc38f34e0e43d5a5d1d21",
            "sha1": "a1385ce20ad79f55df235effd9780c31442aa234",
            "sha256": "ef3179d498793bf4234f708d3be28633ac4883c1d71ccdf49cfa8f22e4a0c118"
        },
        "name": "svchost.exe",
        "parent": {
            "command_line": "C:\\Windows\\System32\\services.exe",
            "entity_id": "{a23eae89-bd28-5903-0000-00102f345d00}",
            "executable": "C:\\Windows\\System32\\services.exe",
            "name": "services.exe",
            "pid": 580
        },
        "pe": {
            "company": "Microsoft Corporation",
            "description": "Host Process for Windows Services",
            "file_version": "10.0.22621.1 (WinBuild.160101.0800)",
            "imphash": "247b9220e5d9b720a82b2c8b5069ad69",
            "original_file_name": "svchost.exe",
            "product": "Microsoft Windows Operating System"
        },
        "pid": 6228,
        "working_directory": "C:\\Windows\\system32\\"
    },
    "related": {
        "hash": ["a1385ce20ad79f55df235effd9780c31442aa234", "774a62c08b8cc38f34e0e43d5a5d1d21", "ef3179d498793bf4234f708d3be28633ac4883c1d71ccdf49cfa8f22e4a0c118", "247b9220e5d9b720a82b2c8b5069ad69"],
        "user": ["SYSTEM"]
    },
    "user": {
        "domain": "NT AUTHORITY",
        "id": "S-1-5-18",
        "name": "SYSTEM"
    },
    "winlog": {
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "computer_name": "WORKSTATION01.contoso.local",
        "event_data": {
            "Company": "Microsoft Corporation",
            "CurrentDirectory": "C:\\Windows\\system32\\",
            "Description": "Host Process for Windows Services",
            "FileVersion": "10.0.22621.1 (WinBuild.160101.0800)",
            "IntegrityLevel": "System",
            "LogonGuid": "{b23eae89-bd56-5903-0000-002005eb0700}",
            "LogonId": "0x3e7",
            "OriginalFileName": "svchost.exe",
            "Product": "Microsoft Windows Operating System",
            "TerminalSessionId": "0"
        },
        "event_id": "1",
        "opcode": "Info",
        "process": { "pid": 3216, "thread": { "id": 3964 } },
        "provider_guid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}",
        "provider_name": "Microsoft-Windows-Sysmon",
        "record_id": "757",
        "user": { "identifier": "S-1-5-18" },
        "version": 5
    }
}
```

## File Structure

```
windows-sysmon/
├── generator.yml
├── README.md
├── templates/
│   ├── 1-process-create.json.jinja
│   ├── 3-network-connection.json.jinja
│   ├── 5-process-terminate.json.jinja
│   ├── 6-driver-loaded.json.jinja
│   ├── 8-create-remote-thread.json.jinja
│   ├── 11-file-create.json.jinja
│   ├── 12-registry-create-delete.json.jinja
│   ├── 13-registry-value-set.json.jinja
│   ├── 15-file-stream-hash.json.jinja
│   ├── 17-pipe-created.json.jinja
│   ├── 18-pipe-connected.json.jinja
│   ├── 22-dns-query.json.jinja
│   ├── 23-file-delete-archived.json.jinja
│   ├── 25-process-tampering.json.jinja
│   └── 26-file-delete-detected.json.jinja
└── samples/
    ├── hosts.csv
    ├── usernames.csv
    ├── processes.json
    ├── dns_domains.json
    ├── network_destinations.json
    ├── registry_paths.json
    ├── file_paths.json
    ├── drivers.json
    └── pipes.json
```

## References

- [Sysmon — Sysinternals | Microsoft Learn](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Elastic Windows Integration — Sysmon Operational](https://github.com/elastic/integrations/tree/main/packages/windows/data_stream/sysmon_operational)
- [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)
- [TrustedSec Sysmon Community Guide](https://github.com/trustedsec/SysmonCommunityGuide)
- [Olaf Hartong's sysmon-modular](https://github.com/olafhartong/sysmon-modular)
