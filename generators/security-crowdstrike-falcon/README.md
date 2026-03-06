# CrowdStrike Falcon Event Stream

Generates realistic CrowdStrike Falcon Event Stream events in raw JSON format, covering endpoint detections (EPP), authentication audits, user activity audits, firewall matches, incident summaries, and remote response sessions. Events use the CrowdStrike Event Streams envelope format with `metadata` and `event` body sections.

CrowdStrike Falcon is an endpoint detection and response (EDR) platform that provides real-time visibility into endpoint activity, detects threats using behavioral analysis and machine learning, and enables automated prevention and response.

## Event Types

| Event Type | Template | Description | Weight |
|---|---|---|---|
| `EppDetectionSummaryEvent` | `epp-detection.json.jinja` | Endpoint detection alerts with MITRE ATT&CK mapping | 250 |
| `AuthActivityAuditEvent` | `auth-audit.json.jinja` | Console authentication events (login, MFA, SAML) | 200 |
| `UserActivityAuditEvent` | `user-audit.json.jinja` | Console user actions (policy changes, IOC management) | 150 |
| `FirewallMatchEvent` | `firewall-match.json.jinja` | Falcon Firewall rule matches | 150 |
| `IncidentSummaryEvent` | `incident-summary.json.jinja` | Incident creation and scoring events | 50 |
| `RemoteResponseSessionStartEvent` | `remote-session-start.json.jinja` | Real Time Response session initiation | 30 |
| `RemoteResponseSessionEndEvent` | `remote-session-end.json.jinja` | Real Time Response session completion | 30 |

## Realism Features

- **7 event types** — EPP detections (~29%), auth audits (~23%), user audits (~17%), firewall matches (~17%), incidents (~6%), remote sessions (~7%)
- **20 detection scenarios** covering all MITRE ATT&CK tactics from Initial Access through Impact, plus CrowdStrike-specific objectives (Malware, Exploit, Machine Learning, Custom Intelligence)
- **25 process chains** — mix of benign (explorer->cmd->whoami) and suspicious (winword->powershell->certutil, rundll32->cmd->net, svchost->powershell reverse shell)
- **Pattern disposition flags** — 20 boolean fields per detection with realistic prevention/detection configurations
- **Shared monotonic offset counter** — consistent event stream ordering across all event types
- **Remote session correlation** — session start events store state; session end events pop from the session pool
- **Session pool bounded to 20** — prevents unbounded memory growth
- **Consistent host correlation** — hostname, agent_id, local_ip, MAC address remain consistent within each event
- **20 hosts** across workstations, servers, and laptops with realistic naming and network topology
- **12 firewall rules** covering network security, threat intelligence, C2 prevention, and remote access
- **20 network destinations** — malicious C2 servers, mining pools, Tor relays, and legitimate internal resources
- **Optional NetworkAccesses/DnsRequests** arrays in detection events (20% chance each)

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `customer_id` | `a1b2c3d4...` | CrowdStrike Customer ID (CID) |
| `falcon_base_url` | `https://falcon.crowdstrike.com` | Falcon console base URL |

## Output Parameters

For production deployment with OpenSearch/Elasticsearch:

```yaml
output:
  - opensearch:
      hosts:
        - ${params.opensearch_host}
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: ${params.opensearch_index}
```

| Parameter | Description |
|---|---|
| `${params.opensearch_host}` | OpenSearch/Elasticsearch host URL |
| `${params.opensearch_user}` | Username for authentication |
| `${secrets.opensearch_password}` | Password (from Eventum keyring) |
| `${params.opensearch_index}` | Target index name |

## Usage

```bash
# Live mode (5 events/second)
eventum generate \
  --path generators/security-crowdstrike-falcon/generator.yml \
  --id falcon \
  --live-mode

# Batch mode (generate as fast as possible)
eventum generate \
  --path generators/security-crowdstrike-falcon/generator.yml \
  --id falcon \
  --live-mode false
```

### startup.yml example

```yaml
generators:
  falcon:
    path: generators/security-crowdstrike-falcon/generator.yml
```

## Sample Output

```json
{
  "metadata": {
    "customerIDString": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
    "offset": 42,
    "eventType": "EppDetectionSummaryEvent",
    "eventCreationTime": 1741276800000,
    "version": "1.0"
  },
  "event": {
    "ProcessStartTime": 1741276500,
    "ProcessEndTime": 0,
    "ProcessId": 15234,
    "ParentProcessId": 8012,
    "Hostname": "DESKTOP-HR01",
    "UserName": "jsmith",
    "Name": "Malicious PowerShell Execution",
    "Description": "A suspicious PowerShell command was detected attempting to download and execute content from a remote server.",
    "Severity": 80,
    "SeverityName": "High",
    "FileName": "powershell.exe",
    "FilePath": "\\Device\\HarddiskVolume3\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "CommandLine": "powershell.exe -nop -w hidden -enc SQBF...",
    "SHA256String": "ae3f4a5b6c7d8e9f...",
    "MD5String": "e5f6a7b8c9d0e1f2...",
    "SHA1String": "e5f6a7b8c9d0e1f2...",
    "LogonDomain": "CORP.ACME.COM",
    "AgentId": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
    "CompositeId": "ldt:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6:15234",
    "AggregateId": "aggr:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6:8012",
    "IOCType": "domain",
    "IOCValue": "evil.example.com",
    "LocalIP": "10.1.10.21",
    "MACAddress": "00:50:56:8a:12:34",
    "Tactic": "Execution",
    "Technique": "PowerShell",
    "Objective": "Falcon Detection Method",
    "PatternDispositionValue": 2176,
    "PatternDispositionDescription": "Prevention, process killed.",
    "PatternDispositionFlags": {
      "Indicator": false,
      "Detect": false,
      "KillProcess": true,
      "KillSubProcess": true,
      "OperationBlocked": true,
      "ProcessBlocked": true
    },
    "DataDomains": ["Endpoint"],
    "GrandparentImageFileName": "\\Device\\HarddiskVolume3\\Windows\\explorer.exe",
    "GrandparentCommandLine": "C:\\Windows\\explorer.exe",
    "ParentImageFileName": "\\Device\\HarddiskVolume3\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
    "ParentCommandLine": "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n ..."
  }
}
```

## File Structure

```
generators/security-crowdstrike-falcon/
  generator.yml                                    # Pipeline config
  README.md                                        # This file
  templates/
    _base.json.jinja                               # Shared macros (metadata envelope)
    epp-detection.json.jinja                       # Endpoint detection summary events
    auth-audit.json.jinja                          # Authentication audit events
    user-audit.json.jinja                          # User activity audit events
    firewall-match.json.jinja                      # Firewall rule match events
    incident-summary.json.jinja                    # Incident summary events
    remote-session-start.json.jinja                # Remote response session start
    remote-session-end.json.jinja                  # Remote response session end
  samples/
    hosts.csv                                      # 20 endpoints (workstations, servers, laptops)
    endpoint_users.csv                             # 15 endpoint users (user, admin, service)
    console_users.csv                              # 8 Falcon console users
    processes.json                                 # 25 process chains (benign + suspicious)
    detection_scenarios.json                       # 20 detection scenarios with MITRE mapping
    firewall_rules.json                            # 12 firewall rules
    network_destinations.json                      # 20 network destinations
    auth_operations.json                           # 9 authentication operations
    user_operations.json                           # 10 user management operations
  output/
    events.json                                    # Generated events (overwritten each run)
```

## References

- [CrowdStrike Falcon Event Streams API](https://falcon.crowdstrike.com/documentation/89/event-streams)
- [CrowdStrike Detection and Prevention Policies](https://falcon.crowdstrike.com/documentation/22/detection-and-prevention-policies)
- [CrowdStrike Falcon Real Time Response](https://falcon.crowdstrike.com/documentation/71/real-time-response)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [CrowdStrike Falcon Firewall Management](https://falcon.crowdstrike.com/documentation/107/falcon-firewall-management)
