# Delinea Secret Server CEF

Synthetic Secret Server 11.3 secret-view audit events for SIEM ingestion and correlation testing. The CEF header retains the historical `Thycotic Software` vendor name used by this version.

## Event types

| Native event | Code | Approximate frequency | ECS category/type |
| --- | --- | --- | --- |
| `SECRET - VIEW` | `10004` | 100%; ordinary views dominate, five linked views recur when anomaly mode is enabled | `iam` / `access` |

The generator models one Secret Server instance. Background events use four fixed actors and four ordinary secret records; actor IDs and source IPs, as well as secret IDs, names and folders, remain consistent.

## Anomaly Chain

When `anomaly_mode: true` (the default), a single actor views five distinct high-value secrets in the same folder over five event timestamps: Domain Controller Admin, Backup Vault Root, Firewall Breakglass, Database Admin and Cloud Tenant Root. Each view is native CEF event `10004`. Correlate `suser` or `suid`, `src`, and five distinct `fileId` values within a short window; `cs3` gives the folder. The generator also emits normal views before and after each chain. Output lines can be interleaved by Eventum; sort by `@timestamp` for sequence analysis.

Set `anomaly_mode: false` for background only. This removes the linked high-value views and does not assign the chain actor or source IP to ordinary events. The pattern indicates unusual secret access, not proof that credentials were disclosed or used.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
| --- | --- | --- |
| `server_host` | `SECRET-SRV-01` | Secret Server syslog host |
| `device_version` | `11.3.000001` | Version in the CEF header; this template is validated for this profile |
| `anomaly_mode` | `true` | Include the five-view chain |
| `anomaly_interval_events` | `80` | Number of routine pairs between chains |
| `chain_user` | `privileged-auditor` | Linked actor username |
| `chain_user_id` | `217` | Linked actor ID |
| `chain_source_ip` | `10.20.30.77` | Linked actor RFC 1918 address |
| `chain_folder` | `Infrastructure` | Folder for linked secrets |
| `chain_folder_id` | `44` | Folder ID in the CEF message |

### Output Parameters

The shipped configuration writes JSON Lines to `output/events.json` with no top-level `params` or `secrets`. To send the generated event objects to another output plugin, replace the `output.file` section and define that plugin's required `${params.*}` and `${secrets.*}` values. For native syslog/CEF ingestion, forward `event.original` as the syslog message; the JSON envelope is for ECS-aware testing.

## Usage

Run from the content-packs repository root:

```bash
eventum generate --path generators/identity-delinea-secret-server/generator.yml --id delinea --live-mode false
eventum generate --path generators/identity-delinea-secret-server/generator.yml --id delinea-live --live-mode true
```

For a background-only run, change `anomaly_mode` to `false` in `generator.yml`.

## Sample output event

This is an actual event from anomaly-mode validation:

```json
{
  "@timestamp": "2026-09-25T14:20:22+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "secret-view",
    "category": [
      "iam"
    ],
    "code": "10004",
    "dataset": "thycotic_ss.logs",
    "kind": "event",
    "original": "Sep 25 14:20:22 SECRET-SRV-01 CEF:0|Thycotic Software|Secret Server|11.3.000001|10004|SECRET - VIEW|2|msg=[[SecretServer]] Event: [Secret] Action: [View] By User: privileged-auditor Item Name: Domain Controller Admin (Item Id: 701) Container Name: Infrastructure (Container Id: 44)  suid=217 suser=privileged-auditor cs4=Privileged Auditor cs4Label=suser Display Name src=10.20.30.77 rt=Sep 25 2026 14:20:22 fname=Domain Controller Admin fileType=Secret fileId=701 cs3Label=Folder cs3=Infrastructure",
    "type": [
      "access"
    ]
  },
  "host": {
    "name": "SECRET-SRV-01"
  },
  "observer": {
    "hostname": "SECRET-SRV-01",
    "product": "Secret Server",
    "vendor": "Thycotic Software",
    "version": "11.3.000001"
  },
  "related": {
    "hosts": [
      "SECRET-SRV-01"
    ],
    "ip": [
      "10.20.30.77"
    ],
    "user": [
      "privileged-auditor"
    ]
  },
  "source": {
    "ip": "10.20.30.77"
  },
  "thycotic_ss": {
    "cef": {
      "class_id": "10004",
      "device_version": "11.3.000001",
      "extension": {
        "cs3": "Infrastructure",
        "cs3Label": "Folder",
        "cs4": "Privileged Auditor",
        "cs4Label": "suser Display Name",
        "fileId": "701",
        "fileType": "Secret",
        "fname": "Domain Controller Admin",
        "msg": "[[SecretServer]] Event: [Secret] Action: [View] By User: privileged-auditor Item Name: Domain Controller Admin (Item Id: 701) Container Name: Infrastructure (Container Id: 44)",
        "rt": "Sep 25 2026 14:20:22",
        "src": "10.20.30.77",
        "suid": "217",
        "suser": "privileged-auditor"
      },
      "name": "SECRET - VIEW",
      "product": "Secret Server",
      "severity": 2,
      "vendor": "Thycotic Software",
      "version": 0
    },
    "event": {
      "secret": {
        "folder": "Infrastructure",
        "folder_id": "44",
        "id": "701",
        "name": "Domain Controller Admin"
      }
    }
  },
  "user": {
    "full_name": "Privileged Auditor",
    "id": "217",
    "name": "privileged-auditor"
  }
}
```

## Format and coverage

The CEF shape follows the complete Secret Server `11.3.000001` `SECRET - VIEW` line in the Elastic integration and Delinea's event catalog. All 12 extension keys in that reference line are emitted: `msg`, `suid`, `suser`, `cs4`, `cs4Label`, `src`, `rt`, `fname`, `fileType`, `fileId`, `cs3Label`, `cs3`. The original syslog/CEF line is preserved in `event.original`; parsed values are also available in ECS and `thycotic_ss.*`. This is a deliberately narrow VIEW profile. Other Secret Server event classes and newer-version CEF variants are outside its validated scope.

## References

- [Delinea Syslog Event List](https://docs.delinea.com/online-help/secret-server/alerts-events/logs/syslog-event-list/index.htm) - `SECRET - VIEW` code `10004`.
- [Delinea Secret Server Reported Events](https://docs.delinea.com/online-help/integrations/splunk/splunk-integration-secret-server/ssvr-reported-events.htm) - CEF field meanings.
- [Delinea Secure Syslog and CEF Logging](https://docs.delinea.com/online-help/secret-server/alerts-events/logs/secure-syslog-cef/index.htm) - external syslog configuration.
- [Elastic Thycotic Secret Server integration](https://www.elastic.co/docs/reference/integrations/thycotic_ss) - complete 11.3 raw line and tested-version statement.
