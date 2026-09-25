# Veeam Backup & Replication Syslog

Generates ECS-compatible JSON with Veeam Backup & Replication 13.1 RFC 5424-style `event.original` records and documented structured-data parameters for interactive authorization and destructive backup actions.

Reference coverage: **27/27 distinct documented event parameter names across IDs 44002, 44003, 10050 and 28200, plus the documented syslog envelope and structured-data IDs. Optional parameters appear only on their applicable event types.**

## Event Types

| Event ID | Action | Routine weight |
| --- | --- | ---: |
| 44003 | Authorization granted | 86% |
| 44002 | Authorization denied | 14% |
| 10050 | Restore point deleted | Anomaly only |
| 28200 | Backup repository deleted | Anomaly only |

Weights are generator design values, not measured vendor production frequencies. One reusable template drives an FSM. The default input emits one event per second, preserving an observable order between anomaly steps.

## Anomaly Chain

With `event.template.params.anomaly_mode: true` (the default), the generator mixes background events with this sequence after every 240 routine events:

1. Two 44002 authorization denials for `veeamadmin` from one unusual address.
2. A 44003 authorization grant follows for that identity and address.
3. A 10050 restore point deletion and a 28200 repository deletion follow on the same backup server. The deleted VM and repository IDs change on each chain.

Rules can detect failure-to-success logon followed by destructive backup operations, and a rapid restore-point-plus-repository deletion. Veeam deletion events identify the Windows-qualified user, while authorization events identify `FriendlyName`; the generator keeps their account suffix equal. The deletion records do not include the login source IP, so correlate by server, normalized account and time.

Set `anomaly_mode: false` to emit only background. No anomaly steps or transition into the chain occur in that mode.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `server_name`, `server_fqdn`, `version` | `VBRSRV01`, `vbrsrv01.contoso.test`, `13.1.1.18` | VBR server identity and version |
| `normal_user`, `normal_source_ip` | `operator`, `10.40.1.24` | Routine authorization identity |
| `anomaly_user`, `anomaly_source_ip` | `veeamadmin`, `198.51.100.91` | Anomaly authorization identity |
| `repository_id`, `repository_name`, `vm_name` | `ed8c61cc-77f0-4f40-b73e-8c92d4a6fb11`, `Backup Repository 01`, `VM02` | Prefixes/identities for distinct anomaly targets |
| `anomaly_interval_events` | `240` | Routine events between chains |
| `anomaly_mode` | `true` | Enable the chain; `false` emits only background |

### Output Parameters

The shipped configuration writes `output/events.json` relative to the generator. It declares no top-level `${params.*}` or `${secrets.*}` overrides. Change `output.file.path` or replace the output plugin to deliver to a SIEM.

## Usage

Run from the content-packs repository root:

```bash
eventum generate --path generators/backup-veeam-vbr/generator.yml --id backup-veeam-vbr --live-mode true
```

Use `--live-mode false` for a fast local sample run.

## Sample Output

This complete event was copied from an enabled-mode generator run:

```json
{"@timestamp": "2026-09-25T11:49:45+00:00", "ecs": {"version": "8.17.0"}, "event": {"kind": "event", "module": "veeam", "dataset": "veeam.vbr.syslog", "code": "28200", "category": ["configuration"], "action": "backup_repository_deleted", "type": ["deletion"], "outcome": "success", "original": "1 2026-09-25T11:49:45+00:00 VBRSRV01 Veeam_MP - - [origin enterpriseId=\"31023\"] [categoryId=0 instanceId=28200 VbrHostName=\"vbrsrv01.contoso.test\" VbrVersion=\"13.1.1.18\" Version=\"1\" Description=\"Backup repository Backup Repository 01 0001 has been deleted.\" RepositoryID=\"ed8c61cc-77f0-4f40-b73e-8c92d4a60001\" Type=\"0\" RepositoryName=\"Backup Repository 01 0001\" ChangesXML=\"\u003cchanges\u003e\u003cobject id=\"ed8c61cc-77f0-4f40-b73e-8c92d4a60001\" name=\"Backup Repository 01 0001\" /\u003e\u003c/changes\u003e\" UserName=\"TECH\\veeamadmin\" UserFullInfo=\"\u003cModifiedUserInfo fullName=\"TECH\\veeamadmin\" loginType=\"0\" /\u003e\"]"}, "message": "Backup repository Backup Repository 01 0001 has been deleted.", "host": {"name": "VBRSRV01"}, "source": {"ip": null}, "user": {"name": "veeamadmin"}, "veeam": {"event_id": 28200, "app": "Veeam_MP", "severity": "warning", "enterprise_id": 31023, "category_id": 0, "parameters": {"ChangesXML": "\u003cchanges\u003e\u003cobject id=\"ed8c61cc-77f0-4f40-b73e-8c92d4a60001\" name=\"Backup Repository 01 0001\" /\u003e\u003c/changes\u003e", "Description": "Backup repository Backup Repository 01 0001 has been deleted.", "RepositoryID": "ed8c61cc-77f0-4f40-b73e-8c92d4a60001", "RepositoryName": "Backup Repository 01 0001", "Type": "0", "UserFullInfo": "\u003cModifiedUserInfo fullName=\"TECH\\veeamadmin\" loginType=\"0\" /\u003e", "UserName": "TECH\\veeamadmin", "VbrHostName": "vbrsrv01.contoso.test", "VbrVersion": "13.1.1.18", "Version": "1"}}}
```

## References and Limits

- [Veeam event 44002](https://helpcenter.veeam.com/docs/vbr/events/event_44002.html) and [44003](https://helpcenter.veeam.com/docs/vbr/events/event_44003.html): interactive authorization.
- [Veeam event 10050](https://helpcenter.veeam.com/docs/vbr/events/event_10050.html) and [28200](https://helpcenter.veeam.com/docs/vbr/events/event_28200.html): restore point and repository deletion.
- [KUMA 4.0 supported event sources](https://support.kaspersky.com/kuma/4.0/en-US/255782.htm): Veeam 12.1 syslog normalizer inventory.

KUMA lists a 12.1 normalizer, whereas these templates follow the 13.1 vendor event reference (build 13.1.1.18). Parser compatibility with the 12.1 normalizer is unverified. Veeam examples omit the syslog PRI prefix; this pack mirrors the published record body. The background stream intentionally covers authorization only.
