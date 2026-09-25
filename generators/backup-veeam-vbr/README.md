# Veeam Backup & Replication Syslog

Generates ECS-enriched JSON events containing the Veeam Backup & Replication 13.1 syslog record in event.original. The native record bodies and parameter names follow Veeam's event reference for build 13.1.1.18.

Reference coverage: **35/35 distinct documented parameter names** across the seven event IDs below. Each event contains only the parameters documented for that ID. The syslog envelope mirrors Veeam's published examples, which omit the PRI prefix. ECS fields are an additional generator mapping, not a vendor or Elastic parser contract.

## Event Types

| Event ID | Veeam event | Routine share |
| --- | --- | ---: |
| 110 | Backup job started | About 16.7% |
| 10010 | Restore point created | About 16.7% |
| 190 | Backup job finished | About 16.7% |
| 44002 | User authorization denied | About 16.7% |
| 44003 | User authorization granted | About 33.3% |
| 10050 | Restore point deleted | One ordinary cleanup event; one more in anomaly mode |
| 28200 | Backup repository deleted | One planned retirement in background mode, or one in the anomaly chain |

Shares are generator design choices, not measured production frequencies. Four backup jobs rotate, each with a stable JobID and a new JobSessionID per run. The start and finish events share JobSessionID. The restore-point event has no JobSessionID in Veeam's documented record and is linked by VM, repository, and time. The default cron emits one event every ten minutes. The five anomaly events therefore span forty minutes.

## Anomaly Chain

With anomaly_mode enabled by default, one chain starts after 240 routine events:

1. Two 44002 denials and a 44003 grant for the same veeamadmin account and source IP.
2. A 10050 deletion of a pre-existing restore point in the secondary repository.
3. A 28200 removal of that same repository from the backup infrastructure.

The 10050 DateTime is fourteen days before its deletion, because Veeam defines that field as the restore point's creation time. Both deletion records share RepositoryID. The deletion events do not carry the login source IP, so a SIEM rule should correlate the normalized account, backup server, repository ID and event time. A useful detection is two denials, a grant, and both deletion IDs within one hour.

With anomaly_mode set to false, the background includes ordinary job sessions, authorization activity from both listed accounts and addresses, one restore-point cleanup on the active repository, and a planned deletion of the same secondary point and repository used by the anomaly. Those last two background events are six hours apart and have no matching two-denial authorization sequence. The event ID, actor, source IP, point ID, and repository ID therefore do not identify the mode by themselves.

The secondary repository is not used by the generated backup jobs, so Veeam can remove it. Veeam documents that repository removal leaves backup files and other data in place; 28200 does not prove file deletion.

## Parameters

### Event Parameters

Edit event.template.params in generator.yml:

| Parameter | Default | Meaning |
| --- | --- | --- |
| server_name | VBRSRV01 | Syslog hostname |
| server_fqdn | vbrsrv01.contoso.test | VbrHostName |
| version | 13.1.1.18 | VbrVersion |
| normal_user, normal_source_ip | operator, 10.40.1.24 | First routine login identity |
| anomaly_user, anomaly_source_ip | veeamadmin, 198.51.100.91 | Second routine login identity and anomaly actor |
| active_repository_id | 88788f9e-d8f5-4eb4-bc4f-9b3f5403bcec | Repository used by recurring backup jobs |
| repository_id, repository_name | ed8c61cc-77f0-4f40-b73e-8c92d4a6fb11, Backup Repository 01 | Secondary repository retired once |
| retired_point_id | 882ace9a-6308-4f2b-bd12-88f004de0162 | Pre-existing point on the secondary repository |
| vm_name | VM02 | Protected VM |
| anomaly_interval_events | 240 | Routine events before the one-time chain; keep at least 240 for background event parity |
| anomaly_mode | true | true mixes in the chain; false emits only background |

### Output Parameters

The shipped configuration writes output/events.json relative to the generator. It has no top-level parameter or secret overrides. Change output.file.path or replace the output plugin to deliver to a SIEM.

## Usage

From the content-packs repository root:

~~~bash
eventum generate --path generators/backup-veeam-vbr/generator.yml --id backup-veeam-vbr --live-mode true
~~~

Use --live-mode false for a bounded sample run. The generator is open-ended; stop the run when enough events have been collected.

## Sample Output

This complete event was copied from an anomaly-mode generator run:

~~~json
{
  "@timestamp": "2026-09-27T09:10:00+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "kind": "event",
    "module": "veeam",
    "dataset": "veeam.vbr.syslog",
    "code": "28200",
    "category": [
      "configuration"
    ],
    "action": "backup_repository_deleted",
    "type": [
      "deletion"
    ],
    "outcome": "success",
    "original": "1 2026-09-27T09:10:00+00:00 VBRSRV01 Veeam_MP - - [origin enterpriseId=\"31023\"] [categoryId=0 instanceId=28200 RepositoryID=\"ed8c61cc-77f0-4f40-b73e-8c92d4a6fb11\" Type=\"0\" RepositoryName=\"Backup Repository 01\" ChangesXML=\"<changes><object id=\"ed8c61cc-77f0-4f40-b73e-8c92d4a6fb11\" name=\"Backup Repository 01\" /></changes>\" UserName=\"TECH\\veeamadmin\" UserFullInfo=\"<ModifiedUserInfo fullName=\"TECH\\veeamadmin\" loginType=\"0\" />\" VbrHostName=\"vbrsrv01.contoso.test\" VbrVersion=\"13.1.1.18\" Version=\"1\" Description=\"Backup repository Backup Repository 01 has been deleted.\"]"
  },
  "message": "Backup repository Backup Repository 01 has been deleted.",
  "host": {
    "name": "VBRSRV01"
  },
  "user": {
    "name": "veeamadmin"
  },
  "veeam": {
    "event_id": 28200,
    "app": "Veeam_MP",
    "severity": "warning",
    "enterprise_id": 31023,
    "category_id": 0,
    "parameters": {
      "ChangesXML": "<changes><object id=\"ed8c61cc-77f0-4f40-b73e-8c92d4a6fb11\" name=\"Backup Repository 01\" /></changes>",
      "Description": "Backup repository Backup Repository 01 has been deleted.",
      "RepositoryID": "ed8c61cc-77f0-4f40-b73e-8c92d4a6fb11",
      "RepositoryName": "Backup Repository 01",
      "Type": "0",
      "UserFullInfo": "<ModifiedUserInfo fullName=\"TECH\\veeamadmin\" loginType=\"0\" />",
      "UserName": "TECH\\veeamadmin",
      "VbrHostName": "vbrsrv01.contoso.test",
      "VbrVersion": "13.1.1.18",
      "Version": "1"
    }
  }
}
~~~

## References and Limits

- [Veeam backup job started, ID 110](https://helpcenter.veeam.com/docs/vbr/events/event_110.html), [restore point created, ID 10010](https://helpcenter.veeam.com/docs/vbr/events/event_10010.html), and [backup job finished, ID 190](https://helpcenter.veeam.com/docs/vbr/events/event_190.html).
- [Veeam authorization denied, ID 44002](https://helpcenter.veeam.com/docs/vbr/events/event_44002.html), and [granted, ID 44003](https://helpcenter.veeam.com/docs/vbr/events/event_44003.html).
- [Veeam restore point deleted, ID 10050](https://helpcenter.veeam.com/docs/vbr/events/event_10050.html), and [backup repository deleted, ID 28200](https://helpcenter.veeam.com/docs/vbr/events/event_28200.html).
- [Veeam removing backup repositories](https://helpcenter.veeam.com/docs/vbr/userguide/repo_delete.html) defines the repository-removal effect.

Veeam's event pages document build 13.1.1.18. Parser compatibility with a different Veeam version or a KUMA normalizer is unverified. The static secondary repository and restore point are assumed to predate the generated stream; the generator emits their removal once. It does not model all Veeam operations or failed backup jobs. File output may be slightly out of timestamp order during accelerated sample generation; sort by @timestamp for correlation.
