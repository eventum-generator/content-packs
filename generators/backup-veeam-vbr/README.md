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
| 10050 | Restore point deleted | Periodic user cleanup, one secondary-point retirement, and one deletion per anomaly episode |
| 28200 | Backup repository deleted | One planned secondary-repository retirement in either mode |

Shares are generator design choices, not measured production frequencies. Four backup jobs rotate, each with a stable JobID and a new JobSessionID per run. The start and finish events share JobSessionID. The restore-point event has no JobSessionID in Veeam's documented record and is linked by VM, repository, and time. The default cron emits one event every ten minutes. The four anomaly events span thirty minutes. The input emits 144 records per day, with one boundary record included in a finite six-day run.

## Anomaly Chain

`anomaly_mode` defaults to `true`. A minimum interval of `anomaly_interval_hours` (default 48 hours) precedes the first episode and each later episode. The scheduler uses source timestamps and waits for a completed job cycle with an undeleted restore point. Each four-event episode is:

1. Two 44002 denials for the same `veeamadmin` account and login IP.
2. A 44003 grant for that account and IP.
3. A 10050 deletion of the newest completed restore point on the active repository.

That point was emitted earlier as 10010 in an ordinary backup session; the corresponding 190 already finished successfully. The deletion carries the same `OibID`, `OriginalOibID`, `RepositoryID`, VM identity and saved creation `DateTime`. A point removed by ordinary cleanup cannot be selected again. Every episode uses a different point UUID and a different completed job session. Veeam's 10010 record has no JobSessionID, so the externally observable connection to the job is VM/repository/time; the shared point ID links its creation and deletion.

Job-cycle alignment can extend the configured minimum. In the six-day validation, default episode starts were 48 hours 40 minutes apart; changing the interval to 60 hours produced 60 hours 40 minutes. Each episode spans thirty minutes. A SIEM rule can correlate two denials, a grant and a restore-point deletion by account, backup server and time. The 10050 record has no login IP or authentication/session ID, so those must not be invented as joins.

`anomaly_mode: false` emits all seven native IDs independently. Both actors/IPs appear in ordinary authorization activity, and the anomaly actor also performs ordinary active-repository point cleanup. No event ID, fixed user, IP, repository or synthetic marker identifies the mode by itself. Four six-day default/custom runs produced 865 records each: two complete episodes in each enabled run and zero in each disabled run.

### Planned Secondary Repository Retirement

This separate background operation occurs once in both modes. A pre-existing, fourteen-day-old secondary point is removed first. Six hours later, event 28200 removes its pre-existing secondary repository from backup infrastructure. Recurring jobs use the distinct active repository throughout. These operations do not repeat, because the generator has not emitted recreation or job reassignment.

Veeam requires that no job references a repository being removed. It documents that repository removal leaves backup files and other data in place; 28200 does not prove physical file deletion. The periodic anomaly does not include repository removal.

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
| hypervisor_server | pdcsrv01.contoso.test | Native ServerName for the protected VM |
| user_domain | TECH | Domain prefix in native operation-user details |
| anomaly_interval_hours | 48 | Minimum source-time interval before and between episodes; clamped to at least one hour and aligned to a completed job cycle |
| anomaly_mode | true | true mixes in periodic episodes; false emits only background |

### Output Parameters

The shipped configuration writes output/events.json relative to the generator. It has no top-level parameter or secret overrides. Change output.file.path or replace the output plugin to deliver to a SIEM.

## Usage

From the content-packs root, make a finite configuration for a six-day batch:

~~~bash
uv run --project ../eventum python - <<'PYCODE'
from pathlib import Path
p = Path("generators/backup-veeam-vbr")
source = (p / "generator.yml").read_text()
finite = source.replace(
    "      count: 1\n",
    '      count: 1\n      start: "2026-09-25T00:00:00+00:00"\n'
    '      end: "2026-10-01T00:00:00+00:00"\n',
    1,
)
(p / "generator.batch.yml").write_text(finite)
PYCODE
flock -x /tmp/eventum-generator-heavy.lock uv run --project ../eventum eventum generate --path generators/backup-veeam-vbr/generator.batch.yml --id vbr --live-mode false --keep-order true
rm generators/backup-veeam-vbr/generator.batch.yml
~~~

For a continuous stream:

~~~bash
uv run --project ../eventum eventum generate --path generators/backup-veeam-vbr/generator.yml --id vbr --live-mode true --keep-order true
~~~

## Sample Output

This complete synthetic 10050 event was copied from the first validated periodic episode:

~~~json
{
  "@timestamp": "2026-09-27T01:30:00+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "kind": "event",
    "module": "veeam",
    "dataset": "veeam.vbr.syslog",
    "code": "10050",
    "category": [
      "file"
    ],
    "action": "restore_point_deleted",
    "type": [
      "deletion"
    ],
    "outcome": "success",
    "original": "1 2026-09-27T01:30:00+00:00 VBRSRV01 Veeam_MP - - [origin enterpriseId=\"31023\"] [categoryId=0 instanceId=10050 OibID=\"fa95965f-64f8-4cc1-8355-77dc18837edb\" OriginalOibID=\"fa95965f-64f8-4cc1-8355-77dc18837edb\" VmRef=\"vm-02\" VmName=\"VM02\" ServerName=\"pdcsrv01.contoso.test\" DateTime=\"09/27/2026 00:10:00\" IsCorrupted=\"False\" Platform=\"0\" StorageSize=\"13873971200\" RepositoryID=\"88788f9e-d8f5-4eb4-bc4f-9b3f5403bcec\" IsFull=\"True\" UserFullInfo=\"<ModifiedUserInfo fullName=\"TECH\\veeamadmin\" loginType=\"0\" />\" VbrHostName=\"vbrsrv01.contoso.test\" VbrVersion=\"13.1.1.18\" Version=\"1\" Description=\"Restore point for VM 'VM02' has been removed by user TECH\\veeamadmin.\"]"
  },
  "message": "Restore point for VM 'VM02' has been removed by user TECH\\veeamadmin.",
  "host": {
    "name": "VBRSRV01"
  },
  "user": {
    "name": "veeamadmin"
  },
  "veeam": {
    "event_id": 10050,
    "app": "Veeam_MP",
    "severity": "warning",
    "enterprise_id": 31023,
    "category_id": 0,
    "parameters": {
      "DateTime": "09/27/2026 00:10:00",
      "Description": "Restore point for VM 'VM02' has been removed by user TECH\\veeamadmin.",
      "IsCorrupted": "False",
      "IsFull": "True",
      "OibID": "fa95965f-64f8-4cc1-8355-77dc18837edb",
      "OriginalOibID": "fa95965f-64f8-4cc1-8355-77dc18837edb",
      "Platform": "0",
      "RepositoryID": "88788f9e-d8f5-4eb4-bc4f-9b3f5403bcec",
      "ServerName": "pdcsrv01.contoso.test",
      "StorageSize": "13873971200",
      "UserFullInfo": "<ModifiedUserInfo fullName=\"TECH\\veeamadmin\" loginType=\"0\" />",
      "VbrHostName": "vbrsrv01.contoso.test",
      "VbrVersion": "13.1.1.18",
      "Version": "1",
      "VmName": "VM02",
      "VmRef": "vm-02"
    }
  }
}
~~~

## References and Limits

- [Veeam backup job started, ID 110](https://helpcenter.veeam.com/docs/vbr/events/event_110.html), [restore point created, ID 10010](https://helpcenter.veeam.com/docs/vbr/events/event_10010.html), and [backup job finished, ID 190](https://helpcenter.veeam.com/docs/vbr/events/event_190.html).
- [Veeam authorization denied, ID 44002](https://helpcenter.veeam.com/docs/vbr/events/event_44002.html), and [granted, ID 44003](https://helpcenter.veeam.com/docs/vbr/events/event_44003.html).
- [Veeam restore point deleted, ID 10050](https://helpcenter.veeam.com/docs/vbr/events/event_10050.html), and [backup repository deleted, ID 28200](https://helpcenter.veeam.com/docs/vbr/events/event_28200.html).
- [Veeam removing backup repositories](https://helpcenter.veeam.com/docs/vbr/userguide/repo_delete.html) defines the repository-removal effect.

Veeam's event pages document build 13.1.1.18. Parser compatibility with a different Veeam version or a KUMA normalizer is unverified. The static secondary repository and restore point are assumed to predate the generated stream; the generator emits their removal once. It does not model all Veeam operations or failed backup jobs. Use `--keep-order true` for ordered file output, and correlate by the source `@timestamp`.

Native XML-valued parameters keep the literal inner quotes shown in Veeam's examples; a generic strict RFC 5424 parser was not verified. The 44002 `Reason=1` parameter is supported by the vendor table, while its published raw example omits it. Complete byte-for-byte equivalence to captures of this configured deployment is not claimed.
