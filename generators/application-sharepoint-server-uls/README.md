# Microsoft SharePoint Server ULS workflow diagnostics

Synthetic SharePoint Server 2016 Unified Logging Service (ULS) diagnostic records for the legacy workflow timer job. The pack models ULS trace-file rows, not SharePoint audit records or Microsoft 365 activity.

## Event types

| Native EventID | Approximate share | ECS category | Meaning |
| --- | ---: | --- | --- |
| `ahk8y` | 33.3% | `process` | Workflow instance begins processing |
| `b6p4` | 33.3% | `process` | Workflow-association SQL command |
| `tzkv` | 33.3% | `process` | SQL command parameters for that lookup |

The template uses FSM mode and emits one record per simulated second from a single farm node. Within each workflow pass, native event timestamps are 10 ms apart; records can reach the output file up to two seconds after their event time. These proportions are synthetic: one `ahk8y`, `b6p4`, and `tzkv` record per modeled workflow pass. Microsoft does not publish a production distribution for these EventIDs.

## Anomaly Chain

With `anomaly_mode: true` (the default), one workflow instance passes through `ahk8y → b6p4 → tzkv` three times after 32 ordinary workflow passes. One of those ordinary passes already uses the same workflow and object IDs, so the ID alone does not identify the anomaly. The nine records share `sharepoint.workflow.instance_id` and the site, web, item, and list IDs. Each pass has its own `sharepoint.uls.correlation_id`, joining its three records within 20 ms of event time. A rule can group by workflow instance, sort by `@timestamp`, and find three starts with association lookups across distinct correlation IDs in a short window. Sort by `@timestamp`; output row order is not a reliable clock.

Microsoft's troubleshooting guide uses these EventIDs and the correlation ID to investigate a workflow timer job stuck at “Pausing.” Repeated processing here is a synthetic investigation lead, not a documented failure signature or proof that the job is stuck. Diagnosing a stuck timer job also requires checking for absent new timer-job entries and the job's state. With `anomaly_mode: false`, the stream includes one isolated ordinary pass for that workflow instance per 32 routine passes, but never a three-pass burst for it.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include three linked workflow passes; `false` produces background only |
| `farm_host` | `sp-app-01` | SharePoint server name |
| `suspect_workflow_id` | `11111111-2222-4333-8444-555555555555` | Clearly synthetic workflow instance used in one benign pass and the anomaly chain |
| `routine_workflows_before_chain` | `32` | Ordinary three-record passes between anomaly chains |

### Output Parameters

No top-level `${params.*}` or `${secrets.*}` are required. Output defaults to `output/events.json`; edit the file output section to deliver elsewhere.

## Usage

From the content-packs repository:

```bash
eventum generate --path generators/application-sharepoint-server-uls/generator.yml --id sharepoint --live-mode false
```

For continuous generation, use `--live-mode true`. Set `event.template.params.anomaly_mode` to `false` for background only. The file output is overwritten when a run starts.

## Sample output

This JSON event was copied from an anomaly-mode run:

```json
{
  "@timestamp": "2026-09-25T14:52:13.010000+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "workflow_association_lookup",
    "category": [
      "process"
    ],
    "code": "b6p4",
    "dataset": "sharepoint.uls",
    "kind": "event",
    "module": "sharepoint",
    "original": "09/25/2026 14:52:13.01\tOWSTIMER.EXE (0x9318)\t0x6DF0\tSharePoint Foundation\tDatabase\tb6p4\tVerboseEx\tSqlCommand: ; EXEC proc_getworkflowassociations '285c2d48-d9c9-45d9-a726-8bc5033790b8', 'acff57c3-ea68-4eda-8f1d-3c641959299f', '6077cc34-5f9c-4bdd-8beb-c2aafe0a5b9e', '39fae561-5463-4dc7-8a8a-65ab28c8cb9b', @contenttypeid, @RequestGuid OUTPUT\t04bf54d9-3c8e-4034-ba8d-2d5749d91f44",
    "type": [
      "info"
    ]
  },
  "host": {
    "name": "sp-app-01"
  },
  "log": {
    "level": "verboseex"
  },
  "message": "SqlCommand: ; EXEC proc_getworkflowassociations '285c2d48-d9c9-45d9-a726-8bc5033790b8', 'acff57c3-ea68-4eda-8f1d-3c641959299f', '6077cc34-5f9c-4bdd-8beb-c2aafe0a5b9e', '39fae561-5463-4dc7-8a8a-65ab28c8cb9b', @contenttypeid, @RequestGuid OUTPUT",
  "process": {
    "name": "OWSTIMER.EXE",
    "pid": 37656,
    "thread": {
      "id": 28144
    }
  },
  "related": {
    "hosts": [
      "sp-app-01"
    ]
  },
  "service": {
    "name": "SharePoint Server",
    "version": "2016"
  },
  "sharepoint": {
    "uls": {
      "area": "SharePoint Foundation",
      "category": "Database",
      "correlation_id": "04bf54d9-3c8e-4034-ba8d-2d5749d91f44",
      "event_id": "b6p4",
      "level": "VerboseEx",
      "message": "SqlCommand: ; EXEC proc_getworkflowassociations '285c2d48-d9c9-45d9-a726-8bc5033790b8', 'acff57c3-ea68-4eda-8f1d-3c641959299f', '6077cc34-5f9c-4bdd-8beb-c2aafe0a5b9e', '39fae561-5463-4dc7-8a8a-65ab28c8cb9b', @contenttypeid, @RequestGuid OUTPUT",
      "process": "OWSTIMER.EXE (0x9318)",
      "thread_id": "0x6DF0",
      "timestamp_local": "09/25/2026 14:52:13.01"
    },
    "workflow": {
      "instance_id": "11111111-2222-4333-8444-555555555555",
      "item_id": "6077cc34-5f9c-4bdd-8beb-c2aafe0a5b9e",
      "list_id": "39fae561-5463-4dc7-8a8a-65ab28c8cb9b",
      "site_id": "285c2d48-d9c9-45d9-a726-8bc5033790b8",
      "web_id": "acff57c3-ea68-4eda-8f1d-3c641959299f"
    }
  }
}
```

## Format and coverage

`event.original` contains a tab-separated ULS row with all nine documented columns: Timestamp, Process, TID, Area, Category, EventID, Level, Message, and Correlation. The source-specific `sharepoint.uls` object preserves these values. This is 9/9 column coverage against Microsoft's ULS format description. `sharepoint.workflow` contains IDs extracted from the linked messages or carried across records with the same correlation ID. The full line is synthetically assembled from a Microsoft-published SharePoint 2010 column description and official workflow examples that explicitly apply to SharePoint Server 2016; it is not a captured vendor line. Other 2016 ULS variants are not validated by this narrow source set. The farm node is modeled in UTC, so the native local timestamp matches ECS `@timestamp`.

The `Verbose` and `VerboseEx` records require those ULS trace levels to be enabled. Microsoft warns that extensive VerboseEx tracing can affect farm performance. KUMA 4.2 lists a SharePoint Server 2016 diagnostic-log file normalizer, but this pack has not been tested against it. Only legacy workflow timer records are modeled; other ULS categories, security audit actions, and Windows Application events are outside this pack.

## References

- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)
- [Microsoft: diagnose a workflow timer job stuck at Pausing, with ULS examples](https://learn.microsoft.com/en-us/troubleshoot/sharepoint/workflows/workflow-timer-job-is-stuck-at-pausing)
- [Microsoft: view SharePoint Server diagnostic logs](https://learn.microsoft.com/en-us/sharepoint/administration/view-diagnostic-logs)
- [Microsoft: ULS trace-file columns and tab delimiter](https://learn.microsoft.com/en-us/previous-versions/office/developer/sharepoint-2010/gg193966%28v%3Doffice.14%29)
