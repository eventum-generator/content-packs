# Apache Cassandra auditlogviewer output

Synthetic human-readable Apache Cassandra 4.0 audit records in the format shown by `auditlogviewer` for `BinAuditLogger`. `event.original` contains the viewer's `Type: AuditLog` and pipe-delimited `LogMessage` text.

## Event Types

| Action | Baseline weight | Cassandra category |
| --- | ---: | --- |
| `select` | 76% | QUERY |
| `update` | 18% | DML |
| `use-keyspace` | 6% | OTHER |
| `create-role` | Chain only | DCL |
| `grant` | Chain only | DCL |
| `drop-role` | Chain only | DCL |

Weights are synthetic, not measured production frequencies. The template plugin uses `fsm` for the multi-event chain.

## Anomaly Chain

The `cassandra` administrator creates `temp_reader` with an obfuscated password, grants it `SELECT` on `finance.payroll`, the new role reads that table from the same unusual source IP, and the administrator drops the role. Correlate by source IP, keyspace, table, role, and a short time window. A rule can detect a short-lived role that receives access to a sensitive table and immediately reads it. The full sequence requires audit categories `DCL` and `QUERY` to be enabled on the relevant node. Sort by `@timestamp` before sequence matching because output line order is not guaranteed.

`event.template.params.anomaly_mode` defaults to `true`. Set it to `false` for ordinary SELECT, UPDATE, and USE records only.

## Parameters

### Event Parameters

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include the temporary-role access chain |
| `host_name` | `cassandra-01.example.test` | Cassandra node name |
| `host_ip` | `10.20.30.10` | Cassandra node IP in the viewer record |
| `keyspace` | `finance` | Generated keyspace |
| `sensitive_table` | `payroll` | Table accessed in the chain |
| `temporary_role` | `temp_reader` | Role created and dropped in the chain |
| `suspect_ip` | `192.0.2.83` | Synthetic chain source IP |

### Output Parameters

The shipped configuration writes `output/events.json` with no connection parameters or secrets. To send events to a SIEM, replace the file output in a local copy and use `${params.siem_host}` and `${secrets.siem_token}` as required by the selected output plugin.

## Usage

```bash
eventum generate --path generators/database-apache-cassandra-audit/generator.yml --id cassandra --live-mode false
eventum generate --path generators/database-apache-cassandra-audit/generator.yml --id cassandra --live-mode true
```

## Sample Output

Copied from an `anomaly_mode: true` run:

```json
{
  "@timestamp": "2026-09-25T13:21:36+00:00",
  "cassandra": {
    "audit": {
      "category": "DCL",
      "operation": "GRANT SELECT ON TABLE finance.payroll TO temp_reader;",
      "temporary_role": "temp_reader",
      "timestamp_ms": 1790342496000,
      "type": "GRANT",
      "viewer_record_type": "AuditLog"
    }
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "grant",
    "category": [
      "iam"
    ],
    "kind": "event",
    "original": "Type: AuditLog\nLogMessage:\nuser:cassandra|host:10.20.30.10:7000|source:/192.0.2.83|port:46265|timestamp:1790342496000|type:GRANT|category:DCL|operation:GRANT SELECT ON TABLE finance.payroll TO temp_reader;",
    "type": [
      "change"
    ]
  },
  "host": {
    "ip": [
      "10.20.30.10"
    ],
    "name": "cassandra-01.example.test"
  },
  "related": {
    "ip": [
      "192.0.2.83",
      "10.20.30.10"
    ],
    "user": [
      "cassandra"
    ]
  },
  "source": {
    "ip": "192.0.2.83",
    "port": 46265
  },
  "user": {
    "name": "cassandra"
  }
}
```

## Coverage and Limits

The official viewer field set is covered 10/10 across applicable operations: `user`, `host`, `source`, `port`, `timestamp`, `type`, `category`, `ks`, `scope`, and `operation`. Global DCL role records omit `ks` and `scope`; table queries include both. Cassandra emits audit records per node only when audit logging is enabled; the default setting is disabled. The model is the text printed by `auditlogviewer` from `BinAuditLogger`, not binary `.cq4` file bytes and not the `FileAuditLogger` SLF4J file layout. The viewer's own diagnostic messages are omitted. Cassandra obfuscates passwords in parsed DCL statements, so the generated role password is masked. KUMA 4.2 lists a Cassandra file source, but compatibility of that normalizer with viewer text is unverified.

## References

- [Apache Cassandra 4.0 audit logging and raw viewer sample](https://cassandra.apache.org/doc/4.0/cassandra/new/auditlogging.html)
- [KUMA 4.2 source catalog](https://support.kaspersky.ru/kuma/4.2/255782)
