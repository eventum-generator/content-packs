# MongoDB 7 Structured Log

Eventum content pack for MongoDB 7 structured JSON log. Emits ECS JSON with the native source record in `event.original`. The native parsed fields are under the source namespace. Default mode includes background and a repeatable anomaly chain; `anomaly_mode: false` emits background only.

## Run

From the content-packs repository root:

```bash
eventum generate --path generators/database-mongodb-log/generator.yml --id database-mongodb-log --live-mode true
```

For a bounded local batch sample, run `timeout 3s eventum generate --path generators/database-mongodb-log/generator.yml --id database-mongodb-log-batch --live-mode false` (timeout exit code 124 is expected for this continuous source).

The file output is `generators/database-mongodb-log/output/events.json`. Set `event.template.params.anomaly_mode: false` to generate only routine activity. The generator emits one event per input tick; timing depends on the Eventum input configuration.

## Events

| Native event | Meaning | Frequency | ECS category |
| --- | --- | --- | --- |
| `client metadata` | Client context and metadata | 1 per session | `network` |
| `Slow query` | Slow command with query metrics | 1 per routine session; 3 per chain | `database` |
| `end connection` | Connection closed | 1 per session | `network` |

## Anomaly Chain

One client connection produces three increasingly broad COLLSCAN slow queries against finance.payroll, then disconnects. Group Slow query messages by ctx and remote, require the same namespace finance.payroll and increasing docsExamined/nreturned over three events, then the matching disconnect. Filter on planSummary=COLLSCAN.

These are selected MongoDB server log messages, not a MongoDB audit log. Server logs can show connection context and query metrics but do not reliably identify the authenticated database user in these records; the chain therefore correlates by ctx and remote address, not user. A COLLSCAN with growing docsExamined is a scan anomaly, not proof of exfiltration.

## Parameters

### Event Parameters

| Parameter | Default | Meaning |
| --- | --- | --- |
| `db_host` | `mongo-01.corp.example` | Server name |
| `db_ip` | `10.110.0.5` | Server address |
| `normal_ip` | `10.110.1.20` | Background client address |
| `anomaly_ip` | `10.99.4.51` | Chain client address |
| `anomaly_namespace` | `finance.payroll` | Collection scanned in chain |
| `anomaly_interval_sessions` | `50` | Routine sessions between chains |
| `anomaly_mode` | `true` | Enable chain; false emits background only |

### Output Parameters

No top-level `${params.*}` or `${secrets.*}` placeholders are shipped. The file output works without credentials. To send to another destination, replace the `output` block with that plugin configuration and keep credentials in Eventum secrets.

## Sample output

This event was captured from an actual generator run with `anomaly_mode: true`:

```json
{
  "@timestamp": "2026-09-25T12:41:53+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "slow-query",
    "category": [
      "database"
    ],
    "dataset": "mongodb.log",
    "kind": "event",
    "original": "{\"attr\": {\"appName\": \"MongoDB Shell\", \"command\": {\"$db\": \"finance\", \"batchSize\": 10000, \"filter\": {}, \"find\": \"payroll\"}, \"docsExamined\": 150000, \"durationMillis\": 850, \"keysExamined\": 0, \"nreturned\": 15000, \"ns\": \"finance.payroll\", \"numYields\": 12, \"planSummary\": \"COLLSCAN\", \"protocol\": \"op_msg\", \"remote\": \"10.99.4.51:61632\", \"reslen\": 2250000, \"type\": \"command\"}, \"c\": \"COMMAND\", \"ctx\": \"conn151\", \"id\": 51803, \"msg\": \"Slow query\", \"s\": \"I\", \"svc\": \"R\", \"t\": {\"$date\": \"2026-09-25T12:41:53.000+00:00\"}}",
    "type": [
      "info"
    ]
  },
  "host": {
    "ip": [
      "10.110.0.5"
    ],
    "name": "mongo-01.corp.example"
  },
  "log": {
    "level": "info"
  },
  "message": "Slow query",
  "mongodb": {
    "log": {
      "attr": {
        "appName": "MongoDB Shell",
        "command": {
          "$db": "finance",
          "batchSize": 10000,
          "filter": {},
          "find": "payroll"
        },
        "docsExamined": 150000,
        "durationMillis": 850,
        "keysExamined": 0,
        "nreturned": 15000,
        "ns": "finance.payroll",
        "numYields": 12,
        "planSummary": "COLLSCAN",
        "protocol": "op_msg",
        "remote": "10.99.4.51:61632",
        "reslen": 2250000,
        "type": "command"
      },
      "c": "COMMAND",
      "ctx": "conn151",
      "id": 51803,
      "msg": "Slow query",
      "s": "I",
      "svc": "R",
      "t": {
        "$date": "2026-09-25T12:41:53.000+00:00"
      }
    }
  },
  "observer": {
    "hostname": "mongo-01.corp.example",
    "ip": "10.110.0.5",
    "product": "MongoDB",
    "type": "database",
    "vendor": "MongoDB"
  },
  "related": {
    "ip": [
      "10.99.4.51"
    ]
  },
  "source": {
    "ip": "10.99.4.51",
    "port": 61632
  },
  "tags": [
    "mongodb-structured-log",
    "preserve_original_event"
  ]
}
```

## Format and references

The native JSON contains all eight common MongoDB structured-log keys (8/8): t, s, c, id, ctx, svc, msg and attr. Event-specific attr fields are included for the selected client metadata, slow query and disconnect messages.

Structured native JSON is retained in event.original and mongodb.log. One ctx and remote endpoint link client metadata, slow queries and disconnect. Fifty collection samples vary routine namespaces and scan metrics.

- [MongoDB Log Messages](https://www.mongodb.com/docs/manual/reference/log-messages/)
- [Kaspersky KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)
