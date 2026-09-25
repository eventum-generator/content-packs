# Apache Kafka StandardAuthorizer audit log

Synthetic Kafka KRaft `StandardAuthorizer` decisions in the exact `Principal = ... is Denied ... based on rule ...` message structure assembled by Kafka. The JSON envelope exposes ECS and parsed Kafka fields while `event.original` preserves the log line.

## Event Types

| Denied operation | Baseline frequency | Request | Category |
| --- | ---: | --- | --- |
| `READ` | 85% | `Fetch` | IAM |
| `WRITE` | 15% | `Produce` | IAM |
| `READ`, `WRITE`, `ALTER_CONFIGS`, `DELETE` | Chain only | `Fetch`, `Produce`, `AlterConfigs`, `DeleteTopics` | IAM |

The baseline weights are synthetic assumptions, not measured Kafka traffic. Only explicit denied requests are generated. Kafka normally logs these at INFO; allowed decisions need DEBUG and are outside this pack.

## Anomaly Chain

One service principal (`User:svc-audit`) from `192.0.2.91` receives denials for `READ`, `WRITE`, `ALTER_CONFIGS`, and `DELETE` against the same `payroll-events` topic in consecutive events. A SIEM rule can group by principal, client IP, broker and topic, then detect this progression of increasingly sensitive operations. Every step has `DefaultDeny`; no access was granted and the sequence alone does not prove compromise.

`anomaly_mode` defaults to `true`. Set it to `false` in `event.template.params` for routine denied requests only.

## Parameters

### Event Parameters

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include the four-step denial chain |
| `broker_host` | `kafka-01.corp.example` | Synthetic Kafka broker |
| `suspicious_principal` | `User:svc-audit` | Principal in the chain |
| `suspicious_client_ip` | `192.0.2.91` | Client IP in the chain |
| `sensitive_topic` | `payroll-events` | Topic in the chain |

### Output Parameters

The shipped configuration writes `output/events.json` with no connection parameters or secrets. To deliver elsewhere, replace the `file` output in a local copy and add `${params.siem_host}` and `${secrets.siem_token}` for the selected output plugin where applicable.

## Usage

```bash
eventum generate --path generators/messaging-apache-kafka-authorizer/generator.yml --id kafka-authorizer --live-mode false
eventum generate --path generators/messaging-apache-kafka-authorizer/generator.yml --id kafka-authorizer --live-mode true
```

## Sample Output

This event was copied from a generator run with `anomaly_mode: true`.

```json
{
  "@timestamp": "2026-09-25T12:39:21+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "authorization-denied",
    "category": [
      "iam"
    ],
    "kind": "event",
    "original": "[2026-09-25 12:39:21,000] INFO Principal = User:svc-audit is Denied operation = READ from host = 192.0.2.91 on resource = Topic:LITERAL:payroll-events for request = Fetch with resourceRefCount = 1 based on rule DefaultDeny (kafka.authorizer.logger)",
    "outcome": "failure",
    "type": [
      "denied"
    ]
  },
  "host": {
    "name": "kafka-01.corp.example"
  },
  "kafka": {
    "authorization_result": "Denied",
    "operation": "READ",
    "principal": "User:svc-audit",
    "request": "Fetch",
    "resource": {
      "name": "payroll-events",
      "pattern_type": "LITERAL",
      "type": "Topic"
    },
    "resource_ref_count": 1,
    "rule": "DefaultDeny"
  },
  "log": {
    "level": "INFO",
    "logger": "kafka.authorizer.logger"
  },
  "related": {
    "ip": [
      "192.0.2.91"
    ],
    "user": [
      "svc-audit"
    ]
  },
  "source": {
    "ip": "192.0.2.91"
  },
  "user": {
    "name": "svc-audit"
  }
}
```

## Coverage and Limits

All eight fields in Kafka's `buildAuditMessage` are preserved and parsed: principal, decision, operation, client host, resource type/pattern/name, request API, resource reference count, and matching rule (8/8 field groups). The Log4j prefix shown in `event.original` is an example layout; actual broker log appenders and timestamps vary. This pack targets KRaft `StandardAuthorizer` with default-deny semantics, not ZooKeeper `AclAuthorizer`, Confluent audit events, or ACL mutation records. The KUMA 4.2 catalog lists Kafka 3.8.1 syslog, but parser compatibility with this specific Log4j envelope is not asserted.

## References

- [Kafka StandardAuthorizer audit message builder](https://apache.googlesource.com/kafka/+/HEAD/metadata/src/main/java/org/apache/kafka/metadata/authorizer/StandardAuthorizerData.java)
- [Kafka 3.8 authorization and ACLs](https://github.com/apache/kafka-site/blob/markdown/content/en/38/security/authorization-and-acls.md)
- [KUMA 4.2 supported event sources](https://support.kaspersky.ru/kuma/4.2/255782)
