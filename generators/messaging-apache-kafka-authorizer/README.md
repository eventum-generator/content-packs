# Apache Kafka StandardAuthorizer Denial Log

Synthetic `kafka-authorizer.log` records of topic operations denied by the KRaft `StandardAuthorizer` in Apache Kafka 3.9.0: misconfigured clients retrying requests they are not allowed to make. The native Log4j line is in `event.original`, with parsed ECS and `kafka.*` fields beside it.

## Selected Profile

- Kafka 3.9.0 in KRaft mode, one combined broker/controller node that is the active controller. `Fetch` and `Produce` are authorized by the broker; `AlterConfigs` and `DeleteTopics` are forwarded to the controller, which authorizes them with the original client principal and address.
- `StandardAuthorizer` with `allow.everyone.if.no.acl.found=false`, initial ACL load complete, no client in `super.users`.
- Twelve SASL-authenticated `User` principals, each bound to one client address in `10.40.3.0/24`, and four existing topics. Clients hold `DESCRIBE` ACLs on the topics but none of the operations they attempt, so every attempt ends in `DefaultDeny`. The broker service principal holds `CLUSTER_ACTION` for request forwarding; `delete.topic.enable=true`.
- Every request names one topic: a full consumer `Fetch` of one partition, a non-transactional, non-idempotent `Produce` to one partition, a legacy `AlterConfigs` for one topic, a `DeleteTopics` for one topic. Kafka therefore logs `resourceRefCount = 1` and exactly one INFO denial per request.
- Default `config/log4j.properties`: logger `kafka.authorizer.logger` at INFO, file `kafka-authorizer.log`, layout `[%d] %p %m (%c)%n`. The JVM runs in UTC; the native line carries no zone.

Only denials of explicitly requested operations are logged at INFO. Allowed decisions (DEBUG), filter and introspection checks (TRACE), authentication and successful traffic are outside this stream, not absent from the modeled cluster.

## Event Types

| Denied operation | Request | Handled by | Share | Denied principals | ECS category / type |
| --- | --- | --- | ---: | --- | --- |
| `READ` | `Fetch` | broker | 53.3-54.3% | all 12 | `api` / `denied` |
| `WRITE` | `Produce` | broker | 36.7-38.0% | 11 | `api` / `denied` |
| `ALTER_CONFIGS` | `AlterConfigs` | controller (forwarded) | 4.8-4.9% | `ops-config`, `ops-topics`, `analyst`, `svc-audit` | `api` / `denied` |
| `DELETE` | `DeleteTopics` | controller (forwarded) | 3.6-4.2% | `ops-config`, `ops-topics`, `analyst`, `svc-audit` | `api` / `denied` |

Shares and volume were measured over four 76 h 20 min runs in both modes: 923-1082 events per day. Which principal is denied which operation on which topic is listed in `samples/denials.json`; application accounts are denied reads and writes, and only the two operations accounts, the analyst and the audit exporter are denied administrative requests.

Each client behaves independently. After a quiet period (log-normal, mean 24 h divided by its `bursts_per_day`), it retries one denied request several times: 1-8 `Fetch` or `Produce` attempts about 25 s apart, or 1-3 administrative attempts about 45 s apart. After a run it may try another operation on the same topic within 10 minutes (30%), and after that a third (30%). About 73% of denials follow a denial of the same principal within 10 minutes; the median gap between two denials of one principal is 41-43 s and the 90th percentile 50-57 min. The input ticks every 10 seconds and carries at most one record; records keep millisecond times inside the tick. Rates and weights are synthetic, not measured Kafka traffic.

## Anomaly Chain

**Sequence.** One principal from its own address is denied `READ`/`Fetch`, `WRITE`/`Produce`, `ALTER_CONFIGS`/`AlterConfigs` and `DELETE`/`DeleteTopics` on the same topic as four consecutive denials of that principal, 20-81 seconds apart and at most about 4 minutes from first to last. Every step is `DefaultDeny`: nothing is read, written, reconfigured or deleted, so no restoring events follow.

**Linking fields.** `kafka.principal` (`user.name`), `source.ip`, `kafka.resource.name` and `host.name`, all present in `event.original`.

**Near misses.** In both modes, about every 6 hours one of the episode-capable principals below runs the first three or the last three steps of the chain on its topic with the same spacing, and stops. Across 16 measured 76 h runs, counts ranged from 2 to 14 of each kind (varying per run), plus 5-12 other runs of three different operations on one topic within 5 minutes.

**Recurrence.** The first episode is due `anomaly_interval_hours` plus a random 0-10 minutes after the first input timestamp; each next one is due the same way after the actual start of the previous one. When an episode is due, its principal stops retrying and the episode usually starts within 20 seconds; if a near miss by the same principal is still running, the start waits for it to finish. Missed episodes are not queued. Start-to-start intervals are therefore the configured interval plus up to about 10 minutes (occasionally more when a start waits for a near miss); final runs measured 24 h 01 min to 24 h 03 min at the default 24, 12 h 03 min to 12 h 06 min at 12, 1 h 02 min to 1 h 09 min at 1.

**Variation.** The episode actor and topic come from the client/topic pairs whose rows in `samples/denials.json` cover all four operations. The shipped samples give six: `analyst` on `audit-internal`, `ops-config` on `metrics-internal` and `payroll-events`, `ops-topics` on `orders-archive` and `audit-internal`, `svc-audit` on `payroll-events`. They are used in a shuffled order that is reshuffled after every six episodes, without the same pair twice in a row, so the first episode differs between runs. Each of these principals is also denied each of the four operations on its topic in ordinary traffic of both modes; every one of the 52 denial rows occurred in every measured run.

**Detection idea.** Group denials by principal, source address and topic and alert when one principal's consecutive denials on one topic run through `READ`, `WRITE`, `ALTER_CONFIGS` and `DELETE` in that order within 5 minutes. Ordinary traffic contains retry bursts, repeats, lone administrative denials and three-step near misses, but never all four steps in that order within 5 minutes, so neither repetition, burst length, a single administrative denial nor three of the four steps identifies the mode. The chain shows attempted breadth of access and administration by one identity, not a compromise.

`anomaly_mode` defaults to `true`. With `false` the generator emits only the ordinary background.

## Parameters

### Event Parameters

Set in `event.template.params` of `generator.yml`. Values are checked when the first event renders.

| Name | Default | Accepted values | Description |
| --- | --- | --- | --- |
| `anomaly_mode` | `true` | boolean | Add recurring episodes to the background. |
| `anomaly_interval_hours` | `24` | finite number, 1-8760 | Hours between episodes, before the random 0-10 minute delay. |
| `broker_host` | `kafka-01.corp.example` | ASCII hostname: letters, digits, `.`, `-`, up to 253 characters | Broker/controller node written to `host.name`. |

### Samples

| File | Fields | Rules |
| --- | --- | --- |
| `samples/clients.json` | `principal`, `ip`, `bursts_per_day` | 2-64 clients; distinct `User:` principals (1-64 of letters, digits, `.`, `_`, `-`); dotted-quad IPv4 strings; `bursts_per_day` 1-1440. |
| `samples/denials.json` | `principal`, `topic`, `operation`, `weight` | Principal from `clients.json`; Kafka topic name (1-249 of letters, digits, `.`, `_`, `-`, not `.` or `..`); `READ`, `WRITE`, `ALTER_CONFIGS` or `DELETE`; integer weight 1-50; one row per principal, topic and operation. Every client needs at least one row. |

Each client cycles through its rows in a shuffled order, taking each row `weight` times per cycle, so every row recurs. With `anomaly_mode: true` at least two client/topic pairs must cover all four operations. The input must stay at one timestamp every 10 seconds.

With an invalid value no event is produced; with an input that is not one timestamp every 10 seconds at most the first event is produced. The Eventum CLI still exits with code 0 and prints nothing at default verbosity: check that the output file is not empty, or run with `-vv`, where the error (`KeyError`) names the rule that failed. Jinja has no raise statement; the template aborts through a failed dictionary lookup whose key is the message.

### Output Parameters

The shipped configuration writes `output/events.json` and needs no connection parameters or secrets. To deliver elsewhere, replace the `file` output in a local copy with the selected output plugin and use `${params.*}` for its host and index and `${secrets.*}` for its credentials.

## Usage

From the `content-packs` repository root, live mode emits each denial when its time comes:

```bash
eventum generate --path generators/messaging-apache-kafka-authorizer/generator.yml --id kafka-authorizer --live-mode true
```

For a finite batch, copy `generator.yml` to `finite.yml` in the same directory, add `start` and `end` to its `input[0].cron` entry, and run the copy:

```yaml
input:
- cron:
    expression: '* * * * * */10'
    count: 1
    start: '2026-09-26T00:00:00Z'
    end: '2026-09-29T00:00:00Z'
```

```bash
eventum generate --path generators/messaging-apache-kafka-authorizer/finite.yml --id kafka-authorizer --live-mode false --keep-order true
```

Output differs between runs. One run of this window produced 3150 events with two complete episodes, starting at 2026-09-27 00:06:55 and 2026-09-28 00:15:31 UTC. `--keep-order true` keeps the file in timestamp order. A window may end inside an episode; the missing steps are simply beyond `end`. Input timestamps with an offset are converted to UTC.

## Sample Output

Third step of the first episode, copied byte for byte from the finite run above (`anomaly_mode: true`):

```json
{"@timestamp": "2026-09-27T00:07:48.336Z", "ecs": {"version": "8.17.0"}, "event": {"action": "authorization-denied", "category": ["api"], "created": "2026-09-27T00:07:48.535Z", "ingested": "2026-09-27T00:07:49.302Z", "kind": "event", "original": "[2026-09-27 00:07:48,336] INFO Principal = User:ops-config is Denied operation = ALTER_CONFIGS from host = 10.40.3.20 on resource = Topic:LITERAL:metrics-internal for request = AlterConfigs with resourceRefCount = 1 based on rule DefaultDeny (kafka.authorizer.logger)", "outcome": "failure", "timezone": "+00:00", "type": ["denied"]}, "host": {"name": "kafka-01.corp.example"}, "kafka": {"authorization_result": "Denied", "log": {"class": "kafka.authorizer.logger", "component": "unknown"}, "operation": "ALTER_CONFIGS", "principal": "User:ops-config", "request": "AlterConfigs", "resource": {"name": "metrics-internal", "pattern_type": "LITERAL", "type": "Topic"}, "resource_ref_count": 1, "rule": "DefaultDeny"}, "log": {"level": "INFO", "logger": "kafka.authorizer.logger"}, "message": "Principal = User:ops-config is Denied operation = ALTER_CONFIGS from host = 10.40.3.20 on resource = Topic:LITERAL:metrics-internal for request = AlterConfigs with resourceRefCount = 1 based on rule DefaultDeny", "related": {"ip": ["10.40.3.20"], "user": ["ops-config"]}, "source": {"ip": "10.40.3.20"}, "tags": ["preserve_original_event"], "user": {"name": "ops-config"}}
```

## Native Format and Coverage

The line consists of the three layout fields and the ten fields that `StandardAuthorizerData.buildAuditMessage` writes; all 13 are generated and parsed.

| Native field | Kafka 3.9.0 source | Output fields |
| --- | --- | --- |
| time `[%d]` | `log4j.properties` layout, ISO8601 in JVM time | `@timestamp` |
| level `%p` | `logAuditMessage`: denied and explicitly requested -> INFO | `log.level` |
| logger `(%c)` | `kafka.authorizer.logger` | `log.logger`, `kafka.log.class` |
| principal | `KafkaPrincipal` as `User:<name>` | `kafka.principal`, `user.name`, `related.user` |
| decision | `Allowed` / `Denied` from the matched rule | `kafka.authorization_result`, `event.outcome` |
| operation | ACL operation name | `kafka.operation` |
| host | client address; restored from the envelope for forwarded requests | `source.ip`, `related.ip` |
| resource type, pattern type, name | `Topic:LITERAL:<topic>` | `kafka.resource.type`, `.pattern_type`, `.name` |
| request | API key name of the request | `kafka.request` |
| resourceRefCount | references to the topic in the request | `kafka.resource_ref_count` |
| rule | `DefaultDeny` when no ACL matches the operation | `kafka.rule` |

`message` holds the body without the layout. `kafka.log.component: unknown` follows the generic Elastic Kafka log pipeline for an unprefixed message. `event.created` and `event.ingested` are synthetic collector times: a read delay of 20 ms to 8 s (median about 0.4 s) and an ingest delay of 50 ms to 20 s (median about 0.9 s). `event.timezone` states the UTC JVM assumption.

## Limitations

- No version-matched live `kafka-authorizer.log` was available. The format is implemented from the tagged 3.9.0 source and its unit-test expectation, not verified byte for byte against a running broker.
- The Elastic Kafka integration publishes no authorizer `sample_event.json`; its authentication test log is a different stream (SASL callback handler). The ECS mapping here is this pack's own.
- The JVM timezone is assumed to be UTC.
- Retry timing is an application-level model (tens of seconds between attempts). Clients that retry in tight loops and flood the log several times per second are not modeled, and there is no daily rhythm.
- Other rules (`MatchingAcl`, `SuperUser`), other resource types, cluster-level denials and other request types are not generated.
- The KUMA 4.2 catalog lists Kafka 3.8.1 over syslog; compatibility of this Log4j file format with that parser is not claimed.

## References

- [StandardAuthorizerData.java (3.9.0)](https://github.com/apache/kafka/blob/3.9.0/metadata/src/main/java/org/apache/kafka/metadata/authorizer/StandardAuthorizerData.java) - audit message, log levels, default rule
- [StandardAuthorizerTest.java (3.9.0)](https://github.com/apache/kafka/blob/3.9.0/metadata/src/test/java/org/apache/kafka/metadata/authorizer/StandardAuthorizerTest.java) - expected denial message
- [KafkaApis.scala (3.9.0)](https://github.com/apache/kafka/blob/3.9.0/core/src/main/scala/kafka/server/KafkaApis.scala) and [ControllerApis.scala (3.9.0)](https://github.com/apache/kafka/blob/3.9.0/core/src/main/scala/kafka/server/ControllerApis.scala) - request authorization and forwarding
- [AuthHelper.scala (3.9.0)](https://github.com/apache/kafka/blob/3.9.0/core/src/main/scala/kafka/server/AuthHelper.scala) and [EnvelopeUtils.scala (3.9.0)](https://github.com/apache/kafka/blob/3.9.0/core/src/main/scala/kafka/server/EnvelopeUtils.scala) - reference counts, forwarded principal and address
- [config/log4j.properties (3.9.0)](https://github.com/apache/kafka/blob/3.9.0/config/log4j.properties) - authorizer appender and layout
- [Kafka 3.9 authorization and ACLs](https://kafka.apache.org/39/documentation.html#security_authz)
- [Log4j 1.x PatternLayout](https://logging.apache.org/log4j/1.x/apidocs/org/apache/log4j/PatternLayout.html)
- [ECS 8.17 event categorization](https://www.elastic.co/guide/en/ecs/8.17/ecs-allowed-values-event-category.html)
- [Elastic Kafka integration](https://github.com/elastic/integrations/tree/main/packages/kafka)
- [KUMA 4.2 supported event sources](https://support.kaspersky.ru/kuma/4.2/255782)
