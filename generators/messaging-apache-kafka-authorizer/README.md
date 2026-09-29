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
| `READ` | `Fetch` | broker | 55.4-56.5% | all 12 | `api` / `denied` |
| `WRITE` | `Produce` | broker | 38.9-40.2% | 11 | `api` / `denied` |
| `ALTER_CONFIGS` | `AlterConfigs` | controller (forwarded) | 2.4-3.0% | `ops-config`, `ops-topics`, `analyst`, `svc-audit` | `api` / `denied` |
| `DELETE` | `DeleteTopics` | controller (forwarded) | 2.0-2.2% | `ops-config`, `ops-topics`, `analyst`, `svc-audit` | `api` / `denied` |

Shares are per day of output and are the same in both modes. Which principal is denied which operation on which topic is listed in `samples/denials.json`; application accounts are denied reads and writes, and only the two operations accounts, the analyst and the audit exporter are denied administrative requests.

## Volume and Timing

- **Application service accounts** (the nine `svc-*` principals) - about 4,500 denials a day, 89% of the log: an even floor around the clock plus a broad daytime rise peaking at 11:00-13:00 of the generator timezone (UTC by default).
- **Analyst and operations accounts** (`analyst`, `ops-config`, `ops-topics`) - about 660 denials a day, 11% of the log: 600 between 08:00 and 18:00 and a small floor at night.
- Each day's count varies by up to 3%. In total 5,100-5,200 denials a day; about 130 an hour at night and 310-330 an hour at the midday peak.

Each client behaves independently and retries one denied request at a time. A retry run is 1-8 `Fetch` or `Produce` attempts, or 1-3 administrative attempts; within a run attempts are 24 s apart at the 10th percentile, 58 s in median and 165 s at the 90th percentile. After a run the client tries another operation on the same topic with probability 0.3 (up to all four operations, in any order), in median 140 s later. Which client starts the next run is drawn by the per-client weight in `samples/clients.json` among clients not already retrying. Across all principals, 93% of denials follow a denial of the same principal within 10 minutes. Consecutive records of the log are 10.6 s apart in median and 99% within 90 s. Rates and weights are synthetic, not measured Kafka traffic.

## Anomaly Chain

`anomaly_mode: true` is the default; `anomaly_mode: false` produces only the background above.

**Sequence.** One principal from its own address is denied `READ`/`Fetch`, `WRITE`/`Produce`, `ALTER_CONFIGS`/`AlterConfigs` and `DELETE`/`DeleteTopics` on the same topic, once each, as four consecutive denials of that principal. Steps follow the spacing of retries of one request, capped so that the four steps stay within 4 minutes; the span from first to last step is about 60-215 s. Every step is `DefaultDeny`: nothing is read, written, reconfigured or deleted, so no restoring events follow.

**Volume.** The record count is the same in both modes: an episode's four records take the place of four records that would otherwise have come at those moments. The episode is the principal's only activity while it runs; it starts only when that principal is not in the middle of a retry run of its own, and the principal's later activity follows the usual law.

**Linking fields.** `kafka.principal` (`user.name`), `source.ip`, `kafka.resource.name` and `host.name`, all present in `event.original`.

**Recurrence.** `anomaly_interval_hours` (default `24`) is measured in event time. The first episode starts within the first min(interval, 24 h) of the run, its hour weighted by the hourly volume of the episode principal's group (application or staff); each later start is drawn in a window of min(interval / 4, 6 h) centred one interval after the previous actual start, weighted by the squared hourly volume plus a small floor, so episodes fall mostly in busy hours. When the drawn principal is in the middle of a retry run, the start slips by a few minutes. Missed episodes are not replayed. Start-to-start intervals are about 21-26 h at the default 24 and 5.4-6.6 h at 6.

**Variation.** The episode principal and topic come from the client/topic pairs whose rows in `samples/denials.json` cover all four operations. The shipped samples give six: `analyst` on `audit-internal`, `ops-config` on `metrics-internal` and `payroll-events`, `ops-topics` on `orders-archive` and `audit-internal`, `svc-audit` on `payroll-events`. They are used in a shuffled order that is reshuffled after every six episodes, without the same pair twice in a row. Each of these principals is also denied each of the four operations on its topic in ordinary traffic of both modes.

**Background without the chain.** Ordinary traffic contains retry runs, lone administrative denials and runs of two, three or four different operations on one topic, but never `READ`, `WRITE`, `ALTER_CONFIGS` and `DELETE` in that order by one principal on one topic within 300 s. An ordinary `DELETE` that would complete that order appears instead as a repeated `ALTER_CONFIGS` attempt at the same time; this is rare, about once in two weeks. The rule also covers the minutes after an episode, so each episode completes the order exactly once.

**Detection idea.** Group denials by principal, source address and topic and alert when one principal is denied `READ`, `WRITE`, `ALTER_CONFIGS` and `DELETE` on one topic, in that order, within 5 minutes. The chain shows attempted breadth of access and administration by one identity, not a compromise.

## Parameters

### Event Parameters

Set in `event.template.params` of `generator.yml`. Values are checked when the first event renders.

| Name | Default | Accepted values | Description |
| --- | --- | --- | --- |
| `anomaly_mode` | `true` | boolean | Add recurring episodes to the background. |
| `anomaly_interval_hours` | `24` | finite number, 1-8760 | Hours between episode starts. |
| `broker_host` | `kafka-01.corp.example` | ASCII hostname: letters, digits, `.`, `-`, up to 253 characters | Broker/controller node written to `host.name`. |

### Samples

| File | Fields | Rules |
| --- | --- | --- |
| `samples/clients.json` | `principal`, `ip`, `group`, `weight` | 2-64 clients; distinct `User:` principals (1-64 of letters, digits, `.`, `_`, `-`); dotted-quad IPv4 strings; `group` `service` or `staff`; `weight` a number 1-1000, the client's relative share of new retry runs within its group. |
| `samples/denials.json` | `principal`, `topic`, `operation`, `weight` | Principal from `clients.json`; Kafka topic name (1-249 of letters, digits, `.`, `_`, `-`, not `.` or `..`); `READ`, `WRITE`, `ALTER_CONFIGS` or `DELETE`; integer weight 1-50; one row per principal, topic and operation. Every client needs at least one row. |

Each client cycles through its rows in a shuffled order, taking each row `weight` times per cycle, so every row recurs. With `anomaly_mode: true` at least two client/topic pairs must cover all four operations.

With an invalid value no event is produced. The Eventum CLI still exits with code 0 and prints nothing at default verbosity: check that the output file is not empty, or run with `-vv`, where the error (`KeyError`) names the rule that failed.

### Output Parameters

The shipped configuration writes `output/events.json` and needs no connection parameters or secrets. To deliver elsewhere, replace the `file` output in a local copy with the selected output plugin and use `${params.*}` for its host and index and `${secrets.*}` for its credentials.

## Usage

From the `content-packs` repository root, live:

```bash
eventum generate --path generators/messaging-apache-kafka-authorizer/generator.yml --id kafka-authorizer --live-mode true
```

`patterns/service-floor.yml` and `patterns/service-day.yml` set the volume of the application accounts, `patterns/staff-office.yml` and `patterns/staff-floor.yml` that of the analyst and operations accounts (the input tagged `staff`). The patterns start at midnight of the current day and never end. For a finite batch, set `start` and `end` in the four files under `patterns/` (for example `start: "2026-10-01T00:00:00Z"`, `end: "2026-10-04T00:00:00Z"`); start at midnight so the daily curve keeps its hours. The second episode can start up to about 51 hours after the run start, so use at least 52 hours to see two at the default interval:

```bash
eventum generate --path generators/messaging-apache-kafka-authorizer/generator.yml --id kafka-authorizer --live-mode false --keep-order true
```

Output differs between runs. `--keep-order true` keeps the file in timestamp order. A window may end inside an episode; the missing steps are simply beyond `end`.

## Sample Output

Third step of an episode (`anomaly_mode: true`, default parameters):

```json
{"@timestamp": "2026-10-01T14:03:17.180Z", "ecs": {"version": "8.17.0"}, "event": {"action": "authorization-denied", "category": ["api"], "created": "2026-10-01T14:03:17.795Z", "ingested": "2026-10-01T14:03:19.008Z", "kind": "event", "original": "[2026-10-01 14:03:17,180] INFO Principal = User:ops-config is Denied operation = ALTER_CONFIGS from host = 10.40.3.20 on resource = Topic:LITERAL:metrics-internal for request = AlterConfigs with resourceRefCount = 1 based on rule DefaultDeny (kafka.authorizer.logger)", "outcome": "failure", "timezone": "+00:00", "type": ["denied"]}, "host": {"name": "kafka-01.corp.example"}, "kafka": {"authorization_result": "Denied", "log": {"class": "kafka.authorizer.logger", "component": "unknown"}, "operation": "ALTER_CONFIGS", "principal": "User:ops-config", "request": "AlterConfigs", "resource": {"name": "metrics-internal", "pattern_type": "LITERAL", "type": "Topic"}, "resource_ref_count": 1, "rule": "DefaultDeny"}, "log": {"level": "INFO", "logger": "kafka.authorizer.logger"}, "message": "Principal = User:ops-config is Denied operation = ALTER_CONFIGS from host = 10.40.3.20 on resource = Topic:LITERAL:metrics-internal for request = AlterConfigs with resourceRefCount = 1 based on rule DefaultDeny", "related": {"ip": ["10.40.3.20"], "user": ["ops-config"]}, "source": {"ip": "10.40.3.20"}, "tags": ["preserve_original_event"], "user": {"name": "ops-config"}}
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
- Retry timing is an application-level model (seconds to minutes between attempts). Clients that retry in tight loops and flood the log several times per second are not modeled, and denials of different clients rarely fall in the same second: consecutive records are 10.6 s apart in median, and 6% are less than a second apart.
- Episode steps come faster than ordinary operation changes: an episode moves to the next operation after about 15-85 s, while an ordinary client switching operations on one topic does so after about 150 s in median (15-17% within a minute).
- Other rules (`MatchingAcl`, `SuperUser`), other resource types, cluster-level denials and other request types are not generated.
- Volumes, hour curves and client weights are synthetic.
- The KUMA 4.2 catalog lists Kafka 3.8.1 over syslog; compatibility of this Log4j file format with that parser is not claimed.

## Performance

About 1,800 records per second on one core: a 14-day default run (72,321 records) takes 40 s.

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
