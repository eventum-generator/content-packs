# MongoDB Server Log (mongod JSON)

Generates the structured server log of one MongoDB Community 7.0 `mongod` (log file in the JSON format of `logv2`, default verbosity, `slowms` 100, SCRAM-SHA-256 authorization) as it is shipped by the Elastic `mongodb.log` integration. Each output line is ECS JSON; `event.original` holds the native log line byte for byte and `mongodb.log.*` holds its parsed fields as the Elastic ingest pipeline produces them.

## Volume and Timing

Line volume follows a UTC hour-of-day curve, about 39,000 lines per day with ±3% day-to-day variation; lines fall at random times inside each band.

| UTC hours | Lines/s |
|---|---:|
| 08-19 | 0.70 |
| 07-08, 19-21 | 0.40 |
| 21-07 | 0.20 |

Service traffic makes up about 91% of the lines. People open sessions in business hours: at the peak (08-18 UTC) about one session per person per hour, 0.4 of that at 07-08 and 18-19 and 0.05 at night. The billing worker connects about every 25 minutes in the day and less often at night, the reporting job runs about five times a day at any hour.

The lines of one moment follow each other within seconds: a connection's `client metadata` comes a median 1.0 s after its `Connection accepted` in the day (90th percentile 3.3 s) and 2.6 s at night (9.6 s); logins, first commands and the batches of one export are spaced the same way. `durationMillis`, `elapsedMillis` and the authentication metrics keep the server-side timing in milliseconds.

## Event Types Covered

Shares over 14 days with `anomaly_mode: false` (552,413 lines).

| `id` | `msg` | Component | Meaning | Share | ECS `event.type` |
|---:|---|---|---|---:|---|
| 51803 | `Slow query` | `COMMAND` | Read above 100 ms: `find` 65.2%, `aggregate` 5.9%, `getMore` batch of an export 0.13% | 71.3% | `info` |
| 22943 | `Connection accepted` | `NETWORK` | New client connection, with the open-connection count | 5.9% | `info` |
| 51800 | `client metadata` | `NETWORK` | Driver handshake document of the connection | 5.9% | `info` |
| 22944 | `Connection ended` | `NETWORK` | Connection closed, with the open-connection count | 5.9% | `info` |
| 5286306 | `Successfully authenticated` | `ACCESS` | SCRAM-SHA-256 login succeeded | 5.4% | `access` |
| 6788700 | `Received first command on ingress connection since session start or auth handshake` | `NETWORK` | First command after the login, with the delay | 5.4% | `info` |
| 5286307 | `Failed to authenticate` | `ACCESS` | Wrong password, `AuthenticationFailed` (18) | 0.03% | `access` |

`Slow query` lines come from `find` and `aggregate` operations above 100 ms and from `getMore` batches of export cursors:

| Operation | Clients | Namespaces | Plan |
|---|---|---|---|
| Point and range `find` | order and catalog services, people | `sales.orders`, `crm.customers`, `billing.*`, `inventory.stock_movements`, `catalog.products`, `sales.carts` | mostly `IXSCAN`, some `COLLSCAN` |
| `aggregate` with `$group` | reporting job, billing worker, people | `sales.orders`, `crm.customers`, `billing.invoices`, `inventory.stock_movements`, `catalog.products` | `COLLSCAN` or `IXSCAN`, `queryFramework: sbe` |
| Export `getMore` (16 MiB batches) | reporting job, DBAs, analysts | `crm.customers` (all documents, one segment, one region or churned customers), `sales.orders` (returned), `billing.invoices` (disputed) | `COLLSCAN`, `originatingCommand` is the opening `find` |

## Workload Model

Rates are chosen assumptions, not vendor-measured frequencies. Both modes run the same activity; an episode adds one session and does not pause, shift or cancel any session, job or pool activity.

- **Service pools:** `orders-api` (four instances, six pooled connections each), `catalog-service` (two instances, four each) and `mongodb_exporter` (one) keep pooled connections. Their slow reads make up most of the log; an `orders-api` instance reads about 1.4 times as often as a `catalog-service` instance. An idle pooled connection closes after a median of 13 minutes (the exporter's after about two hours) and reopens on demand a median 15 s later, logging accept, client metadata, a successful authentication and the first command.
- **Batch jobs:** `billing-worker` (PyMongo) and `nightly-reports` (Go driver): each run opens the driver's two monitoring connections plus one authenticated connection, runs a few aggregations (reports also run exports) and closes all connections.
- **People:** two DBAs (`mongosh`) and two analysts (MongoDB Compass), each at its own workstation address, about 11 sessions per person per day. A session opens two monitoring connections and one authenticated connection, runs a lognormal number of reads (median 4) with lognormal think times (median 40 s), and 5% of reads are exports. Sessions of one person may overlap.
- **Exports:** `crm.customers` (all documents, one segment, one region, churned customers), returned `sales.orders` and disputed `billing.invoices`. The result of a region or churned-customer export fits into one 16 MiB `getMore` batch; the others take several. The four people export about 12 times a day together (`crm.customers` about 8), the reporting job about 4 times.
- **Wrong passwords:** a person mistypes a first attempt with probability 0.07 and each retry with 0.35 (up to six failures); 3% of sessions start from an outdated remembered password (every attempt fails until it is corrected, retry failure 0.6, up to eight). Retries follow after a lognormal delay (median 9 s); after any failure the person gives up with probability 0.1. About 16% of people's logins fail (about 8 a day across the four); a single failure before a success is the most common, and three or more happen about six times a week. A service instance that still holds a rotated secret fails 1 to 12 times in a row (each extra failure less likely, 15 s apart) before it connects, about 1.5 times a day across the instances. Over all logins, 0.55% fail.
- Connection ids continue from a high counter (the server has been up for weeks), and the service pools and their monitoring connections are already open when the log starts, so some `Connection ended` lines close connections accepted earlier.

## Selected Source Profile

The line format and the attribute order of every modelled message follow the `r7.0.43` source tag: `logv2/json_formatter.cpp`, `transport/service_entry_point_impl.cpp` (22943, 22944), `rpc/metadata/client_metadata.cpp` (51800), `db/auth/authentication_session.cpp` and `sasl_commands.cpp` (5286306, 5286307), `transport/ingress_handshake_metrics.cpp` (6788700) and `db/curop.cpp` `OpDebug::report` (51803).

```text
{"t":{"$date":"<iso8601-local ms>"},"s":"I",  "c":"<component>",<pad>"id":<id>,<pad>"ctx":"<ctx>","msg":"<msg>","attr":{...}}
```

- Top-level order `t`, `s`, `c`, `id`, `ctx`, `msg`, `attr`; the formatter pads `s` to 5, `c` to 11 and `id` to 8 characters with spaces after the comma. There is no `svc` field in 7.0. `t.$date` uses the server time zone (`log_timezone`, default `+00:00`) with milliseconds; `@timestamp` is the same instant in UTC.
- `Connection accepted` runs on the `listener` thread; every other line runs on `conn<connectionId>`. `connectionCount` is the number of open connections after the accept or the end.
- `client metadata` is logged for every connection, including the drivers' monitoring connections, which never authenticate. The `doc` is the driver handshake document (application, driver, OS, platform) from the MongoDB handshake specification; driver versions are synthetic.
- Authentication lines are logged by default in 7.0 (`enableDetailedConnectionHealthMetricLogLines`). All modelled drivers authenticate with speculative SCRAM-SHA-256 against `admin`; a wrong password fails at step 2 with `AuthenticationFailed: SCRAM authentication failed, storedKey mismatch` (code 18). `Received first command ...` (6788700, `elapsed` logged as `elapsedMillis`) follows each successful authentication.
- `Slow query` attributes appear in the `OpDebug::report` order; `find` uses the classic engine and `aggregate` with `$group` the slot-based engine, as in 7.0. A `getMore` line carries `originatingCommand`, `cursorid` and `nBatches: 1`, and `cursorExhausted` on the last batch; the opening `find` of an export returns 101 documents in a few milliseconds and is not logged.
- ECS mirrors the Elastic `mongodb` 1.24 pipeline: `@timestamp` from `t.$date`, `log.level` from `s`, `mongodb.log.component`, `mongodb.log.context`, `mongodb.log.id`, `mongodb.log.attr`, `message` from `msg`, `event.original`, `event.type` `access` for `ACCESS` and `info` otherwise, `event.kind`, `event.category: ["database"]`, `tags: ["preserve_original_event"]`. `data_stream`, `event.dataset`, `event.module`, `host.name`, `input.type` and `log.file.path` are agent-side fields; `event.created` and `event.ingested` are the read and ingest times, a few hundred milliseconds to seconds after the line.

## Anomaly Chain

`event.template.params.anomaly_mode` defaults to `true`. With `false`, only background is produced.

An episode is one extra session of one of the four people, from that person's own workstation and account, that starts with repeated wrong passwords and then reads a customer export:

1. Three (55%), four (30%) or five (15%) connect attempts, each a monitoring pair plus one connection with `Failed to authenticate` for the person's user, closed right away; retries follow the ordinary retry delay (median 9 s), and the person does not give up.
2. `Successfully authenticated` of the same user from the same address, `Received first command ...`.
3. Zero to two ordinary reads, then an export of the customers of one region or of the churned customers from `crm.customers`, started at the latest 20 minutes after the first failure: the whole result after the first 101 documents arrives in one `getMore` batch, one `Slow query` line with `cursorExhausted: true`.
4. More ordinary reads, then `Connection ended` for the session's connections.

The person's ordinary sessions go on as usual. The episode's lines take the place of an equal number of service slow-query lines around it, so the daily volume and the hour curve are the same as in background.

Linking fields: the client address in `remote` / `client`, `user`, `conn<N>` / `connectionId` and `uuid` of each connection, the metadata `doc`, the session `lsid`, and the `cursorid` of the export.

Recurrence: the first episode starts within the first min(interval, 24 hours) of the log, at a time drawn from the people's hour curve. Each next episode is due one interval after the actual start of the previous one; its start is drawn in a window of width w = min(interval / 4, 6 hours) centred on the due time, weighted by the squared people curve plus a small floor. Missed intervals are not replayed. The interval is `anomaly_interval_hours` (default 24, minimum 6). At intervals of 8 hours or less some episodes necessarily fall outside business hours.

Variation: the person rotates (never the same as the previous episode) and is otherwise drawn uniformly, as all four have the same session rate. The failure count, delays, connection ids, ports, `uuid`, `lsid`, `cursorid`, the export (region or churned customers, with the background weights of these two exports) and the reads come from the same draws as background.

Every event type, address, user, user-address pair, namespace and export shape of an episode also occurs in background of both modes: runs of three or more failures followed by a success, and single-batch exports of `crm.customers` by all four people, are ordinary. Only the complete order within 30 minutes is kept out of background: when an ordinary `crm.customers` `getMore` would complete it (three failures of one user from one address, then a success of that user, then the `getMore` within 30 minutes of the first failure), an export that has not logged a batch yet reads returned orders or disputed invoices instead (with that person's usual weights), and a later batch of an export already under way is not written. This happens about once a week.

With `anomaly_mode: true` each episode adds its own records, so counts of the chain's parts (runs of three or more failed logins of one person followed by a success, single-batch customer exports) are about one per episode higher: at the default interval about one more such failure run a day, on top of about six a week in background.

Possible detection: per client address, at least three `Failed to authenticate` of one user followed by `Successfully authenticated` of that user and, within 30 minutes of the first failure, a `getMore` on a sensitive collection from that address; join the `conn<N>` of the success to the export line. The log does not show why the logins failed or where the exported documents went.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`. Invalid values stop rendering with a message starting with `MongoDB`.

| Name | Default | Purpose and constraints |
|---|---|---|
| `db_host` | `mongo-01.corp.example` | Server host name in `host.name`; ASCII letters, digits, `.` and `-` |
| `log_timezone` | `+00:00` | Server time zone offset written in `t.$date`, `[+-]HH:MM`; the hour curves stay in UTC |
| `anomaly_interval_hours` | `24` | Episode interval in hours of source time, number from 6 to 8,760 |
| `anomaly_mode` | `true` | `true` adds episodes to background, `false` produces background only |

Clients, collections, queries and exports are defined in `samples/clients.json`, `samples/collections.json`, `samples/queries.json` and `samples/exports.json`. `clients.json` needs two or more `shell` or `compass` clients, and each of them needs a single-batch `crm.customers` export and an export of another collection in `exports.json`.

### Output Parameters

The shipped file output needs no substitutions. To deliver elsewhere, replace the `output` block with another output plugin and pass its host through `${params.*}` and credentials through `${secrets.*}`, for example `${params.opensearch_host}` and `${secrets.opensearch_password}`.

## Usage

Live generation at the configured rate, from the content-packs repository root:

```bash
eventum generate --path generators/database-mongodb-log/generator.yml --id database-mongodb-log --live-mode true --keep-order true
```

Batch generation: set `start` and `end` of the `oscillator` in all seven `patterns/*.yml` files to the same range, with `start` at 00:00 UTC so the hour bands stay in place (for example `start: "2026-09-21T00:00:00Z"` and `end: "2026-09-24T00:00:00Z"`), then run:

```bash
eventum generate --path generators/database-mongodb-log/generator.yml --id database-mongodb-log --live-mode false --keep-order true
```

Output goes to `generators/database-mongodb-log/output/events.json`. Keep `--keep-order true`: `connectionCount` and the connection lifecycle depend on the line order.

The hour curves are sums of `time_patterns` files under `patterns/`: `service-floor` (00-24 UTC), `service-day` (07-21) and `service-core` (08-19) for service lines, `people-floor`, `people-day` (07-19) and `people-core` (08-18) for people's sessions, and `jobs` for report runs and stale-secret series. To change the volume, scale the `ratio` of the three service files by the same factor; a lower volume stretches the gaps between the lines of one moment. To move the working day to another time zone, shift the `low` / `high` bounds of the day and core files. Episode start hours follow the shipped people curve even if you reshape the pattern files.

Performance: about 1,500 lines per second in batch mode on one core.

## Limitations

- No raw 7.0 log line of these message ids was found in vendor material; the byte form comes from the tagged formatter and log-site source, and the padding style is confirmed by the raw 4.4.4 fixture of the Elastic integration. Raw parity with a live server is not established.
- Values are synthetic: driver versions, query shapes, `queryHash` / `planCacheKey`, durations, lock counts, `storage` read sizes and `cpuNanos` are plausible, not measured. Durations of collection scans scale with collection size.
- Not modelled: TLS, load balancer, replica-set and sharding messages, startup and shutdown, `hello`-only connections outside driver monitoring, writes and their slow-operation lines, `Slow query` for commands other than `find`, `aggregate` and `getMore`, the 6.3+ session-workflow slow-response line, errors other than a wrong password, and the Enterprise audit log (a different stream).
- Speculative authentication is assumed for every client; `isSpeculative` is `true` on failures as well. Service pools do not restart, so their monitoring connections are never logged.
- Lines that a server writes within milliseconds of each other (a connection's accept, metadata and login, consecutive batches of one export) are about a second apart in the day and a few seconds at night, so the gaps between their timestamps are longer than `durationMillis` and `elapsedMillis` imply.
- The hour curves are in UTC and repeat every day: there is no weekly cycle, so weekends look like weekdays.
- With `anomaly_mode: true` each episode adds its own records, so counts of the chain's parts are about one per episode higher than in background (see Anomaly Chain).

## Sample Output

The final step of the first episode of a default run: `analyst_ivan` exports the far-east customers of `crm.customers` in one `getMore` batch, 33 s after a successful login that followed three failed logins within 58 s.

```json
{"@timestamp": "2026-09-21T14:12:10.799Z", "data_stream": {"dataset": "mongodb.log", "namespace": "default", "type": "logs"}, "ecs": {"version": "8.11.0"}, "event": {"category": ["database"], "created": "2026-09-21T14:12:11.330Z", "dataset": "mongodb.log", "ingested": "2026-09-21T14:12:11.867Z", "kind": "event", "module": "mongodb", "original": "{\"t\":{\"$date\":\"2026-09-21T14:12:10.799+00:00\"},\"s\":\"I\",  \"c\":\"COMMAND\",  \"id\":51803,   \"ctx\":\"conn89847\",\"msg\":\"Slow query\",\"attr\":{\"type\":\"command\",\"ns\":\"crm.customers\",\"appName\":\"MongoDB Compass\",\"command\":{\"getMore\":6208691475638660086,\"collection\":\"customers\",\"lsid\":{\"id\":{\"$uuid\":\"c25abd1e-cf0c-432c-bbd3-4a051fc380cb\"}},\"$db\":\"crm\"},\"originatingCommand\":{\"find\":\"customers\",\"filter\":{\"address.region\":\"far-east\"},\"lsid\":{\"id\":{\"$uuid\":\"c25abd1e-cf0c-432c-bbd3-4a051fc380cb\"}},\"$db\":\"crm\"},\"planSummary\":\"COLLSCAN\",\"cursorid\":6208691475638660086,\"keysExamined\":0,\"docsExamined\":116411,\"nBatches\":1,\"cursorExhausted\":true,\"numYields\":103,\"nreturned\":5997,\"queryFramework\":\"classic\",\"reslen\":12257781,\"locks\":{\"FeatureCompatibilityVersion\":{\"acquireCount\":{\"r\":104}},\"Global\":{\"acquireCount\":{\"r\":104}}},\"storage\":{\"data\":{\"bytesRead\":206906,\"timeReadingMicros\":7900}},\"cpuNanos\":106188935,\"remote\":\"10.30.2.50:50368\",\"protocol\":\"op_msg\",\"durationMillis\":150}}", "type": ["info"]}, "host": {"name": "mongo-01.corp.example"}, "input": {"type": "logfile"}, "log": {"file": {"path": "/var/log/mongodb/mongod.log"}, "level": "I"}, "message": "Slow query", "mongodb": {"log": {"attr": {"type": "command", "ns": "crm.customers", "appName": "MongoDB Compass", "command": {"getMore": 6208691475638660086, "collection": "customers", "lsid": {"id": {"$uuid": "c25abd1e-cf0c-432c-bbd3-4a051fc380cb"}}, "$db": "crm"}, "originatingCommand": {"find": "customers", "filter": {"address.region": "far-east"}, "lsid": {"id": {"$uuid": "c25abd1e-cf0c-432c-bbd3-4a051fc380cb"}}, "$db": "crm"}, "planSummary": "COLLSCAN", "cursorid": 6208691475638660086, "keysExamined": 0, "docsExamined": 116411, "nBatches": 1, "cursorExhausted": true, "numYields": 103, "nreturned": 5997, "queryFramework": "classic", "reslen": 12257781, "locks": {"FeatureCompatibilityVersion": {"acquireCount": {"r": 104}}, "Global": {"acquireCount": {"r": 104}}}, "storage": {"data": {"bytesRead": 206906, "timeReadingMicros": 7900}}, "cpuNanos": 106188935, "remote": "10.30.2.50:50368", "protocol": "op_msg", "durationMillis": 150}, "component": "COMMAND", "context": "conn89847", "id": 51803}}, "tags": ["preserve_original_event"]}
```

## References

- MongoDB server source, tag `r7.0.43`: https://github.com/mongodb/mongo/tree/r7.0.43/src/mongo (`logv2/json_formatter.cpp`, `db/curop.cpp`, `db/auth/authentication_session.cpp`, `transport/service_entry_point_impl.cpp`, `rpc/metadata/client_metadata.cpp`, `transport/ingress_handshake_metrics.cpp`)
- MongoDB 7.0 log messages: https://www.mongodb.com/docs/v7.0/reference/log-messages/
- MongoDB handshake specification: https://github.com/mongodb/specifications/blob/master/source/mongodb-handshake/handshake.md
- Elastic MongoDB integration, `log` data stream: https://github.com/elastic/integrations/tree/main/packages/mongodb/data_stream/log
