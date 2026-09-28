# MongoDB Server Log (mongod JSON)

Generates the structured server log of one MongoDB Community 7.0 `mongod` (log file in the JSON format of `logv2`, default verbosity, `slowms` 100, SCRAM-SHA-256 authorization) as it is shipped by the Elastic `mongodb.log` integration. Each output line is ECS JSON; `event.original` holds the native log line byte for byte and `mongodb.log.*` holds its parsed fields as the Elastic ingest pipeline produces them.

## Event Types Covered

Shares are measured from the final 72-hour default capture with `anomaly_mode: false` (13,717 lines, about 4,600 per day).

| `id` | `msg` | Component | Meaning | Share | ECS `event.type` |
|---:|---|---|---|---:|---|
| 51803 | `Slow query` | `COMMAND` | Read above 100 ms, or a `getMore` batch of an export | 34.2% | `info` |
| 22943 | `Connection accepted` | `NETWORK` | New client connection, with the open-connection count | 15.1% | `info` |
| 51800 | `client metadata` | `NETWORK` | Driver handshake document of the connection | 15.1% | `info` |
| 22944 | `Connection ended` | `NETWORK` | Connection closed, with the open-connection count | 15.1% | `info` |
| 5286306 | `Successfully authenticated` | `ACCESS` | SCRAM-SHA-256 login succeeded | 10.0% | `access` |
| 6788700 | `Received first command on ingress connection since session start or auth handshake` | `NETWORK` | First command after the login, with the delay | 10.0% | `info` |
| 5286307 | `Failed to authenticate` | `ACCESS` | Wrong password, `AuthenticationFailed` (18) | 0.56% | `access` |

`Slow query` lines come from `find` and `aggregate` operations above 100 ms and from `getMore` batches of export cursors:

| Operation | Clients | Namespaces | Plan |
|---|---|---|---|
| Point and range `find` | order and catalog services, people | `sales.orders`, `crm.customers`, `billing.*`, `inventory.stock_movements`, `catalog.products`, `sales.carts` | mostly `IXSCAN`, some `COLLSCAN` |
| `aggregate` with `$group` | reporting job, billing worker, people | `sales.orders`, `crm.customers`, `billing.invoices`, `inventory.stock_movements`, `catalog.products` | `COLLSCAN` or `IXSCAN`, `queryFramework: sbe` |
| Export `getMore` (16 MiB batches) | reporting job, DBAs, analysts | `crm.customers` (all documents or one segment), `sales.orders` (returned), `billing.invoices` (disputed) | `COLLSCAN`, `originatingCommand` is the opening `find` |

## Workload Model

The generator runs a bounded event simulation of the server's clients. Every delay is exponential or lognormal and every choice is random; both modes run the same processes, and an episode adds one session without pausing, shifting or replacing any background activity. Rates are chosen assumptions, not vendor-measured frequencies.

- **Service pools:** `orders-api` (two instances, six connections each), `catalog-service` (four) and `mongodb_exporter` (one) keep pooled connections that close after a lognormal lifetime (median 40 minutes, 6 hours for the exporter) and reopen on demand after a lognormal delay (median 15 s). Each reopen logs accept, client metadata, a successful authentication and the first command. The services' slow reads follow a service hour-of-day curve (night about a third of the day rate).
- **Batch jobs:** `billing-worker` (PyMongo) connects about every 25 minutes during the day, `nightly-reports` (Go driver) about every 5 hours at any time; each run opens the driver's two monitoring connections plus one authenticated connection, runs a few aggregations (reports also run exports) and closes all connections.
- **People:** two DBAs (`mongosh`) and two analysts (MongoDB Compass), each at its own workstation address, open sessions as a Poisson process thinned by a business-hours curve (peak mean gap 55 minutes, night about 4% of the peak). A session opens two monitoring connections and one authenticated connection, runs a lognormal number of reads (median 4) with lognormal think times (median 40 s), and 5% of reads are exports. Sessions of one person may overlap.
- **Wrong passwords:** a person's first attempt fails with probability 0.12 and each retry with 0.5 (up to six failures); 8% of sessions start from a stale remembered password (every attempt fails until it is corrected, retry failure 0.7, up to nine). Retries follow after a lognormal delay (median 9 s, sigma 0.45); after any failure the person gives up with probability 0.1. Service instances occasionally (mean every 36 hours each) fail two to twelve times in a row with a stale secret before a working connection. A failed attempt closes its connections within milliseconds. Three or more failures of one address within 30 minutes, failures followed by a success, and give-ups are ordinary in both modes (77 failed logins and 26 such three-failure windows across all addresses in the default `false` capture, 26 to 59 per 72 hours over six `false` captures).
- Connection ids continue from a high counter (the server has been up for weeks), and the service pools and their monitoring connections are already open when the capture starts, so some `Connection ended` lines close connections accepted before the window.

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

An episode is one session of one of the four people, from that person's own workstation and account, that starts with repeated wrong passwords and then reads a customer export:

1. Three (55%), four (30%) or five (15%) connect attempts, each a monitoring pair plus one connection with `Failed to authenticate` for the person's user, closed within milliseconds; retries follow the ordinary retry delay (median 9 s), and the person does not give up.
2. `Successfully authenticated` of the same user from the same address, `Received first command ...`.
3. Zero to two ordinary reads, then an export of `crm.customers` (all documents or one segment), started at the latest 20 minutes after the first failure: consecutive `Slow query` `getMore` lines with `COLLSCAN` and 16 MiB batches.
4. More ordinary reads, then `Connection ended` for the session's connections.

Linking fields: the client address in `remote` / `client`, `user`, `conn<N>` / `connectionId` and `uuid` of each connection, the metadata `doc`, the session `lsid`, and the `cursorid` of the export.

Recurrence: the first episode starts within the first min(interval, 24 hours) of the window, at a time drawn from the people's hour curve, plus a random delay (exponential, mean 6 minutes). Each next episode is due one interval after the actual start of the previous one; its start is drawn in a window of width w = min(interval / 4, 6 hours) centred on the due time, weighted by the squared people curve plus a small floor, and then delayed the same way. Missed intervals are not replayed. The interval is `anomaly_interval_hours` (default 24, minimum 6). At intervals of 8 hours or less some episodes necessarily fall outside business hours.

Variation: the person rotates (never the same as the previous episode) and is otherwise drawn uniformly, as all four have the same background session rate. Failure count, delays, connection ids, ports, `uuid`, `lsid`, `cursorid`, the export filter and the reads come from the same draws as background.

Every event type, address, user, user-address pair, namespace and export shape of an episode also occurs in background of both modes: failure runs of three or more followed by a success, and exports of `crm.customers` by all four people, are ordinary. Only the complete order within 30 minutes is kept out of background: when an ordinary `crm.customers` `getMore` would complete it (three failures of one user from one address, then a success of that user, then the `getMore` within 30 minutes of the first failure), that `getMore` line is not written; the export's timing and its other lines are unchanged.

Possible detection: per client address, at least three `Failed to authenticate` of one user followed by `Successfully authenticated` of that user and, within 30 minutes of the first failure, a `getMore` on a sensitive collection from that address; join the `conn<N>` of the success to the export lines. The log does not show why the logins failed or where the exported documents went.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`. Invalid values stop rendering with a message starting with `MongoDB`.

| Name | Default | Purpose and constraints |
|---|---|---|
| `db_host` | `mongo-01.corp.example` | Server host name in `host.name`; ASCII letters, digits, `.` and `-` |
| `log_timezone` | `+00:00` | Server time zone offset used in `t.$date` and for the hour-of-day curves, `[+-]HH:MM` |
| `anomaly_interval_hours` | `24` | Episode interval in hours of source time, number from 6 to 8,760 |
| `anomaly_mode` | `true` | `true` adds episodes to background, `false` produces background only |

Clients, collections, queries and exports are defined in `samples/clients.json`, `samples/collections.json`, `samples/queries.json` and `samples/exports.json`. `clients.json` needs two or more `shell` or `compass` clients.

### Output Parameters

The shipped file output needs no substitutions. To deliver elsewhere, replace the `output` block with another output plugin and pass its host through `${params.*}` and credentials through `${secrets.*}`, for example `${params.opensearch_host}` and `${secrets.opensearch_password}`.

## Usage

From the content-packs repository root:

```bash
# Batch sample
eventum generate --path generators/database-mongodb-log/generator.yml --id database-mongodb-log --live-mode false --keep-order true

# Live generation, about 4,600 lines per day
eventum generate --path generators/database-mongodb-log/generator.yml --id database-mongodb-log --live-mode true --keep-order true
```

Output goes to `generators/database-mongodb-log/output/events.json`. Keep `--keep-order true`: `connectionCount` and the connection lifecycle depend on the line order. The shipped input is unbounded; to check recurrence, set finite `input[0].cron.start` and `end` covering at least two intervals.

## Validation

Final 72-hour captures (2026-09-21 to 2026-09-24, one input tick per second), each checked line by line by a checker for the native byte form (field order, padding, `t.$date`, no `svc`), the per-message attribute order, the ECS mirror, connection state (`connectionId`, `uuid`, `connectionCount` arithmetic, no line after `Connection ended`, first command and slow queries only after a successful login) and the chain:

| Capture | Lines | Complete chains | Gaps between episode starts | Episode spans |
|---|---:|---:|---|---|
| Default 24 h, `true` | 14,196 | 3 | 25.43 h, 23.44 h | 56 to 208 s |
| Default, `false` | 13,717 | 0 | - | - |
| Four more default `false` | 14,507 to 14,818 | 0 | - | - |
| Custom 12 h, `true` | 14,658 | 5 | 11.11 to 13.24 h | 52 to 167 s |
| Custom 12 h, `false` | 14,081 | 0 | - | - |

- The person rotates between consecutive episodes; every user-address pair of an episode also logs in and reads `crm.customers` exports in background.
- The first default episode started at 03:30 UTC: the first start is drawn from the people curve, which gives the hours 00-06 about a 2% chance, and later starts stay within 3 hours of the previous phase. The custom episodes started between 00:01 and 12:55 UTC.
- Near misses over the six `false` captures (180 three-failure-then-success prefixes, export starts per 15 minutes after the first failure; exact = same address and `crm.customers`, other = same address and another collection, elsewhere = `crm.customers` from another address): 0-15 min 0 / 13 / 22, 15-30 min 0 / 6 / 12, 30-45 min 2 / 2 / 11, 45-60 min 1 / 1 / 6. Exact completions inside the window are removed by the rule above (about 15 over 18 days, estimated from the same-address export mix); the other two counts are not changed by it and fall off with session length.
- A calibrated on/off comparison (per-address and per-user gaps and minima, failure runs and give-ups, chain sub-sequences, daily counts, rotation, connection holds, periodicity, constants and mix; five `false` reference captures) finds no difference tied to episodes in the default pair: its verdict is SUSPECT only on two background-level checks, phase concentration of failure lines (in that background capture five separate stale-password and retry runs on different days fell into the same minute-of-hour bin; fresh captures peak at 11-19%) and `connectionId` increasing by exactly one per accepted connection, which is what a standalone mongod writes. The custom pair adds a SUSPECT on two retry gaps inside episodes (2.5 s) below the smallest of 551 background gaps (2.9 s); both come from the same retry-delay distribution as background (medians 8.7 s and 9.2 s) and the tail test is not significant after correction.

## Limitations and Assumptions

- No raw 7.0 log line of these message ids was found in vendor material; the byte form comes from the tagged formatter and log-site source, and the padding style is confirmed by the raw 4.4.4 fixture of the Elastic integration. Raw parity with a live server is not established.
- Values are synthetic: driver versions, query shapes, `queryHash` / `planCacheKey`, durations, lock counts, `storage` read sizes and `cpuNanos` are plausible, not measured. Durations of collection scans scale with collection size.
- Not modelled: TLS, load balancer, replica-set and sharding messages, startup and shutdown, `hello`-only connections outside driver monitoring, writes and their slow-operation lines, `Slow query` for commands other than `find`, `aggregate` and `getMore`, the 6.3+ session-workflow slow-response line, errors other than a wrong password, and the Enterprise audit log (a different stream).
- Speculative authentication is assumed for every client; `isSpeculative` is `true` on failures as well. Service pools do not restart within the window, so their monitoring connections are never logged.
- A mongod writes every line; here the collector emits at most one line per second, so `event.created` trails `@timestamp` by up to about 30 seconds during export bursts (26.6 s at most in the final default capture).

## Sample Output

The first wrong password of the first episode, line 443 of the final default `true` capture, as written by the file output (a background failure by the same person looks the same):

```json
{"@timestamp": "2026-09-21T03:30:11.577Z", "data_stream": {"dataset": "mongodb.log", "namespace": "default", "type": "logs"}, "ecs": {"version": "8.11.0"}, "event": {"category": ["database"], "created": "2026-09-21T03:30:17.584Z", "dataset": "mongodb.log", "ingested": "2026-09-21T03:30:18.784Z", "kind": "event", "module": "mongodb", "original": "{\"t\":{\"$date\":\"2026-09-21T03:30:11.577+00:00\"},\"s\":\"I\",  \"c\":\"ACCESS\",   \"id\":5286307, \"ctx\":\"conn52779\",\"msg\":\"Failed to authenticate\",\"attr\":{\"client\":\"10.30.1.22:61889\",\"isSpeculative\":true,\"isClusterMember\":false,\"mechanism\":\"SCRAM-SHA-256\",\"user\":\"dba_oleg\",\"db\":\"admin\",\"error\":\"AuthenticationFailed: SCRAM authentication failed, storedKey mismatch\",\"result\":18,\"metrics\":{\"conversation_duration\":{\"micros\":7400,\"summary\":[{\"step\":1,\"step_total\":2,\"duration_micros\":90},{\"step\":2,\"step_total\":2,\"duration_micros\":231}]}},\"doc\":{\"application\":{\"name\":\"mongosh 2.3.0\"},\"driver\":{\"name\":\"nodejs|mongosh\",\"version\":\"6.8.0|2.3.0\"},\"platform\":\"Node.js v20.16.0, LE\",\"os\":{\"name\":\"darwin\",\"architecture\":\"arm64\",\"version\":\"23.6.0\",\"type\":\"Darwin\"}},\"extraInfo\":{}}}", "type": ["access"]}, "host": {"name": "mongo-01.corp.example"}, "input": {"type": "logfile"}, "log": {"file": {"path": "/var/log/mongodb/mongod.log"}, "level": "I"}, "message": "Failed to authenticate", "mongodb": {"log": {"attr": {"client": "10.30.1.22:61889", "isSpeculative": true, "isClusterMember": false, "mechanism": "SCRAM-SHA-256", "user": "dba_oleg", "db": "admin", "error": "AuthenticationFailed: SCRAM authentication failed, storedKey mismatch", "result": 18, "metrics": {"conversation_duration": {"micros": 7400, "summary": [{"step": 1, "step_total": 2, "duration_micros": 90}, {"step": 2, "step_total": 2, "duration_micros": 231}]}}, "doc": {"application": {"name": "mongosh 2.3.0"}, "driver": {"name": "nodejs|mongosh", "version": "6.8.0|2.3.0"}, "platform": "Node.js v20.16.0, LE", "os": {"name": "darwin", "architecture": "arm64", "version": "23.6.0", "type": "Darwin"}}, "extraInfo": {}}, "component": "ACCESS", "context": "conn52779", "id": 5286307}}, "tags": ["preserve_original_event"]}
```

## References

- MongoDB server source, tag `r7.0.43`: https://github.com/mongodb/mongo/tree/r7.0.43/src/mongo (`logv2/json_formatter.cpp`, `db/curop.cpp`, `db/auth/authentication_session.cpp`, `transport/service_entry_point_impl.cpp`, `rpc/metadata/client_metadata.cpp`, `transport/ingress_handshake_metrics.cpp`)
- MongoDB 7.0 log messages: https://www.mongodb.com/docs/v7.0/reference/log-messages/
- MongoDB handshake specification: https://github.com/mongodb/specifications/blob/master/source/mongodb-handshake/handshake.md
- Elastic MongoDB integration, `log` data stream: https://github.com/elastic/integrations/tree/main/packages/mongodb/data_stream/log
