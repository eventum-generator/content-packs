# Apache Tomcat JSON Access

Synthetic Apache Tomcat 10.1 JsonAccessLogValve records for one application server, wrapped in ECS JSON. `event.original` preserves the native JSON access record.

## Events

About 46,800 requests per day: browser activity has a low overnight floor and peaks from 08:00 to 18:00 UTC. API clients, health checks and eight release services run around the clock. Individual response sizes and durations vary by request class.

| Event | Approximate share | Category |
| --- | --- | --- |
| Successful responses, including redirects and 304 | 93.5% | Web access |
| Missing resources | 2.2% | Web access |
| Authentication challenges | 1.9% | Authentication |
| Application server errors | 1.3% | Web access |
| Other client errors | 1.1% | Web access |

Application browsing, assets, shopping requests and API calls dominate. Manager requests include ordinary list, deployment and undeployment requests from the same clients used by the anomaly chain.

## Anomaly Chain

A release-service address receives three HTTP 401 responses from `GET /manager/text/list`, then a 200 response to the same request and a 200 response to `PUT /manager/text/deploy?path=/preview-NN`. Correlate by client address within 15 minutes. The manager uses HTTP Basic authentication, so its session ID is `-`. A 401 can be an authentication challenge and does not establish that a named account submitted a bad password.

The first sequence starts within the smaller of 24 hours and the configured interval. Later starts fall within a window centered on the previous start plus the interval. Its width is the smaller of one quarter of that interval and six hours. The release-service population is active around the clock, so episode hours have uniform weighting. Consecutive episodes use different release clients. Ordinary browser sessions remain independent.

`anomaly_mode: false` includes the individual request types and all release clients without the complete chain. Enabling it adds the correlated request sequence. HTTP 200 on a manager command does not establish successful deployment: the command result is in its response body, which this access log does not record.

## Parameters

| Parameter | Default | Meaning |
| --- | --- | --- |
| `server_name` | `tomcat-01.corp.example` | Application server name |
| `server_ip` | `10.120.0.5` | Application server address |
| `jvm_offset_minutes` | `0` | Offset in the native access-log time |
| `anomaly_mode` | `true` | Include correlated manager requests |
| `anomaly_interval_hours` | `24` | Time between episode centers |
| `anomaly_min_interval_hours` | `1` | Lower interval bound |
| `session_pool_cap` | `200` | Maximum concurrent synthetic browser sessions |

Set these values under `event.template.params` in `generator.yml`. Intervals below the minimum use the minimum.

## Usage

From the content-packs root:

```bash
eventum generate --path generators/web-tomcat-json-access/generator.yml --id tomcat --live-mode true
```

For a finite batch, set `oscillator.start` and `oscillator.end` in each file under `patterns/` to explicit UTC dates, for example `2026-09-01T00:00:00+00:00` and `2026-09-05T00:00:00+00:00`. Keep the start at midnight to preserve the working-day hours. Then run:

```bash
eventum generate --path generators/web-tomcat-json-access/generator.yml --id tomcat-batch --live-mode false --keep-order true
```

Output is `output/events.json` relative to the generator directory. Replace the output block to send the records to another destination.

Performance: 10,000 requests rendered in 5.05 seconds (about 1,980 events/s, including startup).

## Sample output

```json
{"@timestamp": "2026-09-01T00:00:02.000Z", "apache_tomcat": {"access": {"elapsedTime": "23398", "http": {"ident": "-", "useragent": "Go-http-client/2.0"}, "localServerName": "tomcat-01.corp.example", "logicalUserName": "-", "sessionId": "-", "user": "-"}}, "destination": {"bytes": 556}, "ecs": {"version": "8.11.0"}, "event": {"category": ["web"], "dataset": "apache_tomcat.access", "duration": 23398000, "kind": "event", "module": "apache_tomcat", "original": "{\"remoteAddr\":\"10.10.0.51\",\"logicalUserName\":\"-\",\"user\":\"-\",\"time\":\"[01/Sep/2026:00:00:02 +0000]\",\"request\":\"POST /api/v1/auth/token HTTP/1.1\",\"statusCode\":\"200\",\"size\":\"556\",\"elapsedTime\":\"23398\",\"sessionId\":\"-\",\"localServerName\":\"tomcat-01.corp.example\",\"requestHeaders\": {\"Referer\":\"-\",\"User-Agent\":\"Go-http-client/2.0\"}}", "outcome": "success", "type": ["access"]}, "host": {"hostname": "tomcat-01.corp.example", "ip": ["10.120.0.5"], "name": "tomcat-01.corp.example"}, "http": {"request": {"method": "POST"}, "response": {"body": {"bytes": 556}, "status_code": 200}, "version": "1.1"}, "observer": {"product": "Tomcat", "type": "web", "vendor": "Apache"}, "related": {"ip": ["10.10.0.51"]}, "source": {"address": "10.10.0.51", "ip": "10.10.0.51"}, "tags": ["apache_tomcat-access", "preserve_original_event"], "url": {"original": "/api/v1/auth/token", "path": "/api/v1/auth/token"}, "user_agent": {"original": "Go-http-client/2.0"}}
```

## Limitations

This is a synthetic application workload, not a production traffic distribution. Request rates, sizes and durations are illustrative. Related requests can be seconds apart. Browser session identities are synthetic and retained only for the active session pool. Only HTTP/1.1 requests and the configured access-log fields are covered. No application response bodies, deployment results or Tomcat lifecycle records are included.

The native pattern is `%a %l %u %t "%r" %s %b %D %S %v %{Referer}i %{User-Agent}i`. Its eleven top-level JSON keys include the nested request-header object. Native scalar values are strings, absent values and zero-byte bodies are `-`, and `%D` is measured in microseconds. ECS fields are enrichment outside the native record.

## References

- [Tomcat 10.1 JSON Access Log Valve](https://tomcat.apache.org/tomcat-10.1-doc/config/valve.html#JSON_Access_Log_Valve)
- [JsonAccessLogValve source](https://github.com/apache/tomcat/blob/10.1.x/java/org/apache/catalina/valves/JsonAccessLogValve.java)
- [Manager text interface](https://tomcat.apache.org/tomcat-10.1-doc/manager-howto.html)
- [Elastic Apache Tomcat integration](https://www.elastic.co/docs/reference/integrations/apache_tomcat)
