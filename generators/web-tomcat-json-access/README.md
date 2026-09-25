# Apache Tomcat JSON Access

Eventum content pack for Tomcat JsonAccessLogValve. Emits ECS JSON with the native source record in `event.original`. The native parsed fields are under the source namespace. Default mode includes background and a repeatable anomaly chain; `anomaly_mode: false` emits background only.

## Run

From the content-packs repository root:

```bash
eventum generate --path generators/web-tomcat-json-access/generator.yml --id web-tomcat-json-access --live-mode true
```

For a bounded local batch sample, run `timeout 3s eventum generate --path generators/web-tomcat-json-access/generator.yml --id web-tomcat-json-access-batch --live-mode false` (timeout exit code 124 is expected for this continuous source).

The file output is `generators/web-tomcat-json-access/output/events.json`. Set `event.template.params.anomaly_mode: false` to generate only routine activity. The generator emits one event per input tick; timing depends on the Eventum input configuration.

## Events

| Native event | Meaning | Frequency | ECS category |
| --- | --- | --- | --- |
| `HTTP access` | Routine request and response | 1 per routine tick | `web` |
| `Manager 401` | Denied manager request | 3 per chain | `web` |
| `Manager 200` | Manager access response | 1 per chain | `web` |
| `Deploy POST` | Manager deploy request | 1 per chain | `web` |
| `App GET` | Request to deployed path | 1 per chain | `web` |

## Anomaly Chain

One client receives three /manager/html 401 responses, then 200, POSTs a manager deploy request and accesses the deployed path. Group by source.ip in a short window; detect repeated /manager/html 401, then 200 with user.name, POST /manager/text/deploy with the same sessionId, and a subsequent GET of /support/.

The 13 JSON keys correspond to the configured access-log pattern, not every field the valve can emit. HTTP access logs show status and requests; a 200 response to /manager/text/deploy does not independently prove successful deployment. The chain should be treated as suspicious request activity until confirmed against Tomcat manager or application logs.

## Parameters

### Event Parameters

| Parameter | Default | Meaning |
| --- | --- | --- |
| `server_name` | `tomcat-01.corp.example` | Tomcat host name |
| `server_ip` | `10.120.0.5` | Tomcat address |
| `anomaly_ip` | `10.99.4.51` | Chain client address |
| `anomaly_user` | `manager` | Authenticated manager user |
| `anomaly_interval_events` | `250` | Routine events between chains |
| `anomaly_mode` | `true` | Enable chain; false emits background only |

### Output Parameters

No top-level `${params.*}` or `${secrets.*}` placeholders are shipped. The file output works without credentials. To send to another destination, replace the `output` block with that plugin configuration and keep credentials in Eventum secrets.

## Sample output

This event was captured from an actual generator run with `anomaly_mode: true`:

```json
{
  "@timestamp": "2026-09-25T12:43:41+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "http-access",
    "category": [
      "web"
    ],
    "dataset": "tomcat.access",
    "kind": "event",
    "original": "{\"elapsedTime\": \"429\", \"localServerName\": \"tomcat-01.corp.example\", \"method\": \"POST\", \"path\": \"/manager/text/deploy\", \"protocol\": \"HTTP/1.1\", \"query\": \"?war=file:/tmp/support.war\\u0026path=/support\", \"remoteAddr\": \"10.99.4.51\", \"request\": \"POST /manager/text/deploy?war=file:/tmp/support.war\\u0026path=/support HTTP/1.1\", \"sessionId\": \"B4MANAGER1\", \"size\": \"142\", \"statusCode\": \"200\", \"time\": \"[25/Sep/2026:12:43:41 +0000]\", \"user\": \"manager\"}",
    "outcome": "success",
    "type": [
      "access"
    ]
  },
  "host": {
    "ip": [
      "10.120.0.5"
    ],
    "name": "tomcat-01.corp.example"
  },
  "http": {
    "request": {
      "method": "POST"
    },
    "response": {
      "bytes": 142,
      "status_code": 200
    },
    "version": "1.1"
  },
  "message": "POST /manager/text/deploy?war=file:/tmp/support.war&path=/support HTTP/1.1",
  "observer": {
    "hostname": "tomcat-01.corp.example",
    "ip": "10.120.0.5",
    "product": "Tomcat",
    "type": "web",
    "vendor": "Apache"
  },
  "related": {
    "ip": [
      "10.99.4.51"
    ],
    "user": [
      "manager"
    ]
  },
  "source": {
    "ip": "10.99.4.51"
  },
  "tags": [
    "tomcat-json-access",
    "preserve_original_event"
  ],
  "tomcat": {
    "access": {
      "elapsedTime": "429",
      "localServerName": "tomcat-01.corp.example",
      "method": "POST",
      "path": "/manager/text/deploy",
      "protocol": "HTTP/1.1",
      "query": "?war=file:/tmp/support.war&path=/support",
      "remoteAddr": "10.99.4.51",
      "request": "POST /manager/text/deploy?war=file:/tmp/support.war&path=/support HTTP/1.1",
      "sessionId": "B4MANAGER1",
      "size": "142",
      "statusCode": "200",
      "time": "[25/Sep/2026:12:43:41 +0000]",
      "user": "manager"
    }
  },
  "url": {
    "path": "/manager/text/deploy",
    "query": "?war=file:/tmp/support.war&path=/support"
  },
  "user": {
    "name": "manager"
  }
}
```

## Format and references

The native JSON contains every field in this configured valve pattern (13/13); the sample does not purport to cover every optional JsonAccessLogValve pattern token.

Native JsonAccessLogValve record is retained in event.original and tomcat.access. All valve-rendered values are strings; missing values use - and zero-byte size uses -. Fifty request samples vary routine paths and status codes.

- [Tomcat 10.1 Valve Configuration](https://tomcat.apache.org/tomcat-10.1-doc/config/valve.html#JSON_Access_Log_Valve)
- [Tomcat JsonAccessLogValve API](https://tomcat.apache.org/tomcat-10.1-doc/api/org/apache/catalina/valves/JsonAccessLogValve.html)
- [Kaspersky KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)
