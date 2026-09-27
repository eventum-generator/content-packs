# Kaspersky CyberTrace ArcSight CEF detections

Synthetic Kaspersky CyberTrace 4.0 detection events in the CEF pattern that Kaspersky documents for ArcSight, for SIEM detection engineering and parser testing. Each detection records that an event from an endpoint matched a URL or file hash from Kaspersky Threat Data Feeds. Eventum writes ECS JSON and places the CEF line in `event.original`.

## Event Types Covered

| CEF `reason` (feed category) | Matched object | Share | ECS `event.category` |
| --- | --- | --- | --- |
| `KL_Malicious_URL` | URL from the Malicious URL Data Feed | 57.5% | `threat` |
| `KL_Malicious_Hash_MD5` | File MD5 from the Malicious Hash Data Feed | 20.6% | `threat` |
| `KL_Phishing_URL` | URL from the Phishing URL Data Feed | 21.9% | `threat` |

Shares were measured over four synthetic days of the default configuration (about 530 detections per day). The rate and shares are scenario assumptions, not Kaspersky measurements.

84 endpoints (`samples/endpoints.csv`) produce detections independently. Each endpoint has its own activity level, and the gaps between its incidents follow a skewed random distribution. User endpoints are about three times as active from 06:00 to 17:00 UTC as at night; service accounts are active around the clock. An incident is one of the following:

- a malicious or phishing URL match, often repeated within seconds as the page or download is retried;
- a phishing redirect, in which two phishing URLs match within seconds;
- a download: a malicious URL, then a file MD5 about a minute or two later, and often further contacts with other malicious URLs over the next minutes;
- a hash-first detection: a file MD5, sometimes rescanned, sometimes followed by a malicious URL contact;
- beacon-like repeats: one malicious URL contacted two to six times over one or two hours.

Most endpoints have one user. A few are shared hosts with several users, and six run under two service accounts (`svc-sccm`, `svc-build`, three endpoints each). Indicators come from `samples/malicious_urls.json`, `samples/phishing_urls.json` and `samples/hashes.json`, each with fixed feed record fields (mask, first and last seen dates, popularity, threat name, category or industry, file hashes and size). All domains use reserved `.test`, `.example` and `.invalid` names, and all addresses are documentation or RFC 1918 ranges.

## Anomaly Chain

With `anomaly_mode: true` (the default), the generator adds a recurring episode on one endpoint:

1. **URL match**: the endpoint and user match a malicious URL (`KL_Malicious_URL`), sometimes repeated within seconds.
2. **File hash match**: about a minute or two later, the same endpoint and user match a malicious file MD5 (`KL_Malicious_Hash_MD5`).
3. **Same URL again**: a few minutes later, the same endpoint and user match the URL from step 1 again. Half of the episodes then contact another malicious URL, as ordinary downloads do.

**Linking fields**: CEF `src` and `suser` (`source.ip`, `user.name`), and `request` (`url.original`) or `cs5` (`kaspersky.cybertrace.matched_indicator`) for the repeated URL.

**Recurrence**: the first episode starts one hour after the generator starts, plus a random delay. Each next episode is due `anomaly_interval_hours` (default 24, minimum 3) after the actual start of the previous one and starts after a random delay of up to one hour, or up to one eighth of the interval when that is shorter. Episodes are scheduled on event time. A missed episode is not caught up.

**Variation**: each episode picks another endpoint, URL and file hash than the previous one; the user is the one on that endpoint, so a user who works on several endpoints can appear in consecutive episodes. The endpoint and user continue their ordinary detections during the episode.

**Background**: every part of the episode also occurs in ordinary traffic in both modes: all endpoints, users, URLs and hashes; repeated matches of one URL within seconds or minutes; a URL followed by a file hash; a file hash followed by a URL. Only the complete sequence (a URL, then a file hash, then the same URL, for one endpoint and user) is absent from the background: an ordinary match that would complete it within two hours is given another URL. With `anomaly_mode: false` the generator produces this background only.

**Detection idea**: per `src` and `suser`, alert when a URL match is followed by an MD5 match and then by a match of the same URL within one hour. It suggests that the host fetched a file from a known malicious URL, the file was detected, and the host went back to the same resource. CyberTrace detections alone do not prove that the URL delivered that file.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`.

| Name | Default | Description |
| --- | --- | --- |
| `anomaly_mode` | `true` | Add the recurring URL, file hash, same URL episode. `false` produces background only. |
| `anomaly_interval_hours` | `24` | Hours from the start of one episode to the time the next is due. Minimum 3. |

### Output Parameters

The shipped `generator.yml` writes to a local file and needs no top-level `params` or `secrets`. To send events to a backend, replace `output` and reference top-level placeholders, for example:

```yaml
output:
  - opensearch:
      hosts:
        - ${params.opensearch_host}
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: kaspersky-cybertrace
```

A CEF collector needs the `event.original` line rather than the ECS JSON document.

## Usage

```bash
# Batch: generate as fast as possible
eventum generate --path generators/security-kaspersky-cybertrace/generator.yml --id cybertrace --live-mode false

# Live: detections at their event times
eventum generate --path generators/security-kaspersky-cybertrace/generator.yml --id cybertrace --live-mode true
```

Events are written to `generators/security-kaspersky-cybertrace/output/events.json`.

## Sample Output

The file hash match of an anomaly episode, copied byte for byte from a default-configuration run (one JSON document per line):

```json
{"@timestamp": "2026-09-02T02:55:14.484147+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "indicator_match", "category": ["threat"], "code": "KL_Malicious_Hash_MD5", "dataset": "kaspersky.cybertrace", "kind": "alert", "original": "CEF:0|Kaspersky|Kaspersky CyberTrace for ArcSight|2.0|2|CyberTrace Detection Event|8| reason=KL_Malicious_Hash_MD5 dst=- src=10.20.4.175 fileHash=A0F85F1082FB3D525DAE8F5522EABC8B request=- sourceServiceName=ExampleVendor sproc=EndpointSecurity suser=o.popov msg=CyberTrace detected KL_Malicious_Hash_MD5 externalId=7096745 flexString1=16.06.2022 03:53 flexString2=04.06.2026 22:17 cn2=3 cs3=HEUR:Trojan-Dropper.Win32.Agent.gen cs4=http://cdn-docs33.test/update/patch.bin fsize=3775663 cs5Label=MatchedIndicator cs5=A0F85F1082FB3D525DAE8F5522EABC8B cn3Label=Confidence cn3=100 cs6Label=Context cs6=MD5:A0F85F1082FB3D525DAE8F5522EABC8B SHA1:B1F4FB26D4C2BECFCC5D810E0A69C45E11101A89 SHA256:03FE587258F70945E8D4F039ADE809B8B1FA7339260C38A90175C218D6C9F79D file_size:3775663 first_seen:16.06.2022 03:53 last_seen:04.06.2026 22:17 popularity:3 threat:HEUR:Trojan-Dropper.Win32.Agent.gen ", "severity": 8, "type": ["indicator"]}, "file": {"hash": {"md5": "a0f85f1082fb3d525dae8f5522eabc8b", "sha1": "b1f4fb26d4c2becfcc5d810e0a69c45e11101a89", "sha256": "03fe587258f70945e8d4f039ade809b8b1fa7339260c38a90175c218d6c9f79d"}, "size": 3775663}, "kaspersky": {"cybertrace": {"confidence": 100, "external_id": 7096745, "matched_indicator": "A0F85F1082FB3D525DAE8F5522EABC8B", "record_context": "MD5:A0F85F1082FB3D525DAE8F5522EABC8B SHA1:B1F4FB26D4C2BECFCC5D810E0A69C45E11101A89 SHA256:03FE587258F70945E8D4F039ADE809B8B1FA7339260C38A90175C218D6C9F79D file_size:3775663 first_seen:16.06.2022 03:53 last_seen:04.06.2026 22:17 popularity:3 threat:HEUR:Trojan-Dropper.Win32.Agent.gen "}}, "observer": {"product": "Kaspersky CyberTrace for ArcSight", "vendor": "Kaspersky"}, "related": {"hash": ["a0f85f1082fb3d525dae8f5522eabc8b", "b1f4fb26d4c2becfcc5d810e0a69c45e11101a89", "03fe587258f70945e8d4f039ade809b8b1fa7339260c38a90175c218d6c9f79d"], "ip": ["10.20.4.175"], "user": ["o.popov"]}, "source": {"ip": "10.20.4.175"}, "user": {"name": "o.popov"}}
```

## Format and Limitations

- **CEF pattern**: the header, the order of the extension keys and the `cs5`/`cn3`/`cs6` labels follow the CyberTrace 4.0 ArcSight integration procedure. The `2.0` in the header is part of that pattern, not a product version.
- **Actionable fields** are emitted in the CEF keys that the same procedure lists for each feed (Malicious URL: `cs1`, `flexString1`, `flexString2`, `cn2`, `cs3`, `cs4`, `cs2`; Phishing URL: `cs1`, `flexString1`, `flexString2`, `cn2`, `deviceFacility`, `cs2`; Malicious Hash: `flexString1`, `flexString2`, `cn2`, `cs3`, `cs4`, `fsize`), in the order of its tables. The order and the `-` for an empty field follow the complete CyberTrace 5.3 ArcSight record; no complete 4.0 record was found, so 4.0 byte parity is not established.
- **Record context** (`cs6`) uses the `Name:Value ` layout of the 5.3 record (fields sorted by name, each followed by a space). Hash records carry the fields of the 4.0 plain-text sample. URL records carry only their flat feed fields (`category` or `industry`, `first_seen`, `last_seen`, `mask`, `popularity`); nested feed fields (`files`, `whois`, `geo`, `IP`) are omitted because their flattening is not documented.
- **Matched indicator** for URL detections is the feed record's `mask`; the documentation says only that it is the detected indicator.
- **Incoming event fields**: `src`, `dst`, `suser`, `request`, `fileHash` and `externalId` are values that CyberTrace extracts from the incoming endpoint event. `sourceServiceName=ExampleVendor` and `sproc=EndpointSecurity` stand for the vendor and product of that event source. `externalId` is modeled as the endpoint's own event counter. Hash detections carry `dst=-` because a file event has no destination.
- **Time**: the pattern has no time field. `@timestamp` is the Eventum event time.
- **Transport**: in the documented ArcSight integration, the ArcSight Forwarding Connector exchanges events with Feed Service over raw TCP. The shipped file output does not reproduce the network transport.
- **Scope**: detection events only; no Feed Service alert events, no raw endpoint telemetry. Confidence is always 100, as in every documented example.

## References

- [CyberTrace 4.0: configuring CyberTrace for ArcSight (CEF pattern, actionable fields)](https://support.kaspersky.com/cybertrace/2020/en-us/174019.htm)
- [CyberTrace 4.0: event format patterns and a plain-text MD5 detection](https://support.kaspersky.com/cybertrace/2020/en-us/197106.htm)
- [CyberTrace 5.3: complete ArcSight CEF detection record](https://support.kaspersky.ru/cyber-trace/5.3/313250)
- [CyberTrace 4.0: verification feed categories](https://support.kaspersky.com/cybertrace/2020/en-us/171415.htm)
- [Kaspersky Threat Data Feeds: Malicious URL Data Feed record fields](https://tip.kaspersky.com/Help/TIDF/en-US/MaliciousUrlFeed.htm)
- [Kaspersky Threat Data Feeds: Phishing URL Data Feed record fields](https://tip.kaspersky.com/Help/TIDF/en-US/PhishingUrlFeed.htm)
- [Kaspersky Threat Data Feeds: Malicious Hash Data Feed record fields](https://tip.kaspersky.com/Help/TIDF/en-US/MaliciousHashFeed.htm)
- [CyberTrace 4.0: ArcSight Forwarding Connector (raw TCP)](https://support.kaspersky.com/cybertrace/2020/en-us/167564.htm)
