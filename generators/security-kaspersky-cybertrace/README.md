# Kaspersky CyberTrace ArcSight CEF detections

Synthetic detection events for Kaspersky CyberTrace 4.0 using its documented, configurable ArcSight CEF pattern. Eventum writes ECS JSON and places the CEF message in event.original. The 2.0 text in the CEF device-version segment is part of Kaspersky's ArcSight pattern; it is not a claim that the modeled CyberTrace product version is 2.0.

## Event types

| Category in CEF reason | Matched indicator | Approximate share |
| --- | --- | --- |
| KL_Malicious_URL | Malicious URL | 65% |
| KL_Phishing_URL | Phishing URL | 25% |
| KL_Malicious_Hash_MD5 | Malicious file MD5 | 10% |

One event is generated every five synthetic minutes, about 288 detections per day across more than 40 modeled endpoint addresses. Shares and rate are scenario assumptions, not Kaspersky production measurements. Category names and indicator types follow Kaspersky's documented verification examples.

## Anomaly Chain

With anomaly_mode: true, one sequence begins after 12 routine events, about one synthetic hour:

1. An endpoint at 10.20.1.44 under user operator matches a malicious URL.
2. Five minutes later, the same endpoint and user match a malicious MD5.
3. Five minutes later, the endpoint and user match the original URL again.

Correlate CEF src and suser, then compare reason and cs5 (MatchedIndicator) within ten minutes. The sequence suggests repeated contact after a file-hash detection. It assumes the incoming endpoint telemetry carries a stable device IP, user, URL and file hash. CyberTrace detections alone do not prove that the URL delivered that file or identify a process relationship.

Background mode contains each exact individual target indicator signature, including endpoint, user, destination and record context. The URL and MD5 matches are spaced about 12 hours apart; no individual event exposes the mode. anomaly_mode defaults to true and inserts the sequence once per run. Set it to false for background only. Sort on @timestamp when inspecting output because concurrent writes can reorder lines.

## Parameters

### Event Parameters

Edit event.template.params in generator.yml.

| Name | Default | Purpose |
| --- | --- | --- |
| anomaly_mode | true | Include the one-time URL → MD5 → URL sequence. |
| anomaly_delay_events | 12 | Routine detections before the sequence. |
| target_endpoint_ip | 10.20.1.44 | Endpoint in occasional individual matches and the sequence. |
| target_destination_ip | 198.51.100.10 | Destination extracted from those incoming events. |
| target_user | operator | User in those incoming events. |
| target_url | https://malware.example.test/dropper | Repeated URL indicator. |
| target_md5 | C912705B4BBB14EC7E78FA8B370532C9 | MD5 indicator. |

### Output Parameters

File output works as shipped and needs no top-level params or secrets. To send events elsewhere, replace output.file with another output plugin and declare top-level params/secrets for that destination.

## Usage

Run from the content-packs repository:

~~~bash
eventum generate --path generators/security-kaspersky-cybertrace/generator.yml --id cybertrace --live-mode false
eventum generate --path generators/security-kaspersky-cybertrace/generator.yml --id cybertrace --live-mode true
~~~

Events are written to generators/security-kaspersky-cybertrace/output/events.json. A CEF collector needs event.original, rather than the surrounding ECS JSON.

## Sample output

This complete MD5 detection is from an anomaly-mode Eventum run:

~~~json
{
  "@timestamp": "2026-09-25T18:55:00+00:00",
  "destination": {
    "ip": "198.51.100.10"
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "indicator_match",
    "category": [
      "threat"
    ],
    "code": "KL_Malicious_Hash_MD5",
    "dataset": "kaspersky.cybertrace",
    "kind": "alert",
    "original": "CEF:0|Kaspersky|Kaspersky CyberTrace for ArcSight|2.0|2|CyberTrace Detection Event|8| reason=KL_Malicious_Hash_MD5 dst=198.51.100.10 src=10.20.1.44 fileHash=C912705B4BBB14EC7E78FA8B370532C9 request=- sourceServiceName=ExampleVendor sproc=EndpointSecurity suser=operator msg=CyberTrace detected KL_Malicious_Hash_MD5 externalId=675033 cs5Label=MatchedIndicator cs5=C912705B4BBB14EC7E78FA8B370532C9 cn3Label=Confidence cn3=100 cs6Label=Context cs6=MD5:C912705B4BBB14EC7E78FA8B370532C9",
    "severity": 8,
    "type": [
      "indicator"
    ]
  },
  "file": {
    "hash": {
      "md5": "c912705b4bbb14ec7e78fa8b370532c9"
    }
  },
  "kaspersky": {
    "cybertrace": {
      "confidence": 100,
      "external_id": 675033,
      "matched_indicator": "C912705B4BBB14EC7E78FA8B370532C9",
      "record_context": "MD5:C912705B4BBB14EC7E78FA8B370532C9"
    }
  },
  "observer": {
    "product": "Kaspersky CyberTrace for ArcSight",
    "vendor": "Kaspersky"
  },
  "related": {
    "ip": [
      "10.20.1.44",
      "198.51.100.10"
    ],
    "user": [
      "operator"
    ]
  },
  "source": {
    "ip": "10.20.1.44"
  },
  "user": {
    "name": "operator"
  }
}
~~~

## Scope and evidence

This is the Kaspersky:CyberTrace:ArcSight CEF Detection Event stream, distinct from Kaspersky NGFW Firewall, KATA, Security Center, mail and proxy streams. The CyberTrace 4.0 ArcSight integration guide supplies the chosen Kaspersky CEF header, order of 16 populated extension keys, and cs5/cn3/cs6 label literals. This configured variant clears the optional actionable fields as the guide permits. The selected output values are synthetic substitutions for the documented patterns, not a replay of device output. The externalId seed varies between runs and increments within a run.

The ArcSight CEF pattern does not contain a timestamp field. @timestamp is therefore the synthetic Eventum event time, not a timestamp parsed from event.original. CEF src is the incoming event's endpoint IP (%DeviceIp%), not the CyberTrace server address. CEF cs6 contains the documented-style record context: mask for URL matches or MD5 for hash matches. ECS url.original or file.hash.md5 is populated according to the matched indicator.

Kaspersky publishes a complete plain-text CyberTrace 4.0 MD5 detection and a complete ArcSight CEF record for CyberTrace 5.3. The 5.3 record corroborates the Kaspersky header, confidence pair and colon-separated context, but cannot establish byte-exact 4.0 output. The exact live substitutions, escaping and target-collector compatibility remain unverified without a 4.0 capture. KUMA 4.2 lists a regexp CyberTrace normalizer, not a documented parser for this custom ArcSight CEF pattern. Kaspersky's ArcSight connector guide specifies Raw TCP; the shipped file output does not reproduce that transport. Use a matching CEF parser or configure CyberTrace's event format for the target SIEM.

Both modes were run and checked for all categories, exact CEF-pattern structure, raw/ECS field consistency, UTC five-minute cadence, unique externalId values, and the sequence distinction. The README sample was copied from the generated anomaly run.

## References

- [CyberTrace 4.0 ArcSight integration CEF pattern and actionable fields](https://support.kaspersky.com/cybertrace/2020/en-us/174019.htm)
- [CyberTrace 4.0 configurable event formats and plain-text sample](https://support.kaspersky.com/cybertrace/2020/en-us/197106.htm)
- [CyberTrace 5.3 complete CEF detection example](https://support.kaspersky.ru/cyber-trace/5.3/313250)
- [CyberTrace 4.0 release features](https://support.kaspersky.com/cybertrace/2020/en-us/192225.htm)
- [Kaspersky verification feed categories and indicator examples](https://support.kaspersky.com/cybertrace/2020/en-us/171415.htm)
- [KUMA 4.2 supported source normalizers](https://support.kaspersky.ru/kuma/4.2/255782)
- [Kaspersky ArcSight Forwarding Connector setup (Raw TCP)](https://support.kaspersky.com/cybertrace/2020/en-us/167564.htm)
