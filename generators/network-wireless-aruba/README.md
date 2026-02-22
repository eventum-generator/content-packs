# Aruba Wireless Controller Event Generator

Produces realistic Aruba ArubaOS wireless controller syslog events (ECS-compatible JSON) covering the full wireless client lifecycle (association, 802.1X/web/MAC authentication, role assignment, deauthentication, disassociation), AP management (up/down), security events (rogue and interfering AP detection), and RF management (ARM channel changes).

## Event Types Covered

| Message ID | Process | Event Type | Description | Frequency | ECS Action |
|------------|---------|------------|-------------|-----------|------------|
| 522008 | authmgr | Auth Success | User authentication successful via RADIUS | ~24.9% | `user-authentication-successful` |
| 522275 | authmgr | Auth Failed | User authentication failed | ~1.6% | `user-authentication-failed` |
| 501030 | stm | Station Associated | Client associated to AP | ~19.7% | `station-associated` |
| 501199 | stm | User Authenticated | User authenticated with role assignment | ~19.8% | `user-authenticated` |
| 501060 | stm | Station Disassociated | Client disassociated from AP | ~14.7% | `station-disassociated` |
| 501080 | stm | User De-authenticated | Client de-authenticated | ~7.9% | `user-de-authenticated` |
| 501217 | stm | User Entry Deleted | User session cleanup | ~7.9% | `user-entry-deleted` |
| 302004 | sapd | AP Up | Access point came online | ~0.8% | `ap-up` |
| 302006 | sapd | AP Down | Access point went offline | ~0.3% | `ap-down` |
| 124001 | wms | Rogue AP | Rogue AP detected by WIDS | ~0.5% | `rogue-ap-detected` |
| 404003 | sapd | Interfering AP | Interfering AP detected | ~0.8% | `interfering-ap-detected` |
| 500010 | sapd | Channel Change | ARM changed radio channel | ~1.2% | `channel-change` |

## Realism Features

- **Weighted event distribution** matching production enterprise WLAN traffic patterns (~50 APs, ~500 clients)
- **Correlated client sessions** — station-associated (501030) events produce client context (MAC, IP, AP, SSID, VLAN) consumed by disassociation (501060) events with matching fields
- **Cross-template correlation** — authentication, role assignment, deauthentication, and entry deletion events read from the active client pool for consistent MAC/IP/username pairing
- **Multiple SSIDs** — Corp-WiFi (802.1X, 55%), Guest-WiFi (web-auth, 20%), IoT-Network (MAC-auth, 15%), Exec-WiFi (802.1X, 10%) with appropriate VLAN and role assignment
- **20 access points** across 3 buildings (HQ, DC, Branch) with realistic naming and IP assignment
- **Realistic deauthentication reasons** — Client initiated (30%), Idle timeout (25%), Session timeout (15%), RADIUS disconnect (10%), AP handoff (10%)
- **Rogue AP detection** — random SSIDs (NETGEAR-5G, linksys, FreeWiFi) with confidence levels and classification
- **ARM channel changes** — radio-aware channel selection (2.4GHz: 1/6/11, 5GHz: 36-165) with interference-based reasons
- **Authentic BSD syslog format** — `event.original` includes full Aruba syslog message with priority, timestamp, hostname, process/PID, message ID, and severity
- **Full ECS compliance** — `aruba.wireless.*` namespace, `observer.*` (vendor: Aruba, product: ArubaOS, type: wireless), `log.syslog.*`, `related.*` arrays
- **Authentication failure scenarios** — 60% real users (expired creds/typos), 40% unknown/attacker usernames

## Parameters

### Event Parameters

Edit the `params` section under `event.template` in `generator.yml`:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `controller_hostname` | `aruba-mc01` | Wireless controller hostname |
| `controller_ip` | `192.168.1.1` | Controller management IP |
| `ecs_version` | `8.17.0` | ECS version string |
| `agent_id` | `b2c3d4e5-...` | Filebeat agent ID |
| `agent_version` | `8.17.0` | Filebeat version string |
| `client_pool_size` | `150` | Max active client sessions in correlation pool |

### Output Parameters

For OpenSearch/Elasticsearch output, use `${params.*}` and `${secrets.*}`:

```yaml
output:
  - opensearch:
      hosts:
        - ${params.opensearch_host}
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: ${params.opensearch_index}
```

## Usage

```bash
# Install Eventum
uv tool install eventum-generator

# Run the generator
eventum generate \
  --path generators/network-wireless-aruba/generator.yml \
  --id aruba-wlan \
  --live-mode
```

### Adjusting Event Rate

Change the `count` in the input section:

```yaml
input:
  - cron:
      expression: "* * * * * *"
      count: 5    # 5 events/second (300/min, 18K/hour)
```

### Multi-Generator Setup (startup.yml)

```yaml
generators:
  aruba-wlan:
    path: generators/network-wireless-aruba/generator.yml
    live_mode: true
```

## Sample Output

### User Authentication Successful (522008)

```json
{
  "@timestamp": "2026-02-22T17:46:52+00:00",
  "agent": {
    "ephemeral_id": "a187a43d-0584-42c8-97d5-987db199c5b8",
    "id": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
    "name": "aruba-mc01",
    "type": "filebeat",
    "version": "8.17.0"
  },
  "aruba": {
    "wireless": {
      "aaa_profile": "Corp_AAA",
      "ap_name": "AP-HQ-F2-01",
      "auth_method": "802.1x",
      "auth_server": "RADIUS-Primary",
      "bssid": "00:0b:86:a1:21:00",
      "client_mac": "6a:2b:14:60:aa:fd",
      "message_id": "522008",
      "process": "authmgr",
      "role": "authenticated",
      "ssid": "Corp-WiFi",
      "vlan": 100
    }
  },
  "data_stream": {
    "dataset": "aruba.wireless",
    "namespace": "default",
    "type": "logs"
  },
  "destination": {
    "address": "10.1.1.100",
    "ip": "10.1.1.100"
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "user-authentication-successful",
    "category": ["authentication"],
    "code": "522008",
    "dataset": "aruba.wireless",
    "kind": "event",
    "module": "aruba",
    "original": "<165>Feb 22 17:46:52 2026 aruba-mc01 authmgr[3469]: <522008> <NOTI> <aruba-mc01 192.168.1.1> User Authentication Successful: username=jsmith MAC=6a:2b:14:60:aa:fd IP=10.100.149.48 role=authenticated VLAN=100 AP=AP-HQ-F2-01 SSID=Corp-WiFi AAA profile=Corp_AAA auth method=802.1x auth server=RADIUS-Primary",
    "outcome": "success",
    "severity": 5,
    "type": ["start"]
  },
  "host": {
    "hostname": "aruba-mc01"
  },
  "log": {
    "level": "notice",
    "syslog": {
      "facility": {"code": 20, "name": "local4"},
      "priority": 165,
      "severity": {"code": 5, "name": "Notice"}
    }
  },
  "network": {
    "vlan": {"id": "100"}
  },
  "observer": {
    "hostname": "aruba-mc01",
    "ip": ["192.168.1.1"],
    "name": "aruba-mc01",
    "product": "ArubaOS",
    "type": "wireless",
    "vendor": "Aruba"
  },
  "related": {
    "hosts": ["aruba-mc01", "AP-HQ-F2-01"],
    "ip": ["10.100.149.48", "10.1.1.100", "192.168.1.1"],
    "user": ["jsmith"]
  },
  "source": {
    "ip": "10.100.149.48",
    "mac": "6a:2b:14:60:aa:fd",
    "user": {"name": "jsmith"}
  },
  "tags": ["aruba-wireless", "forwarded"],
  "user": {
    "name": "jsmith"
  }
}
```

## File Structure

```
network-wireless-aruba/
  generator.yml                                # Pipeline config (input → event → output)
  README.md                                    # This file
  samples/
    access_points.csv                          # 20 APs across 3 buildings (HQ, DC, Branch)
    ssids.json                                 # 4 SSIDs with auth method, VLAN, and weight
    usernames.csv                              # 25 enterprise users with department
  templates/
    124001-rogue-ap.json.jinja                 # Rogue AP detected by WIDS
    302004-ap-up.json.jinja                    # Access point came online
    302006-ap-down.json.jinja                  # Access point went offline
    404003-interfering-ap.json.jinja           # Interfering AP detected
    500010-channel-change.json.jinja           # ARM radio channel change
    501030-station-associated.json.jinja       # Client associated to AP (producer)
    501060-station-disassociated.json.jinja    # Client disassociated from AP (consumer)
    501080-user-deauthenticated.json.jinja     # Client de-authenticated
    501199-user-authenticated.json.jinja       # User authenticated with role
    501217-user-entry-deleted.json.jinja       # User session cleanup
    522008-auth-success.json.jinja             # RADIUS authentication successful
    522275-auth-failed.json.jinja              # RADIUS authentication failed
```

## References

- [ArubaOS Syslog Messages Reference Guide](https://www.arubanetworks.com/techdocs/ArubaOS_8_6_0_0/Content/ArubaOS_Syslog/syslog_messages.htm)
- [ArubaOS 8.x Configuration Guide - Syslog](https://support.hpe.com/hpesc/public/docDisplay?docId=emr_na-c05321932)
- [Aruba Instant Syslog Messages Reference](https://www.arubanetworks.com/techdocs/Instant_4.2.2_Syslog_Messages/Content/Syslog_Messages_Reference_Guide.htm)
- [Splunk Add-on for Aruba Networks](https://ta-aruba-networks.readthedocs.io/en/latest/sourcetypes.html)
- [Elastic Common Schema (ECS) Reference](https://www.elastic.co/guide/en/ecs/current/index.html)
- [Google Chronicle - Aruba WC Parser](https://cloud.google.com/chronicle/docs/ingestion/default-parsers/aruba-wc)
