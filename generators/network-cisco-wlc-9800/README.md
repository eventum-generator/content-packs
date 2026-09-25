# Cisco Catalyst 9800 wireless client state syslog

Synthetic `%CLIENT_ORCH_LOG-7-...` messages for client RUN, delete, and IP update states in Cisco Catalyst 9800 IOS XE 17.11.

## Event Types

| State change | Baseline frequency | Category |
| --- | ---: | --- |
| `CLIENT_MOVED_TO_RUN_STATE` | 65% | Network |
| `CLIENT_MOVED_TO_DELETE_STATE` | 20% | Network |
| `CLIENT_IP_UPDATED` | 15% | Network |
| RUN/delete on three APs, then IP update | Chain only | Network |

The baseline weights are synthetic assumptions, not measured controller traffic.

## Anomaly Chain

One client MAC (`02aa.bbcc.ddee`), username and IP enters RUN on `AP-Floor1`, is deleted, enters RUN and is deleted on `AP-Floor2`, then enters RUN and updates its IP record on `AP-Floor3`. A SIEM rule can group by client MAC and SSID, sort by `@timestamp`, and detect rapid AP changes with repeated disconnects. File line order is not the contract. These messages describe association state, not an authentication result, so the sequence signals unusual roaming or instability rather than proving an intrusion.

`anomaly_mode` defaults to `true`. Set it to `false` in `event.template.params` for ordinary client state events only.

## Parameters

### Event Parameters

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include rapid three-AP client movement |
| `controller_name` | `wlc9800-01.corp.example` | Controller host name |
| `ssid` | `corp-wifi` | WLAN SSID |
| `suspicious_user` | `visitor01` | User in the chain |
| `suspicious_mac` | `02aa.bbcc.ddee` | Client MAC in the chain |
| `suspicious_ip` | `192.0.2.91` | Client IP in the chain |

### Output Parameters

The shipped configuration writes `output/events.json` and needs no connection parameters or secrets. Replace the `file` output in a local copy and add `${params.siem_host}` and `${secrets.siem_token}` for the selected output plugin where applicable.

## Usage

```bash
eventum generate --path generators/network-cisco-wlc-9800/generator.yml --id cisco-wlc-9800 --live-mode false
eventum generate --path generators/network-cisco-wlc-9800/generator.yml --id cisco-wlc-9800 --live-mode true
```

## Sample Output

This event was copied from a generator run with `anomaly_mode: true`.

```json
{
  "@timestamp": "2026-09-25T12:42:02+00:00",
  "cisco_wlc": {
    "ap_name": "AP-Floor1",
    "chassis": "1 R0/0",
    "client_state": "run",
    "ssid": "corp-wifi"
  },
  "client": {
    "ip": "192.0.2.91",
    "mac": "02aa.bbcc.ddee"
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "run",
    "category": [
      "network"
    ],
    "code": "CLIENT_MOVED_TO_RUN_STATE",
    "kind": "event",
    "original": "Sep 25 12:42:02.000 UTC: %CLIENT_ORCH_LOG-7-CLIENT_MOVED_TO_RUN_STATE: Chassis 1 R0/0: wncd: Username (visitor01), MAC: 02aa.bbcc.ddee, IP 192.0.2.91 associated to AP (AP-Floor1) with SSID (corp-wifi)",
    "type": [
      "start"
    ]
  },
  "host": {
    "name": "wlc9800-01.corp.example"
  },
  "log": {
    "level": "debug"
  },
  "process": {
    "name": "wncd"
  },
  "related": {
    "ip": [
      "192.0.2.91"
    ],
    "user": [
      "visitor01"
    ]
  },
  "user": {
    "name": "visitor01"
  }
}
```

## Coverage and Limits

The selected Cisco client-state messages expose eight elements, all preserved and parsed: timestamp, message code, username, MAC, client IP, AP name, SSID, and client state (8/8). The vendor samples have redacted MAC/IP fragments; this pack uses synthetic complete values. The `wireless client syslog-detailed` setting is needed for these messages. The source examples show that usernames can temporarily be `null` during AP transition; this pack models named clients only. KUMA 4.2 lists older AireOS WLC 2500/5500/8500 syslog, so those normalizers are not asserted compatible with Catalyst 9800 IOS XE messages.

## References

- [Cisco Catalyst 9800 IOS XE 17.11 client-state syslog guide](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/17-11/config-guide/b_wl_17_eleven_cg/m_syslog_server.html)
- [KUMA 4.2 supported event sources](https://support.kaspersky.ru/kuma/4.2/255782)
