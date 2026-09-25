# F5 BIG-IP Advanced Firewall Manager

F5 BIG-IP AFM layer 3/4 firewall and Network DoS CEF events. Eventum emits ECS JSON and preserves the CEF message in `event.original`. This is the Advanced Firewall Module stream, not BIG-IP ASM / Advanced WAF HTTP request logging.

## Event types

| AFM action or status | Synthetic frequency | ECS category |
| --- | --- | --- |
| Network `Accept` | 50% of background records | network |
| Network `Open` | 25% of background records | network |
| Network `Closed` | 25% of background records | network |
| DoS `Attack Started` | Once per anomaly sequence | network, intrusion_detection |
| DoS `Attack Sampled` with `Drop` | Three times per anomaly sequence | network, intrusion_detection |
| DoS `Attack Stopped` | Once per anomaly sequence | network, intrusion_detection |

The one-record-per-second input, routine proportions, and DoS sequence frequency are synthetic demo settings, not measured AFM rates. Routine `Open` and `Closed` records share a source/destination tuple and port.

## Anomaly Chain

After 48 routine records, a Network DoS attack starts, produces three dropped bad-checksum samples, and stops. The five records share `f5.afm.attack_id`, `source.ip`, `destination.ip`, `destination.port`, and `observer.name`. A SIEM rule can correlate a start followed by repeated drops for one attack ID; a separate rule can count distinct attack IDs from one source over time. The sample count is synthetic and does not encode packet volume.

`anomaly_mode: true` is the default. `false` emits only ordinary `Accept`, `Open`, and `Closed` network records. Correlate by `@timestamp` because output lines can arrive out of order.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`.

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Enable the Network DoS sequence. |
| `anomaly_interval_events` | `48` | Background records before each sequence. |
| `bigip_host` | `bigip-afm.lab.example` | Synthetic BIG-IP hostname. |
| `bigip_management_ip` | `10.0.0.5` | Management address in CEF and ECS. |
| `product_version` | `11.3.0.2790.300` | Version of the documented DoS CEF example. |
| `virtual_server` | `/Common/app-vs` | Synthetic virtual server. |
| `vlan` | `/Common/external` | VLAN in CEF extension fields. |
| `attack_source_ipv6` | `2001:db8:10::99` | Documentation-range IPv6 source of the sequence. |
| `attack_destination_ipv6` | `2001:db8:20::3` | Documentation-range IPv6 target of the sequence. |

### Output Parameters

The shipped file output needs no overrides. Replace `output.file` with another output plugin and use top-level `${params.*}` or `${secrets.*}` substitutions for destination settings when needed.

## Usage

From the content-packs repository:

```bash
eventum generate --path generators/network-f5-bigip-afm/generator.yml --id afm --live-mode false
eventum generate --path generators/network-f5-bigip-afm/generator.yml --id afm --live-mode true
```

Output: `generators/network-f5-bigip-afm/output/events.json`. Extract `event.original` to send the CEF message body to a Syslog/CEF collector.

## Sample output

Copied from an actual anomaly-mode run:

```json
{
  "@timestamp": "2026-09-25T14:41:09+00:00",
  "destination": {
    "ip": "2001:db8:20::3",
    "port": 80
  },
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "dos_sampled",
    "category": [
      "network",
      "intrusion_detection"
    ],
    "code": "Bad TCP checksum",
    "dataset": "f5.afm",
    "kind": "event",
    "original": "CEF:0|F5|Advanced Firewall Module|11.3.0.2790.300|Bad TCP checksum|Drop|8|dvchost=bigip-afm.lab.example dvc=10.0.0.5 rt=Sep 25 2026 14:41:09 act=Drop cn1=3083822790 cn1Label=attack_id cs1=Attack Sampled cs1Label=attack_status src= spt=52123 dst= dpt=80 cs2=/Common/external cs2Label=vlan cs3=/Common/app-vs cs3Label=virtual_name cn4=0 cn4Label=route_domain c6a2=2001:db8:10::99 c6a2Label=source_address c6a3=2001:db8:20::3 c6a3Label=destination_address",
    "type": [
      "denied"
    ]
  },
  "f5": {
    "afm": {
      "action": "Drop",
      "attack_id": 3083822790,
      "attack_name": "Bad TCP checksum",
      "attack_status": "Attack Sampled",
      "virtual_server": "/Common/app-vs",
      "vlan": "/Common/external"
    }
  },
  "network": {
    "transport": "tcp"
  },
  "observer": {
    "ip": [
      "10.0.0.5"
    ],
    "name": "bigip-afm.lab.example",
    "product": "Advanced Firewall Module",
    "vendor": "F5",
    "version": "11.3.0.2790.300"
  },
  "related": {
    "ip": [
      "2001:db8:10::99",
      "2001:db8:20::3",
      "10.0.0.5"
    ]
  },
  "source": {
    "ip": "2001:db8:10::99",
    "port": 52123
  }
}
```

## Scope and validation

The F5 External Monitoring 13.0.0 guide includes complete AFM CEF examples for Network Event `Accept`, `Open`, and `Closed`, and a Network DoS `Attack Sampled` event from BIG-IP 11.3.0. The generated CEF retains every extension key from the corresponding selected examples. IPs, virtual servers, timestamps, and attack IDs are synthetic. The guide documents `Attack Started` and `Attack Stopped` states and allowed actions, but shows a full DoS CEF line only for `Attack Sampled`; the start/stop lines are modeled from that layout and field catalog. The `11.3.0.2790.300` version reflects the DoS example; the cited IPv4 Network Event examples use another 11.3.0 build.

Both modes were generated and parsed as JSON. The five-step DoS sequence appeared only in anomaly mode. KUMA 4.2 lists F5 BIG-IP AFM CEF over Syslog; this pack preserves a CEF message body but does not add a Syslog envelope, and compatibility with its out-of-the-box normalizer has not been tested.

## References

- [F5 External Monitoring 13.0.0: AFM CEF examples, Network Event fields, and Network DoS fields](https://techdocs.f5.com/kb/en-us/products/big-ip_ltm/manuals/product/bigip-external-monitoring-implementations-13-0-0/15.html)
- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)
