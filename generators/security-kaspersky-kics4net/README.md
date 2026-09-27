# Kaspersky Industrial CyberSecurity for Networks 4.2 CEF events

Synthetic Kaspersky Industrial CyberSecurity for Networks (KICS for Networks) 4.2 events for SIEM detection engineering and parser testing in industrial (OT) networks. The generator covers the Asset Management events that KICS registers when it sees new devices and address changes in traffic, and the Intrusion Detection events for ARP spoofing signs. Each record follows the EventMessage structure that KICS sends to a SIEM system in CEF. Eventum writes ECS JSON and places the CEF line in `event.original`.

## Event Types Covered

| KICS event type | Event title (CEF `name`) | Technology | Share | ECS `event.category` |
| --- | --- | --- | --- | --- |
| `4000005003` | New device detected on network | Asset Management | 22.6% | `host` |
| `4000005007` | New device IP address detected | Asset Management | 18.5% | `host` |
| `4000005009` | IP address added to the device | Asset Management | 9.0% | `host` |
| `4000005008` | MAC address added to the device | Asset Management | 1.6% | `host` |
| `4000005010` | New device MAC address detected | Asset Management | 1.7% | `host` |
| `4000005005` | IP address conflict detected | Asset Management | 17.9% | `network` |
| `4000004001` | Symptoms of ARP spoofing detected in ARP replies | Intrusion Detection | 20.2% | `intrusion_detection`, `network` |
| `4000004002` | Symptoms of ARP spoofing detected in ARP requests | Intrusion Detection | 8.4% | `intrusion_detection`, `network` |

Shares were measured over four and a half synthetic days of the default configuration (about 240 events per day). Rates and shares are scenario assumptions, not Kaspersky measurements.

The monitored plant has three subnets, each seen by one monitoring point: two production cells (`10.20.30.0/24`, `10.20.31.0/24`) with PLCs, HMIs and switches, and a SCADA subnet (`10.20.40.0/24`) with SCADA and historian servers, engineering workstations and gateways. The 60 known devices are listed in `samples/assets.csv`, and nine of them are redundant pairs with a backup MAC address. The 36 transient devices in `samples/transients.csv` are engineering, contractor and diagnostic laptops that come and go. All addresses are RFC 1918, MAC addresses are random within vendor prefixes, and all names are synthetic.

Three kinds of independent processes produce the events. Gaps between events of each device are random and skewed, and each device has its own activity level.

- **Transient devices** visit the network mostly from 05:00 to 16:00 UTC. On a visit, a device that was removed from the devices table is detected again as a new device, usually with a DHCP address, sometimes with the static IP of an existing device, which then conflicts one to three times within minutes. A known device gets a new or an additional DHCP address. Sometimes a known device is misconfigured with the IP of an existing device: it conflicts, sends ARP traffic for that IP a few minutes later, or both. Each laptop has a service profile of three device IPs it is usually misconfigured with.
- **Known devices** occasionally get an additional IP or MAC address or a new IP address (a secondary interface or a replaced module).
- **Redundant pairs** fail over around the clock: the backup takes over the shared IP (ARP spoofing signs, often with an IP conflict) and the primary takes it back tens of minutes later.

ARP spoofing signs come in bursts that share one `attackStartTimestamp`, and the target (`targetIpAddress`) is an HMI, server, workstation or gateway in the same subnet as the claimed IP. The score adds the device's importance (PLCs highest) to a per-type base score, and the severity follows the documented bands.

## Anomaly Chain

With `anomaly_mode: true` (the default), the generator adds a recurring episode in which a device appears and impersonates an existing one:

1. **New device**: a transient device is detected as a new device (`4000005003`) with the IP of an existing device X.
2. **IP conflict**: usually one to a few minutes later, KICS registers an IP address conflict (`4000005005`) on X: the owner is X's known MAC, the challenger is the new device. Sometimes the conflict repeats within minutes.
3. **ARP spoofing**: a few minutes later, the new device sends spoofed ARP for X (`4000004001` or `4000004002`) to a host in X's subnet, often as a burst of several events.

The measured episodes spanned 2 to 19 minutes; the first ARP event always follows the new-device event within 50 minutes.

**Linking fields**: the sender MAC (`smac`, `source.mac`), equal to `ownerMac` of step 1 and `challengerMac` of step 2; the claimed IP (`src`, `source.ip`), equal to `ownerIp` of steps 1 and 2 and `substitutedIpAddress` of step 3.

**Recurrence**: the first episode is due one hour after the generator starts. Each next episode is due `anomaly_interval_hours` (default 24, minimum 3) after the actual start of the previous one. It starts after a random delay of up to one hour, or up to one eighth of the interval when that is shorter, and then waits for a time of day at which transient devices visit (most episodes start in working hours, a few at night). Episodes are scheduled on event time. A missed episode is not caught up.

**Variation**: each episode picks another transient device and another impersonated IP than the previous one, the IP from that device's service profile. The target is drawn like ordinary ARP targets, and the gaps follow the ordinary distributions. The device continues its ordinary activity during the episode. KICS registers no event when a conflict or ARP spoofing ends, so the episode has no closing record.

**Background**: every part of the episode also occurs in ordinary traffic in both modes: all devices, IPs and targets; a laptop detected as new with the IP of an existing device, followed by conflicts; a known laptop conflicting with an existing device and then sending ARP for its IP; repeated conflicts and ARP bursts; failovers of redundant pairs. Only the complete sequence (new device with IP X, conflict on X challenged by the same MAC, ARP spoofing signs for X from that MAC, within one hour) is absent from the background: an ordinary ARP event that would complete it is given another IP of the same subnet. With `anomaly_mode: false` the generator produces this background only.

**Detection idea**: per `smac`, alert when a new device is detected with IP X, then challenges X in an IP address conflict, and then shows ARP spoofing signs for X within one hour. It suggests that an unknown device took over an existing device's address and redirects its traffic. Each step alone is common in an OT network with laptops and redundant controllers.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`.

| Name | Default | Description |
| --- | --- | --- |
| `anomaly_mode` | `true` | Add the recurring new device, IP conflict, ARP spoofing episode. `false` produces background only. |
| `anomaly_interval_hours` | `24` | Hours from the start of one episode to the time the next is due. Range 3-8760. |
| `server_host` | `10.20.40.5` | KICS for Networks Server address (`hostname`). |
| `device_version` | `4.2.0.335` | KICS for Networks version in the CEF header. |

### Output Parameters

The shipped `generator.yml` writes to a local file and needs no top-level `params` or `secrets`. To send events to a backend, replace `output` and reference top-level placeholders, for example:

```yaml
output:
  - opensearch:
      hosts:
        - ${params.opensearch_host}
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: kaspersky-kics-networks
```

A CEF collector needs the `event.original` line rather than the ECS JSON document.

## Usage

```bash
# Batch: generate as fast as possible
eventum generate --path generators/security-kaspersky-kics4net/generator.yml --id kics4net --live-mode false

# Live: events at their event times
eventum generate --path generators/security-kaspersky-kics4net/generator.yml --id kics4net --live-mode true
```

Events are written to `generators/security-kaspersky-kics4net/output/events.json`.

## Sample Output

The ARP spoofing step of an anomaly episode from a default-configuration run:

```json
{"@timestamp": "2026-09-26T04:29:46.124+00:00", "destination": {"ip": "10.20.30.26", "mac": "00-1B-1B-3D-E3-8D"}, "ecs": {"version": "8.17.0"}, "event": {"action": "Symptoms of ARP spoofing detected in ARP replies", "category": ["intrusion_detection", "network"], "code": "4000004001", "dataset": "kaspersky.kics_networks", "kind": "alert", "original": "CEF:0|Kaspersky Lab|Kaspersky Industrial CyberSecurity for Networks|4.2.0.335|4000004001|Symptoms of ARP spoofing detected in ARP replies|6|dateTime=2026-09-26T04:29:46.124Z hostname=10.20.40.5 messageType=Event score=7.5 dmac=00:1b:1b:3d:e3:8d dst=10.20.30.26 smac=00:21:cc:44:78:79 src=10.20.30.15 start=2026-09-26T04:29:46.200Z technology=Intrusion Detection protocol=ARP monitoringPoint=MP-CellA-SPAN eventIdentifier=3926816 substitutedIpAddress=10.20.30.15 targetIpAddress=10.20.30.26 attackStartTimestamp=2026-09-26T04:29:46.124Z srcAssetName=ENG-LT01 srcVendor=Lenovo srcOS=Windows 10 Enterprise dstAssetName=HMI-A03 dstVendor=Siemens dstOS=WinCC Unified", "risk_score": 7.5, "severity": 6, "type": ["indicator"]}, "kaspersky": {"kics_networks": {"event_identifier": 3926816, "message_type": "Event", "monitoring_point": "MP-CellA-SPAN", "score": 7.5, "substituted_ip": "10.20.30.15", "target_ip": "10.20.30.26", "technology": "Intrusion Detection"}}, "observer": {"hostname": "10.20.40.5", "product": "Kaspersky Industrial CyberSecurity for Networks", "vendor": "Kaspersky Lab", "version": "4.2.0.335"}, "related": {"ip": ["10.20.30.15", "10.20.30.26"]}, "source": {"ip": "10.20.30.15", "mac": "00-21-CC-44-78-79"}}
```

## Limitations

- Kaspersky publishes the EventMessage field table but no complete raw record. The header values (`CEF:0|Kaspersky Lab|Kaspersky Industrial CyberSecurity for Networks|<version>|<event type>|<title>|<severity>|`) follow the table; `dateTime`, `hostname`, `messageType` and `score`, which the table lists outside the extension, are written as the first extension keys. Key order, value formats of `technology`, MAC addresses and `start`, and the absence of a syslog header are assumptions; byte parity with a live KICS installation is not established.
- Event titles are the event type names; installations may show other titles. Base scores are synthetic; only the score-to-severity bands (3, 6, 9) are documented.
- Only Asset Management address events and ARP spoofing signs are covered. Process Control, Intrusion Detection rules, Command Control, PLC project events, application messages and audit messages are outside this pack. Optional common fields (`cnt`, `end`, ports, `vlanId`, `triggeredRule`, industrial addresses, device network name and model) are not generated.
- The default output is a file with ECS JSON; KICS sends CEF through a SIEM connector. KUMA 4.2 lists a syslog normalizer for KICS for Networks 4.2; compatibility with it is not established.
- Rates, shares, device pools and the service-profile behaviour are scenario assumptions.
- A background ARP spoofing burst that would complete the chain claims a different IP, picked per record. About once per 36 capture-days this leaves a conflict on one IP followed by ARP spoofing for another IP inside the hour, and a burst can carry several substituted IPs under one attack start. At an 8 h interval about 30% of episodes start at night against about 14% of background activity.

## References

- [KICS for Networks 4.2: Format of messages forwarded to a SIEM system](https://support.kaspersky.com/KICSforNetworks/4.2/en-US/283821.htm)
- [KICS for Networks 4.2: Event types in Kaspersky Security Center](https://support.kaspersky.com/KICSforNetworks/4.2/en-us/177537.htm)
- [KICS for Networks 4.2: Scores and severities of events](https://support.kaspersky.com/KICSforNetworks/4.2/en-US/104097.htm)
- [KICS for Networks 4.2: Event registration technologies](https://support.kaspersky.com/KICSforNetworks/4.2/en-US/152004.htm)
- [KICS for Networks 4.2: Asset Management methods and modes](https://support.kaspersky.com/KICSforNetworks/4.2/en-US/177331.htm)
- [KUMA 4.2: Supported sources](https://support.kaspersky.ru/kuma/4.2/255782)
