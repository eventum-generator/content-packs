# Kaspersky Industrial CyberSecurity for Networks 4.2 CEF events

Synthetic Kaspersky Industrial CyberSecurity for Networks (KICS for Networks) 4.2 events for SIEM detection engineering and parser testing in industrial (OT) networks. The generator covers the Asset Management events that KICS registers when it sees new devices and address changes in traffic, and the Intrusion Detection events for ARP spoofing signs. Each record follows the EventMessage structure that KICS sends to a SIEM system in CEF. Eventum writes ECS JSON and places the CEF line in `event.original`.

## Event Types Covered

| KICS event type | Event title (CEF `name`) | Technology | Share | ECS `event.category` |
| --- | --- | --- | --- | --- |
| `4000005007` | New device IP address detected | Asset Management | 39.5% | `host` |
| `4000005003` | New device detected on network | Asset Management | 26.0% | `host` |
| `4000005009` | IP address added to the device | Asset Management | 24.8% | `host` |
| `4000005008` | MAC address added to the device | Asset Management | 2.9% | `host` |
| `4000005005` | IP address conflict detected | Asset Management | 2.0% | `network` |
| `4000005010` | New device MAC address detected | Asset Management | 1.9% | `host` |
| `4000004001` | Symptoms of ARP spoofing detected in ARP replies | Intrusion Detection | 1.8% | `intrusion_detection`, `network` |
| `4000004002` | Symptoms of ARP spoofing detected in ARP requests | Intrusion Detection | 1.0% | `intrusion_detection`, `network` |

Shares are typical of the default configuration in both modes. Rates and shares are scenario assumptions, not Kaspersky measurements.

## Volume

About 690 records a day (+/- 3% from day to day). Laptop activity and address changes of known devices follow the plant's working day in UTC: about 13 records an hour from 19:00 to 04:00 (night shift), about 19 at 04:00 and 17:00-19:00, about 33 at 05:00 and 15:00-17:00, and about 45 from 06:00 to 15:00. Failovers of redundant pairs happen around the clock. The rate is set by the five files in `patterns/`.

## Background Model

The monitored plant has three subnets, each seen by one monitoring point: two production cells (`10.20.30.0/24`, `10.20.31.0/24`) with PLCs, HMIs and switches, and a SCADA subnet (`10.20.40.0/24`) with SCADA and historian servers, engineering workstations and gateways. The 60 known devices are listed in `samples/assets.csv`; nine of them are redundant pairs with a backup MAC address, and each device has a peer, the HMI or server that polls it (`peer`). The 54 transient devices in `samples/transients.csv` are engineering, contractor and diagnostic laptops that come and go; three of them are commissioning laptops with the IPs of the devices they service (`service_ips`). All addresses are RFC 1918, MAC addresses are random within vendor prefixes, and all names are synthetic.

- **Laptops** (about 90% of records) get a new DHCP address (`4000005007`), an additional DHCP address (`4000005009`), or are detected again as a new device after removal from the devices table (`4000005003`). Each laptop has its own activity level.
- **Commissioning laptops** come up with the IP of the device they service in about one of five appearances (mostly the first of their two service IPs). While that device is disconnected, the laptop is only registered with the IP (new device or added IP). While it is online, the laptop is either detected as a new device with the IP and then conflicts with the device one to three times within minutes, or, as a known laptop, it conflicts and/or shows ARP spoofing signs for the IP towards the device's peer. Any other laptop does this rarely, with the IP of some device.
- **Known devices** occasionally get an additional IP or MAC address or a new IP address (a secondary interface or a replaced module).
- **Redundant pairs** fail over about twice a day in total, mostly three flaky pairs: the backup takes over the shared IP (ARP spoofing signs, often with an IP conflict) and the primary takes it back tens of minutes later.

Detections are a small part of the data: about 10 ARP spoofing bursts (20 records) and 9 IP conflict incidents (14 records) a day, two thirds of them from the three commissioning laptops and a fifth from the redundant pairs. ARP spoofing signs come in bursts that share one `attackStartTimestamp`; the target (`targetIpAddress`) is usually the claimed device's peer, otherwise another HMI, server, workstation or gateway of its subnet. The score adds the device's importance (PLCs highest) to a per-type base score, and the severity follows the documented bands.

## Anomaly Chain

With `anomaly_mode: true` (the default), the generator adds a recurring episode in which a laptop appears with the address of an existing device and impersonates it:

1. **New device**: a commissioning laptop is detected as a new device (`4000005003`) with the IP of an existing device X (its main service IP).
2. **IP conflict**: usually one to ten minutes later, KICS registers an IP address conflict (`4000005005`) on X: the owner is X's known MAC, the challenger is the laptop. Sometimes the conflict repeats within minutes.
3. **ARP spoofing**: a few minutes later, one record of ARP spoofing signs (`4000004001` or `4000004002`) from the laptop for X, towards X's peer.

An episode usually spans about 2 to 20 minutes and up to about 40 minutes at night, when records are sparse; the three steps always fall within one hour.

**Linking fields**: the sender MAC (`smac`, `source.mac`), equal to `ownerMac` of step 1 and `challengerMac` of step 2; the claimed IP (`src`, `source.ip`), equal to `ownerIp` of steps 1 and 2 and `substitutedIpAddress` of step 3.

**Recurrence**: the first episode starts within `anomaly_interval_hours` (at most 24 hours) of the start of the data, at an hour drawn from the working-day curve. Each next episode is due `anomaly_interval_hours` (default 24, minimum 3) after the actual start of the previous one and starts within one eighth of the interval (at most three hours) before or after that time, favouring working hours. A missed episode is not caught up.

**Variation**: each episode uses another commissioning laptop and another IP than the previous one; the IP is the laptop's main service IP and the target is that device's peer, the same combination the laptop's ordinary ARP spoofing signs usually have. Episode records take the place of ordinary records at the same moments, so the daily volume and hour curve are the same in both modes, and the laptop's ordinary activity continues during the episode. KICS registers no event when a conflict or ARP spoofing ends, so the episode has no closing record.

**Background**: every part of the episode also occurs in ordinary data in both modes: all laptops, IPs, laptop-IP pairs and targets; a commissioning laptop detected as new with its service IP, followed by conflicts; a known laptop conflicting with the device and then sending ARP for its IP; repeated conflicts and ARP bursts; failovers of redundant pairs. Only the complete sequence (new device with IP X, conflict on X challenged by the same MAC, ARP spoofing signs for X from that MAC, within one hour) is absent from the background: an ordinary ARP spoofing burst that would complete it claims another IP of the same subnet. With `anomaly_mode: false` the generator produces this background only.

**Detection idea**: per `smac`, alert when a new device is detected with IP X, then challenges X in an IP address conflict, and then shows ARP spoofing signs for X within one hour. It suggests that an unknown device took over an existing device's address and redirects its traffic. Each step alone is common in an OT network with commissioning laptops and redundant controllers.

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

Live mode:

```bash
eventum generate --path generators/security-kaspersky-kics4net/generator.yml --id kics4net --live-mode true
```

Batch mode needs a bounded time range: set `start` and `end` of the `oscillator` in all five `patterns/*.yml` files to the same range, with `start` at 00:00 UTC so the hour bands stay in place (for example `start: "2026-09-01T00:00:00Z"` and `end: "2026-09-15T00:00:00Z"`), then run:

```bash
eventum generate --path generators/security-kaspersky-kics4net/generator.yml --id kics4net --live-mode false --keep-order true
```

Events are written to `generators/security-kaspersky-kics4net/output/events.json`.

Performance: about 2,500 records per second in batch mode (14 days, 9,700 records, in about 4 seconds).

## Sample Output

The ARP spoofing step of an anomaly episode from a default-configuration run:

```json
{"@timestamp": "2026-09-21T13:21:12.824+00:00", "destination": {"ip": "10.20.40.10", "mac": "18-66-DA-E1-D7-BD"}, "ecs": {"version": "8.17.0"}, "event": {"action": "Symptoms of ARP spoofing detected in ARP requests", "category": ["intrusion_detection", "network"], "code": "4000004002", "dataset": "kaspersky.kics_networks", "kind": "alert", "original": "CEF:0|Kaspersky Lab|Kaspersky Industrial CyberSecurity for Networks|4.2.0.335|4000004002|Symptoms of ARP spoofing detected in ARP requests|6|dateTime=2026-09-21T13:21:12.824Z hostname=10.20.40.5 messageType=Event score=7.6 dmac=18:66:da:e1:d7:bd dst=10.20.40.10 smac=f8:bc:12:48:ef:ed src=10.20.40.18 start=2026-09-21T13:21:15.491Z technology=Intrusion Detection protocol=ARP monitoringPoint=MP-SCADA-SPAN eventIdentifier=2353604 substitutedIpAddress=10.20.40.18 targetIpAddress=10.20.40.10 attackStartTimestamp=2026-09-21T13:21:12.824Z srcAssetName=ENG-LT06 srcVendor=Dell srcOS=Windows 10 Enterprise dstAssetName=SCADA-SRV01 dstVendor=Dell dstOS=Windows Server 2019", "risk_score": 7.6, "severity": 6, "type": ["indicator"]}, "kaspersky": {"kics_networks": {"event_identifier": 2353604, "message_type": "Event", "monitoring_point": "MP-SCADA-SPAN", "score": 7.6, "substituted_ip": "10.20.40.18", "target_ip": "10.20.40.10", "technology": "Intrusion Detection"}}, "observer": {"hostname": "10.20.40.5", "product": "Kaspersky Industrial CyberSecurity for Networks", "vendor": "Kaspersky Lab", "version": "4.2.0.335"}, "related": {"ip": ["10.20.40.18", "10.20.40.10"]}, "source": {"ip": "10.20.40.18", "mac": "F8-BC-12-48-EF-ED"}}
```

## Limitations

- Kaspersky publishes the EventMessage field table but no complete raw record. The header values (`CEF:0|Kaspersky Lab|Kaspersky Industrial CyberSecurity for Networks|<version>|<event type>|<title>|<severity>|`) follow the table; `dateTime`, `hostname`, `messageType` and `score`, which the table lists outside the extension, are written as the first extension keys. Key order, value formats of `technology`, MAC addresses and `start`, and the absence of a syslog header are assumptions; byte parity with a live KICS installation is not established.
- Event titles are the event type names; installations may show other titles. Base scores are synthetic; only the score-to-severity bands (3, 6, 9) are documented.
- Only Asset Management address events and ARP spoofing signs are covered. Process Control, Intrusion Detection rules, Command Control, PLC project events, application messages and audit messages are outside this pack. Optional common fields (`cnt`, `end`, ports, `vlanId`, `triggeredRule`, industrial addresses, device network name and model) are not generated.
- The default output is a file with ECS JSON; KICS sends CEF through a SIEM connector. KUMA 4.2 lists a syslog normalizer for KICS for Networks 4.2; compatibility with it is not established.
- Rates, shares, device pools, peers, service IPs and the plant's UTC working day are scenario assumptions. Laptops change addresses often (commissioning laptops about 23 to 30 records a day each), more than a quiet plant would show.
- Records that KICS registers seconds apart are further apart here: records of one ARP spoofing burst are a median 100 seconds apart (90% within 6 minutes), repeated conflicts a median 3 minutes, and at night episode steps can be up to half an hour apart.
- An ordinary ARP spoofing burst that would complete the anomaly sequence claims another IP of the same subnet, so a conflict on one IP can be followed within the hour by ARP spoofing signs from the same laptop for a neighbouring IP. This happens a few times a week.
- With `anomaly_mode: true` each episode adds one new-device, one or more conflict and one ARP spoofing record for a commissioning laptop and its main service IP, so these records are about one per episode more frequent than in `anomaly_mode: false`. At intervals shorter than a day, episodes continue around the clock, so a larger share of them falls at night than of ordinary activity.

## References

- [KICS for Networks 4.2: Format of messages forwarded to a SIEM system](https://support.kaspersky.com/KICSforNetworks/4.2/en-US/283821.htm)
- [KICS for Networks 4.2: Event types in Kaspersky Security Center](https://support.kaspersky.com/KICSforNetworks/4.2/en-us/177537.htm)
- [KICS for Networks 4.2: Scores and severities of events](https://support.kaspersky.com/KICSforNetworks/4.2/en-US/104097.htm)
- [KICS for Networks 4.2: Event registration technologies](https://support.kaspersky.com/KICSforNetworks/4.2/en-US/152004.htm)
- [KICS for Networks 4.2: Asset Management methods and modes](https://support.kaspersky.com/KICSforNetworks/4.2/en-US/177331.htm)
- [KUMA 4.2: Supported sources](https://support.kaspersky.ru/kuma/4.2/255782)
