# ESET PROTECT On-Prem CEF events

Generates ECS JSON containing a bare CEF event in `event.original` for ESET PROTECT On-Prem 11.1.20.0. The modeled log categories are Firewall, HIPS, and Threat. ESET PROTECT sends these categories to a configured Syslog server when export is enabled; the shipped generator writes a local JSON file.

## Event types

The `any` template selects independent background events using a synthetic 45/30/25 mix. These weights are for SIEM demonstrations, not measured ESET production rates. At one event every five minutes, the generator emits 288 records per simulated day across 48 fictional Windows endpoints.

| CEF category | Background weight | ECS category | Modeled event |
| --- | ---: | --- | --- |
| `ESET Firewall Event` | 45% | network | TCP port-scan detection blocked |
| `ESET Threat Event` | 30% | malware | File threat cleaned by deleting |
| `ESET HIPS Event` | 25% | intrusion_detection | Suspicious executable launch blocked |

The 11.1 vendor CEF reference supplies real raw examples and field definitions for these categories. The generator includes their sample fields, with varying endpoint, file, user, source IP, and port values. The exact background frequencies and detection names are synthetic.

## Anomaly Chain

`anomaly_mode` defaults to `true`. After 80 routine records, the generator emits one four-event episode on a sampled endpoint: three HIPS blocks for the same executable path, five minutes apart, followed five minutes later by a Threat event that cleans a file at that path. The HIPS application is Explorer, and the endpoint remains the same through the episode. A retrying launcher or repeated delivery could produce this pattern; the records alone do not prove persistence.

A detection rule can join the endpoint `deviceExternalId`, compare HIPS `cs5` to the path in Threat `filePath` after decoding the file URI, and require the three blocks and one cleanup within 15 minutes. `cs8` is present only in the Threat event, so it is not a cross-event join key.

The chain occurs once per generator run. Subsequent events use the background mix. With `anomaly_mode: false`, only independent background events are emitted. Both modes draw endpoint IDs, paths, user names, and hashes from the same samples; no one event value marks the anomaly mode.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`.

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include one HIPS-to-threat episode |
| `anomaly_interval_events` | `80` | Routine records before the episode |
| `protect_version` | `11.1.20.0` | On-Prem server build in the CEF header |
| `protect_host` | `protect-01.example.test` | Management-server name in normalized ECS fields |

The endpoints and files are in `samples/`. The ESET 11.1.20.0 build is listed in the vendor's version catalog. Changing the version does not change this pack's 11.1 CEF field profile.

### Output Parameters

The shipped configuration writes `output/events.json` and needs no top-level parameters or secrets. To send records to a backend, replace the file output and declare top-level `params` for its endpoint and `secrets` for credentials. Top-level `${params.name}`/`${secrets.name}` substitutions are separate from `event.template.params`.

## Usage

Run from the content-packs root:

```bash
# Bounded accelerated sample. Exit 124 is expected when timeout stops it.
timeout 2 eventum generate --path generators/security-eset-protect/generator.yml --id eset-sample --live-mode false

# Wall-clock stream: one event on each five-minute tick.
eventum generate --path generators/security-eset-protect/generator.yml --id eset-live --live-mode true
```

## Sample output

Copied from an anomaly-mode validation run; the CEF payload is the `event.original` value.

```json
{
  "@timestamp": "2026-09-25T23:50:00+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "kind": "alert",
    "module": "eset",
    "dataset": "eset.protect",
    "code": "183",
    "action": "Cleaned by deleting",
    "category": [
      "malware"
    ],
    "type": [
      "info"
    ],
    "severity": 5,
    "original": "CEF:0|ESET|Protect|11.1.20.0|183|File scanner cleaned a virus|5|dvc=10.20.1.41 dvchost=ws-sales-01 deviceExternalId=e88ea65e-c3ba-4df7-83ad-d96c51022096 ESETProtectDeviceGroupName=All/Workstations ESETProtectDeviceOsName=Microsoft Windows 11 Pro ESETProtectDeviceGroupDescription=Workstations rt=Sep 25 2026 23:50:00 cat=ESET Threat Event cs1=Win32/Injector.ABC cs1Label=Threat Name cs2=29000 (20260925) cs2Label=Engine Version cs3=Virus cs3Label=Threat Type cs4=Real-time file system protection cs4Label=Scanner ID cs5=virlog.dat cs5Label=Scan ID act=Cleaned by deleting fileType=File filePath=file:///C:/Users/Public/Downloads/update-helper.exe cn1=1 cn1Label=Handled suser=EXAMPLE\\\\sales01 sprod=C:\\\\Windows\\\\explorer.exe cs7=Event occurred on a newly created file cs7Label=Circumstances deviceCustomDate1=Sep 25 2026 23:50:00 deviceCustomDate1Label=FirstSeen cs8=6a7854893797b375f63a0c7c41d1f8a9945eec36 cs8Label=Hash"
  },
  "host": {
    "name": "ws-sales-01",
    "id": "e88ea65e-c3ba-4df7-83ad-d96c51022096",
    "ip": [
      "10.20.1.41"
    ],
    "os": {
      "name": "Microsoft Windows 11 Pro"
    }
  },
  "observer": {
    "name": "protect-01.example.test",
    "product": "Protect",
    "vendor": "ESET",
    "version": "11.1.20.0"
  },
  "eset": {
    "protect": {
      "category": "threat",
      "class_id": "183",
      "action": "Cleaned by deleting"
    }
  },
  "related": {
    "ip": [
      "10.20.1.41"
    ],
    "user": [
      "EXAMPLE\\sales01"
    ],
    "hash": [
      "6a7854893797b375f63a0c7c41d1f8a9945eec36"
    ]
  },
  "file": {
    "path": "C:\\Users\\Public\\Downloads\\update-helper.exe",
    "hash": {
      "sha1": "6a7854893797b375f63a0c7c41d1f8a9945eec36"
    }
  },
  "user": {
    "name": "EXAMPLE\\sales01"
  }
}
```

## Fidelity and references

The CEF header and category-specific keys follow the ESET PROTECT On-Prem 11.1 reference. Windows paths in CEF extensions use escaped backslashes; Threat `filePath` is a file URI. The output is ECS JSON containing a bare CEF payload, not a complete network Syslog frame. The normalized ECS envelope, traffic rate, sample detections, fixed engine number, and endpoint inventory are synthetic.

The On-Prem 11.1 reference is internally inconsistent for the firewall class ID: it lists the firewall range as 200–299 but shows `109` in its firewall example. The generator uses `209`, consistent with that range and an ESET Protect Cloud CEF example; the exact On-Prem 11.1 firewall ID remains unverified. The vendor examples also print `CEF:O` with the letter O, while CEF version zero is `CEF:0`. The generator emits `CEF:0`.

- [ESET PROTECT On-Prem 11.1 CEF fields and raw examples](https://help.eset.com/protect_admin/11.1/en-US/events_exported_to_cef_format.html)
- [ESET PROTECT On-Prem 11.1 Syslog export settings](https://help.eset.com/protect_admin/11.1/en-US/admin_server_settings_export_to_syslog.html)
- [ESET On-Prem build versions](https://help.eset.com/latestVersions/)
- [ESET Protect Cloud firewall example showing class ID 209](https://help.eset.com/protect_cloud/en-US/events_exported_to_cef_format.html)
- [KUMA 4.2 ESET PROTECT 11.0 CEF normalizer list](https://support.kaspersky.ru/kuma/4.2/255782)

KUMA's listed normalizer targets 11.0; parsing this 11.1 bare CEF payload or its Syslog-wrapped form has not been verified against KUMA.
