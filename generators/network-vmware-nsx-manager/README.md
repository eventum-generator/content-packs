# VMware NSX Manager audit syslog

Synthetic NSX Manager `ACCESS_CONTROL` login records in the `nsx@6876` syslog form published by Broadcom.

## Event Types

| Action | Baseline frequency | Category |
| --- | ---: | --- |
| `login-success` - routine administrator login | 80% of routine picks | Authentication |
| `login-failure` then `login-success` - Skyline service pair | 20% of routine picks | Authentication |
| Four `login-failure` records then `login-success` for `admin` | Chain only | Authentication |

The weights are synthetic assumptions. Broadcom documents a real Skyline collector behavior in which one failed login is immediately followed by a success; that pair is included as ordinary background.

## Anomaly Chain

Four failed `ACCESS_CONTROL` logins for `admin` from `192.0.2.91` are followed by a success from the same client on the same manager. A SIEM rule can distinguish this burst from the routine Skyline failure-success pair using the count, account, source IP and short time window. Sort by `@timestamp` when matching the sequence; file line order is not guaranteed. The records prove authentication outcomes, not what the account did after login. A login retry burst is suspicious context, not proof of compromise.

`anomaly_mode` defaults to `true`. Set `event.template.params.anomaly_mode: false` for only routine administrator logins and Skyline pairs.

## Parameters

### Event Parameters

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include the correlated administrator retry burst |
| `manager_host` | `nsx-mgr-01` | NSX Manager hostname |
| `admin_user` | `admin` | Account in the anomaly chain |
| `suspect_ip` | `192.0.2.91` | Client IP in the anomaly chain |
| `skyline_user` | `skyline-svc` | Routine integration account |
| `skyline_ip` | `10.20.5.20` | Routine integration client IP |

### Output Parameters

The shipped config writes `output/events.json` and needs no connection parameters or secrets. For SIEM delivery, replace the file output in a local copy and configure `${params.siem_host}` and `${secrets.siem_token}` for the selected output plugin where applicable.

## Usage

```bash
eventum generate --path generators/network-vmware-nsx-manager/generator.yml --id nsx --live-mode false
eventum generate --path generators/network-vmware-nsx-manager/generator.yml --id nsx --live-mode true
```

## Sample Output

This event was copied from a generator run with `anomaly_mode: true`.

```json
{
  "@timestamp": "2026-09-25T13:08:37+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "login-success",
    "category": [
      "authentication"
    ],
    "kind": "event",
    "original": "2026-09-25T13:08:37.000Z nsx-mgr-01 NSX 21593 SYSTEM [nsx@6876 audit=\"true\" comp=\"nsx-manager\" level=\"INFO\" subcomp=\"http\"] UserName=admin@192.0.2.91, ModuleName=\"ACCESS_CONTROL\", Operation=\"LOGIN\", Operation status=\"success\"",
    "outcome": "success",
    "type": [
      "start"
    ]
  },
  "host": {
    "name": "nsx-mgr-01"
  },
  "log": {
    "file": {
      "path": "/var/log/syslog"
    },
    "level": "info"
  },
  "related": {
    "ip": [
      "192.0.2.91"
    ],
    "user": [
      "admin"
    ]
  },
  "source": {
    "ip": "192.0.2.91"
  },
  "user": {
    "name": "admin"
  },
  "vmware": {
    "nsx": {
      "component": "nsx-manager",
      "module_name": "ACCESS_CONTROL",
      "operation": "LOGIN",
      "operation_status": "success",
      "subcomponent": "http"
    }
  }
}
```

## Coverage and Limits

The selected Broadcom example exposes the timestamp, hostname, app, process ID, syslog message ID, `nsx@6876` structured data, username and source IP, module, operation and status; all 10 selected groups are preserved in `event.original`. ECS extracts the host, user, client and outcome. The unquoted `UserName=admin@IP` form follows Broadcom's 2022 NSX-T sample; other releases may quote the value or use LDAP user detail strings. Broadcom says successful `LOGIN` events are suppressed in NSX 4.2.x and 9.0.x by a product defect, so this failure-to-success pattern is for pre-4.2 behavior and must not be assumed visible on affected versions. The cited 2022 article does not identify a minor NSX release; parser compatibility must be checked against the actual deployment.

This pack uses NSX Manager syslog, not ESXi `hostd.log`. It is an adjacent high-value SIEM source but is not listed as a dedicated VMware NSX normalizer in the KUMA 4.2 catalog.

## References

- [Broadcom 2022 NSX Manager failure-success syslog examples](https://knowledge.broadcom.com/external/article/318390/skyline-collector-nsxt-endpoints-cause-f.html)
- [Broadcom NSX Manager audit record fields](https://knowledge.broadcom.com/external/article/323547/nsx-manager-audit-logs-not-showing-sourc.html)
- [Broadcom successful LOGIN omission in NSX 4.2.x and 9.0.x](https://knowledge.broadcom.com/external/article/399588)
- [KUMA 4.2 supported source catalog](https://support.kaspersky.ru/kuma/4.2/255782)
