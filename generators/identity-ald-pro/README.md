# ALD Pro Domain Controller Audit Generator

Produces ECS JSON events carrying native MIT KDC, 389 Directory Server access, and extended audit records from an ALD Pro domain controller. The source layout and raw record syntax follow the [ALD Pro SIEM integration guide](https://www.aldpro.ru/integrations/item/kaspersky-kuma). The JSON envelope includes parsed fields for correlation; `event.original` preserves the source-style line or LDIF change record. Nine native event shapes are emitted by 11 FSM templates plus one shared rendering macro.

## Event Types

| Event | Baseline frequency | Category | Source |
|---|---:|---|---|
| AS_REQ ISSUE (TGT) | 55% | Authentication | MIT KDC `/var/log/auth.log` |
| TGS_REQ ISSUE (service ticket) | 39% | Authentication | MIT KDC `/var/log/auth.log` |
| AS_REQ PREAUTH_FAILED | 6% | Authentication | MIT KDC `/var/log/auth.log` |
| GSSAPI BIND and RESULT | Chain only | Authentication | 389 DS `access` |
| Group MOD, RESULT, and audit change | Chain only | IAM | 389 DS `access` and `audit` |
| SUDO rule MOD, RESULT, and audit change | Chain only | IAM | 389 DS `access` and `audit` |

Baseline weights are synthetic defaults, not measured ALD Pro production rates. The FSM emits one 13-event anomaly chain after every 300 routine events when `anomaly_mode` is `true`.

## Anomaly Chain

Four `AS_REQ PREAUTH_FAILED` records for different principals arrive from `10.99.8.42`. The same address then obtains a TGT for `helpdesk.admin`. A GSSAPI LDAP bind succeeds on one 389 DS connection. That connection adds `svc_sync` to the `admins` group, then changes the `maintenance` SUDO rule to `cmdCategory: all`. Each LDAP modify has matching `conn`/`op` request and result records plus an LDIF audit record with the actor DN and changed attribute. The SUDO audit record is modeled from ALD Pro's documented SUDO storage and the FreeIPA schema; the vendor integration guide does not publish this exact example.

Detection ideas: password spraying across principals from one IP followed by a successful TGT; successful TGT followed by a GSSAPI bind and privileged group membership change; a privileged group addition followed by broadening a SUDO rule. Join KDC events on source IP and principal, LDAP access records on `conn`/`op`, and LDAP audit records on actor DN and target DN. The audit record does not carry the LDAP connection ID, so match it to the access record by target and time. Set `anomaly_mode: false` for background-only generation; this removes every attack-chain step.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
|---|---|---|
| `dc_host` | `dc-1.lab.example` | Domain controller hostname |
| `realm` | `LAB.EXAMPLE` | Kerberos realm |
| `base_dn` | `dc=lab,dc=example` | LDAP suffix |
| `directory_instance` | `LAB-EXAMPLE` | 389 DS instance name in log paths |
| `attack_ip` | `10.99.8.42` | Correlated chain client IP |
| `compromised_user` | `helpdesk.admin` | Account that succeeds after failed attempts |
| `added_user` | `svc_sync` | Account added to the privileged group |
| `privileged_group` | `admins` | Group modified in the chain |
| `sudo_rule` | `maintenance` | Rule broadened in the chain |
| `anomaly_mode` | `true` | Emit the chain; `false` emits only background |
| `ecs_version` | `8.11.0` | ECS version in the normalized envelope |

Routine principals and client hosts are in `samples/principals.json`.

### Output Parameters

The shipped generator writes `output/events.json` and needs no output parameters or secrets. To send records to OpenSearch, replace the `output` block with an output plugin and provide the corresponding substitution values, for example:

```yaml
output:
  - opensearch:
      hosts:
        - ${params.opensearch_host}
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: ${params.opensearch_index}
```

| Placeholder | Purpose |
|---|---|
| `${params.opensearch_host}` | OpenSearch URL |
| `${params.opensearch_user}` | User name |
| `${secrets.opensearch_password}` | Password from the Eventum keyring |
| `${params.opensearch_index}` | Target index |

## Usage

Run from the content-packs repository root:

```bash
# Batch mode
eventum generate --path generators/identity-ald-pro/generator.yml --id ald-pro --live-mode false

# Live mode, five events per second
eventum generate --path generators/identity-ald-pro/generator.yml --id ald-pro --live-mode true
```

The batch command runs continuously until interrupted. Change the `anomaly_mode` parameter to `false` to generate only routine Kerberos events.

## Sample Output

This complete event was copied from a generator run:

```json
{"@timestamp": "2026-09-25T10:37:58+00:00", "agent": {"type": "eventum"}, "aldpro": {"dirsrv": {"audit": {"attribute": "member", "attribute_operation": "add", "attribute_value": "uid=svc_sync,cn=users,cn=accounts,dc=lab,dc=example", "changetype": "modify", "dn": "cn=admins,cn=groups,cn=accounts,dc=lab,dc=example", "entryusn": 100001, "modifiersname": "uid=helpdesk.admin,cn=users,cn=accounts,dc=lab,dc=example", "modifytimestamp": "20260925103758Z", "result": 0, "time": "20260925103758"}}}, "ecs": {"version": "8.11.0"}, "event": {"action": "modify-member", "category": ["iam"], "dataset": "aldpro.dirsrv_audit", "kind": "event", "module": "aldpro", "original": "time: 20260925103758\ndn: cn=admins,cn=groups,cn=accounts,dc=lab,dc=example\nresult: 0\nchangetype: modify\nadd: member\nmember: uid=svc_sync,cn=users,cn=accounts,dc=lab,dc=example\n-\nreplace: modifiersname\nmodifiersname: uid=helpdesk.admin,cn=users,cn=accounts,dc=lab,dc=example\n-\nreplace: modifytimestamp\nmodifytimestamp: 20260925103758Z\n-\nreplace: entryusn\nentryusn: 100001\n-", "outcome": "success", "type": ["change"]}, "host": {"name": "dc-1.lab.example"}, "log": {"file": {"path": "/var/log/dirsrv/slapd-LAB-EXAMPLE/audit"}}, "message": "time: 20260925103758\ndn: cn=admins,cn=groups,cn=accounts,dc=lab,dc=example\nresult: 0\nchangetype: modify\nadd: member\nmember: uid=svc_sync,cn=users,cn=accounts,dc=lab,dc=example\n-\nreplace: modifiersname\nmodifiersname: uid=helpdesk.admin,cn=users,cn=accounts,dc=lab,dc=example\n-\nreplace: modifytimestamp\nmodifytimestamp: 20260925103758Z\n-\nreplace: entryusn\nentryusn: 100001\n-", "related": {"user": ["helpdesk.admin", "svc_sync"]}, "user": {"domain": "LAB.EXAMPLE", "name": "helpdesk.admin"}}
```

## Source and Scope

The [ALD Pro SIEM guide](https://www.aldpro.ru/integrations/item/kaspersky-kuma) documents the raw KDC `AS_REQ`/`TGS_REQ` results, 389 DS `BIND`/`MOD`/`RESULT` records, and LDIF audit changes. Its Windows event numbers label analogous detection scenarios; they are not emitted ALD Pro event codes. The 389 DS `access` log is enabled by default; the extended `audit` log must be enabled to collect attribute-level changes. OS `auditd`, Samba, DNS, and ALD Pro UI audit are separate sources and are outside this generator.

The [ALD Pro SUDO policy guide](https://www.aldpro.ru/professional/ALD_Pro_Module_06a/ALD_Pro_group_policy.html) documents rules under `cn=sudorules,cn=sudo` and `--cmdcat=all`. The [FreeIPA SUDO schema](https://www.freeipa.org/page/SUDO_Schema_Design) defines `cmdCategory`. A source-specific Elastic ALD Pro `sample_event.json` was not found. Validation covered all 31 selected native fields from the vendor's KDC, access, and audit examples, mapped to ECS or `aldpro.*`; the metric is not coverage of all ALD Pro logs or Elastic integration fields.
