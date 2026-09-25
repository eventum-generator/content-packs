# OpenLDAP auditlog.ldif

Synthetic change records from the OpenLDAP `slapo-auditlog` overlay. Each ECS JSON event retains the native multiline LDIF record in `event.original`.

## Event Types

| Change | Baseline frequency | Meaning |
| --- | ---: | --- |
| `modify` of description | 40% | Routine account metadata edit |
| `modify` of telephoneNumber | 25% | Routine contact edit |
| `modify` of title | 20% | Routine role label edit |
| `modify` of mail | 15% | Routine address edit |
| `add` user / `modify` group and password | Chain only | Privileged account establishment |

The baseline weights are synthetic assumptions. The FSM inserts a three-record sequence after routine changes when anomaly mode is enabled.

## Anomaly Chain

The same `uid=svc-maint` actor creates `uid=svc-backup`, adds that DN to `cn=directory-admins`, then replaces the new account's `userPassword`. The target DN links the first and third records; the group record's `member` value points to that same DN. A detection rule can flag a newly created account entering a privileged group followed by a password change. The generated LDIF also carries `modifiersName`, `modifyTimestamp`, and `entryCSN` for correlation.

`anomaly_mode` defaults to `true`. Set it to `false` in `event.template.params` for ordinary metadata edits only.

## Parameters

### Event Parameters

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include the three-change chain |
| `host_name` | `ldap01.corp.example` | Directory server name |
| `base_dn` | `dc=corp,dc=example` | Synthetic directory suffix |
| `operator_dn` | `uid=svc-maint,ou=People,dc=corp,dc=example` | Actor in the chain |
| `backdoor_uid` | `svc-backup` | Account created in the chain |
| `privileged_group` | `directory-admins` | Group modified in the chain |

### Output Parameters

The shipped configuration writes `output/events.json` and needs no connection parameters or secrets. To use a SIEM output, replace the `file` output in a local copy and pass its endpoint and credentials through `${params.siem_host}` and `${secrets.siem_token}` placeholders.

## Usage

```bash
eventum generate --path generators/identity-openldap-auditlog/generator.yml --id openldap-auditlog --live-mode false
eventum generate --path generators/identity-openldap-auditlog/generator.yml --id openldap-auditlog --live-mode true
```

## Sample Output

This event was copied from a real generator run.

```json
{
  "@timestamp": "2026-09-25T12:21:25+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "ldap-modify",
    "category": [
      "iam"
    ],
    "kind": "event",
    "original": "# modify 1790338885 dc=corp,dc=example uid=svc-maint,ou=People,dc=corp,dc=example\ndn: cn=directory-admins,ou=Groups,dc=corp,dc=example\nchangetype: modify\nadd: member\nmember: uid=svc-backup,ou=People,dc=corp,dc=example\n-\nreplace: entryCSN\nentryCSN: 20260925122125.000000Z#001062#000#000000\n-\nreplace: modifiersName\nmodifiersName: uid=svc-maint,ou=People,dc=corp,dc=example\n-\nreplace: modifyTimestamp\nmodifyTimestamp: 20260925122125Z\n-\n# end modify 1790338885",
    "outcome": "success",
    "type": [
      "change"
    ]
  },
  "host": {
    "name": "ldap01.corp.example"
  },
  "ldap": {
    "auditlog": {
      "actor_dn": "uid=svc-maint,ou=People,dc=corp,dc=example",
      "attribute": "member",
      "base_dn": "dc=corp,dc=example",
      "change_type": "modify",
      "entry_csn": "20260925122125.000000Z#001062#000#000000",
      "target_dn": "cn=directory-admins,ou=Groups,dc=corp,dc=example",
      "value": "uid=svc-backup,ou=People,dc=corp,dc=example"
    }
  },
  "related": {
    "user": [
      "uid=svc-maint,ou=People,dc=corp,dc=example",
      "cn=directory-admins,ou=Groups,dc=corp,dc=example"
    ]
  },
  "user": {
    "name": "uid=svc-maint,ou=People,dc=corp,dc=example"
  }
}
```

## Coverage and Limits

The selected LDIF fields are represented in all relevant records: operation markers, target DN, change type, changed attribute and value, actor, modify timestamp, and entry CSN (8/8). Add records also include object classes, entry UUID, and create metadata. `event.original` preserves the complete synthetic LDIF. `ldap.auditlog` is a convenience extraction, not an alternate OpenLDAP wire format. The overlay records directory changes on the configured backend; it does not record binds, searches, or failed authentication. Enabling the overlay and forwarding its file are separate deployment steps. The synthetic password is a nonfunctional placeholder hash and must not be reused as a credential.

## References

- [OpenLDAP 2.5 Administrator's Guide: Audit Logging overlay](https://www.openldap.org/doc/admin25/overlays.html#12.2.%20Audit%20Logging)
- [OpenLDAP auditlog examples](https://www.openldap.org/doc/admin25/overlays.html)
