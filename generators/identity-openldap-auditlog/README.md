# OpenLDAP 2.6.15 auditlog LDIF

Produces successful directory changes from the OpenLDAP `slapo-auditlog` overlay. Native multiline LDIF is preserved in `event.original`; ECS fields identify the server, bound administrator and client. Bind, search and failed-operation logs are outside this write-audit feed.

## Event Types

| Change | Approximate background share | Category |
| --- | ---: | --- |
| Person description, telephone, title or mail | 86% | IAM change |
| Password replacement | 5% | IAM change |
| Group membership addition or removal | 6% | IAM change |
| Temporary service-account creation | 2% | IAM creation |
| Expired service-account deletion | 2% | IAM deletion |

Rounded shares vary. About 1,980 changes/day represent one directory with 800 existing people and short-lived worker accounts. Automation operates throughout the day; volume rises from about one to 1.9 changes/minute between 08:00 and 18:00 UTC. Human administrator activity is ten times less likely outside those hours. Metadata changes dominate; password rotations, provisioning and membership changes are ordinary administration. These are synthetic workload assumptions.

Three administrators use distinct client addresses. LDAP connections receive fresh, increasing numbers and varying ephemeral ports; one connection can carry several changes. Temporary accounts live for two to four hours. Their remaining group membership is removed before account deletion. Membership additions and removals respect the current directory state. Both modes use the same lifetimes and restoration behavior.

## Anomaly Chain

`anomaly_mode: true` adds a linked sequence: an administrator creates a temporary service account, adds it to `directory-admins`, then replaces its password within 15 minutes. The account DN, administrator and client address join the three records. All three administrators can appear in episodes and ordinary work. Account prefixes and individual change types also appear in ordinary work.

The first episode begins within the first `min(anomaly_interval_hours, 24)` hours. Later starts fall within half of `min(interval / 4, 6 hours)` on either side of one interval after the preceding actual start. Placement follows the daily activity curve, with stronger daytime weighting for later starts. Missed historical episodes are not replayed. Default recurrence is two hours; the minimum is one hour.

With `anomaly_mode: false`, the complete sequence is absent. Ordinary creation, privileged-group changes and password rotation still occur. Enabled episodes add their own linked changes. The new account and its membership expire on the ordinary two-to-four-hour schedule. Other accounts continue their ordinary activity throughout.

## Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include recurring linked sequences |
| `anomaly_interval_hours` | `2` | Recurrence in hours, minimum 1 |
| `host_name` | `ldap01.corp.example` | Directory server hostname |
| `base_dn` | `dc=corp,dc=example` | Directory suffix |
| `operator_dn` | `uid=svc-maint,ou=People,dc=corp,dc=example` | Maintenance administrator DN |
| `backdoor_uid` | `svc-backup` | One account prefix shared by ordinary work and episodes |
| `privileged_group` | `directory-admins` | Existing privileged group |

Client addresses are in `samples/clients.json`. Keep `operator_dn` under `base_dn` and use ASCII DN components without LDIF-special characters. The three administrators have write rights to the modeled people and groups. The groups and organizational units already exist. Generated worker names must not collide with existing accounts.

## Usage

From the content-packs root:

```bash
eventum generate --path generators/identity-openldap-auditlog/generator.yml --id openldap --live-mode true --keep-order true
```

For a finite batch, copy the generator directory, set `oscillator.start` and `oscillator.end` in both `patterns/*.yml` files to UTC midnight boundaries, then run:

```bash
eventum generate --path /path/to/copy/generator.yml --id openldap-batch --live-mode false --keep-order true
```

The default output is `output/events.json`. Replace the file output when sending records directly to a SIEM. No secrets or endpoint parameters are required by the shipped configuration. A native LDIF collector joins records from `# add`, `# modify` or `# delete` through the matching `# end` line and the blank separator.

Performance: approximately 3,100 events/second for a four-day batch on the authoring machine.

## Sample Output

One complete synthetic event:

```json
{"@timestamp": "2026-09-20T01:26:42.938437+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "ldap-add", "category": ["iam"], "kind": "event", "original": "# add 1789867602 dc=corp,dc=example uid=svc-maint,ou=People,dc=corp,dc=example IP=10.24.1.11:46066 conn=1012\ndn: uid=svc-worker-000001,ou=People,dc=corp,dc=example\nchangetype: add\nobjectClass: top\nobjectClass: person\nobjectClass: organizationalPerson\nobjectClass: inetOrgPerson\nuid: svc-worker-000001\ncn: Service Account svc-worker-000001\nsn: Service\nuserPassword: {SSHA}6W3S5Qd7mfKOi9XaQIvaLxOeyv0wMDAwMDA4Nw==\nstructuralObjectClass: inetOrgPerson\nentryUUID: 94eb35b2-ea54-4956-bd14-4f22ba691e8f\ncreatorsName: uid=svc-maint,ou=People,dc=corp,dc=example\ncreateTimestamp: 20260920012642Z\nentryCSN: 20260920012642.938437Z#000000#000#000000\nmodifiersName: uid=svc-maint,ou=People,dc=corp,dc=example\nmodifyTimestamp: 20260920012642Z\n# end add 1789867602\n\n", "outcome": "success", "type": ["creation"]}, "host": {"name": "ldap01.corp.example"}, "ldap": {"auditlog": {"actor_dn": "uid=svc-maint,ou=People,dc=corp,dc=example", "attribute": "uid", "base_dn": "dc=corp,dc=example", "change_type": "add", "connection_id": 1012, "entry_csn": "20260920012642.938437Z#000000#000#000000", "operation": null, "peer_ip": "10.24.1.11", "peer_port": 46066, "target_dn": "uid=svc-worker-000001,ou=People,dc=corp,dc=example", "value": "svc-worker-000001"}}, "related": {"ip": ["10.24.1.11"], "user": ["uid=svc-maint,ou=People,dc=corp,dc=example", "uid=svc-worker-000001,ou=People,dc=corp,dc=example"]}, "source": {"ip": "10.24.1.11", "port": 46066}, "user": {"name": "uid=svc-maint,ou=People,dc=corp,dc=example"}}
```

## Source Fidelity and Limits

The native profile follows OpenLDAP 2.6.15 `auditlog.c`, `slap_add_opattrs` and `slapo-auditlog(5)`: operation/epoch/suffix/modifier/client/connection header, LDIF body, matching end marker and blank separator. Add operational attributes follow the server's append order. Modify records contain the requested change followed by `entryCSN`, `modifiersName` and `modifyTimestamp`. Delete records have no attribute body. CSNs include the event's microseconds and the single-server ID `000`.

The directory represents short-lived worker provisioning, not permanent account administration. Volumes, lifetimes, addresses and account details are synthetic. Individual audit changes may be tens of seconds apart. Values are ASCII without binary attributes or LDIF line folding. Password values are synthetic SSHA digest-plus-salt strings. Native epoch headers have second precision; CSNs retain microseconds.

There is no replication, failed LDAP operation, access log, `modrdn`, proxy authorization, `# realdn:` or optional `auditContext`. The bound identity equals the recorded modifier. ECS and `ldap.auditlog` are parsed context around the native block. The profile is source-derived; byte parity with a running 2.6.15 daemon and a downstream parser has not been established.

## References

- [OpenLDAP 2.6.15 source archive](https://www.openldap.org/software/download/OpenLDAP/openldap-release/openldap-2.6.15.tgz): `servers/slapd/overlays/auditlog.c`, `servers/slapd/add.c`, and `doc/man/man5/slapo-auditlog.5`.
- [OpenLDAP audit logging guide](https://project.openldap.org/doc/admin26/overlays.html#12.2.%20Audit%20Logging): overlay configuration and LDIF records.
