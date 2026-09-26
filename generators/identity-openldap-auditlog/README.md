# OpenLDAP 2.6.15 auditlog LDIF

Generates changes from the OpenLDAP 2.6.15 `slapo-auditlog` overlay. Its native multi-line LDIF block is preserved in `event.original`; the surrounding JSON adds ECS fields for SIEM use. This is an LDAP write-audit stream, not bind, search, or authentication telemetry.

## Event Types

| Change | Background selection weight | Meaning |
| --- | ---: | --- |
| `modify` person attribute | 88% | Description, phone, title, or address update |
| `modify` `userPassword` | 5% | Routine password rotation |
| `modify` group `member` | 5% | Bounded membership add or delete |
| `add` person | 2% | New service account |

The weights and one-change-per-minute cadence are synthetic workload choices, not measured OpenLDAP rates. One directory server receives changes from three bound administrators over distinct LDAP connections. Eighty existing people and three existing service accounts form the initial directory; new service-account DNs never repeat within the supported counter range. Group additions are tracked so the same membership is not added twice without an intervening delete. The member-state list holds at most 20 pairs; the service-account selection pool holds at most 40 names.

## Anomaly Chain

After `anomaly_after_changes` ordinary records, `uid=svc-maint` creates `uid=svc-backup`, adds that DN to `cn=directory-admins`, then replaces its `userPassword`. The three successful LDIF records share the actor, originating IP, connection number, target identity, and adjacent minute timestamps. The group record's `member` value points to the new account. A detection can require a new service account to enter the privileged group and have its password rotated within a short window.

`anomaly_mode` defaults to `true` and emits this chain once. With `false`, the same candidate account is still created as an ordinary change, but the linked membership and password sequence is absent. Background uses the same actor and connection, includes independent account creation, membership changes (including occasional changes to the privileged group), and password rotations. Neither a fixed actor nor an event type identifies anomaly mode by itself. The actor's directory rights and the preexisting `ou=People`, `ou=Groups` and group entries are deployment assumptions for this synthetic instance.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include the one-time linked sequence |
| `anomaly_after_changes` | `60` | Ordinary changes before candidate creation; must be positive |
| `host_name` | `ldap01.corp.example` | Directory server host |
| `base_dn` | `dc=corp,dc=example` | Backend suffix for native header and DNs |
| `operator_dn` | `uid=svc-maint,ou=People,dc=corp,dc=example` | Bound administrator used in routine events and the chain; keep it under `base_dn` |
| `backdoor_uid` | `svc-backup` | New service account present in both modes; keep distinct from existing or routine `svc-worker-*` UIDs |
| `privileged_group` | `directory-admins` | Existing group modified by the chain and sometimes by background |

The three synthetic client IPs, ports and connection numbers are template constants. If `base_dn` changes, update `operator_dn` too. Customization must avoid a preexisting `backdoor_uid`, or the add operation would fail in a real directory.

### Output Parameters

The shipped configuration writes `output/events.json` and requires no endpoint or credentials. Replace the `file` output in a local copy when sending ECS records to a SIEM. Its `${params.*}` and `${secrets.*}` placeholders, if any, depend on that output plugin; the shipped configuration has none.

## Usage

From the `content-packs` repository root, a continuous local stream uses:

```bash
uv run --project ../eventum eventum generate --path generators/identity-openldap-auditlog/generator.yml --id openldap-auditlog --live-mode true
```

For a finite batch, copy `generator.yml` inside its generator directory, add `start` and `end` to `input[0].cron`, and run the copy with `--live-mode false --keep-order true`. A six-hour inclusive interval produces 361 records with the default one-minute cron and includes the chain.

A collector must join each native block from `# add` or `# modify` through the matching `# end ...` line and the separating blank line before parsing it. These are file records written by `slapo-auditlog`; they have no syslog envelope. The JSON `output/events.json` is Eventum's ECS wrapper, not a native OpenLDAP log file.

## Sample Output

This complete JSON event is copied from the default anomaly-on finite run. It is synthetic, not captured from a running LDAP server.

```json
{
  "@timestamp": "2026-09-25T01:01:00+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "ldap-modify",
    "category": [
      "iam"
    ],
    "kind": "event",
    "original": "# modify 1790298060 dc=corp,dc=example uid=svc-maint,ou=People,dc=corp,dc=example IP=10.24.1.11:52111 conn=1002\ndn: cn=directory-admins,ou=Groups,dc=corp,dc=example\nchangetype: modify\nadd: member\nmember: uid=svc-backup,ou=People,dc=corp,dc=example\n-\nreplace: entryCSN\nentryCSN: 20260925010100.000000Z#000062#000#000000\n-\nreplace: modifiersName\nmodifiersName: uid=svc-maint,ou=People,dc=corp,dc=example\n-\nreplace: modifyTimestamp\nmodifyTimestamp: 20260925010100Z\n-\n# end modify 1790298060\n\n",
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
      "connection_id": 1002,
      "entry_csn": "20260925010100.000000Z#000062#000#000000",
      "operation": "add",
      "peer_ip": "10.24.1.11",
      "peer_port": 52111,
      "target_dn": "cn=directory-admins,ou=Groups,dc=corp,dc=example",
      "value": "uid=svc-backup,ou=People,dc=corp,dc=example"
    }
  },
  "related": {
    "ip": [
      "10.24.1.11"
    ],
    "user": [
      "uid=svc-maint,ou=People,dc=corp,dc=example",
      "uid=svc-backup,ou=People,dc=corp,dc=example"
    ]
  },
  "source": {
    "ip": "10.24.1.11",
    "port": 52111
  },
  "user": {
    "name": "uid=svc-maint,ou=People,dc=corp,dc=example"
  }
}
```

## Source and Fidelity

The [OpenLDAP 2.6.15 LTS source archive](https://www.openldap.org/software/download/OpenLDAP/openldap-release/openldap-2.6.15.tgz) contains `doc/man/man5/slapo-auditlog.5` and `servers/slapd/overlays/auditlog.c`. The man page defines six comment-header fields: operation, epoch, backend suffix, recorded `modifiersName`, originating IP and port, and connection number. The source writes successful add/modify operations as LDIF, then a matching end comment and blank separator. It uses `modifiersName` for add/modify, falling back to the requestor DN. The generator uses the same bound identity and modifier, so it does not need the optional `# realdn:` line. The [2.6 administrator guide](https://project.openldap.org/doc/admin26/overlays.html#12.2.%20Audit%20Logging) provides a complete add example; the 2.6.15 man page provides a complete modify example.

For the selected profile, all six header fields, `dn`, `changetype`, changed attributes, operational attributes, end marker and blank separator are represented in `event.original`. The field map covers 21/21 selected add components and 15/15 selected modify components; optional `# realdn:` and `auditContext` are absent under the chosen bound-identity and entry profile. Add records include 12 selected attributes, including the operational fields in the official add example. Modify records follow the official operation/value/separator grammar and update `entryCSN`, `modifiersName` and `modifyTimestamp`. Values used here are ASCII and need no LDIF base64 value folding. Synthetic `userPassword` values are correctly formed SSHA digest-plus-salt values derived from synthetic strings; they are not credentials for a real directory. `ldap.auditlog` is a parsed convenience namespace, not a second native format.

**Runtime capture gap:** the format and field order are grounded in the exact 2.6.15 source and man page, but no raw output from a running 2.6.15 daemon was available. The PR remains draft until the configuration, operational-attribute ordering, multi-line collection and SIEM parser are checked against a live capture. The [OpenLDAP 2.6 release page](https://www.openldap.org/software/download/) identifies 2.6.15 as its current LTS release at the time of this audit.
