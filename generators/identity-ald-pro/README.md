# ALD Pro Domain Controller Audit Generator

Produces ECS JSON for selected MIT KDC, 389 Directory Server access and extended audit records from one ALD Pro domain controller. `event.original` carries the corresponding native line or multiline LDIF change record. The source profile follows the vendor's SIEM guide dated **06/10/2025**, whose examples are dated 2023/2024 without identifying installed ALD Pro or component builds.

## Event Types

| Event | Workload | Source |
|---|---|---|
| AS_REQ NEEDED_PREAUTH / ISSUE | Preauthentication challenge and successful TGT issuance | `/var/log/auth.log` |
| TGS_REQ ISSUE | Service tickets using an already observed TGT | `/var/log/auth.log` |
| AS_REQ PREAUTH_FAILED | Isolated failures and periodic password spray | `/var/log/auth.log` |
| SSL connection, TLS, UNBIND, clean disconnect | Administrative LDAP sessions | 389 DS `access` |
| GSSAPI BIND / RESULT | Three rounds: op 0/1 return err 14, op 2 succeeds | 389 DS `access` |
| MOD / RESULT | Successful changes to existing groups or SUDO rules | 389 DS `access` |
| Add / delete member LDIF | Membership changes and restoration | 389 DS `audit` |
| Replace / delete cmdCategory LDIF | SUDO activation and restoration | 389 DS `audit` |
| Replace description LDIF | Ordinary policy maintenance | 389 DS `audit` |

The selected small-domain workload averages **61,200 records/day**: 0.5 records/s overnight and about 1 record/s during 08:00-18:00 UTC+03:00. Arrival times vary within two-second baseline periods, with additional office-hour activity and a small daily volume variation. Human accounts are less active overnight; service accounts continue throughout the day. KDC traffic dominates, with about 2% failed authentication attempts. LDAP administration is sparse and more frequent during office hours. These rates are synthetic workload assumptions, not vendor production measurements.

Both modes include both administrators, both shared administrative client IPs, all event classes and ordinary changes to the same eight policy resources. Each ordinary LDAP session changes one attribute. Membership and SUDO activations last about one hour, followed by visible deletion of the added member or `cmdCategory` value. A capture can end before a pending restoration appears.

## Anomaly Chain

`anomaly_mode` defaults to `true`; `false` emits background without a complete chain. An episode contains:

1. PREAUTH_FAILED for four distinct principals from one shared client IP, approximately one minute apart.
2. Successful TGT issuance and an `ldap/<dc_host>` service ticket for the selected administrator from that IP.
3. A fresh SSL connection and three successful GSSAPI negotiation rounds, retaining the authenticated administrator DN.
4. Addition of the existing `added_user` to an existing group, followed by `cmdCategory: all` on the corresponding existing SUDO rule. Each change has a MOD request, successful RESULT and audit record.
5. Ordinary administrator sessions that remove both permissions after about one hour.

The chain completes within 15 minutes. Administrators and policy resources change between consecutive episodes. Both administrative IPs also carry ordinary activity. No anomaly label is added to the records. The first episode starts within the first 24 hours, or within the configured interval when it is shorter. Later starts vary around the configured interval, favoring office hours. The default is 24 hours with a six-hour start window; a 12-hour interval has a three-hour window. The supported minimum interval is six hours.

Detection ideas: four-principal password spray followed by TGT success, an LDAP service ticket and administrative changes from the same IP and successful principal. Join KDC records by source IP, principal and ticket `authtime`; join access records by `conn` and `op`. Audit records contain actor and target DNs but no connection ID.

## Source Profile and Limits

The inventory contains two enabled administrators, unlocked user and service principals, and eight existing group/SUDO-rule pairs. The selected service account initially belongs to none of these groups. Each SUDO rule is enabled, applies to its selected group/hosts and initially has no explicit allowed commands or command category. Setting `cmdCategory: all` enables commands; deleting that value restores the dormant rule. Its native RDN is `ipauniqueid=<uuid>`, while `cn` is its display name. The profile does not create or delete accounts, groups or rules.

The password-policy profile uses `maxfail=3` and a 120-second failure window. At most two unsuccessful attempts occur for a principal within that window before a pause; successful AS issuance resets its failure count. TGT lifetime is a synthetic eight-hour assumption. A service ticket requires a preceding TGT for the same user/IP and retains its authentication time.

The access log and `nsslapd-auditlog-logging-enabled=on` are required for the selected source records. Administrative clients connect directly through LDAP. This profile selects C-locale month names, source timezone UTC+03:00, the eight request encryption types shown in the vendor guide, and no optional audit display attributes. LDAP requests and results occupy separate record arrivals, typically about one to four seconds apart. Their `etime` equals the observed request/result duration, with `wtime + optime = etime`; this sparse workload does not reproduce subsecond LDAP throughput.

Native KDC syslog and audit `time` have second precision in UTC+03:00; access timestamps retain fractional seconds and an explicit offset. Audit `modifytimestamp` is UTC GeneralizedTime. ECS `@timestamp` is the full observation timestamp, including fractions absent from some raw records. Source IP and authenticated user on later access/audit records are enrichment from the modeled LDAP connection. Audit `object_name` is inventory enrichment for the group or rule display name.

Vendor examples establish the selected KDC, access and group-member audit grammars. SUDO LDIF is derived from FreeIPA's schema and the 389 DS serializer, rather than an exact ALD Pro SUDO capture. Tagged MIT Kerberos 1.18.3, FreeIPA 4.9.11 and 389 DS 1.4.4.20 sources support the selected semantics; those versions are not asserted to be bundled with ALD Pro. Exact release/raw parity and a matching Elastic integration remain unconfirmed. Other LDAP operations, internal user updates, OS auditd, Samba, DNS, application UI audit and Windows event IDs are outside this feed.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`. Principal/client/service inventory is in `samples/principals.json`. Keep at least three distinct ordinary principal names separate from the two administrator names. Policy resources are listed in `samples/resources.json`; the group and SUDO parameters below override its first entry. Hostnames, realms, account names and DN components use ASCII labels without quotes, backslashes, whitespace or newlines; custom suffixes/services must be consistent with the sample inventory. Supply a valid UUID for the existing SUDO rule.

| Parameter | Default | Purpose |
|---|---|---|
| `dc_host` | `dc-1.lab.example` | Source hostname and LDAP service principal host |
| `dc_ip` | `10.20.0.10` | Native LDAP connection destination |
| `realm` | `LAB.EXAMPLE` | Kerberos realm |
| `base_dn` | `dc=lab,dc=example` | Existing LDAP suffix |
| `directory_instance` | `LAB-EXAMPLE` | 389 DS instance in paths |
| `attack_ip` | `10.99.8.42` | Client shared by ordinary activity and episodes |
| `admin_ip` | `10.20.4.22` | Second ordinary administrative client |
| `compromised_user` | `helpdesk.admin` | Existing administrator shared with background |
| `routine_admin` | `directory.admin` | Second existing administrator |
| `added_user` | `svc_sync` | Existing account whose membership changes |
| `privileged_group` | `admins` | Existing group display name / DN component |
| `sudo_rule` | `maintenance` | Existing rule display name, inventory enrichment |
| `sudo_rule_uuid` | `a4a19e36-4c0c-4d2f-97aa-e7fe42aa6ae1` | Existing rule's native `ipauniqueid` RDN |
| `anomaly_interval_hours` | `24` | Recurrence, values below 6 clamp to 6 hours |
| `anomaly_mode` | `true` | Periodic episodes mixed with background; false is background only |
| `ecs_version` | `8.11.0` | ECS version |

### Output Parameters

The shipped generator writes `output/events.json` and requires no output parameters or secrets. For OpenSearch, replace the file output and supply substitutions:

```yaml
output:
  - opensearch:
      hosts: ["${params.opensearch_host}"]
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: ${params.opensearch_index}
```

| Placeholder | Purpose |
|---|---|
| `${params.opensearch_host}` | OpenSearch URL |
| `${params.opensearch_user}` | User name |
| `${secrets.opensearch_password}` | Password from Eventum keyring |
| `${params.opensearch_index}` | Target index |

## Usage

From the content-packs repository root:

```bash
uv run --project ../eventum eventum generate --path generators/identity-ald-pro/generator.yml --id ald-pro --live-mode false --keep-order true
uv run --project ../eventum eventum generate --path generators/identity-ald-pro/generator.yml --id ald-pro --live-mode true --keep-order true
```

Both commands run continuously until interrupted. For a finite batch, set ISO 8601 `oscillator.start` and `oscillator.end` in both `patterns/*.yml`, using UTC midnight boundaries for full days. Set `anomaly_mode: false` for ordinary activity. Live mode follows the source rate.

## Sample Output

A complete SUDO audit record from an anomaly-enabled run:

```json
{
  "@timestamp": "2026-09-20T01:03:03.401103+00:00",
  "aldpro": {
    "dirsrv": {
      "audit": {
        "attribute": "cmdCategory",
        "attribute_operation": "replace",
        "attribute_value": "all",
        "changetype": "modify",
        "dn": "ipauniqueid=a4a19e36-4c0c-4d2f-97aa-e7fe42aa6ae4,cn=sudorules,cn=sudo,dc=lab,dc=example",
        "entryusn": 100002,
        "modifiersname": "uid=directory.admin,cn=users,cn=accounts,dc=lab,dc=example",
        "modifytimestamp": "20260920010303Z",
        "object_name": "operations-3",
        "result": 0,
        "time": "20260920040303"
      }
    }
  },
  "ecs": {
    "version": "8.11.0"
  },
  "event": {
    "action": "replace-cmdCategory",
    "category": [
      "iam"
    ],
    "dataset": "aldpro.dirsrv_audit",
    "kind": "event",
    "module": "aldpro",
    "original": "time: 20260920040303\ndn: ipauniqueid=a4a19e36-4c0c-4d2f-97aa-e7fe42aa6ae4,cn=sudorules,cn=sudo,dc=lab,dc=example\nresult: 0\nchangetype: modify\nreplace: cmdCategory\ncmdCategory: all\n-\nreplace: modifiersname\nmodifiersname: uid=directory.admin,cn=users,cn=accounts,dc=lab,dc=example\n-\nreplace: modifytimestamp\nmodifytimestamp: 20260920010303Z\n-\nreplace: entryusn\nentryusn: 100002\n-\n\n",
    "outcome": "success",
    "type": [
      "change"
    ]
  },
  "host": {
    "name": "dc-1.lab.example"
  },
  "log": {
    "file": {
      "path": "/var/log/dirsrv/slapd-LAB-EXAMPLE/audit"
    }
  },
  "message": "time: 20260920040303\ndn: ipauniqueid=a4a19e36-4c0c-4d2f-97aa-e7fe42aa6ae4,cn=sudorules,cn=sudo,dc=lab,dc=example\nresult: 0\nchangetype: modify\nreplace: cmdCategory\ncmdCategory: all\n-\nreplace: modifiersname\nmodifiersname: uid=directory.admin,cn=users,cn=accounts,dc=lab,dc=example\n-\nreplace: modifytimestamp\nmodifytimestamp: 20260920010303Z\n-\nreplace: entryusn\nentryusn: 100002\n-\n\n",
  "related": {
    "user": [
      "directory.admin"
    ]
  },
  "source": {
    "ip": "10.20.4.22"
  },
  "user": {
    "domain": "LAB.EXAMPLE",
    "name": "directory.admin"
  }
}
```

## References

- [ALD Pro SIEM integration guide, dated 06/10/2025](https://www.aldpro.ru/integrations/item/kaspersky-kuma): source paths, native examples, access tags/timing, group member add/remove, audit configuration.
- [ALD Pro policy course](https://www.aldpro.ru/professional/ALD_Pro_Module_06a/ALD_Pro_group_policy.html): password policy, SUDO storage and `--cmdcat=all`; current page labels the course 3.1.0, without versioning the older SIEM captures.
- [FreeIPA 4.9.11 SUDO plugin](https://github.com/freeipa/freeipa/blob/release-4-9-11/ipaserver/plugins/sudorule.py): UUID RDN and command-category exclusions.
- [FreeIPA 4.9.11 SUDO tests](https://github.com/freeipa/freeipa/blob/release-4-9-11/ipatests/test_integration/test_sudo.py): clearing command category to restore no allowed commands.
- [MIT Kerberos 1.18.3 TGS handling](https://github.com/krb5/krb5/blob/krb5-1.18.3-final/src/kdc/do_tgs_req.c): service ticket retains authentication time from its subject ticket.
- [389 DS timing semantics](https://www.port389.org/docs/389ds/design/access-log-new-time-stats-design.html): `wtime`, `optime`, `etime`.
- [389 DS 1.4.4.20 audit serializer](https://github.com/389ds/389-ds-base/blob/389-ds-base-1.4.4.20/ldap/servers/slapd/auditlog.c), [modify frontend](https://github.com/389ds/389-ds-base/blob/389-ds-base-1.4.4.20/ldap/servers/slapd/modify.c), [backend](https://github.com/389ds/389-ds-base/blob/389-ds-base-1.4.4.20/ldap/servers/slapd/back-ldbm/ldbm_modify.c): successful RESULT before audit write, local audit time and blank record termination.
