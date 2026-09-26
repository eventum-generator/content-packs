# ALD Pro Domain Controller Audit Generator

Produces ECS JSON for selected MIT KDC, 389 Directory Server access and extended audit records from one ALD Pro domain controller. `event.original` carries the corresponding native line or multiline LDIF change record. The source profile follows the vendor's SIEM guide dated **06/10/2025**, whose examples are dated 2023/2024 and do not identify the installed ALD Pro/component builds. This generator therefore does not claim exact fidelity to a particular ALD Pro release.

## Event Types

| Event | Workload | Category | Source |
|---|---|---|---|
| AS_REQ ISSUE | Frequent successful TGT issuance | Authentication | `/var/log/auth.log` |
| TGS_REQ ISSUE | Frequent service tickets using an already issued TGT | Authentication | `/var/log/auth.log` |
| AS_REQ PREAUTH_FAILED | Isolated background failures and periodic spray | Authentication | `/var/log/auth.log` |
| SSL connection, TLS, UNBIND, clean disconnect | Every selected LDAP session | Network | 389 DS `access` |
| GSSAPI BIND / RESULT | Three rounds: op 0/1 return err 14, op 2 succeeds | Authentication | 389 DS `access` |
| MOD / RESULT | Existing group or SUDO rule, success after a completed bind | IAM | 389 DS `access` |
| Add / delete member LDIF | Observable membership changes and restoration | IAM | 389 DS `audit` |
| Replace / delete cmdCategory LDIF | Observable SUDO activation and restoration | IAM | 389 DS `audit` |

Both modes emit all these classes, both administrators and both administrative client IPs. Ordinary activations change one object; cleanup can restore both. An episode changes the group and SUDO rule on the same freshly numbered connection after a four-principal spray. There is no chain label, synthetic sequence number or separate attack-only actor/action in the output.

The selected small-domain workload emits **30 records per minute**, averaging 0.5 records/s or 43,200 records/day. Input records arrive in minute buckets. A complete bounded LDAP trace occupies up to 18 records in a bucket; its native timestamps describe a subsecond transaction. Remaining KDC events advance by one second within that bucket. This burst pattern, 12% ordinary-session selection on eligible minute buckets and latency distributions are synthetic assumptions, not vendor production measurements. Session durations use bounded log-normal samples, with smaller exponential queue waits. Their request/result timestamps agree with `etime`; `wtime + optime = etime` in the selected model.

## Anomaly Chain

`anomaly_mode` defaults to `true`; `false` emits background without the complete sequence. The default recurrence is **24 hours**, with a supported minimum of **6 hours**. The first episode becomes eligible after one interval. Its next due time is based on the actual first failure, not an event counter.

1. Four distinct principals receive one PREAUTH_FAILED each from `attack_ip`, one minute apart. The fourth is `compromised_user`.
2. One minute later that administrator receives a TGT and an `ldap/<dc_host>` service ticket with the TGT's authentication time.
3. A fresh 389 DS SSL connection completes all three GSSAPI rounds. Its authenticated DN remains constant.
4. The connection adds the pre-existing `added_user` to the pre-existing privileged group, then sets the pre-existing SUDO rule's `cmdCategory` to `all`. Each change has a MOD request, matching successful RESULT and a following audit record.
5. After at least one hour, ordinary administrator sessions visibly remove the member and delete the existing `cmdCategory: all` value. Subsequent episodes wait for both states to be restored.

The four failures span three minutes; the final successful session follows at four minutes. Each episode has a new monotonic `conn` and new `entryusn` values. Immutable account/group/rule identities are reused because these are changes to existing resources. When an episode is due, new ordinary activations stop until due cleanup completes. Restoration runs at the first eligible minute bucket, less than 61 seconds after the one-hour hold. Eligibility can postpone an episode by up to 61 minutes; missed episodes are not replayed in a burst. A finite capture may end with ordinary permissions still active. No invisible reset is emitted to close its tail.

Detection ideas: four-principal password spray followed by TGT success and an LDAP service ticket; GSSAPI authentication followed by group addition and SUDO activation on one connection. Join KDC on source IP/principal and ticket `authtime`, and access on `conn`/`op`. Audit records have no connection ID: match successful MOD to actor/target and the same native second. Native `time` is local time without an offset; this profile selects UTC for the source server. `modifytimestamp` is UTC GeneralizedTime. KDC syslog and audit timestamps have second precision, so their ECS `@timestamp` preserves seconds. Access retains the fractional native timestamp. Interleaved audit events can consequently have an ECS timestamp earlier than the preceding access RESULT by less than one second. No subsecond audit timestamp is invented.

## Source Profile and Limits

The selected inventory contains two enabled administrators with rights to modify both targets, existing unlocked principals, one existing group and one existing service account initially outside it. The existing SUDO rule is enabled, applies to the selected group/hosts and has no `memberAllowCmd`, `memberDenyCmd` or `cmdCategory` initially. That dormant rule allows no commands until `cmdCategory: all` is set. FreeIPA rejects setting that category while explicit allowed commands exist; this generator does not model such a contradictory rule. The rule's native RDN is **`ipauniqueid=<uuid>`**, not its display name `cn`. Recovery deletes the category rather than replacing it with an invalid category value.

The selected password policy uses `maxfail=3` and `failinterval=120` seconds. Ordinary failures are globally separated by at least ten minutes; each spray victim fails only once per episode. Successful AS issuance resets that principal's failure count. No account-lock event or fabricated unlock is needed. TGT cache lifetime is a synthetic eight-hour assumption; a TGS is emitted only after an observed TGT for the same user/IP and uses that TGT's `authtime`.

The access log must be enabled and `nsslapd-auditlog-logging-enabled=on` must be configured for the extended audit feed. Direct administrative LDAP clients use the pre-existing account rights and do not represent a portal HTTP proxy. This profile selects no optional audit display attributes, C-locale English month names, source timezone UTC, two AES request encryption types and one sequential LDAP connection at a time. These are explicit configuration/workload assumptions. The template retains a fixed inventory and two permission flags, a ticket cache capped at 48 entries, one trace capped at 18 records and scalar scheduler/counter state. Successful changes are reflected only when their raw RESULT is emitted; their audit record follows. No resource creation/deletion or unbounded entity pool is modeled.

Complete vendor examples establish the selected KDC, access and group-member audit grammars. SUDO LDIF is inferred from FreeIPA's schema and 389 DS's documented serializer, not an exact ALD Pro SUDO capture. Tagged upstream MIT Kerberos 1.18.3, FreeIPA 4.9.11 and 389 DS 1.4.4.20 sources support ticket, rule and audit/result semantics; those versions are not asserted to be bundled with ALD Pro. The selected native-field map covers 38/38 modeled fields, not all ALD Pro fields. No matching Elastic ALD Pro integration or live source/parser validation is available. Keep exact-version/raw parity unconfirmed.

Connection IP and authenticated actor context on later LDAP access records are ECS enrichment from the synthetic connection/bind, because those lines do not repeat the original address. Audit `object_name` is inventory enrichment for the group or rule display name; the native record contains its DN. Other LDAP operations, internal updates, NEEDED_PREAUTH, OS auditd, Samba, DNS, application UI audit and Windows event IDs are outside this selected feed.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`. Principal/client/service inventory is in `samples/principals.json`. Keep the first two principal names, `svc_backup`, and `compromised_user` distinct so the spray has four targets. Hostnames, realms, account names and DN components use ASCII labels without quotes, backslashes, whitespace or newlines; custom suffixes/services must be consistent with the sample inventory. Supply a valid UUID for the existing SUDO rule.

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
uv run --project ../eventum eventum generate --path generators/identity-ald-pro/generator.yml --id ald-pro --live-mode false
uv run --project ../eventum eventum generate --path generators/identity-ald-pro/generator.yml --id ald-pro --live-mode true
```

Both commands run continuously until interrupted. To make a finite batch, set the cron input's ISO 8601 `start` and `end`. Thirty records are generated for each included minute bucket. Change `anomaly_mode` to `false` for the ordinary feed.

## Sample Output

The complete example below is copied from the final default anomaly-enabled finite run:

```json
{
  "@timestamp": "2026-09-27T01:05:00+00:00",
  "aldpro": {
    "dirsrv": {
      "audit": {
        "attribute": "cmdCategory",
        "attribute_operation": "replace",
        "attribute_value": "all",
        "changetype": "modify",
        "dn": "ipauniqueid=a4a19e36-4c0c-4d2f-97aa-e7fe42aa6ae1,cn=sudorules,cn=sudo,dc=lab,dc=example",
        "entryusn": 100084,
        "modifiersname": "uid=helpdesk.admin,cn=users,cn=accounts,dc=lab,dc=example",
        "modifytimestamp": "20260927010500Z",
        "object_name": "maintenance",
        "result": 0,
        "time": "20260927010500"
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
    "original": "time: 20260927010500\ndn: ipauniqueid=a4a19e36-4c0c-4d2f-97aa-e7fe42aa6ae1,cn=sudorules,cn=sudo,dc=lab,dc=example\nresult: 0\nchangetype: modify\nreplace: cmdCategory\ncmdCategory: all\n-\nreplace: modifiersname\nmodifiersname: uid=helpdesk.admin,cn=users,cn=accounts,dc=lab,dc=example\n-\nreplace: modifytimestamp\nmodifytimestamp: 20260927010500Z\n-\nreplace: entryusn\nentryusn: 100084\n-\n\n",
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
  "message": "time: 20260927010500\ndn: ipauniqueid=a4a19e36-4c0c-4d2f-97aa-e7fe42aa6ae1,cn=sudorules,cn=sudo,dc=lab,dc=example\nresult: 0\nchangetype: modify\nreplace: cmdCategory\ncmdCategory: all\n-\nreplace: modifiersname\nmodifiersname: uid=helpdesk.admin,cn=users,cn=accounts,dc=lab,dc=example\n-\nreplace: modifytimestamp\nmodifytimestamp: 20260927010500Z\n-\nreplace: entryusn\nentryusn: 100084\n-\n\n",
  "related": {
    "user": [
      "helpdesk.admin"
    ]
  },
  "user": {
    "domain": "LAB.EXAMPLE",
    "name": "helpdesk.admin"
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
