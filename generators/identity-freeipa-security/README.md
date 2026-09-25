# FreeIPA Directory Server security log

Generates ECS-enriched events carrying the native JSON security log of the 389 Directory Server used by FreeIPA. The scope is LDAP bind outcomes, not FreeIPA's Kerberos, HTTP, access, or audit logs.

## Event types

| Native event | Routine mix | ECS category | Meaning |
| --- | --- | --- | --- |
| `BIND_SUCCESS` | About 90% of routine binds | authentication | LDAP simple bind accepted |
| `BIND_FAILED` | About 10% of routine binds | authentication | Invalid password |

One `any` template renders each input tick. Each bind receives a distinct, increasing `conn_id` and an `op_id` of zero. The native JSON is preserved in `event.original`; `freeipa.security.*` and ECS fields are projections for detection work.

## Anomaly Chain

`anomaly_mode` defaults to `true`. After 80 ordinary events, three `BIND_FAILED` records for `cn=Directory Manager` arrive from `198.51.100.77`, followed one second later by `BIND_SUCCESS` for the same DN and IP. Connection IDs increase, so the attempts are separate LDAP connections. Correlate `client_ip`, `dn`, `root_dn` and `event`, then alert on failed privileged binds followed by success in a short window. With `anomaly_mode: false`, only routine binds are emitted.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`.

| Name | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include the bind-failure-to-success chain |
| `anomaly_interval_events` | `80` | Ordinary events between chains |
| `server_host` | `ipa-01.example.test` | Directory Server host |
| `server_ip` | `10.20.0.10` | LDAP server address |
| `suspicious_ip` | `198.51.100.77` | Chain client address |
| `directory_suffix` | `dc=example,dc=test` | Routine user DN suffix |

### Output Parameters

The shipped configuration writes `output/events.json` and requires no output overrides. To send events to another backend, replace the `output.file` block with the appropriate output plugin and supply endpoint values via top-level `${params.*}` and credentials via `${secrets.*}`.

## Usage

```bash
eventum generate --path generators/identity-freeipa-security/generator.yml --id freeipa --live-mode false
eventum generate --path generators/identity-freeipa-security/generator.yml --id freeipa --live-mode true
```

## Sample output

Copied from an anomaly-mode run:

```json
{"@timestamp": "2026-09-25T12:37:44+00:00", "ecs": {"version": "8.17.0"}, "event": {"kind": "event", "module": "freeipa", "dataset": "freeipa.security", "action": "bind_success", "category": ["authentication"], "type": ["start"], "outcome": "success", "original": "{\"date\":\"[25/Sep/2026:12:37:44.000000000 +0000]\",\"utc_time\":\"1790339864.000000000\",\"event\":\"BIND_SUCCESS\",\"dn\":\"cn=Directory Manager\",\"bind_method\":\"SIMPLE\",\"root_dn\":true,\"client_ip\":\"198.51.100.77\",\"server_ip\":\"10.20.0.10\",\"ldap_version\":3,\"conn_id\":83,\"op_id\":0,\"msg\":\"\"}"}, "host": {"name": "ipa-01.example.test", "ip": ["10.20.0.10"]}, "source": {"ip": "198.51.100.77"}, "user": {"name": "cn=Directory Manager"}, "freeipa": {"security": {"event": "BIND_SUCCESS", "dn": "cn=Directory Manager", "bind_method": "SIMPLE", "root_dn": true, "conn_id": 83, "op_id": 0, "msg": ""}}}
```

## Compatibility and references

The [FreeIPA directory documentation](https://www.freeipa.org/page/Directory_Server) identifies 389 Directory Server as its LDAP backend. [Red Hat's security-log reference](https://docs.redhat.com/en/documentation/red_hat_directory_server/13/html/configuration_and_schema_reference/log-files-reference) documents JSON keys and bind events modeled here. Verify that the deployed 389 DS version writes this security log. This pack does not reproduce the older access-log text format.

[KUMA 4.2 lists FreeIPA with a JSON normalizer](https://support.kaspersky.ru/kuma/4.2/255782), but its [collection instructions](https://support.kaspersky.ru/kuma/4.2/258520) wrap access, audit, error, HTTP, and Kerberos logs in an rsyslog JSON envelope. That is a different schema from this native `security` file. Compatibility with KUMA's bundled FreeIPA normalizer is **not established**; use a parser for 389 DS security JSON or build a separate KUMA-style wrapper. No Elastic FreeIPA security-log integration sample was used as a source reference.
