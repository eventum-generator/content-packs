# FreeRADIUS 3.2.10 Linelog Generator

Produces ECS JSON from a FreeRADIUS 3.2.10 **file `linelog` profile** with `Accepted user`, `Rejected user`, `Connect`, and `Disconnect` lines. Both background-only and anomaly modes are supported; `anomaly_mode: true` is the default. The file line is preserved in `event.original` and `message`, without a syslog header. `host.name` and `radius.client_shortname` are configured enrichment, not text from that line.

## Required FreeRADIUS profile

These lines require explicit `linelog` configuration. FreeRADIUS's built-in `log.auth` is `no` in the tagged 3.2.10 configuration, and the default `linelog` authentication messages do **not** include the calling station or NAS port. Add the following named instance to `mods-available/linelog`, then enable that file through `mods-enabled/linelog`:

```text
linelog auth_siemaudit {
    filename = ${logdir}/linelog
    permissions = 0600
    format = ""
    reference = "messages.%{%{reply:Packet-Type}:-default}"
    messages {
        Access-Accept = "Accepted user: [%{User-Name}] (cli %{Calling-Station-Id} port %{NAS-Port})"
        Access-Reject = "Rejected user: [%{User-Name}] (cli %{Calling-Station-Id} port %{NAS-Port})"
    }
}
```

Keep the tagged `linelog log_accounting` instance with `filename = ${logdir}/linelog-accounting`, `reference = "Accounting-Request.%{%{Acct-Status-Type}:-unknown}"`, and these Start/Stop formats:

```text
Start = "Connect: [%{User-Name}] (did %{Called-Station-Id} cli %{Calling-Station-Id} port %{NAS-Port} ip %{Framed-IP-Address})"
Stop = "Disconnect: [%{User-Name}] (did %{Called-Station-Id} cli %{Calling-Station-Id} port %{NAS-Port} ip %{Framed-IP-Address}) %{Acct-Session-Time} seconds"
```

Call `auth_siemaudit` in the active virtual server's `post-auth` section for Access-Accept and inside its `Post-Auth-Type REJECT` section for Access-Reject. Call `log_accounting` in its `accounting` section. For the tagged default site, edit `sites-available/default` and ensure it is enabled through `sites-enabled/default`. Place these calls inside the existing sections; this is a placement sketch, not a replacement for the site file:

```text
post-auth {
    auth_siemaudit
    Post-Auth-Type REJECT {
        auth_siemaudit
    }
}
accounting {
    log_accounting
}
```

Authentication and accounting therefore go to **two separate files**. A SIEM collector must read both files and parse the shown line formats. This pack does not model the built-in authentication log or syslog. Validate the modified server configuration before deploying it.

The [tagged 3.2.10 `linelog` configuration](https://github.com/FreeRADIUS/freeradius-server/blob/release_3_2_10/raddb/mods-available/linelog) defines the file destinations and accounting formats; its default authentication formats are shorter. The [tagged default virtual server](https://github.com/FreeRADIUS/freeradius-server/blob/release_3_2_10/raddb/sites-available/default) defines the `post-auth` and `accounting` sections. The [tagged server configuration](https://github.com/FreeRADIUS/freeradius-server/blob/release_3_2_10/raddb/radiusd.conf.in) sets built-in `log.auth` to `no`.

## Behavior and anomaly

Every 30 seconds the generator emits one record. Routine authentication attempts use a pool of 20 user/station pairs from the parameters and `samples/clients.json`. The same target user and calling station used in the anomaly also make ordinary attempts and sessions in the background. About 70% of routine attempts are accepted and 30% rejected; those are synthetic weights, not measured FreeRADIUS rates. Each accepted attempt is followed by an accounting Start for that user/station. Active sessions stay open for 10, 15, 20, or 30 minutes; a Stop is emitted when a session is due, and `Acct-Session-Time` equals the actual Start-to-Stop elapsed seconds. Pending sessions are bounded by the client pool. An open session at the end of a finite run has no synthetic Stop.

When `anomaly_mode` is enabled, one chain starts after at least `anomaly_after_attempts` routine authentication decisions: three consecutive rejects, one accept, then an accounting Start for the configured target user/station. Its Stop occurs at least 15 minutes later and carries the actual elapsed duration. The chain appears only once per generator run. Background rejects for this target are separated by at least 10 minutes, so they do not form the same three-reject sequence. Correlate on user and calling station across auth and accounting lines; the chain has no special marker in the event.

## Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
|---|---|---|
| `anomaly_mode` | `true` | Emit the one-shot chain |
| `anomaly_after_attempts` | `250` | Minimum routine authentication decisions before the chain can start |
| `radius_host` | `radius-01` | ECS host enrichment |
| `nas_client` | `wifi-controller-01` | ECS RADIUS client short-name enrichment |
| `ordinary_user` | `employee01` | First background user |
| `ordinary_station` | `02-11-22-33-44-55` | First background calling station |
| `ordinary_nas_port` | `12` | First background NAS port |
| `ordinary_framed_ip` | `10.50.0.45` | First background framed IP |
| `unusual_user` | `admin01` | Correlation target, also present in background |
| `unusual_station` | `02-AA-BB-CC-DD-EE` | Target calling station |
| `unusual_nas_port` | `23` | Target NAS port |
| `unusual_framed_ip` | `10.50.0.46` | Target framed IP |
| `called_station` | `02-66-77-88-99-AA` | Accounting called station |

Keep station, port, and framed-IP combinations distinct from each other and from `samples/clients.json` when customizing the pool. The shipped output is `output/events.json`; replace the `output` block to send ECS events elsewhere. No credentials are required for the file output.

## Usage

From the content-packs repository root:

```bash
eventum generate --path generators/identity-freeradius/generator.yml --id freeradius --live-mode true
```

For a finite historical validation, copy `generator.yml` alongside the original, set `input[0].cron.start` and `end` in the copy, and run with `--live-mode false --keep-order true`. The default configuration has no end time and is intended to run until stopped.

## Sample output

This complete event is copied unchanged from the finite default/anomaly-on run. Its matching `Connect` was emitted at `2026-09-25T05:01:00+00:00`.

```json
{"@timestamp": "2026-09-25T05:16:00+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "disconnect", "category": ["session"], "dataset": "freeradius.linelog", "duration": 900000000000, "kind": "event", "module": "freeradius", "original": "Disconnect: [admin01] (did 02-66-77-88-99-AA cli 02-AA-BB-CC-DD-EE port 23 ip 10.50.0.46) 900 seconds", "outcome": "success", "type": ["end"]}, "host": {"name": "radius-01"}, "message": "Disconnect: [admin01] (did 02-66-77-88-99-AA cli 02-AA-BB-CC-DD-EE port 23 ip 10.50.0.46) 900 seconds", "radius": {"acct_session_time": 900, "acct_status_type": "Stop", "called_station_id": "02-66-77-88-99-AA", "calling_station_id": "02-AA-BB-CC-DD-EE", "client_shortname": "wifi-controller-01", "framed_ip_address": "10.50.0.46", "nas_port": 23}, "service": {"name": "radiusd"}, "source": {"ip": "10.50.0.46", "mac": "02-AA-BB-CC-DD-EE"}, "user": {"name": "admin01"}}
```

This profile is grounded in tagged FreeRADIUS configuration, but no raw capture from a running FreeRADIUS 3.2.10 installation was available. Full native-output fidelity and compatibility with a FreeRADIUS syslog-specific SIEM normalizer remain unverified.
