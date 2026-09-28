# OpenVPN Community Server Log Generator

Produces ECS JSON from the **server file log** of one OpenVPN 2.6.14 Community remote-access server (`--log-append`, `--verb 3`, UDP, certificate authentication, `--ifconfig-pool-persist`, no `--duplicate-cn`): client connections from the TLS initial packet to the pushed data-channel options, session replacements when a certificate's common name connects again, clean exits and ping timeouts. Background-only and anomaly modes are supported; `anomaly_mode: true` is the default. Each native line is kept verbatim in `event.original`; `message` is the line without its timestamp.

## Log profile

The server writes to a file, so every line is `YYYY-MM-DD HH:MM:SS <prefix> <text>` in the server's local time (UTC here), with no syslog header. Before the client certificate is verified the prefix is the client's real address `IP:port`; once the connection is established it becomes `CN/IP:port`. The generated lines are the verbosity 1-3 messages of these OpenVPN 2.6.14 code paths, with their source text:

| Stage | Line text |
| --- | --- |
| New client | `TLS: Initial packet from [AF_INET]IP:port, sid=xxxxxxxx xxxxxxxx` |
| Certificate chain | `VERIFY OK: depth=1, CN=<CA>` and `VERIFY OK: depth=0, CN=<client>` |
| TLS | `Control Channel: TLSv1.3, cipher TLSv1.3 TLS_AES_256_GCM_SHA384, peer certificate: 2048 bits RSA, signature: RSA-SHA256, peer temporary key: 253 bits X25519` |
| Established | `[CN] Peer Connection Initiated with [AF_INET]IP:port` |
| Same CN still connected | `MULTI: new connection by client 'CN' will cause previous active sessions by this client to be dropped.  Remember to use the --duplicate-cn option ...` |
| Address | `MULTI_sva: pool returned IPv4=10.8.0.N, IPv6=(Not enabled)`, `MULTI: Learn: 10.8.0.N -> CN/IP:port`, `MULTI: primary virtual IP for CN/IP:port: 10.8.0.N` |
| Options | `PUSH: Received control message: 'PUSH_REQUEST'`, `Data Channel: cipher 'AES-256-GCM', peer-id: N`, `Timers: ping 10, ping-restart 240`, `Protocol options: protocol-flags cc-exit tls-ekm dyn-tls-crypt` |
| Clean exit (client exit notification) | `Delayed exit in 5 seconds`, 5 s later `SIGTERM[soft,delayed-exit] received, client-instance exiting` |
| Client vanished | `[CN] Inactivity timeout (--ping-restart), restarting`, `SIGUSR1[soft,ping-restart] received, client-instance restarting` |

The server runs `keepalive 10 120`, so it pings every 10 s, drops a silent instance after 240 s and pushes `ping-restart 120` to clients. A replaced instance is closed without a line of its own. `peer-id` is the lowest free slot; each common name keeps its pool address across sessions.

## Event Types

Measured in the final default-on 96-hour capture (14,405 lines, starting 2026-09-21 00:00 UTC):

| `event.action` | Native line | Share | ECS category |
| --- | --- | ---: | --- |
| `tls-initial-packet` | `TLS: Initial packet from ...` | 7.3% | `network` |
| `certificate-verified` | `VERIFY OK: depth=1, CN=<CA>` and `VERIFY OK: depth=0, CN=<client>` | 14.6% | `authentication` |
| `control-channel-established` | `Control Channel: TLSv1.3, ..., peer temporary key: 253 bits X25519` | 7.3% | `network` |
| `peer-connection-initiated` | `[CN] Peer Connection Initiated with ...` | 7.3% | `session` |
| `virtual-address-assigned` | `MULTI_sva: pool returned IPv4=...` | 7.3% | `network` |
| `route-learned` | `MULTI: Learn: ...` | 7.3% | `network` |
| `primary-virtual-address` | `MULTI: primary virtual IP for ...` | 7.3% | `network` |
| `push-request` | `PUSH: Received control message: 'PUSH_REQUEST'` | 7.3% | `network` |
| `data-channel-established` | `Data Channel: cipher 'AES-256-GCM', peer-id: N` | 7.3% | `network` |
| `timers` | `Timers: ping 10, ping-restart 240` | 7.3% | `network` |
| `protocol-options` | `Protocol options: protocol-flags ...` | 7.3% | `network` |
| `exit-scheduled` | `Delayed exit in 5 seconds` | 4.0% | `session` |
| `client-exited` | `SIGTERM[soft,delayed-exit] received, client-instance exiting` | 4.0% | `session` |
| `duplicate-cn-replaced` | `MULTI: new connection by client 'CN' ...` | 2.0% | `session` |
| `inactivity-timeout` | `[CN] Inactivity timeout (--ping-restart), restarting` | 1.2% | `session` |
| `client-restarted` | `SIGUSR1[soft,ping-restart] received, client-instance restarting` | 1.2% | `session` |

1,051 connections, 289 of them replacing a live instance of the same CN (the 4 episodes contributed 17 of those). `user.name` is set only on lines that carry the client CN; the `depth=1` line names the CA.

The site has 60 users (`samples/clients.json`), each with a certificate CN, a persistent pool address and two or three usual public addresses: a home connection, a mobile carrier address shared with some other users, and for some users a branch-office NAT address shared by that office. Each user is an independent random process with its own activity weight and network instability: an idle gap (lognormal, thinned by an office-hours curve in UTC), a connection from one of the user's addresses, and session segments. A segment is short (median about 2.5 minutes) on an unstable network, more likely right after a reconnect, and long (median 90 minutes) otherwise. It ends with a clean exit (client exit notification), a vanished client (server ping timeout after 240 s), or a reconnect from the same or another of the user's networks: at once on an OS network event, or after the client's own 120 s ping-restart. A reconnect that reaches the server before the old instance times out replaces it and logs the duplicate-CN line. All rates are synthetic, not measured OpenVPN statistics. Up to three lines are emitted per second; a second with nothing due is silent. The log starts with no clients connected.

## Anomaly Chain

One client certificate used from two places at once. With `--duplicate-cn` off, each new connection with a CN that is already connected replaces the old one; the replaced device notices only when its ping-restart fires and reconnects, replacing the other:

1. The user's device connects from one of the user's usual addresses (full connection sequence).
2. A second device with the same certificate connects from another of the user's usual addresses; OpenVPN logs `MULTI: new connection by client '<CN>' ...` from the new address.
3. The replaced device reconnects about two minutes later (its pushed ping-restart 120, the connect retry and the handshake) and replaces the second one; the duplicate-CN line now shows the first address.
4. This repeats: four to six replacements in all (4: 60%, 5: 30%, 6: 10%), alternating between the two addresses. Then one device stops trying and the other stays connected for an ordinary session that ends with a clean exit (75%) or a ping timeout.

Linking fields: `user.name` (the certificate CN in the prefix and the duplicate-CN text), `source.ip` of each `duplicate-cn-replaced` line, the pool address in `openvpn.virtual_ip`.

Recurrence: with `anomaly_mode: true` (the default) the first episode starts within `min(anomaly_interval_hours, 24 h)` of the first event, at an hour drawn from the background office-hours curve. Each next episode is due `anomaly_interval_hours` after the actual start of the previous one and starts inside a window of `w = min(interval / 4, 6 h)` centred on that due time, weighted by the squared office-hours curve plus a small floor, so start hours do not drift and missed intervals are never caught up. Consecutive starts are therefore `interval ± w/2` apart (24 ± 3 h by default), later only when no user is eligible at the drawn moment (the episode then starts at the first second one is). The first replacement follows the start after a lognormal delay (median 15 minutes, 1-60 minutes). In two final default-on 96-hour captures the 4 episodes each started 23.5, 21.0 and 23.5 hours apart (at 16-19 UTC) and 21.5, 23.9 and 25.3 hours apart (at 11-13 UTC); an 8-hour-interval capture of the same length had 11 episodes, 7.2-8.9 hours apart. With a short interval the window is narrow (2 h at 8 h) and some due times fall at night, so a share of episodes then starts outside office hours. Each episode picks a user with the background activity weights among users who are idle, whose own next connection comes after the episode ends, who had no replacement in the last ten minutes and who have already connected from at least two of their addresses earlier in the run, never the previous episode's user; the two addresses are two of those, drawn with the user's address weights, so every CN|address pair of an episode has occurred in ordinary traffic before it. The user's own traffic is neither suspended nor moved.

Everything the chain uses also occurs in ordinary traffic of both modes: every user|address pair, duplicate-CN replacements from the same and from another address, reconnects after about two minutes, several replacements of one CN within minutes, and two replacements that return to the first address. Only the complete ordered chain is absent from background: an ordinary reconnect whose replacement line would be the fourth alternating replacement of its CN within ten minutes of the first comes from the address of the session it replaces instead (a client restart on the same network). Its time and all other lines are unchanged. In seven background-only 96-hour captures (672 hours), three alternating replacements of one CN (X, Y, X) spanned 360-480, 480-600, 600-720 and 720-840 seconds from the first in 25, 37, 28 and 17 cases. The next replacement of that CN came 480-600 seconds after the first in 11 cases, all from an address other than Y, and 600-720 seconds after it in 11 cases, 3 of them from Y: the timing runs smoothly across the ten-minute boundary, and only the return to Y stops inside it.

Detection idea: four or more `MULTI: new connection by client '<CN>'` lines for one CN within ten minutes, alternating between two source addresses (X, Y, X, Y): two devices hold the same certificate and keep evicting each other. Roaming users produce single replacements or a return to the first network, not a sustained alternation.

With `anomaly_mode: false`, only background is generated.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Emit recurring episodes; `false` gives background only |
| `anomaly_interval_hours` | `24` | Hours from one episode start to the next due time; 2 to 720 (a value outside fails the render) |
| `vpn_host` | `vpn-01` | `host.name` enrichment (the server's own lines carry no host name) |
| `ca_common_name` | `Example Corp VPN CA` | CN of the issuing CA in the `depth=1` verification line |

Users, pool addresses and usual public addresses are in `samples/clients.json`. Keep CNs and pool addresses unique when editing it; every user needs at least two addresses.

### Output Parameters

The shipped output writes `output/events.json` and uses no `${params.*}` or `${secrets.*}` placeholders. To send events elsewhere, replace the `output` block and pass values through placeholders, for example an `opensearch` output with `hosts: ["${params.opensearch_host}"]` and `password: ${secrets.opensearch_password}`, with the secret stored in the Eventum keyring.

## Usage

Live mode, up to three lines per second, until stopped:

```bash
eventum generate --path generators/network-openvpn-community/generator.yml --id openvpn --live-mode true
```

Batch mode: add `start` and `end` to `input[0].cron` in a copy of `generator.yml`, then:

```bash
eventum generate --path generator.yml --id openvpn --live-mode false --keep-order true
```

## Limitations

- No raw log from a running OpenVPN 2.6.14 server was available. Every line follows the format strings of the tagged 2.6.14 source (see References) for the profile above; values such as the TLS suite, certificate key size, key-exchange group (X25519) and protocol flags are fixed for one OpenSSL 3 build and 2.6 clients.
- Not every verbosity-3 line is generated: `peer info: IV_*` lines, `SENT CONTROL [CN]: 'PUSH_REPLY,...'`, data-channel MTU and key lines, hourly TLS renegotiations (`TLS: soft reset` and the repeated `VERIFY OK` lines) and startup/status lines are omitted. A parser that expects them sees fewer lines per session.
- No failed certificate verifications, `tls-crypt` unwrapping failures from scanners, TCP transport, IPv6 pool or `--duplicate-cn` servers.
- A replaced device learns about the replacement only through its ping-restart; the server's handling is modelled from `multi_delete_dup`, not observed.
- Office hours are in UTC, with no weekday cycle. The server's local time is UTC.
- At most three lines are written per second. When several connections fall into the same seconds, later lines move by one or two seconds (for example the `SIGUSR1` line after its `Inactivity timeout` line, or `SIGTERM` six or seven seconds after `Delayed exit`).
- In background, four alternating replacements of one CN never fall within ten minutes of the first; this is the chain itself. A detector with fewer steps or a longer window also matches background near misses.

## Sample output

First replacement of the first episode of the final default-on capture (line 3272), copied unchanged:

```json
{"@timestamp": "2026-09-21T20:13:00+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "duplicate-cn-replaced", "category": ["session"], "dataset": "openvpn.server", "kind": "event", "module": "openvpn", "original": "2026-09-21 20:13:00 hugo.moreau/192.0.2.11:6598 MULTI: new connection by client \u0027hugo.moreau\u0027 will cause previous active sessions by this client to be dropped.  Remember to use the --duplicate-cn option if you want multiple clients using the same certificate or username to concurrently connect.", "type": ["end"]}, "host": {"name": "vpn-01"}, "message": "hugo.moreau/192.0.2.11:6598 MULTI: new connection by client \u0027hugo.moreau\u0027 will cause previous active sessions by this client to be dropped.  Remember to use the --duplicate-cn option if you want multiple clients using the same certificate or username to concurrently connect.", "process": {"name": "openvpn"}, "related": {"ip": ["192.0.2.11"], "user": ["hugo.moreau"]}, "source": {"ip": "192.0.2.11", "port": 6598}, "user": {"name": "hugo.moreau"}}
```

## References

- OpenVPN 2.6.14 source, tag `v2.6.14`: [`error.c`](https://github.com/OpenVPN/openvpn/blob/v2.6.14/src/openvpn/error.c) and [`otime.c`](https://github.com/OpenVPN/openvpn/blob/v2.6.14/src/openvpn/otime.c) (line layout and timestamp), [`multi.c`](https://github.com/OpenVPN/openvpn/blob/v2.6.14/src/openvpn/multi.c) (prefix, duplicate-CN replacement, pool and route lines), [`socket.c`](https://github.com/OpenVPN/openvpn/blob/v2.6.14/src/openvpn/socket.c), [`ssl.c`](https://github.com/OpenVPN/openvpn/blob/v2.6.14/src/openvpn/ssl.c), [`ssl_openssl.c`](https://github.com/OpenVPN/openvpn/blob/v2.6.14/src/openvpn/ssl_openssl.c), [`ssl_verify.c`](https://github.com/OpenVPN/openvpn/blob/v2.6.14/src/openvpn/ssl_verify.c), [`init.c`](https://github.com/OpenVPN/openvpn/blob/v2.6.14/src/openvpn/init.c), [`ping.c`](https://github.com/OpenVPN/openvpn/blob/v2.6.14/src/openvpn/ping.c), [`forward.c`](https://github.com/OpenVPN/openvpn/blob/v2.6.14/src/openvpn/forward.c), [`push.c`](https://github.com/OpenVPN/openvpn/blob/v2.6.14/src/openvpn/push.c), [`sig.c`](https://github.com/OpenVPN/openvpn/blob/v2.6.14/src/openvpn/sig.c), [`errlevel.h`](https://github.com/OpenVPN/openvpn/blob/v2.6.14/src/openvpn/errlevel.h) (verbosity of each message).
- [OpenVPN 2.6 reference manual](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual.html): `--duplicate-cn`, `--keepalive`, `--ifconfig-pool-persist`, `--log-append`, `--verb`.
- No Elastic integration for OpenVPN server logs exists; the ECS projection (`event.action` names, `openvpn.virtual_ip`, `openvpn.peer_id`) is this pack's own parser output, not a vendor schema.
