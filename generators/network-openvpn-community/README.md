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
| Address | `MULTI_sva: pool returned IPv4=10.8.X.Y, IPv6=(Not enabled)`, `MULTI: Learn: 10.8.X.Y -> CN/IP:port`, `MULTI: primary virtual IP for CN/IP:port: 10.8.X.Y` |
| Options | `PUSH: Received control message: 'PUSH_REQUEST'`, `Data Channel: cipher 'AES-256-GCM', peer-id: N`, `Timers: ping 10, ping-restart 240`, `Protocol options: protocol-flags cc-exit tls-ekm dyn-tls-crypt` |
| Clean exit (client exit notification) | `Delayed exit in 5 seconds`, 5 s later `SIGTERM[soft,delayed-exit] received, client-instance exiting` |
| Client vanished | `[CN] Inactivity timeout (--ping-restart), restarting`, `SIGUSR1[soft,ping-restart] received, client-instance restarting` |

The server runs `keepalive 10 120`, so it pings every 10 s, drops a silent instance after 240 s and pushes `ping-restart 120` to clients. A replaced instance is closed without a line of its own. `peer-id` is the lowest free slot; each common name keeps its pool address (`10.8.0.0/22` pool) across sessions.

## Volume and Timing

About 50,000 lines per day (daily volume varies by about ±3%), following an office-hours curve in UTC:

| UTC hours | Lines/s |
| --- | ---: |
| 00-07, 23-24 | 0.15 |
| 07-08, 18-21 | 0.55 |
| 08-18 | 1.0 |
| 21-23 | 0.30 |

New connections arrive at the rate this curve allows, about 3,700 per day. The connection lines of one client fall within 0-3 seconds of its `TLS: Initial packet` line, `SIGTERM` follows `Delayed exit in 5 seconds` after exactly 5 seconds, and the `SIGUSR1` line shares the second of its `Inactivity timeout` line. In a busy second up to about 35 lines of several clients are written.

## Event Types

Measured in a default 96-hour run with `anomaly_mode: true` (202,110 lines, starting 2026-09-01 00:00 UTC):

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
| `exit-scheduled` | `Delayed exit in 5 seconds` | 4.3% | `session` |
| `client-exited` | `SIGTERM[soft,delayed-exit] received, client-instance exiting` | 4.3% | `session` |
| `duplicate-cn-replaced` | `MULTI: new connection by client 'CN' ...` | 1.8% | `session` |
| `inactivity-timeout` | `[CN] Inactivity timeout (--ping-restart), restarting` | 1.2% | `session` |
| `client-restarted` | `SIGUSR1[soft,ping-restart] received, client-instance restarting` | 1.2% | `session` |

14,709 connections, 3,596 of them replacing a live instance of the same CN (the 4 episodes contributed 16 of those). `user.name` is set only on lines that carry the client CN; the `depth=1` line names the CA.

The site has 800 users (`samples/clients.json`), each with a certificate CN, a persistent pool address and two or three usual public addresses: a home connection (unique per user; documentation ranges `198.51.100.0/24`, `203.0.113.0/24` and the benchmarking range `198.18.0.0/15`), a mobile carrier address shared with a few other users (`192.0.2.40-199`), and for 37% of users a branch-office NAT address shared by that office (`192.0.2.10-19`), for most of them used about as often as the home connection. Each user has a bounded activity weight (0.35-4.0) and a network instability of their own. A connection starts from one of the user's addresses (by the user's address weights), and a session consists of segments. A segment is short (median about 2.5 minutes) on an unstable network, more likely right after a reconnect, and long otherwise (median 90 minutes divided by the user's activity weight: a more active user has more, shorter sessions). It ends with a clean exit (client exit notification), a vanished client (server ping timeout after 240 s), or a reconnect from the same or another of the user's networks: at once on an OS network event, or after the client's own 120 s ping-restart. A reconnect that reaches the server before the old instance times out replaces it and logs the duplicate-CN line. After a session a user stays offline for a lognormal pause (median 45 minutes divided by the activity weight, at least 5 minutes); new connections go to users who are offline and past that pause, in proportion to their activity weight. Each user connects about 4.6 times a day on average, from about 1.5 times a day for the least active users to about 14 for the most active; up to about 440 clients are connected at the office-hours peak. All rates are synthetic, not measured OpenVPN statistics. The log starts with no clients connected.

## Anomaly Chain

One client certificate used from two places at once. With `--duplicate-cn` off, each new connection with a CN that is already connected replaces the old one; the replaced device notices only when its ping-restart fires and reconnects, replacing the other:

1. The user's device connects from one of the user's usual addresses (full connection sequence).
2. After a lognormal delay (median 15 minutes, 1-60 minutes) a second device with the same certificate connects from another of the user's usual addresses; OpenVPN logs `MULTI: new connection by client '<CN>' ...` from the new address.
3. The replaced device reconnects about two minutes after it was dropped (its pushed ping-restart 120 and the connect retry) and replaces the second one; the duplicate-CN line now shows the first address.
4. The second device does the same: four replacements in all, alternating X, Y, X, Y between the two addresses within about six minutes. Then the second device stops trying and the first stays connected for an ordinary session that ends with a clean exit (75%) or a ping timeout.

Linking fields: `user.name` (the certificate CN in the prefix and the duplicate-CN text), `source.ip` of each `duplicate-cn-replaced` line, the pool address in `openvpn.virtual_ip`.

Recurrence: with `anomaly_mode: true` (the default) the first episode starts within `min(anomaly_interval_hours, 24 h)` of the first line, at an hour drawn from the office-hours curve. Each next episode is due `anomaly_interval_hours` after the actual start of the previous one and starts inside a window of `w = min(interval / 4, 6 h)` centred on that due time, weighted by the squared office-hours curve plus a small floor, so start hours do not drift and missed intervals are never caught up. Consecutive starts are therefore `interval ± w/2` apart (24 ± 3 h by default); an episode starts later only when no user is eligible at the drawn moment, and then within a minute of one becoming eligible. With a short interval the window is narrow (2 h at 8 h) and some due times fall at night, so a share of episodes then starts outside office hours.

The episode user is drawn like any new connection: by activity weight among users who are offline and past their pause after the last session. The draw is limited to the most active users (activity weight at least 2.4, 79 of the 800) with at least two addresses that each carry a third or more of the user's address weight: 39 users in the shipped `samples/clients.json`. Each CN|address pair an episode can use occurs about 11 to 47 times in four days of ordinary traffic (median about 18). In addition the user has connected from two of those addresses earlier, had no replacement in the last ten minutes and is not the previous episode's user; the two addresses are two of those already used, drawn with the user's address weights, so every CN|address pair of an episode has occurred in ordinary traffic before it. The episode is one of the user's sessions: afterwards the user takes the usual pause and connects as before. With `anomaly_mode: true` each episode adds its own lines on top of ordinary traffic (five connections and four duplicate-CN replacements of one user), so replacement counts are about four per episode higher than with `anomaly_mode: false`.

Everything the chain uses also occurs in ordinary traffic of both modes: every user|address pair, duplicate-CN replacements from the same and from another address, reconnects about two minutes after a drop, several replacements of one CN within minutes, and three replacements that alternate X, Y, X. Only the complete ordered chain is absent from ordinary traffic: an ordinary reconnect whose replacement line would be the fourth alternating replacement of its CN within ten minutes of the first comes from the address of the session it replaces instead (a client restart on the same network). Its time and all other lines are unchanged.

Detection idea: four or more `MULTI: new connection by client '<CN>'` lines for one CN within ten minutes, alternating between two source addresses (X, Y, X, Y): two devices hold the same certificate and keep evicting each other. Roaming users produce single replacements or a return to the first network, not a sustained alternation.

With `anomaly_mode: false`, only ordinary traffic is generated.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Purpose |
| --- | --- | --- |
| `anomaly_mode` | `true` | Emit recurring episodes; `false` gives background only |
| `anomaly_interval_hours` | `24` | Hours from one episode start to the next due time; 2 to 720 (a value outside stops generation with an error) |
| `vpn_host` | `vpn-01` | `host.name` enrichment (the server's own lines carry no host name) |
| `ca_common_name` | `Example Corp VPN CA` | CN of the issuing CA in the `depth=1` verification line |

Users, pool addresses and usual public addresses are in `samples/clients.json`. Keep CNs and pool addresses unique when editing it; every user needs at least two addresses. Episodes start only if some very active user has two frequently used addresses (see Anomaly Chain).

### Output Parameters

The shipped output writes `output/events.json` and uses no `${params.*}` or `${secrets.*}` placeholders. To send events elsewhere, replace the `output` block and pass values through placeholders, for example an `opensearch` output with `hosts: ["${params.opensearch_host}"]` and `password: ${secrets.opensearch_password}`, with the secret stored in the Eventum keyring.

## Usage

Live mode at the configured rate, until stopped:

```bash
eventum generate --path generators/network-openvpn-community/generator.yml --id openvpn --live-mode true
```

Batch mode: set `start` and `end` of the `oscillator` in all four `patterns/*.yml` files to the same range, with `start` at 00:00 UTC so the hour bands stay in place (for example `start: "2026-09-01T00:00:00Z"` and `end: "2026-09-05T00:00:00Z"`), then run:

```bash
eventum generate --path generators/network-openvpn-community/generator.yml --id openvpn --live-mode false --keep-order true
```

The hour curve is the sum of four `time_patterns` files under `patterns/`: `baseline` (00-24 UTC), `daytime` (07-21), `office` (08-18) and `evening` (21-23). To change the volume, scale the `ratio` of every pattern file by the same factor and the number of users in `samples/clients.json` with it, so each user's own connection rate stays the same. Episode start hours follow the shipped curve even if you reshape the pattern files. In live mode each line is written some time after the timestamp it carries: typically a few seconds (under a minute in office hours), up to about 6 minutes at night.

Performance: about 3,200 lines per second of CPU time in batch mode (14 days, 706,000 lines, in 220 CPU seconds).

## Limitations

- No raw log from a running OpenVPN 2.6.14 server was available. Every line follows the format strings of the tagged 2.6.14 source (see References) for the profile above; values such as the TLS suite, certificate key size, key-exchange group (X25519) and protocol flags are fixed for one OpenSSL 3 build and 2.6 clients.
- Not every verbosity-3 line is generated: `peer info: IV_*` lines, `SENT CONTROL [CN]: 'PUSH_REPLY,...'`, data-channel MTU and key lines, hourly TLS renegotiations (`TLS: soft reset` and the repeated `VERIFY OK` lines) and startup/status lines are omitted. A parser that expects them sees fewer lines per session.
- No failed certificate verifications, `tls-crypt` unwrapping failures from scanners, TCP transport, IPv6 pool or `--duplicate-cn` servers.
- A replaced device learns about the replacement only through its ping-restart; the server's handling is modelled from `multi_delete_dup`, not observed.
- Office hours are in UTC with stepped hour bands and no weekday cycle. The server's local time is UTC.
- The connection sequences of two newly arriving clients never overlap in time: one client's lines are complete before the next new client's `TLS: Initial packet` line. Reconnects and session ends do interleave with them.
- Home addresses of most users come from the benchmarking range `198.18.0.0/15`, which does not occur on the public internet.
- In ordinary traffic, four alternating replacements of one CN never fall within ten minutes of the first; this is the chain itself. A detector with fewer steps or a longer window also matches ordinary near misses.
- With `anomaly_mode: true`, replacement counts are about four per episode higher than with `anomaly_mode: false` (the episode's own lines).

## Sample output

First replacement of the first episode of a default 96-hour run (line 19,537), copied unchanged:

```json
{"@timestamp": "2026-09-01T11:47:19+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "duplicate-cn-replaced", "category": ["session"], "dataset": "openvpn.server", "kind": "event", "module": "openvpn", "original": "2026-09-01 11:47:19 nikolai.hart/198.51.100.58:59766 MULTI: new connection by client \u0027nikolai.hart\u0027 will cause previous active sessions by this client to be dropped.  Remember to use the --duplicate-cn option if you want multiple clients using the same certificate or username to concurrently connect.", "type": ["end"]}, "host": {"name": "vpn-01"}, "message": "nikolai.hart/198.51.100.58:59766 MULTI: new connection by client \u0027nikolai.hart\u0027 will cause previous active sessions by this client to be dropped.  Remember to use the --duplicate-cn option if you want multiple clients using the same certificate or username to concurrently connect.", "process": {"name": "openvpn"}, "related": {"ip": ["198.51.100.58"], "user": ["nikolai.hart"]}, "source": {"ip": "198.51.100.58", "port": 59766}, "user": {"name": "nikolai.hart"}}
```

## References

- OpenVPN 2.6.14 source, tag `v2.6.14`: [`error.c`](https://github.com/OpenVPN/openvpn/blob/v2.6.14/src/openvpn/error.c) and [`otime.c`](https://github.com/OpenVPN/openvpn/blob/v2.6.14/src/openvpn/otime.c) (line layout and timestamp), [`multi.c`](https://github.com/OpenVPN/openvpn/blob/v2.6.14/src/openvpn/multi.c) (prefix, duplicate-CN replacement, pool and route lines), [`socket.c`](https://github.com/OpenVPN/openvpn/blob/v2.6.14/src/openvpn/socket.c), [`ssl.c`](https://github.com/OpenVPN/openvpn/blob/v2.6.14/src/openvpn/ssl.c), [`ssl_openssl.c`](https://github.com/OpenVPN/openvpn/blob/v2.6.14/src/openvpn/ssl_openssl.c), [`ssl_verify.c`](https://github.com/OpenVPN/openvpn/blob/v2.6.14/src/openvpn/ssl_verify.c), [`init.c`](https://github.com/OpenVPN/openvpn/blob/v2.6.14/src/openvpn/init.c), [`ping.c`](https://github.com/OpenVPN/openvpn/blob/v2.6.14/src/openvpn/ping.c), [`forward.c`](https://github.com/OpenVPN/openvpn/blob/v2.6.14/src/openvpn/forward.c), [`push.c`](https://github.com/OpenVPN/openvpn/blob/v2.6.14/src/openvpn/push.c), [`sig.c`](https://github.com/OpenVPN/openvpn/blob/v2.6.14/src/openvpn/sig.c), [`errlevel.h`](https://github.com/OpenVPN/openvpn/blob/v2.6.14/src/openvpn/errlevel.h) (verbosity of each message).
- [OpenVPN 2.6 reference manual](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual.html): `--duplicate-cn`, `--keepalive`, `--ifconfig-pool-persist`, `--log-append`, `--verb`.
- No Elastic integration for OpenVPN server logs exists; the ECS projection (`event.action` names, `openvpn.virtual_ip`, `openvpn.peer_id`) is this pack's own parser output, not a vendor schema.
