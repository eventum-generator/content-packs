# Symantec Endpoint Protection Manager External Logs

Generates Symantec Endpoint Protection Manager (SEPM) 14.3 external-log records, meaning the comma-delimited payloads SEPM sends to a syslog server, as ECS JSON for teams that test SIEM parsing and detection. Covers the Administrative, Policy and Agent Activity logs of one SEPM server. The native payload is kept verbatim in `event.original`, in the labelled layout of the Elastic `symantec_endpoint` integration fixtures. The rest of the document follows that integration's output (`symantec_endpoint.log.*`, `event.provider`).

## Event Types

Shares are those of about two weeks of default output (`anomaly_mode: true`). All types occur in both modes.

| SEPM log | Native description | `event.action` | Share | Category |
|---|---|---|---:|---|
| Agent Activity | `The management server received the client log successfully` | `client-log-received` | 81.1% | — |
| Agent Activity | `The client has downloaded the policy successfully` | `policy-downloaded` | 17.0% | — |
| Policy | `Policy has been edited: Edited shared <type> policy: <name>` | `policy-edited` | 0.74% | — |
| Agent Activity | `The client has downloaded the auto-upgrade configuration file successfully` | `auto-upgrade-config-downloaded` | 0.64% | — |
| Administrative | `Administrator log on succeeded` | `admin-logon` (`success`) | 0.38% | authentication |
| Administrative | `Administrator  log on failed` | `admin-logon` (`failure`) | 0.05% | authentication |
| Administrative | `Group '<name>' was added` | `group-added` | 0.05% | — |

Category follows the Elastic pipeline, which sets `event.category` and `event.outcome` only for log-on records.

### Volume and Populations

About 9,500 records per day, following the working day in UTC: about 680 per hour from 08:00 to 18:00, about 320 per hour at 07:00 and 18:00, and about 170 per hour at night.

- **Clients** (60 hosts, `samples/clients.json`). The 10 servers (`Servers` group) upload logs around the clock, about 8 uploads per server per hour. The 50 workstations (`Workstations`, `Finance`, `Sales` groups) are switched on from 07:00 to 19:00 UTC and upload about 9 times an hour each; at night only about 10 of them, a different set each night, stay on. About one upload in 125 is an auto-upgrade configuration download instead, roughly one per client per day.
- **Administrators** (12 accounts, `samples/admins.json`) work console sessions on their own schedules. The time between sessions is lognormal in working hours, with a per-account median of 1.25 to 9 hours, so sessions follow the working day; about 3% of administrator records fall between 20:00 and 07:00. Four busy accounts log on about 4 to 7 times a day, the others once or twice. A session starts with log-on attempts: 7% of first attempts fail, and 35% of retries after a failure fail too, so fewer sessions have two failures than one (about one attempt in ten fails). Retries follow seconds to minutes later; after 10% of failures the administrator gives up. SEPM locks an account for 15 minutes after five failures in a row, and the next attempt comes after the lockout. After a successful log-on, a quarter of sessions end without an operation; otherwise operations follow (each is followed by another with probability 0.6), a few seconds to 20 minutes apart. An operation is an edit of one of eight shared policies (`samples/policies.json`), or in 7% of cases a new group. Each administrator prefers a few policies (`focus` in `samples/admins.json`), for example the helpdesk account edits the USB device control policy; about a third of edits edit the same policy again in the same session. The console writes no logout record.
- **Policy downloads** follow each edit. Every client in a group assigned to the edited policy downloads it once, even after several edits: 75% within five minutes and 92% within ten (the next heartbeat), the rest, which were offline, minutes to hours later. Workstations switched off at night download the policy after they are switched on in the morning.

Rates and mixes are synthetic workload choices, not measured SEPM production frequencies.

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the generator emits only the background above, which never holds the complete chain. Every step still occurs there on its own and in partial sequences: log-ons with two or more failures followed by a success (a few per week), edits of a policy the same administrator edited within the past hour (20 to 30 a day), and failures without a following success.

Sequence, one episode (one extra console session of one administrator, on top of the account's own sessions):

1. Two to four `Administrator  log on failed` records, seconds apart, from the same retry distribution as the background, conditioned on at least two failures and a success before the lockout.
2. `Administrator log on succeeded`.
3. `Policy has been edited ... policy: <P>`: the first operation edits policy P. The clients assigned to P download it.
4. Zero to two other operations: edits of other policies, or a new group.
5. A second edit of P (the change reverted), which the clients download again.
6. Zero or more other operations, counted as in a background session, ending no later than the account's own next session.

Linking fields: `symantec_endpoint.log.admin` (`user.name`) across all steps, and `symantec_endpoint.log.policy_name` across steps 3 and 5. Client downloads link to an edit only through time and the policy's groups, because Agent Activity records carry no policy name. From the first failure to the second edit an episode spans about 2 to 20 minutes, rarely about an hour. All gaps between steps come from the background distributions.

Episode actors: each episode uses one of the busy administrator and policy pairs, the ones edited at least four times a day in the background (helpdesk-sec and the USB device control policy, sepm-ops and the exceptions policy, jdoe and the workstation AV policy, msmith and the workstation firewall policy with the shipped samples), weighted by how often each pair occurs. Each of these pairs occurs dozens of times a week in the background, on most days. The administrator is out of session, has no session of their own due within the hour and no failed log-ons pending; the account's own sessions happen as usual.

Recurrence: the interval is `anomaly_interval_hours`, 24 hours by default and at least 6. The first episode starts within min(24 h, interval) of the start of the data, at an hour drawn from the administrators' daily curve. Each later episode is due one interval after the actual start of the previous one and starts within a window of min(interval/4, 6 h) centred on that due time, preferring working hours; later episodes therefore recur at about the same time of day as the first. Missed episodes are not replayed. Consecutive episodes use a different administrator and a different policy. Measured: 14 episodes in 14 days at 24 hours (start gaps 21.4 to 27.4 hours) and 5 episodes in 10 days at 48 hours (47.4 to 50.2 hours).

Detection idea: one administrator fails to log on several times, then succeeds, edits a shared policy, and edits the same policy again within two hours. That pattern fits a guessed or stolen console account used to weaken protection briefly and cover it up. Each step and each pair of steps is ordinary administration here. The background never completes the sequence within 2 hours of the first failure: such an edit goes to another policy the administrator edits. Beyond 2 hours, the same sequence occurs in the background as it naturally would.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Description |
|---|---|---|
| `anomaly_mode` | `true` | Include periodic anomaly episodes; `false` gives background only |
| `anomaly_interval_hours` | `24` | Hours between episode starts; 6 to 8760, other values fail validation |
| `site_name` | `Site HQ-SEPM01` | SEPM site name (`Site:` field) |
| `server_name` | `HQ-SEPM01` | SEPM server name (`Server:` / `Server Name:` field) |
| `sepm_domain` | `Default` | SEPM domain (`Domain:` / `Domain Name:` field) |
| `machine_domain` | `corp.contoso.com` | Client machine domain, the last Agent Activity field |

Administrators come from `samples/admins.json` (`user`, `median_hours` of working time between sessions, `focus`: preferred policies with a weight multiplier). Shared policies come from `samples/policies.json` (`name`, `type`, assigned `groups`, `weight`), and clients from `samples/clients.json` (`host`, `user`, `group`). Episodes use the pairs edited at least four times a day, or the four most frequent pairs if fewer qualify; rotation needs pairs with at least two administrators and two policies. Values must not contain commas, which are the payload delimiter.

### Output Parameters

The shipped output writes `output/events.json` and needs no credentials. To send events elsewhere, replace the output and pass values through top-level placeholders, for example:

```yaml
output:
  - opensearch:
      hosts:
        - ${params.opensearch_host}
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: sepm-external
```

A collector that expects the native payload should read `event.original`.

## Usage

Live mode:

```bash
eventum generate --path generators/security-symantec-sepm/generator.yml --id sepm --live-mode true
```

Batch mode, as fast as possible:

```bash
eventum generate --path generators/security-symantec-sepm/generator.yml --id sepm --live-mode false
```

The files in `patterns/` set the daily volume curve and start on 2026-01-01 with no end. For a finite batch window, set `start` and `end` in each of them, for example `start: "2026-09-01T00:00:00Z"` and `end: "2026-09-15T00:00:00Z"`; keep `start` at midnight so the hours of the curve stay in place.

Performance: about 6,300 events per second in batch mode (14 days, 132,000 events, in 21 seconds).

## Sample Output

An episode's second edit of the policy (step 5), copied byte for byte from 7 days of default output (line 59253):

```json
{"@timestamp": "2026-09-07T09:43:32.311Z", "ecs": {"version": "8.11.0"}, "event": {"action": "policy-edited", "dataset": "symantec_endpoint.log", "kind": "event", "original": "Site: Site HQ-SEPM01,Server: HQ-SEPM01,Domain: Default,Admin: msmith,Event Description: Policy has been edited: Edited shared Firewall policy: Workstations Firewall Policy,Workstations Firewall Policy", "provider": "Policy Log"}, "message": "Policy has been edited: Edited shared Firewall policy: Workstations Firewall Policy", "symantec_endpoint": {"log": {"admin": "msmith", "domain_name": "Default", "event_description": "Policy has been edited: Edited shared Firewall policy: Workstations Firewall Policy", "policy_name": "Workstations Firewall Policy", "server": "HQ-SEPM01", "site": "Site HQ-SEPM01"}}, "user": {"domain": "Default", "name": "msmith"}}
```

## Limitations

- **Field order and layout.** Broadcom KB 155205 gives the field order of each log type and a few description examples, but no complete wire sample. The labelled layout (`Site: `, `Server: `, `Domain: `, `Admin: `, `Event Description: `; `Server Name: ` and `Domain Name: ` in Agent Activity) and the exact strings `Policy has been edited: Edited shared <type> policy: <name>` and `Administrator  log on failed` (with the double space) are copied from the Elastic integration test fixtures.
- **Inferred and excluded content.** The policy types other than Intrusion Prevention use the same wording, which is inferred. Policy add or delete, logout and other administrative descriptions have no verbatim example and are not generated. System (server activity) logs and all client-side logs (scan, risk, traffic, security) are not generated.
- **No syslog envelope.** The syslog header (`SymantecServer` program, priority) is not emitted, and neither are the dump-file time stamp and severity columns. `@timestamp` is the receive time in UTC with milliseconds; the working day is fixed at 08:00-18:00 UTC with no weekends or holidays.
- **Timing.** Records the server writes at the same moment are seconds apart instead of milliseconds, and a burst of policy downloads spreads over a few minutes. Log-on retries are about 18 seconds apart at the median.
- **Episode excess.** With `anomaly_mode: true` each episode adds its own records, so log-ons with two or more failures followed by a success are about one a day more frequent than in the background alone (a few per week), and the episode's administrator has one more session that day.
- **Payload limits.** A log-on record carries no source address, so the chain links by account only. Policy records do not show what changed, so the revert is inferred from the repeated edit. Agent Activity records do not name the policy downloaded.
- **Derived fields.** `event.action` is added for convenience and is not set by the Elastic pipeline.
- **Compatibility.** No recording from a live SEPM server was available for comparison. KUMA 4.2 lists a Symantec normalizer; compatibility with it is not verified.

## References

- [Broadcom KB 155205: External Logging settings and log event severity levels for SEPM (field order, policy event ids)](https://knowledge.broadcom.com/external/article/155205)
- [Broadcom KB 205271: changing the SEPM external-log delimiter (comma by default)](https://knowledge.broadcom.com/external/article/205271)
- [Broadcom TechDocs: unlocking an administrator account after too many logon attempts (five failures, 15-minute lockout by default)](https://techdocs.broadcom.com/us/en/symantec-security-software/endpoint-security-and-management/endpoint-protection/all/managing-groups-clients-and-administrators/managing-administrator-accounts-v17364367-d1e6/unlocking-an-administrator-s-account-after-too-man-v14183699-d1e543.html)
- [Elastic `symantec_endpoint` integration test fixtures](https://github.com/elastic/integrations/tree/main/packages/symantec_endpoint/data_stream/log/_dev/test/pipeline)
- [Elastic `symantec_endpoint` ingest pipeline](https://github.com/elastic/integrations/blob/main/packages/symantec_endpoint/data_stream/log/elasticsearch/ingest_pipeline/default.yml)
- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)
