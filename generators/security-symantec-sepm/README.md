# Symantec Endpoint Protection Manager External Logs

Generates Symantec Endpoint Protection Manager (SEPM) 14.3 external-log records, meaning the comma-delimited payloads SEPM sends to a syslog server, as ECS JSON for teams that test SIEM parsing and detection. Covers the Administrative, Policy and Agent Activity logs of one SEPM server. The native payload is kept verbatim in `event.original`, in the labelled layout of the Elastic `symantec_endpoint` integration fixtures. The rest of the document follows that integration's output (`symantec_endpoint.log.*`, `event.provider`).

## Event Types

Measured on a 10-day default capture (`anomaly_mode: true`, 29,971 events). All types occur in both modes.

| SEPM log | Native description | `event.action` | Share | Category |
|---|---|---|---:|---|
| Agent Activity | `The client has downloaded the policy successfully` | `policy-downloaded` | 48.7% | — |
| Agent Activity | `The management server received the client log successfully` | `client-log-received` | 45.8% | — |
| Administrative | `Administrator log on succeeded` | `admin-logon` (`success`) | 1.8% | authentication |
| Policy | `Policy has been edited: Edited shared <type> policy: <name>` | `policy-edited` | 1.7% | — |
| Agent Activity | `The client has downloaded the auto-upgrade configuration file successfully` | `auto-upgrade-config-downloaded` | 1.2% | — |
| Administrative | `Administrator  log on failed` | `admin-logon` (`failure`) | 0.6% | authentication |
| Administrative | `Group '<name>' was added` | `group-added` | 0.1% | — |

Category follows the Elastic pipeline, which sets `event.category` and `event.outcome` only for log-on records.

- **Administrators** (12 accounts, `samples/admins.json`) each follow their own random schedule of console sessions. The time between sessions is lognormal, with a per-account median of 1.5 to 9 hours. A session starts with log-on attempts: 20% of first attempts fail, and 45% of retries after a failure fail too. Retries follow seconds to minutes later, and after 12% of failures the administrator gives up. After a successful log-on the session holds zero or more operations (half of sessions end after each one), a few seconds to 20 minutes apart. An operation is an edit of one of eight shared policies (`samples/policies.json`, weighted), or in 7% of cases a new group. About a third of edits edit the same policy again. The console writes no logout record.
- **Clients** (60 hosts, `samples/clients.json`, in the Workstations, Finance, Sales and Servers groups) upload logs on independent lognormal schedules. Each host has its own median gap of 20 to 80 minutes. Every host also downloads the auto-upgrade configuration every day or so.
- **Policy downloads** follow each edit. Every client in a group assigned to the edited policy downloads it: 88% within about five minutes (the next heartbeat), and the rest, which are offline, minutes to hours later. A client with a download already pending downloads once.

One input tick per second emits the earliest due record, or nothing. Rates and mixes are synthetic workload choices, not measured SEPM production frequencies.

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the generator emits only the background above, which never holds the complete chain. Every step still occurs there on its own and in partial sequences. Per 10-day background capture (six captures):

- 12 to 27 log-ons with two or more failures followed by a success;
- 109 to 138 edits of a policy the same administrator edited within the past hour;
- 10 to 19 failures with no success within 10 minutes;
- after two failures, a success and an edit of P, 27 of 91 later edits by the same administrator 2 to 4 hours after the first failure go to P again (18 of 104 at 4 to 6 hours). Within 2 hours none does, because that edit would complete the chain.

Sequence, one episode (one extra console session of one administrator):

1. Two or more `Administrator  log on failed` records, seconds apart. The extra failures come from the same retry distribution as the background, conditioned on at least two (at most seven failures in a row).
2. `Administrator log on succeeded`.
3. `Policy has been edited ... policy: <P>`: the first operation of the session edits policy P. The clients assigned to P download it.
4. Zero to two other operations: edits of other policies, or a new group.
5. A second edit of P (the change reverted), which the clients download again.
6. Zero or more other operations, counted as in a background session (another one follows with probability 0.5). Then the session ends.

Linking fields: `symantec_endpoint.log.admin` (`user.name`) across all steps, and `symantec_endpoint.log.policy_name` across steps 3 and 5. Client downloads link to an edit only through time and the policy's groups, because Agent Activity records carry no policy name. Measured episode spans, from the first failure to the second edit: 1.5 to 9.1 minutes. All gaps between steps come from the background distributions.

Recurrence: the interval is `anomaly_interval_hours`, 24 hours by default and at least 6. The first episode is due at a random point within the first min(4 h, interval/6) of the run. Each episode starts at the first tick at or after its due time when an administrator is out of session, is not the previous episode's administrator, and has no own session due within 2 hours. The administrator is picked with the same per-account session-rate weighting as the background. The next episode is due one interval plus a random delay of up to min(4 h, interval/6) after the actual start, so start times drift across the day. Missed episodes are not replayed. Each episode picks a different administrator and a different policy than the previous one. The account's own schedule resumes unchanged afterwards, and no background activity is suspended or shifted.

Measured:

- 10 episodes in 10 days at 24 hours (start gaps 25.3 to 27.0 hours);
- 5 episodes in 10 days at 48 hours (48.3 to 51.3 hours).

Administrators and policies rotated every time. Across the reference off captures, every episode administrator also has background fail-fail-success log-ons, and every episode administrator-and-policy pair also occurs among background edits.

Detection idea: one administrator fails to log on several times, then succeeds, edits a shared policy, and edits the same policy again within two hours. That pattern fits a guessed or stolen console account used to weaken protection briefly and cover it up. Each step and each pair of steps is ordinary administration here. The background never completes the sequence within 2 hours of the first failure: a background edit that would complete it keeps its time and goes to a different policy. Beyond 2 hours, the same sequence occurs in the background as it naturally would.

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

Administrators come from `samples/admins.json` (`user`, `median_hours` between sessions). Shared policies come from `samples/policies.json` (`name`, `type`, assigned `groups`, `weight`), and clients from `samples/clients.json` (`host`, `user`, `group`). Rotation between episodes needs at least two administrators and two policies. Values must not contain commas, which are the payload delimiter.

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

Batch mode, as fast as possible (the cron input runs until stopped unless `start` and `end` are set on it):

```bash
eventum generate --path generators/security-symantec-sepm/generator.yml --id sepm --live-mode false
```

## Sample Output

An episode's second edit of the policy (step 5), copied byte for byte from the default capture (line 356):

```json
{"@timestamp": "2026-09-01T01:23:24.130Z", "ecs": {"version": "8.11.0"}, "event": {"action": "policy-edited", "dataset": "symantec_endpoint.log", "kind": "event", "original": "Site: Site HQ-SEPM01,Server: HQ-SEPM01,Domain: Default,Admin: helpdesk-sec,Event Description: Policy has been edited: Edited shared Virus and Spyware Protection policy: Workstations AV Policy,Workstations AV Policy", "provider": "Policy Log"}, "message": "Policy has been edited: Edited shared Virus and Spyware Protection policy: Workstations AV Policy", "symantec_endpoint": {"log": {"admin": "helpdesk-sec", "domain_name": "Default", "event_description": "Policy has been edited: Edited shared Virus and Spyware Protection policy: Workstations AV Policy", "policy_name": "Workstations AV Policy", "server": "HQ-SEPM01", "site": "Site HQ-SEPM01"}}, "user": {"domain": "Default", "name": "helpdesk-sec"}}
```

## Limitations

- **Field order and layout.** Broadcom KB 155205 gives the field order of each log type and a few description examples, but no complete wire sample. The labelled layout (`Site: `, `Server: `, `Domain: `, `Admin: `, `Event Description: `; `Server Name: ` and `Domain Name: ` in Agent Activity) and the exact strings `Policy has been edited: Edited shared <type> policy: <name>` and `Administrator  log on failed` (with the double space) are copied from the Elastic integration test fixtures.
- **Inferred and excluded content.** The policy types other than Intrusion Prevention use the same wording, which is inferred. Policy add or delete, logout and other administrative descriptions have no verbatim example and are not generated. System (server activity) logs and all client-side logs (scan, risk, traffic, security) are not generated.
- **No syslog envelope.** The syslog header (`SymantecServer` program, priority) is not emitted, and neither are the dump-file time stamp and severity columns. `@timestamp` is the receive time in UTC with milliseconds. Sessions and uploads have no diurnal pattern.
- **Payload limits.** A log-on record carries no source address, so the chain links by account only. Policy records do not show what changed, so the revert is inferred from the repeated edit. Agent Activity records do not name the policy downloaded.
- **Derived fields.** `event.action` is added for convenience and is not set by the Elastic pipeline.
- **Compatibility.** No live SEPM capture was available for comparison. KUMA 4.2 lists a Symantec normalizer; compatibility with it is not verified.

## References

- [Broadcom KB 155205: External Logging settings and log event severity levels for SEPM (field order, policy event ids)](https://knowledge.broadcom.com/external/article/155205)
- [Broadcom KB 205271: changing the SEPM external-log delimiter (comma by default)](https://knowledge.broadcom.com/external/article/205271)
- [Elastic `symantec_endpoint` integration test fixtures](https://github.com/elastic/integrations/tree/main/packages/symantec_endpoint/data_stream/log/_dev/test/pipeline)
- [Elastic `symantec_endpoint` ingest pipeline](https://github.com/elastic/integrations/blob/main/packages/symantec_endpoint/data_stream/log/elasticsearch/ingest_pipeline/default.yml)
- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)
