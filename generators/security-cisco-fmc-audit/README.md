# Cisco Secure Firewall Management Center Audit

Generates Cisco Secure Firewall Management Center (FMC) 7.4 audit Syslog records as ECS JSON: web-interface page views, network object creation, NAT policy saves, and the system pre-deploy task records that follow a save. The FMC-originating Syslog line is kept verbatim in `event.original`, in the forms of Cisco TechNote 221019 (FMCv 7.4.0). Managed FTD connection, intrusion and file events are a separate stream.

## Event Types

Measured on a 14-day default capture (`anomaly_mode: true`, 3,100 events). All classes occur in both modes.

| Native `Sender` / `Subsystem`, `Action` | `event.action` | Share | Category |
|---|---|---:|---|
| `sfdccsm` / `Devices > NAT > NGFW NAT Policy Editor`, `Page View` | `page-view` | 35.0% | web |
| `sfdccsm` / `Devices > NAT`, `Page View` | `page-view` | 17.7% | web |
| `mojo_server.pl` / `/ui/ddd/`, `Page View` | `page-view` | 13.4% | web |
| `sfdccsm` / `Devices > NAT > NAT Policy Editor`, `Save Policy <policy>` | `nat-policy-save` | 10.4% | configuration |
| `ActionQueueScrape.pl` / `Login`, `Login Success` (`csm_processes@Default User IP`) | `login-success` | 8.8% | authentication |
| `ActionQueueScrape.pl` / `Task Queue`, `Successful task completion : Pre-deploy Global Configuration Generation` (`admin@localhost`) | `task-completion` | 8.8% | configuration |
| `sfdccsm` / `Objects > Object Management > NetworkObject`, `create <object>` | `network-object-create` | 5.8% | configuration |

Ten administrator accounts (`samples/admins.json`) each follow their own random schedule: sessions every few hours to a few days (lognormal, per-account median 4 to 20 hours between sessions), from the account's usual workstation address or, in about 15% of sessions, a second address. A session opens on the dashboard or the NAT list and holds one to about twenty actions seconds to minutes apart (most often a few):

- **Page views** of the NAT list, the NAT policy editor and the dashboard.
- **Network object creation** with a new name (`<prefix>-<number>`, prefixes in `generator.yml`). More than half of the creations are followed later in the session by a NAT policy save (the object put into a rule).
- **NAT policy save** of one of seven policies (`generator.yml`), always from the editor, which is shown again within a second, as in the Cisco sample. About a fifth of saves are saved again later in the session.

In 85% of saves the system then logs `csm_processes` `Login Success` a few seconds to two minutes later (median about 20 seconds) and the pre-deploy task completion about a second after that, as in the Cisco sample. One input tick per second emits the earliest due record, or nothing. Rates, durations and the action mix are synthetic workload choices, not measured FMC production frequencies.

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the generator emits only the background above, which never holds the complete chain; every step still occurs there on its own and in partial sequences. Per 14-day background capture: 83 to 125 saves within an hour after the same account and address created an object, and 61 to 84 saves of a policy that the same account and address already saved within the hour.

Sequence, one episode (one session of one account, from one of that account's usual addresses):

1. Zero to two page views.
2. `NetworkObject, create <object>`: a new network object.
3. Zero to two page views, then the NAT policy editor and `Save Policy <P>`; the editor is shown again, the system login and pre-deploy task follow as for any save.
4. Zero to four page views.
5. `Save Policy <P>` of the same policy: the change is reverted, followed again by the editor view and the pre-deploy task.
6. Zero to two page views; the session ends (the web interface writes no logout record).

Linking fields: `user.name` and `source.ip` (the `User_Name@User_IP` sender part) across steps 2, 3 and 5, and the policy name (`cisco.fmc.audit.policy`, parsed from `Save Policy <P>`) across steps 3 and 5. The system records carry `csm_processes@Default User IP` and `admin@localhost` and link to a save only by time. Measured episode spans (create to second save): 0.8 to 8.0 minutes across the 14-day captures (default and 48-hour). All gaps come from the same distributions as background actions.

Recurrence: the first episode is due `anomaly_interval_hours` after the first tick (default 24, minimum 6). It starts at a random delay of up to 30 minutes (up to an eighth of the interval for short intervals) after it is due, on the first moment an account is out of session with no own session due within 3 hours; otherwise it waits. The next episode is due one interval after the actual start; missed episodes are not replayed. Each episode picks a different account (weighted by how often each account works) and a different policy than the previous one, and a new object name. The episode is an extra session: the account's own schedule resumes unchanged, and no background activity is suspended or shifted. Measured: 13 episodes in 14 days at 24 hours (start gaps 24.0 to 24.4 hours), 6 in 14 days at 48 hours (48.3 to 48.6 hours); rotated accounts and policies in every case, every episode account and address also occurs in background, and most account, address and policy combinations do (with 7 policies and 10 accounts a few combinations are rare in a two-week capture).

Detection idea: one account creates a network object, saves a NAT policy and saves the same policy again within an hour - a NAT change pushed to the pre-deploy stage and reverted soon after, for example a short-lived exposure of an internal host. Each step alone, and each pair of steps, is ordinary administration here. Background never completes the sequence: an ordinary save that would complete it is replaced by an editor page view. The audit record does not show what changed, so the revert is inferred from the repeated save.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Description |
|---|---|---|
| `anomaly_mode` | `true` | Include periodic anomaly episodes; `false` gives background only |
| `anomaly_interval_hours` | `24` | Hours between episode starts; 6 to 8760, other values fail validation |
| `management_center` | `firepower` | FMC hostname in the Syslog header and `observer.hostname` |

Accounts come from `samples/admins.json` (`user`, `ip`, `alt_ip`, `median_hours` between sessions), NAT policies from `nat_policies` and object name prefixes from `object_prefixes` in `generator.yml`. Episode rotation needs at least two accounts and two policies.

### Output Parameters

The shipped output writes `output/events.json` and needs no credentials. To send events elsewhere, replace the output and pass values through top-level placeholders, for example:

```yaml
output:
  - opensearch:
      hosts:
        - ${params.opensearch_host}
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: fmc-audit
```

A collector that expects the native Syslog line should read `event.original`.

## Usage

Live mode:

```bash
eventum generate --path generators/security-cisco-fmc-audit/generator.yml --id fmc --live-mode true
```

Batch mode, as fast as possible (the cron input runs until stopped unless `start` and `end` are set on it):

```bash
eventum generate --path generators/security-cisco-fmc-audit/generator.yml --id fmc --live-mode false
```

## Sample Output

An episode's second save (step 5), copied byte for byte from a default capture regenerated after the day-padding fix (line 243):

```json
{"@timestamp": "2026-09-02T00:27:23+00:00", "cisco": {"fmc": {"audit": {"message": "Save Policy NAT-DMZ-Web", "policy": "NAT-DMZ-Web", "sender": "sfdccsm", "subsystem": "Devices > NAT > NAT Policy Editor", "tag": "FMC-AUDIT", "user": "jsmith", "user_ip": "10.1.20.14"}}}, "ecs": {"version": "8.17.0"}, "event": {"action": "nat-policy-save", "category": ["configuration"], "dataset": "cisco_fmc.audit", "kind": "event", "module": "cisco_fmc", "original": "Sep 02 00:27:23 firepower: [FMC-AUDIT] sfdccsm: jsmith@10.1.20.14, Devices > NAT > NAT Policy Editor, Save Policy NAT-DMZ-Web", "type": ["change"]}, "message": "Devices > NAT > NAT Policy Editor, Save Policy NAT-DMZ-Web", "observer": {"hostname": "firepower", "product": "Secure Firewall Management Center", "vendor": "Cisco", "version": "7.4.0"}, "process": {"name": "sfdccsm"}, "related": {"hosts": ["firepower"], "ip": ["10.1.20.14"], "user": ["jsmith"]}, "source": {"ip": "10.1.20.14"}, "user": {"name": "jsmith"}}
```

## Limitations

- The only complete native examples are the eight lines of Cisco TechNote 221019 (FMCv 7.4.0). Every generated line uses one of those seven forms; only the user, address, object name, policy name and time vary. The administration guide describes the layout (`Date Time Host: [Tag] Sender: User_Name@User_IP, Subsystem, Action`) and lists many more subsystems, but gives no further verbatim lines, so other menus, object types, deletions, deployments and human logins and logouts are not generated. Real audit streams cover far more of the interface than NAT.
- Failed logins are not modeled: the guide states that audit records of login errors carry neither user nor source address.
- The `[FMC-AUDIT]` tag is the one configured in the TechNote; it is user-defined on a real FMC. The collector-side prefix of the TechNote lines (receive time, `localhost`, sender address) is not emitted. The BSD Syslog header has no year or zone and one-second precision; `@timestamp` supplies the date and the time of day is UTC. Web sessions have no diurnal pattern. The day of month is zero-padded, as in the admin guide sample (`Mar 01`).
- The object name is synthetic and the Syslog record never names the rule or object a save changed; the pre-deploy task records link to a save only by time, as in the source.
- `cisco.fmc.audit.*` is parsed from the line (`policy` and `object` from the action text); `event.*`, `user.*`, `source.*`, `process.*`, `observer.*` and `related.*` are ECS normalization, not source fields. No Elastic integration for FMC audit Syslog was found to mirror.
- KUMA 4.2 lists a Secure Firewall Management Center normalizer for CEF; this pack does not generate CEF and does not claim compatibility with that normalizer. No live capture was available for comparison.

## References

- [Cisco TechNote 221019: configure FMC to send audit logs to a Syslog server (7.4.0 examples)](https://www.cisco.com/c/en/us/support/docs/security/secure-firewall-management-center/221019-configure-fmc-to-send-audit-logs-to-a-sy.html)
- [Cisco Secure FMC Administration Guide 7.4: Audit and Syslog](https://www.cisco.com/c/en/us/td/docs/security/secure-firewall/management-center/admin/740/management-center-admin-74/health-audit.html)
- [KUMA 4.2 supported sources](https://support.kaspersky.ru/kuma/4.2/255782)
