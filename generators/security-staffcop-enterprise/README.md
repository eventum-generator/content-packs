# Staffcop Enterprise Syslog

Synthetic Staffcop Enterprise 5.8 Syslog connector records in the vendor's native key-value format: screenshot and activity statistics events from 40 employee workstations, with the names of every policy the event matched. For SIEM and UEBA rule authors working with Staffcop data; it does not emit the optional CEF format.

## Event Types

Shares measured on the final 100-hour default capture (31,290 records, anomaly mode on).

| Native `event` | Share | ECS category | Meaning |
|---|---:|---|---|
| `Screenshot` | 89.9% | `host` | Workstation screenshot, with zero or more matched policies |
| `Stat` | 10.1% | `host` | Activity statistics record closing a work bout in one application |

Policy matches (share of all records; one record may match several): `Мессенджеры` 4.4%, `Облачные хранилища` 3.6%, `Финансовые данные` 3.5%, `Социальные сети` 2.1%, `Перехват PrintScreen` 1.3%. 86% of records match no policy, 13% one, 0.7% two or three.

Each employee has a fixed workstation and address (`samples/employees.csv`: 10 finance, 9 sales, 9 development, 5 HR, 7 IT) and works independently: bouts start as a Poisson process with a per-employee rate and a personal working-hours curve (quiet nights, a lunch dip, quiet weekends); a bout is one or more screenshots in one application, sometimes closed by a `Stat` record, with log-normal gaps. The application mix depends on the department; policy matches depend on the application and on whether the employee works with finance data. Rates and probabilities are synthetic training assumptions, not measured Staffcop volume.

The syslog header carries the connector dump time: the vendor documents a dump "once in 5 minutes", so headers advance in steps of about 300 s, and each record lands in the first dump after its agent upload delay. The `time` field and `@timestamp` hold the event time; `event.created` holds the dump time. The server `id` increases with random steps because events of other types, not selected by the connector filter, consume ids too.

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the generator emits the background only and the complete chain never occurs.

Sequence, one finance employee U within 30 minutes:

1. `Screenshot` in an office application (`excel`, `1cv8`, `winword`, `outlook` or `explorer`) matching `Финансовые данные`.
2. `Screenshot` in the same application matching `Перехват PrintScreen`.
3. `Screenshot` in a browser (`chrome` or `msedge`) matching `Облачные хранилища`.
4. `Stat` for that browser matching both `Облачные хранилища` and `Финансовые данные` (plus any other policy of step 3, each kept with the background probability).

Linking fields: `user.name`, `host.name`, `host.ip` (one workstation per employee), `process.name` between steps 1-2 and 3-4, `rule.name`.

Recurrence: an episode becomes due every `anomaly_interval_hours` of source time (default 24, minimum 2), first one interval after generation starts. Once due, it starts after a random delay whose rate follows the finance staff's working-hours load (mean 45 minutes at full load, so an episode due at night or on a weekend waits for working hours). The next due time counts from the actual start; a late episode never causes catch-up. Measured: default 24 h, 3 episodes in 100 h, start gaps 26.8/25.4 h, spans 162-1360 s; custom 8 h, 9 episodes, gaps 8.2-14.1 h.

Variation: the employee is drawn from the finance group weighted by the same rate and working-hours load as their background bouts, excluding the previous episode's employee; applications are drawn from that employee's department mix; gaps use the background in-bout gap (median 40 s) and a between-bout gap (median 150 s). The episode adds four records and never pauses or shifts the employee's background.

Detection idea: per employee, a screenshot of finance data, then a PrintScreen capture, then cloud storage use, closed by a statistics record that matches both the cloud storage and finance policies, all within 30 minutes. Every step occurs in the background of both modes, including the final `Stat` with both policies (about 26 per 100 hours) and partial chains by the same employee (finance -> PrintScreen, PrintScreen -> cloud, cloud -> dual `Stat`, the first three steps together). Only the complete ordered sequence is kept out of the background: an ordinary `Stat` that would complete it loses its finance policy.

The policies are Staffcop's own matches, not proof of intent: the chain is a correlation pattern for rule testing, and a policy count is not a severity scale.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
|---|---|---|
| `anomaly_mode` | `true` | Add periodic episodes to the background |
| `anomaly_interval_hours` | `24` | Episode interval in source hours, 2-8760 |
| `syslog_host` | `staffcop-srv` | Staffcop server hostname in the syslog header and `observer.hostname` |
| `policy_finance` | `Финансовые данные` | Finance-data policy (chain steps 1 and 4) |
| `policy_printscreen` | `Перехват PrintScreen` | PrintScreen policy (chain step 2) |
| `policy_cloud` | `Облачные хранилища` | Cloud storage policy (chain steps 3 and 4) |
| `policy_social` | `Социальные сети` | Social networks policy (background) |
| `policy_messengers` | `Мессенджеры` | Messengers policy (background) |

Policy names are user-defined in Staffcop; the defaults are illustrative. Employees, workstations and addresses come from `samples/employees.csv` (`finance=yes` marks possible episode actors).

### Output Parameters

The shipped config writes `output/events.json` with the `json` formatter and needs no `${params.*}` or `${secrets.*}`. To send events elsewhere, replace the `output` section, for example:

```yaml
output:
  - opensearch:
      hosts: ["${params.opensearch_url}"]
      username: ${params.opensearch_user}
      password: ${secrets.opensearch_password}
      index: staffcop-enterprise
```

## Usage

Live mode:

```bash
eventum generate --path generators/security-staffcop-enterprise/generator.yml --id staffcop --live-mode true
```

Batch mode needs a bounded input: add `start` and `end` to the `cron` input, then run:

```bash
eventum generate --path generators/security-staffcop-enterprise/generator.yml --id staffcop --live-mode false
```

## Limitations

- The vendor publishes three raw native lines (a `Screenshot` without policies, a `Screenshot` with `policy_1`, a `Stat` with `policy_1` and `policy_2`) and no field specification. Only these two `event` values are shown verbatim, so intercepted files, keyboard, web and other Staffcop event classes are not modelled, and application names follow the lowercase style of the example (`safari`).
- The order of `policy_N` is not documented and is random here. The day-of-month padding in both clocks is assumed to be the syslog space padding (`Sep  5`). Both clocks carry no year or time zone; the generator treats them as UTC with second precision.
- Records are ordered by event time, while a real `/var/log/syslog` is ordered by dump time; agent upload delays (median 15 s, occasionally minutes) are modelled only in the header time.
- The optional CEF export and SIEM-side normalizers are out of scope. No Elastic integration exists for Staffcop, so the ECS mapping is inferred (`rule.name` holds the matched policies).

## Sample Output

The final `Stat` of the first episode, copied byte for byte from the final default-mode capture:

```json
{"@timestamp": "2026-09-29T06:30:50+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "Stat", "category": ["host"], "created": "2026-09-29T06:33:49+00:00", "dataset": "staffcop.syslog", "id": "484668", "kind": "event", "original": "Sep 29 06:33:49 staffcop-srv staffcop: id=\"484668\" time=\"Sep 29 06:30:50\" event=\"Stat\" computer=\"WS-120\" ip=\"10.20.4.194\" user=\"d.smirnov\" app=\"chrome\" policy_1=\"\u0424\u0438\u043d\u0430\u043d\u0441\u043e\u0432\u044b\u0435 \u0434\u0430\u043d\u043d\u044b\u0435\" policy_2=\"\u041e\u0431\u043b\u0430\u0447\u043d\u044b\u0435 \u0445\u0440\u0430\u043d\u0438\u043b\u0438\u0449\u0430\"", "type": ["info"]}, "host": {"ip": ["10.20.4.194"], "name": "WS-120"}, "log": {"syslog": {"appname": "staffcop", "hostname": "staffcop-srv"}}, "observer": {"hostname": "staffcop-srv", "product": "Staffcop Enterprise", "vendor": "Atom Security"}, "process": {"name": "chrome"}, "related": {"hosts": ["WS-120"], "ip": ["10.20.4.194"], "user": ["d.smirnov"]}, "rule": {"name": ["\u0424\u0438\u043d\u0430\u043d\u0441\u043e\u0432\u044b\u0435 \u0434\u0430\u043d\u043d\u044b\u0435", "\u041e\u0431\u043b\u0430\u0447\u043d\u044b\u0435 \u0445\u0440\u0430\u043d\u0438\u043b\u0438\u0449\u0430"]}, "user": {"name": "d.smirnov"}}
```

Decoded, `event.original` reads `Sep 29 06:33:49 staffcop-srv staffcop: id="484668" time="Sep 29 06:30:50" event="Stat" computer="WS-120" ip="10.20.4.194" user="d.smirnov" app="chrome" policy_1="Финансовые данные" policy_2="Облачные хранилища"`.

## References

- [Staffcop Enterprise 5.8: SIEM integration through the Syslog connector (native samples, five-minute dump, CEF option)](https://docs.staffcop.ru/1ver/integrations/syslog_connector.html)
- [Staffcop Enterprise 5.8 changelog: all matched policies passed through Syslog](https://docs.staffcop.ru/changelog.html)
- [Staffcop Enterprise 5.8: RuSIEM integration (rsyslog forwarding, PrintScreen policy example)](https://docs.staffcop.ru/1ver/integrations/rusiem_staffcop.html)
