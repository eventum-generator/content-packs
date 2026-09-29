# Staffcop Enterprise Syslog

Synthetic Staffcop Enterprise 5.8 Syslog connector records in the vendor's native key-value format: screenshot and activity statistics events from 40 employee workstations, with the names of every policy the event matched. For SIEM and UEBA rule authors working with Staffcop data; it does not emit the optional CEF format.

## Event Types

Shares over one week (Monday to Sunday, 45,463 records) with default settings.

| Native `event` | Share | ECS category | Meaning |
|---|---:|---|---|
| `Screenshot` | 88.7% | `host` | Workstation screenshot, with zero or more matched policies |
| `Stat` | 11.3% | `host` | Activity statistics record closing a work bout in one application |

Policy matches (share of all records; one record may match several): `Облачные хранилища` 6.9%, `Финансовые данные` 6.5%, `Мессенджеры` 3.7%, `Перехват PrintScreen` 2.7%, `Социальные сети` 2.3%. 81% of records match no policy, 16% one, 3% two or more.

Each employee has a fixed workstation and address (`samples/employees.csv`: 10 finance, 9 sales, 9 development, 5 HR, 7 IT) and works independently: a bout is one or more screenshots in one application, sometimes closed by a `Stat` record. The application mix depends on the department; policy matches depend on the application and on whether the employee works with finance data. Finance workstations produce about a third of all records (about 1.6 times the per-employee volume of other departments), and finance staff regularly exchange documents through cloud storage in the browser: short bouts whose screenshots show a cloud storage page, often with finance documents, usually closed by a `Stat` that matches both policies (about 70 such `Stat` records per weekday across the department). Rates and probabilities are synthetic training assumptions, not measured Staffcop volume.

## Volume and Timing

About 8,600 records per weekday and 1,300 per weekend day. Hours are UTC on the log clock:

| Hours (UTC) | Weekday records/h | Weekend records/h |
|---|---:|---|
| 00-07, 21-24 | about 31 | about 31 |
| 07-08 | about 140 | about 31 |
| 08-09, 13-14, 18-19 | about 500 | about 78 |
| 09-13, 14-18 | about 790 | about 78 |
| 19-21 | 80-180 | 31-78 |

Each employee has a personal working day shifted by up to 1.5 hours, so who is active follows the curve, not only how much is logged. Screenshots of one bout are a median of about one minute apart in office hours and about three minutes apart at night, when little else happens.

The syslog header carries the connector dump time: the vendor documents a dump "once in 5 minutes", so headers advance in steps of about 300 s, and each record lands in the first dump after its agent upload delay. The `time` field and `@timestamp` hold the event time with second precision; `event.created` holds the dump time. The server `id` increases with random steps because events of other types, not selected by the connector filter, consume ids too.

## Anomaly Chain

`anomaly_mode` defaults to `true`. With `false` the generator emits the background only and the complete chain never occurs.

Sequence, one finance employee U within 30 minutes:

1. `Screenshot` in an office application (`excel`, `1cv8`, `winword`, `outlook` or `explorer`) matching `Финансовые данные`.
2. `Screenshot` in the same application matching `Перехват PrintScreen`.
3. `Screenshot` in a browser (`chrome` or `msedge`) matching `Облачные хранилища`.
4. `Stat` for that browser matching both `Облачные хранилища` and `Финансовые данные` (plus any other policy of step 3, each kept with the background probability).

Linking fields: `user.name`, `host.name`, `host.ip` (one workstation per employee), `process.name` between steps 1-2 and 3-4, `rule.name`.

Recurrence: the first episode starts within the first `min(anomaly_interval_hours, 24)` hours, at a time drawn from the office volume curve. Each later episode is due `anomaly_interval_hours` (default 24, minimum 2) after the actual start of the previous one and starts within a window of `min(interval / 4, 6 h)` centred on that due time, favouring the busiest hours of the window; a late episode never causes catch-up. With the default interval episodes fall on consecutive days, usually between 08:00 and 18:00 UTC, including light weekend daytime.

Variation: the employee is drawn from the finance group weighted by the same rate and personal working-hours curve as their ordinary bouts, never the previous episode's employee; applications are drawn from that employee's department mix; gaps use the ordinary in-bout gap (median 40 s) and a between-bout gap (median 150 s), and the whole episode takes at most 20 minutes (10 minutes at night and on weekends). The four episode records take the place of four ordinary records, so the hourly volume is the same in both modes; the employee's own bouts before, during and after the episode go on as usual.

Detection idea: per employee, a screenshot of finance data, then a PrintScreen capture, then cloud storage use, closed by a statistics record that matches both the cloud storage and finance policies, all within 30 minutes. Every step occurs in the ordinary activity of every finance employee in both modes (in any four days each finance employee has several of each, including the `Stat` with both policies), and so do partial chains by the same employee (finance -> PrintScreen, PrintScreen -> cloud, cloud -> dual `Stat`, the first three steps together). Only the complete ordered sequence is kept out of the ordinary activity: an ordinary `Stat` that would complete it within 30 minutes matches the cloud storage policy only.

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

Policy names are user-defined in Staffcop; the defaults are illustrative. Employees, workstations and addresses come from `samples/employees.csv` (`finance=yes` marks possible episode actors); edit that file to change names, hosts, addresses or departments (departments `finance`, `sales`, `dev`, `hr`, `it`).

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

Batch mode needs a finite window: in every file under `patterns/` set `oscillator.start` to a Monday at `00:00:00Z` (the weekday bands count from it) and `end` to the end of the window, then run:

```bash
eventum generate --path generators/security-staffcop-enterprise/generator.yml --id staffcop --live-mode false
```

The files under `patterns/` also set the volume: `multiplier.ratio` is the number of records per band per day (`night.yml`, `daytime.yml`) or per week (`weekdays/`); scale all ratios by the same factor to model a larger or smaller office without changing the hour curve.

Performance: about 1,100 records/s (14 days, 91,000 records, in 81 s).

## Limitations

- The vendor publishes three raw native lines (a `Screenshot` without policies, a `Screenshot` with `policy_1`, a `Stat` with `policy_1` and `policy_2`) and no field specification. Only these two `event` values are shown verbatim, so intercepted files, keyboard, web and other Staffcop event classes are not modelled, and application names follow the lowercase style of the example (`safari`).
- The order of `policy_N` is not documented and is random here. The day-of-month padding in both clocks is assumed to be the syslog space padding (`Sep  5`). Both clocks carry no year or time zone; the data treats them as UTC with second precision.
- Records are ordered by event time, while a real `/var/log/syslog` is ordered by dump time; agent upload delays (median 15 s, occasionally minutes) appear only in the header time.
- Volume follows one fixed weekly curve: no holidays, vacations, month-end peaks or differences between weekdays.
- At night screenshots of one bout are minutes apart rather than about a minute.
- With `anomaly_mode: true` each episode has its own four records, so counts of the chain parts (finance, PrintScreen and cloud storage screenshots, `Stat` records with both policies) are about one per episode higher than with `false`.
- The optional CEF export and SIEM-side normalizers are out of scope. No Elastic integration exists for Staffcop, so the ECS mapping is inferred (`rule.name` holds the matched policies).

## Sample Output

The final `Stat` of an episode:

```json
{"@timestamp": "2026-09-07T09:16:05+00:00", "ecs": {"version": "8.17.0"}, "event": {"action": "Stat", "category": ["host"], "created": "2026-09-07T09:19:07+00:00", "dataset": "staffcop.syslog", "id": "526503", "kind": "event", "original": "Sep  7 09:19:07 staffcop-srv staffcop: id=\"526503\" time=\"Sep  7 09:16:05\" event=\"Stat\" computer=\"WS-151\" ip=\"10.20.4.66\" user=\"e.kuznetsova\" app=\"chrome\" policy_1=\"\u0424\u0438\u043d\u0430\u043d\u0441\u043e\u0432\u044b\u0435 \u0434\u0430\u043d\u043d\u044b\u0435\" policy_2=\"\u041e\u0431\u043b\u0430\u0447\u043d\u044b\u0435 \u0445\u0440\u0430\u043d\u0438\u043b\u0438\u0449\u0430\"", "type": ["info"]}, "host": {"ip": ["10.20.4.66"], "name": "WS-151"}, "log": {"syslog": {"appname": "staffcop", "hostname": "staffcop-srv"}}, "observer": {"hostname": "staffcop-srv", "product": "Staffcop Enterprise", "vendor": "Atom Security"}, "process": {"name": "chrome"}, "related": {"hosts": ["WS-151"], "ip": ["10.20.4.66"], "user": ["e.kuznetsova"]}, "rule": {"name": ["\u0424\u0438\u043d\u0430\u043d\u0441\u043e\u0432\u044b\u0435 \u0434\u0430\u043d\u043d\u044b\u0435", "\u041e\u0431\u043b\u0430\u0447\u043d\u044b\u0435 \u0445\u0440\u0430\u043d\u0438\u043b\u0438\u0449\u0430"]}, "user": {"name": "e.kuznetsova"}}
```

Decoded, `event.original` reads `Sep  7 09:19:07 staffcop-srv staffcop: id="526503" time="Sep  7 09:16:05" event="Stat" computer="WS-151" ip="10.20.4.66" user="e.kuznetsova" app="chrome" policy_1="Финансовые данные" policy_2="Облачные хранилища"`.

## References

- [Staffcop Enterprise 5.8: SIEM integration through the Syslog connector (native samples, five-minute dump, CEF option)](https://docs.staffcop.ru/1ver/integrations/syslog_connector.html)
- [Staffcop Enterprise 5.8 changelog: all matched policies passed through Syslog](https://docs.staffcop.ru/changelog.html)
- [Staffcop Enterprise 5.8: RuSIEM integration (rsyslog forwarding, PrintScreen policy example)](https://docs.staffcop.ru/1ver/integrations/rusiem_staffcop.html)
