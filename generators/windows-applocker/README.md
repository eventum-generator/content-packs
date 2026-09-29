# windows-applocker

Microsoft-Windows-AppLocker records from the **EXE and DLL** and **MSI and
Script** channels, emitted as Winlogbeat-style ECS JSON with the raw event
XML in `event.original`. A fleet of workstations runs applications, scripts
and installers under an enforced AppLocker policy: signed binaries in
`Program Files`, `System32` and the corporate app folder are allowed
(8002/8005), while executables and scripts launched from user-writable
folders (`Downloads`, `Desktop`, `%TEMP%`, roaming profiles) are blocked
(8004/8007). Three hosts run the policy in Audit-only mode for scripts, so
their would-be blocks surface as 8006 instead. Two administrators
(`adm.tkachenko`, `adm.lindqvist`) log on to random hosts for short visits;
the default admin rules allow what they launch from user folders.

## Run

From the content-packs repository root:

```bash
eventum generate --path generators/windows-applocker/generator.yml --id windows-applocker --live-mode true
```

Batch to a file:

```bash
eventum generate --path generators/windows-applocker/generator.yml --id windows-applocker --live-mode false
```

Output goes to `generators/windows-applocker/output/events.json`.

The hour-of-day curve lives in `patterns/` (`baseline.yml`,
`workday.yml`, `office.yml`). Each file starts on `2026-01-01T00:00:00Z`
and runs with `end: never`, so a batch run needs a finite window: set
`start` and `end` in all three files, with `start` at midnight UTC so
the office-hours bands keep their hours. Scale every `ratio` by the
same factor to change the volume.

Performance: about 1,000 records per second of generation on one core.

## Events

About 9,250 records a day from 18 workstations and two administrators:

| Event ID | Channel | Meaning | Share | Per host per day | ECS category |
| --- | --- | --- | --- | --- | --- |
| `8002` | EXE and DLL | Executable/DLL allowed to run | 76.0% | ~390 | `process` |
| `8005` | MSI and Script | Script/MSI allowed to run | 20.9% | ~108 | `process` |
| `8004` | EXE and DLL | Executable/DLL prevented from running | 2.0% | ~10 | `process` |
| `8007` | MSI and Script | Script/MSI prevented from running | 1.0% | ~6 (on the 15 enforced hosts) | `process` |
| `8006` | MSI and Script | Script/MSI would have been blocked (Audit only) | ~0.2% | ~6.5 (on the 3 audit hosts) | `process` |

`event.code` is a string; `event.action` is `None` and `event.type` is
`["start"]`, matching the Elastic Windows integration output for these
channels. `log.level` / `winlog.level` follow the Microsoft event table:
information for 8002/8005, warning for 8006, error for 8004/8007.

## Volume and Timing

Volume follows a working day in UTC; every day has the same shape
(within about 3%):

| UTC hours | Records per second (fleet) | Share of daily volume |
| --- | --- | --- |
| 00:00-07:00 | ~0.012 | 3.2% |
| 07:00-08:00 | ~0.08 | 3.2% |
| 08:00-17:00 | ~0.24 | 85.0% |
| 17:00-19:00 | ~0.08 | 6.4% |
| 19:00-24:00 | ~0.012 | 2.3% |

Each standard user works on their own workstation in one logon session
of most of a day (the screen stays locked overnight), about one logon
per user per day; a new session starts with `explorer.exe`. Users differ
in pace by up to a factor of about three. Each administrator makes about
three visits a day to random workstations, each a short session of
roughly 40 minutes with a burst of launches. Inside a session, about
84% of operations launch an application, 15% start a script host or
`msiexec` that loads several scripts or packages, and 1.5% try a file
from a user-writable folder. A blocked file is retried with falling
probability (one attempt more common than two, two than three).

## Anomaly Chain

Inside a standard user's ordinary logon session on their own enforced
workstation, in order and within about 25 minutes:

1. **8004** - an executable from a user-writable folder is blocked (with
   the odd immediate retry).
2. **8007** - a script or installer from a user-writable folder is blocked.
3. **8002** - a living-off-the-land proxy binary
   (`rundll32`/`regsvr32`/`mshta`/`certutil`/`MSBuild`) launches and is
   allowed by the Windows-folder default rule.

**Linking fields.** All three share `host.name`,
`winlog.user_data.TargetUser` (the user SID) and
`winlog.user_data.TargetLogonId` (the logon session). A detector groups by
that triple and looks for a blocked exe, then a blocked script, then a
proxy-binary launch inside one session.

**Recurrence.** Episodes recur every `anomaly_interval_hours` of source
time (default 24 h, minimum 6 h). The first episode starts within
`min(interval, 24 h)` of the start of the data, at an hour drawn from the
volume curve above. Each next episode is due one interval after the
actual previous start and starts within a window of
`w = min(interval / 4, 6 h)` centred on that time, with busy hours
strongly preferred, so start hours do not drift; missed time is not
caught up. If no eligible session is open at that moment, the start
waits for one (at most a few minutes in practice). The acting user is
drawn with the same activity weights as ordinary work, and both user and
host differ from the previous episode's, so actors rotate. The episode's
records are added to the user's ordinary session; the session's own
launches continue at their usual pace before, during and after it.
AppLocker changes no state, so there is nothing to restore.

**Variation.** File names, retry counts, inter-step delays, the proxy
binary, the acting user and session are all drawn per episode from the same
generators the background uses; no value is constant.

**Detection idea.** Alert on the ordered triple above within one
`(host, TargetUser, TargetLogonId)`. Note that every individual step and
every two-step prefix also occurs in normal traffic (see below), so only the
full ordered sequence is distinctive.

**anomaly_mode.** Default `true` mixes the chain into the background. With
`false` the generator emits background only and never produces the complete
ordered chain. Every ingredient the chain uses - blocked exes and scripts
from user folders, repeated blocks by one user within minutes, proxy-binary
launches, and the partial two-step combinations - occurs in the background
of both modes, on the same users and workstations the episodes use; only
the full three-step sequence within one session is withheld from the
background. A proxy-binary launch that would complete that sequence in
ordinary activity is replaced by the launch of another application.

## Parameters

### Event Parameters

| Parameter | Default | Meaning |
| --- | --- | --- |
| `anomaly_mode` | `true` | Mix in the anomaly chain; `false` emits background only |
| `anomaly_interval_hours` | `24` | Source-time interval between episodes (6-8760) |

Hosts, users, allowed applications, blocked user-folder files and scripts
are defined in `samples/` (`hosts.json`, `users.json`, `apps.json`,
`user_files.json`, `scripts.json`, `user_scripts.json`). Edit those files to
retarget the fleet; every path, SID and signer there is synthetic.

### Output Parameters

No `${params.*}` or `${secrets.*}` placeholders ship. Local file output
needs no credentials. Replace the `output` block with a destination plugin
(and keep any credentials in Eventum secrets) to forward events - for
example a Windows event collector or a SIEM ingest endpoint.

## Sample output

One record of the default output (an allowed Chrome launch, 8002):

```json
{
  "@timestamp": "2026-09-01T10:00:56.705Z",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "None",
    "category": [
      "process"
    ],
    "code": "8002",
    "dataset": "windows.applocker_exe_and_dll",
    "kind": "event",
    "original": "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Microsoft-Windows-AppLocker\" Guid=\"{cbda4dbf-8d5d-4f69-9578-be14aa540d22}\"/><EventID>8002</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime=\"2026-09-01T10:00:56.7054870Z\"/><EventRecordID>169311</EventRecordID><Correlation/><Execution ProcessID=\"10540\" ThreadID=\"30480\"/><Channel>Microsoft-Windows-AppLocker/EXE and DLL</Channel><Computer>ws-legal-106.contoso.local</Computer><Security UserID=\"S-1-5-21-1504711230-2873091451-3906125842-1139\"/></System><UserData><RuleAndFileData xmlns=\"http://schemas.microsoft.com/schemas/event/Microsoft.Windows/1.0.0.0\"><PolicyNameLength>3</PolicyNameLength><PolicyName>EXE</PolicyName><RuleId>{921CC481-6E17-4653-8F75-050B80ACCA20}</RuleId><RuleNameLength>60</RuleNameLength><RuleName>(Default Rule) All files located in the Program Files folder</RuleName><RuleSddlLength>63</RuleSddlLength><RuleSddl>D:(XA;;FX;;;S-1-1-0;(APPID://PATH Contains \"%PROGRAMFILES%\\*\"))</RuleSddl><TargetUser>S-1-5-21-1504711230-2873091451-3906125842-1139</TargetUser><TargetProcessId>29320</TargetProcessId><FilePathLength>51</FilePathLength><FilePath>%PROGRAMFILES%\\GOOGLE\\CHROME\\APPLICATION\\CHROME.EXE</FilePath><FileHashLength>32</FileHashLength><FileHash>5407D34AF3F59BE98E28F7E62FA638D7A825927136FCE00705FDD29C5958F50D</FileHash><FqbnLength>89</FqbnLength><Fqbn>O=GOOGLE LLC, L=MOUNTAIN VIEW, S=CALIFORNIA, C=US\\GOOGLE CHROME\\CHROME.EXE\\118.0.5993.118</Fqbn><TargetLogonId>0x1bb7a92</TargetLogonId><FullFilePathLength>53</FullFilePathLength><FullFilePath>C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe</FullFilePath></RuleAndFileData></UserData></Event>",
    "provider": "Microsoft-Windows-AppLocker",
    "type": [
      "start"
    ]
  },
  "file": {
    "hash": {
      "sha256": "5407D34AF3F59BE98E28F7E62FA638D7A825927136FCE00705FDD29C5958F50D"
    },
    "name": "chrome.exe",
    "pe": {
      "file_version": "118.0.5993.118",
      "original_file_name": "CHROME.EXE",
      "product": "GOOGLE CHROME"
    },
    "x509": {
      "subject": {
        "country": [
          "US"
        ],
        "locality": "MOUNTAIN VIEW",
        "organization": [
          "GOOGLE LLC"
        ],
        "state_or_province": [
          "CALIFORNIA"
        ]
      }
    }
  },
  "host": {
    "name": "ws-legal-106.contoso.local"
  },
  "log": {
    "level": "information"
  },
  "message": "%PROGRAMFILES%\\GOOGLE\\CHROME\\APPLICATION\\CHROME.EXE was allowed to run.",
  "process": {
    "pid": 10540
  },
  "tags": [
    "preserve_original_event"
  ],
  "user": {
    "id": "S-1-5-21-1504711230-2873091451-3906125842-1139"
  },
  "winlog": {
    "channel": "Microsoft-Windows-AppLocker/EXE and DLL",
    "computer_name": "ws-legal-106.contoso.local",
    "event_id": "8002",
    "level": "information",
    "opcode": "Info",
    "process": {
      "pid": 10540,
      "thread": {
        "id": 30480
      }
    },
    "provider_guid": "{cbda4dbf-8d5d-4f69-9578-be14aa540d22}",
    "provider_name": "Microsoft-Windows-AppLocker",
    "record_id": "169311",
    "task": "None",
    "time_created": "2026-09-01T10:00:56.705Z",
    "user": {
      "identifier": "S-1-5-21-1504711230-2873091451-3906125842-1139"
    },
    "user_data": {
      "FileHash": "5407D34AF3F59BE98E28F7E62FA638D7A825927136FCE00705FDD29C5958F50D",
      "FileHashLength": 32,
      "FilePath": "%PROGRAMFILES%\\GOOGLE\\CHROME\\APPLICATION\\CHROME.EXE",
      "FilePathLength": 51,
      "Fqbn": "O=GOOGLE LLC, L=MOUNTAIN VIEW, S=CALIFORNIA, C=US\\GOOGLE CHROME\\CHROME.EXE\\118.0.5993.118",
      "FqbnLength": 89,
      "FullFilePath": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
      "FullFilePathLength": 53,
      "PolicyName": "EXE",
      "PolicyNameLength": 3,
      "RuleId": "{921CC481-6E17-4653-8F75-050B80ACCA20}",
      "RuleName": "(Default Rule) All files located in the Program Files folder",
      "RuleNameLength": 60,
      "RuleSddl": "D:(XA;;FX;;;S-1-1-0;(APPID://PATH Contains \"%PROGRAMFILES%\\*\"))",
      "RuleSddlLength": 63,
      "TargetLogonId": "0x1bb7a92",
      "TargetProcessId": 29320,
      "TargetUser": "S-1-5-21-1504711230-2873091451-3906125842-1139",
      "xml_name": "RuleAndFileData"
    },
    "version": 0
  }
}
```

## Limitations

- Only the runtime events 8002-8007 are modeled. Policy-application events
  (8000/8001), the "component not available" 8008, the Windows 8/Server 2012
  packaged-app IDs (8020-8027) and the Server 2016/Windows 10 Config CI and
  Managed Installer IDs (8028-8040) are out of scope, as is the Packaged app
  channel.
- `RuleSddl` uses the documented path-rule SDDL form; the exact SDDL of a
  real deployment depends on its policy.
- `FileHash` values are synthetic SHA-256 digests, not hashes of real
  binaries; `Fqbn`, PE and x509 fields follow the format of the Microsoft
  and Elastic examples.
- The XML carries the `RuleAndFileData` fields in the documented order;
  DLL-load records and non-`RuleAndFileData` layouts are not produced.
- Script and MSI rule GUIDs, the two custom rules (CorpApps, Configuration
  Manager cache) and their names are invented for this synthetic policy;
  only the three EXE default-rule GUIDs match Microsoft's default policy.
- Every day has the same office-hours shape; there is no weekly cycle
  (weekends look like weekdays) and no holidays. Block rates (~10 blocked
  executables and ~6 blocked scripts per host per day) are set by hand,
  not measured from a real fleet; a well-tuned managed fleet may block less.
- Records of one moment (a script host and the scripts it loads, a
  blocked file and its immediate retries) are a few seconds apart (median
  about 4 s in office hours, up to minutes at night) rather than
  milliseconds.
- In ordinary activity, a session where a blocked executable was
  followed by a blocked script has no proxy-binary launch until about
  32 minutes after that blocked executable.
- With `anomaly_mode: true` each episode adds its own records, so counts
  of blocked executables, blocked scripts and proxy-binary launches are
  about one per episode higher than with `false`.
- Fleet size, session lengths and the application mix are synthetic.

## References

- [Using Event Viewer with AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker) - event IDs, levels and message text.
- [Microsoft Q&A: AppLocker Event 8004 XML](https://learn.microsoft.com/en-us/answers/questions/884797/win11-home-applocker-prevents-an-app-from-starting) - full EXE and DLL block record.
- [Elastic Windows integration - AppLocker data streams](https://github.com/elastic/integrations/tree/main/packages/windows/data_stream) - `applocker_exe_and_dll` and `applocker_msi_and_script` fixtures and field mappings.
