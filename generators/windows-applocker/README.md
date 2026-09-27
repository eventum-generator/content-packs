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

## Events

Measured over a 96 h default-on capture (43,514 records from 18 workstations):

| Event ID | Channel | Meaning | Share | Per host per day | ECS category |
| --- | --- | --- | --- | --- | --- |
| `8002` | EXE and DLL | Executable/DLL allowed to run | 76.0% | ~459 | `process` |
| `8005` | MSI and Script | Script/MSI allowed to run | 20.9% | ~126 | `process` |
| `8004` | EXE and DLL | Executable/DLL prevented from running | 2.0% | ~12 | `process` |
| `8007` | MSI and Script | Script/MSI prevented from running | 0.9% | ~5.5 | `process` |
| `8006` | MSI and Script | Script/MSI would have been blocked (Audit only) | 0.2% | ~1.2 (on the 3 audit hosts) | `process` |

`event.code` is a string; `event.action` is `None` and `event.type` is
`["start"]`, matching the Elastic Windows integration output for these
channels. `log.level` / `winlog.level` follow the Microsoft event table:
information for 8002/8005, warning for 8006, error for 8004/8007.

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
time (default 24 h, minimum 6 h). The first episode starts about 1 h after
the generation start; each next start is measured from the actual previous
start (no catch-up for missed time) plus a random delay of up to
`min(1 h, interval/8)`. If no eligible session is open at that moment, the
start waits for one (checked once a minute). The episode runs inside a
session that is already open, and the session's ordinary activity continues
around it. The acting user and host both differ from the previous
episode's, so actors rotate. AppLocker changes no state, so there is nothing
to restore.

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
of both modes; only the full three-step sequence within one session is
withheld from the background.

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

Byte-exact record from the default-on 96 h capture (an allowed Chrome
launch, 8002):

```json
{
  "@timestamp": "2026-09-01T01:10:10.819Z",
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
    "original": "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Microsoft-Windows-AppLocker\" Guid=\"{cbda4dbf-8d5d-4f69-9578-be14aa540d22}\"/><EventID>8002</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime=\"2026-09-01T01:10:10.8199730Z\"/><EventRecordID>1573108</EventRecordID><Correlation/><Execution ProcessID=\"8136\" ThreadID=\"4164\"/><Channel>Microsoft-Windows-AppLocker/EXE and DLL</Channel><Computer>ws-ops-116.contoso.local</Computer><Security UserID=\"S-1-5-21-1504711230-2873091451-3906125842-1212\"/></System><UserData><RuleAndFileData xmlns=\"http://schemas.microsoft.com/schemas/event/Microsoft.Windows/1.0.0.0\"><PolicyNameLength>3</PolicyNameLength><PolicyName>EXE</PolicyName><RuleId>{921CC481-6E17-4653-8F75-050B80ACCA20}</RuleId><RuleNameLength>60</RuleNameLength><RuleName>(Default Rule) All files located in the Program Files folder</RuleName><RuleSddlLength>63</RuleSddlLength><RuleSddl>D:(XA;;FX;;;S-1-1-0;(APPID://PATH Contains \"%PROGRAMFILES%\\*\"))</RuleSddl><TargetUser>S-1-5-21-1504711230-2873091451-3906125842-1212</TargetUser><TargetProcessId>5448</TargetProcessId><FilePathLength>51</FilePathLength><FilePath>%PROGRAMFILES%\\GOOGLE\\CHROME\\APPLICATION\\CHROME.EXE</FilePath><FileHashLength>32</FileHashLength><FileHash>5407D34AF3F59BE98E28F7E62FA638D7A825927136FCE00705FDD29C5958F50D</FileHash><FqbnLength>89</FqbnLength><Fqbn>O=GOOGLE LLC, L=MOUNTAIN VIEW, S=CALIFORNIA, C=US\\GOOGLE CHROME\\CHROME.EXE\\118.0.5993.118</Fqbn><TargetLogonId>0x3b1a180</TargetLogonId><FullFilePathLength>53</FullFilePathLength><FullFilePath>C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe</FullFilePath></RuleAndFileData></UserData></Event>",
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
    "name": "ws-ops-116.contoso.local"
  },
  "log": {
    "level": "information"
  },
  "message": "%PROGRAMFILES%\\GOOGLE\\CHROME\\APPLICATION\\CHROME.EXE was allowed to run.",
  "process": {
    "pid": 8136
  },
  "tags": [
    "preserve_original_event"
  ],
  "user": {
    "id": "S-1-5-21-1504711230-2873091451-3906125842-1212"
  },
  "winlog": {
    "channel": "Microsoft-Windows-AppLocker/EXE and DLL",
    "computer_name": "ws-ops-116.contoso.local",
    "event_id": "8002",
    "level": "information",
    "opcode": "Info",
    "process": {
      "pid": 8136,
      "thread": {
        "id": 4164
      }
    },
    "provider_guid": "{cbda4dbf-8d5d-4f69-9578-be14aa540d22}",
    "provider_name": "Microsoft-Windows-AppLocker",
    "record_id": "1573108",
    "task": "None",
    "time_created": "2026-09-01T01:10:10.819Z",
    "user": {
      "identifier": "S-1-5-21-1504711230-2873091451-3906125842-1212"
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
      "TargetLogonId": "0x3b1a180",
      "TargetProcessId": 5448,
      "TargetUser": "S-1-5-21-1504711230-2873091451-3906125842-1212",
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
- Activity is flat over 24 h: users stay logged on (screen locked) for most
  of the day and there is no day/night shape. Block rates (~12 blocked
  executables and ~5.5 blocked scripts per host per day) are set by hand,
  not measured from a real fleet; a well-tuned managed fleet may block less.
- Fleet size, session lengths and the application mix are synthetic.

## References

- [Using Event Viewer with AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker) - event IDs, levels and message text.
- [Microsoft Q&A: AppLocker Event 8004 XML](https://learn.microsoft.com/en-us/answers/questions/884797/win11-home-applocker-prevents-an-app-from-starting) - full EXE and DLL block record.
- [Elastic Windows integration - AppLocker data streams](https://github.com/elastic/integrations/tree/main/packages/windows/data_stream) - `applocker_exe_and_dll` and `applocker_msi_and_script` fixtures and field mappings.
