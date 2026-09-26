# Microsoft AD CS Audit Generator

Produces ECS JSON for a single Windows Server 2012 Certification Authority's Security-channel events. `event.original` reconstructs version 0 Event XML and `winlog.event_data` retains its selected native fields. Complete same-version XML captures remain **BLOCKED_RAW_EVIDENCE**.

## Event Types

| Event ID | Activity | Illustrative background pattern |
| --- | --- | --- |
| 4886 | Certificate request received | One per ordinary request |
| 4887 | Request approved and certificate issued | 94% of ordinary non-privileged dispositions |
| 4888 | Certificate request denied | 6% of ordinary non-privileged dispositions |
| 4885 | CA audit filter changed | About every eight hours, followed by restoration after about one hour |

One event is emitted per minute. An ordinary request is followed on the next tick by its issued or denied disposition, preserving CA host, `RequestId`, `Requester`, `Attributes`, process and thread. Record IDs increase with gaps for other Security-channel events; request IDs increase once per receipt. The workload models one in-flight request rather than a concurrent CA queue. A finite capture can end between a receipt and its disposition.

The fictional published ordinary template `CorpUserCN` uses `CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME` (`0x40000000`) with no supplied-subject or directory-path flag. The synthetic AD inventory sets each requester's `cn` equal to its account name, so the issued Subject is `CN=<account>`. This is an explicitly configured template, not the built-in `User` template. The fictional published `CorpUserSuppliedSAN` template uses `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` (`0x00000001`); its synthetic CSR supplies that same simple CN. Both templates have suitable enrollment permissions and permit automatic issuance without manager approval or authorized signatures. The scenario also assumes the CA policy `EDITF_ATTRIBUTESUBJECTALTNAME2` is enabled so that a `SAN:upn=...` request attribute can be honored. This CA flag and a template's `Supply in the request` setting are distinct controls. The template setting alone does not establish that an attribute becomes the issued SAN. The account used for filter changes also has CA administration and restart permissions. Neither these permissions, certificate contents nor authentication capability can be established from the selected audit records.

Ordinary privileged-UPN requests use that same template and account, with approved exercise activity separated from audit changes by at least 30 minutes. Other requests use the configured ordinary template. A 4888 disposition of `-2146875375` (`0x80094811`, `CERTSRV_E_KEY_LENGTH`) means the submitted public key is shorter than the template minimum. It does not mean the requester lacked enrollment permission.

These rates, maintenance cycles and approval assumptions are synthetic training settings, not measured production behavior. Audit-filter changes are unusual in a normal CA deployment.

## Anomaly Chain

`anomaly_mode: true` is the default. Episodes recur using generated event time, with a default interval of 24 hours:

1. After the due time and completion of the current ordinary pair, 4885 changes the scenario's stored filter from 127 to 119.
2. The same administrator submits a 4886 request on `CorpUserSuppliedSAN` with the configured privileged UPN on the next minute tick.
3. The following tick emits 4887 for the same native `RequestId`, requester and attributes.

Filter 119 removes bit 8 for revocation/CRL auditing. Bit 4 for requests and issuance and bit 16 for security-setting changes remain enabled. This does **not** disable all CA auditing or suppress the subsequent request/issue records. The new filter value is native evidence; the initial 127 and administrative authority are scenario assumptions. Later 119-to-127 restoration is emitted as an ordinary 4885 before another episode can reduce the filter again. Background also changes both values, so a single filter value or actor does not reveal anomaly mode.

The CA service is assumed to restart successfully 45 seconds after each filter-change event. The next request begins at least 59 seconds after that event at the shipped cadence and uses the next modeled CA process. Start/stop events 4880/4881 are outside this selected four-ID stream. The selected records cannot independently prove that restart completed or when the revocation/CRL filter became effective. Revocation and CRL actions are outside this selected stream.

Episodes use increasing request IDs, fresh timestamps and newly sampled public-key identifiers and logon IDs. The three selected records span two minute intervals. A detector can combine a recent revocation/CRL audit reduction with a sensitive requested UPN and successful disposition on the same CA. Request/issue linkage is native by ID; linking the filter-change actor to the requester also requires name/domain and time. The records do not prove that the resulting certificate authenticates as the requested UPN.

Scheduling waits for an ordinary pair and, if necessary, a filter restoration. It does not replay missed intervals in a burst. The interval is measured from the emitted episode filter change to the next due time. In the verified default finite run, reductions begin at 24h02m and 48h04m; a custom 12-hour run starts at 12h02m, 24h04m, 36h06m and 48h08m. Ordinary maintenance may delay scheduling further. `anomaly_mode: false` emits the same background classes and actors without this complete short correlation.

## Parameters

### Event Parameters

Edit `event.template.params` in `generator.yml`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `anomaly_mode` | `true` | Include repeated short correlations; false emits background |
| `anomaly_interval_hours` | `24` | First wait and recurrence; finite numeric values below six hours are clamped to six |
| `ca_host` | `ca01.corp.example` | CA server name |
| `domain` | `CORP` | Requester domain |
| `ca_name` | `CORP-CA` | Configured CA display name, collector enrichment |
| `suspicious_requester` | `svc-enroll` | Administrator used in episodes and ordinary activity |
| `privileged_upn` | `administrator@corp.example` | Requested UPN in both modes |
| `routine_template` | `CorpUserCN` | Fictional published CN-from-AD template |
| `enrollment_template` | `CorpUserSuppliedSAN` | Fictional published enrollment template |

Keep the shipped one-minute/count-one profile when interpreting restart and chain timings. Names and request attributes are serialized through JSON and XML escaping; use valid Windows account, CA host, template and UPN values. Account names used as CN values must not require DN escaping: exclude comma, plus, quotes, backslash, angle brackets, semicolon, equals and leading/trailing whitespace. Changing template names assumes equivalent published name flags and permissions.

### Output Parameters

The shipped configuration writes `output/events.json` and has no top-level `${params.*}` or `${secrets.*}` placeholders. Replace the file output or change its path to deliver elsewhere.

## Usage

From the content-packs repository root:

```bash
uv run --project ../eventum eventum generate --path generators/identity-microsoft-adcs/generator.yml --id microsoft-adcs --live-mode true --keep-order true
```

For two complete default episodes, copy `generator.yml` beside it as `finite.yml` and add these fields to the cron input:

```yaml
start: 2026-09-25T00:00:00+00:00
end: 2026-09-27T01:05:00+00:00
```

Then run:

```bash
uv run --project ../eventum eventum generate --path generators/identity-microsoft-adcs/finite.yml --id microsoft-adcs-finite --live-mode false --keep-order true
```

The finite window emits 2,946 records. Repeat with `anomaly_mode: false` to check the same background interval with zero complete injected correlations. Without finite cron bounds, sample mode generates continuously. All native and ECS times normalize to UTC, including CLI timezones other than UTC.

## Sample Output

This actual 4887 record is the disposition of the first episode's request in the final default finite run:

```json
{
  "@timestamp": "2026-09-26T00:04:00.904088+00:00",
  "ecs": {
    "version": "8.17.0"
  },
  "event": {
    "action": "certificate-issued",
    "category": [
      "iam"
    ],
    "code": "4887",
    "kind": "event",
    "original": "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Microsoft-Windows-Security-Auditing\" Guid=\"{54849625-5478-4994-A5BA-3E3B0328C30D}\"/><EventID>4887</EventID><Version>0</Version><Level>0</Level><Task>12805</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime=\"2026-09-26T00:04:00.904088Z\"/><EventRecordID>342078</EventRecordID><Correlation/><Execution ProcessID=\"892\" ThreadID=\"412\"/><Channel>Security</Channel><Computer>ca01.corp.example</Computer><Security/></System><EventData><Data Name=\"RequestId\">3720</Data><Data Name=\"Requester\">CORP\\svc-enroll</Data><Data Name=\"Attributes\">CertificateTemplate:CorpUserSuppliedSAN\nSAN:upn=administrator@corp.example</Data><Data Name=\"Disposition\">3</Data><Data Name=\"SubjectKeyIdentifier\">b8 39 ac a8 96 d6 5a bc c6 9d 99 fe 0e f1 bf 45 d2 78 d6 23</Data><Data Name=\"Subject\">CN=svc-enroll</Data></EventData></Event>",
    "outcome": "success",
    "provider": "Microsoft-Windows-Security-Auditing",
    "type": [
      "creation"
    ]
  },
  "host": {
    "name": "ca01.corp.example"
  },
  "observer": {
    "name": "CORP-CA",
    "type": "certificate-authority"
  },
  "related": {
    "user": [
      "svc-enroll"
    ]
  },
  "user": {
    "domain": "CORP",
    "name": "svc-enroll"
  },
  "winlog": {
    "channel": "Security",
    "computer_name": "ca01.corp.example",
    "event_data": {
      "Attributes": "CertificateTemplate:CorpUserSuppliedSAN\nSAN:upn=administrator@corp.example",
      "Disposition": "3",
      "RequestId": "3720",
      "Requester": "CORP\\svc-enroll",
      "Subject": "CN=svc-enroll",
      "SubjectKeyIdentifier": "b8 39 ac a8 96 d6 5a bc c6 9d 99 fe 0e f1 bf 45 d2 78 d6 23"
    },
    "event_id": "4887",
    "keywords": [
      "Audit Success"
    ],
    "level": "information",
    "opcode": "Info",
    "process": {
      "pid": 892,
      "thread": {
        "id": 412
      }
    },
    "provider_guid": "{54849625-5478-4994-A5BA-3E3B0328C30D}",
    "provider_name": "Microsoft-Windows-Security-Auditing",
    "record_id": "342078",
    "task": "Certification Services",
    "time_created": "2026-09-26T00:04:00.904088Z"
  }
}
```

## Source and Scope

- [Microsoft PKI event appendix](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn786423(v=ws.11)) defines the four event meanings and displayed fields.
- [CA audit-filter table](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn786422(v=ws.11)) and [MS-CSRA GetAuditFilter](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-csra/58fed3ab-91fe-43a8-bebb-447eb2f8f694) establish the mask and affected operations. The filter table requires CA service restart after registry changes.
- [Audit Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services) must be enabled, with the applicable success/failure audit policy, in addition to the CA audit filter.
- [Windows Server 2012 provider metadata](https://gist.github.com/andrewkroh/cf48e95aa2f80f33484126e421f888ba) supplies version 0 EventData names and order. It is a firsthand provider-binary dump, not a complete live four-event fixture.
- [MS-WCCE request attributes](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/92f07a54-2889-45e3-afd0-94b60daa80ec), [template name flags](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/cf805c29-6f58-4087-a395-3d0233a89f3c) and [Microsoft's CA SAN-setting assessment](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-insecure-adcs-certificate-enrollment) distinguish request attributes, supplied extensions and CA policy.
- [MS-CRTD name-flag values](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/1192823c-d839-4bc3-9b6b-fa8c53507ae1) and [MS-WCCE CA subject processing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/a1f27ffb-7f74-4fa1-8841-7cde4ba0bcfe) define the CN-from-AD and supplied-subject profiles.
- [Microsoft error codes](https://learn.microsoft.com/en-us/windows/win32/com/com-error-codes-4) defines the minimum-key-length denial.
- [Public-key identifier algorithms](https://learn.microsoft.com/en-us/windows/win32/api/certenroll/ne-certenroll-keyidentifierhashalgorithm) distinguish SKI from a certificate thumbprint or serial number.
- [Elastic System integration](https://www.elastic.co/docs/reference/integrations/system) collects Security-channel data. Its [generic Security fixture](https://github.com/elastic/integrations/blob/main/packages/system/data_stream/security/_dev/test/pipeline/test-security-windows2012-4768.json-expected.json) informs shared winlog types; an AD CS-specific fixture is unavailable for this profile.

The generator covers all selected v0 EventData fields: 5/5 for 4885, 3/3 for 4886 and 6/6 each for 4887/4888. This is schema coverage, not full raw-record parity. Certificate serial numbers, certificate thumbprints, validity dates, complete CSR/certificate material and v1 extra fields are absent from this selected schema and are not invented. The synthesized 20-byte spaced SKI represents a public-key identifier; it is not cryptographically derived from a supplied CSR or certificate. Issued Subject follows the selected fictional template profile: CN from AD for ordinary requests and the supplied CSR CN for the enrollment template. The synthetic AD `cn`/CSR values equal the requester account. Denied Subject is empty.

The System envelope is reconstructed from provider metadata and generic Security examples. Complete same-version live XML for all four IDs, exact envelope keywords/correlation/formatting and live Winlogbeat/SIEM parser acceptance remain unverified. A newer v1 capture cannot establish v0 byte parity. State retains one request pair, finite maintenance phases, scalar native record/request counters and bounded scheduler/restart slots. Completed request payloads and restart slots are cleared; no certificate, episode or request-history collection grows.
