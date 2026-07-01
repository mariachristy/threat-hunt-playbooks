# HUNT-004: Data Staging Patterns Preceding Exfiltration (Archive Creation + Unusual Volume)

## Hunt Metadata

| Field | Value |
|---|---|
| Hunt ID | HUNT-004 |
| Hunt Type | Hypothesis-driven |
| MITRE ATT&CK Technique(s) | T1560 (Archive Collected Data), T1074 (Data Staged), T1048 (Exfiltration Over Alternative Protocol) |
| MITRE ATT&CK Tactic | TA0009 Collection, TA0010 Exfiltration |
| Data Sources | Sysmon (Event ID 1, 11), Zscaler proxy logs, file server access logs |
| Hunt Owner | Detection Engineering |
| Status | Recurring (Monthly) |

---

## 1. PREPARE — Hypothesis

**Trigger:**
Generalized from a real detection engineering task: building Splunk queries to detect file uploads to LLM/AI platforms via Zscaler proxy logs surfaced a broader pattern worth hunting — before any exfiltration over a web channel happens, there's usually a staging step (archive creation, file consolidation into a single directory) that's far less noisy to detect than the upload itself, and happens on the endpoint rather than the network.

**Hypothesis statement:**
> If an adversary or insider is preparing to exfiltrate data, then we will observe archive utility execution (7zip, WinRAR, tar, PowerShell Compress-Archive) creating unusually large or numerous archives in user-writable directories, shortly before a corresponding upload event to an external destination.

**Scope:**
- In scope: All endpoints with file/process telemetry; correlate with the existing [`T1048_Exfil_via_Web_Upload.spl`](../../detection-rules/TA0010-Exfiltration/T1048_Exfil_via_Web_Upload.spl) rule output
- Out of scope: IT/backup service accounts performing scheduled archival (excluded after baseline)

---

## 2. EXECUTE — Investigation

**Step 1: Identify archive creation events by non-IT users**
```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| eval process_name=lower(mvindex(split(Image, "\\"), -1))
| search process_name IN ("7z.exe","7zg.exe","winrar.exe","rar.exe","tar.exe","powershell.exe")
| where (process_name="powershell.exe" AND match(lower(CommandLine), "compress-archive"))
     OR process_name!="powershell.exe"
| eval target_path=lower(coalesce(CommandLine, ""))
| eval suspicious_location=if(match(target_path, "\\\\desktop\\\\|\\\\downloads\\\\|\\\\temp\\\\|\\\\appdata\\\\"), "Yes", "No")
| table _time, ComputerName, User, process_name, CommandLine, suspicious_location
| sort -_time
```

**Step 2: Correlate archive file creation with file size (Sysmon Event ID 11 — FileCreate)**
```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
| eval file_ext=lower(mvindex(split(TargetFilename, "."), -1))
| search file_ext IN ("zip","rar","7z","tar","gz")
| eval file_path=lower(TargetFilename)
| stats count AS archives_created, values(TargetFilename) AS files BY ComputerName, User, _time
| where archives_created >= 1
| sort -_time
```

**Step 3: Pivot — correlate staging hosts/users against the existing exfil-upload detection within a 2-hour window**
```spl
| multisearch
    [ search index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
      process_name IN ("7z.exe","winrar.exe","rar.exe")
      | eval event_type="archive_staging" | eval key_user=User
      | table _time, event_type, key_user, ComputerName, CommandLine ]
    [ search index=notable source="Data Exfiltration via Web Upload*"
      | eval event_type="web_upload" | eval key_user=src_user
      | table _time, event_type, key_user, total_upload_mb, destinations ]
| stats
    values(event_type) AS observed_events,
    values(CommandLine) AS staging_commands,
    values(total_upload_mb) AS upload_volumes,
    values(destinations) AS upload_destinations,
    range(_time) AS time_span_seconds
    BY key_user
| where "archive_staging" IN observed_events AND "web_upload" IN observed_events
| where time_span_seconds <= 7200
| table key_user, staging_commands, upload_volumes, upload_destinations, time_span_seconds
```

**Findings log:**
| Timestamp | Host | User | Staging Activity | Upload Correlation | Disposition |
|---|---|---|---|---|---|
| *(fill in during actual hunt execution)* | | | | | |

---

## 3. ACT — Outcomes

- [ ] True positive found → escalate to IR/HR (insider risk) or IR (compromise), preserve archive + upload evidence
- [x] **Detection gap identified** → Archive staging (Step 1/2) has no dedicated real-time correlation rule yet; current exfil coverage only looks at the upload side. Candidate new rule: `T1560_Archive_Staging_Detection.spl`
- [ ] False positive baseline → legitimate compression for email attachment size limits, dev/log archiving — document patterns to exclude
- [ ] No findings → maintain monthly cadence aligned with exfil rule review

---

## 4. KNOWLEDGE — Documentation & Handoff

**Key takeaways:**
- The staging step is a much lower-noise signal than the upload step, but only valuable when correlated *with* the upload — staging alone has too many legitimate use cases
- Time-boxing the correlation (staging → upload within 2 hours) is what separates signal from noise in Step 3; widen the window if attackers are patient, but expect more false positives
- This hunt directly extends the LLM-upload detection engineering work — same proxy log foundation, extended to generic exfiltration destinations

**Reusable artifacts:**
- Archive-creation SPL pattern (Step 1) — reusable as a standalone collection-stage detection
- Staging→upload time-correlation pattern (Step 3) — generalizable to any "precursor activity → outcome activity" hunt structure

**Recommended hunt cadence:** Monthly; trigger ad-hoc during any active insider risk investigation

**References:**
- MITRE ATT&CK T1560: https://attack.mitre.org/techniques/T1560/
- MITRE ATT&CK T1074: https://attack.mitre.org/techniques/T1074/
