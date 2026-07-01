# HUNT-002: Living-off-the-Land Binary (LOLBin) Chains Masquerading as Admin Activity

## Hunt Metadata

| Field | Value |
|---|---|
| Hunt ID | HUNT-002 |
| Hunt Type | Hypothesis-driven |
| MITRE ATT&CK Technique(s) | T1218 (System Binary Proxy Execution), T1027 (Obfuscated Files/Information), T1036 (Masquerading) |
| MITRE ATT&CK Tactic | TA0005 Defense Evasion, TA0002 Execution |
| Data Sources | Sysmon (Event ID 1, 7), WinEventLog:Security (4688), EDR process tree (CrowdStrike Falcon) |
| Hunt Owner | Detection Engineering |
| Status | Recurring (Quarterly) |

---

## 1. PREPARE — Hypothesis

**Trigger:**
Generalized from SOC experience: native Windows binaries (rundll32, certutil, regsvr32, mshta, msiexec) are routinely abused for execution and defense evasion because they're trusted, signed, and rarely blocked. EDR tools flag the obvious cases, but attackers increasingly chain 2-3 LOLBins together (e.g., certutil downloads → rundll32 executes) specifically to break single-stage detection logic.

**Hypothesis statement:**
> If an adversary is using LOLBins for command-and-control staging or execution, then we will observe process chains where one LOLBin spawns or is followed within a short window by a second LOLBin or network connection — a pattern legitimate admin/software activity rarely produces.

**Scope:**
- In scope: All endpoints with Sysmon or EDR telemetry
- Out of scope: Known software deployment tooling (SCCM, Intune) — baseline excluded after Step 1

---

## 2. EXECUTE — Investigation

**Step 1: Baseline — identify normal LOLBin usage by parent process and frequency**
```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| eval lolbin=lower(mvindex(split(Image, "\\"), -1))
| search lolbin IN ("certutil.exe","rundll32.exe","regsvr32.exe","mshta.exe","msiexec.exe","installutil.exe","regsvcs.exe","msbuild.exe","wmic.exe")
| eval parent=lower(mvindex(split(ParentImage, "\\"), -1))
| stats count BY lolbin, parent
| sort -count
```
*(Use this output to build your allowlist of expected parent→LOLBin pairs, e.g., `msiexec.exe → services.exe` is normal; `winword.exe → mshta.exe` is not.)*

**Step 2: Hunt for LOLBin chaining — one LOLBin spawning another within 2 minutes**
```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| eval process_name=lower(mvindex(split(Image, "\\"), -1))
| eval parent_name=lower(mvindex(split(ParentImage, "\\"), -1))
| eval lolbin_list="certutil.exe,rundll32.exe,regsvr32.exe,mshta.exe,msiexec.exe,installutil.exe,regsvcs.exe,msbuild.exe,wmic.exe,bitsadmin.exe"
| where process_name IN (split(lolbin_list, ",")) AND parent_name IN (split(lolbin_list, ","))
| where process_name != parent_name
| table _time, ComputerName, User, parent_name, process_name, ParentCommandLine, CommandLine
| sort _time
```

**Step 3: Pivot — check for network connections originating from flagged LOLBin processes**
```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
[ search index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  process_name IN ("certutil.exe","rundll32.exe","regsvr32.exe","mshta.exe","bitsadmin.exe")
  | rename ProcessGuid AS ProcessGuid
  | table ProcessGuid ]
| table _time, ComputerName, Image, DestinationIp, DestinationPort, DestinationHostname
```

**Findings log:**
| Timestamp | Host | LOLBin Chain | Network Activity | Disposition |
|---|---|---|---|---|
| *(fill in during actual hunt execution)* | | | | |

---

## 3. ACT — Outcomes

- [ ] True positive found → escalate, isolate host, full process tree review in EDR
- [x] **Detection gap identified** → LOLBin chaining is *not* well covered by the existing detection-rules library (current rules check single-stage LOLBin use, not chains). Candidate for a new rule: `T1218_LOLBin_Chain_Detection.spl`
- [ ] False positive baseline → document legitimate chains found in Step 1 as a permanent allowlist lookup
- [ ] No findings → re-run quarterly; LOLBin abuse patterns evolve with new living-off-the-land techniques (track via LOLBAS project)

---

## 4. KNOWLEDGE — Documentation & Handoff

**Key takeaways:**
- Single-stage LOLBin detections (most SIEM out-of-the-box content) miss chained abuse — chaining is the higher-fidelity signal
- Building the parent→child baseline (Step 1) is the most time-consuming but most valuable part of this hunt; reuse it across future hunts
- Cross-reference with [LOLBAS project](https://lolbas-project.github.io/) regularly — new binaries get added to the living-off-the-land catalog frequently

**Reusable artifacts:**
- LOLBin allowlist lookup (from Step 1 baseline)
- Chain-detection SPL pattern (Step 2) — generalize this to detect *any* two-stage suspicious process pattern, not just LOLBins

**Recommended hunt cadence:** Quarterly, or after any LOLBAS project update with new technique additions

**References:**
- MITRE ATT&CK T1218: https://attack.mitre.org/techniques/T1218/
- LOLBAS Project: https://lolbas-project.github.io/
