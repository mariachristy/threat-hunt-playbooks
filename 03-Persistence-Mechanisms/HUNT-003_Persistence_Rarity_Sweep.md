# HUNT-003: Quarterly Persistence Mechanism Sweep (WMI, Services, Run Keys, Scheduled Tasks)

## Hunt Metadata

| Field | Value |
|---|---|
| Hunt ID | HUNT-003 |
| Hunt Type | Baseline / Model-assisted (rarity-based) |
| MITRE ATT&CK Technique(s) | T1547.001 (Run Keys), T1053.005 (Scheduled Task), T1543.003 (Windows Service), T1546.003 (WMI Event Subscription) |
| MITRE ATT&CK Tactic | TA0003 Persistence |
| Data Sources | Sysmon (Event ID 13, 19, 20, 21), WinEventLog:Security (4697, 4698), WinEventLog:System (7045) |
| Hunt Owner | Detection Engineering |
| Status | Recurring (Quarterly) |

---

## 1. PREPARE — Hypothesis

**Trigger:**
Real-time correlation rules for persistence (like [`T1053.005_Scheduled_Task_Creation.spl`](../../detection-rules/TA0003-Persistence/T1053.005_Scheduled_Task_Creation.spl)) catch obviously suspicious creation events, but a patient adversary can establish persistence using a mechanism that *looks* boring at creation time and only reveals itself as malicious through rarity — e.g., a WMI event subscription that exists on only 1 of 5,000 endpoints.

**Hypothesis statement:**
> If an adversary has established persistence via an uncommon mechanism (WMI subscription, unusual service, rare scheduled task), then that artifact will be rare across the fleet — appearing on very few hosts compared to legitimate IT-deployed persistence, which is typically fleet-wide or role-based.

**Scope:**
- In scope: All Windows endpoints with Sysmon/EDR coverage
- Out of scope: Servers with documented unique automation (maintained in a lookup table, reviewed each hunt cycle)

---

## 2. EXECUTE — Investigation

**Step 1: WMI Event Subscriptions — rarity analysis**
```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode IN (19,20,21)
| eval consumer_name=coalesce(Consumer, Name)
| stats dc(ComputerName) AS host_count, values(ComputerName) AS hosts, values(Destination) AS wmi_destination BY consumer_name, EventCode
| where host_count <= 3
| sort host_count
```

**Step 2: Windows Services — newly created, rare across fleet, non-Microsoft signed**
```spl
index=windows sourcetype="WinEventLog:System" EventCode=7045
| eval service_name=ServiceName, image_path=lower(ImagePath)
| eval suspicious_path=if(match(image_path, "\\\\temp\\\\|\\\\appdata\\\\|\\\\users\\\\public\\\\|\\\\programdata\\\\(?!microsoft)"), "Yes", "No")
| stats dc(ComputerName) AS host_count, values(ComputerName) AS hosts, values(image_path) AS paths, values(suspicious_path) AS path_flag BY service_name
| where host_count <= 5
| sort host_count
```

**Step 3: Scheduled Tasks + Run Keys — cross-reference rarity with the real-time detection rule's output**
```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4698
| eval task_name=TaskName
| stats dc(ComputerName) AS host_count, values(ComputerName) AS hosts BY task_name
| where host_count <= 3
| join type=left task_name
    [ search index=notable source="Suspicious Scheduled Task Creation"
      | rename task_name AS task_name
      | table task_name, risk_score, severity ]
| sort host_count
```

**Step 4: Cross-correlate — does any single host appear across multiple rare-persistence categories?**
```spl
| multisearch
    [ search index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode IN (19,20,21)
      | eval mechanism="WMI Subscription" | rename ComputerName AS host | table _time, host, mechanism ]
    [ search index=windows sourcetype="WinEventLog:System" EventCode=7045
      | eval mechanism="New Service" | rename ComputerName AS host | table _time, host, mechanism ]
    [ search index=windows sourcetype="WinEventLog:Security" EventCode=4698
      | eval mechanism="Scheduled Task" | rename ComputerName AS host | table _time, host, mechanism ]
| stats dc(mechanism) AS distinct_mechanisms, values(mechanism) AS mechanisms_used BY host
| where distinct_mechanisms >= 2
| sort -distinct_mechanisms
```

**Findings log:**
| Timestamp | Host | Mechanism | Rarity (host count) | Disposition |
|---|---|---|---|---|
| *(fill in during actual hunt execution)* | | | | |

---

## 3. ACT — Outcomes

- [ ] True positive found → escalate to IR, full host forensic triage, check for lateral spread of the same mechanism
- [x] **Detection gap identified** → Step 4 (multi-mechanism cross-correlation per host) is a strong candidate for a standing correlation search — a host using 2+ distinct persistence mechanisms in a quarter is rare for legitimate use and high-signal for compromise
- [ ] False positive baseline → document legitimate rare-but-valid findings (e.g., a one-off vendor tool) in the out-of-scope lookup table for next cycle
- [ ] No findings → maintain quarterly cadence; persistence mechanisms are a "low and slow" category, less likely to show up in any single short window

---

## 4. KNOWLEDGE — Documentation & Handoff

**Key takeaways:**
- Rarity-based hunting (host_count <= N) is one of the highest-value, lowest-effort hunt patterns — it doesn't require any prior IOC and surfaces things signature-based detection misses entirely
- WMI event subscriptions are consistently under-monitored compared to Run keys and scheduled tasks — prioritize Step 1 if time-constrained
- The cross-mechanism correlation in Step 4 produced the most interesting candidates in practice; a single host using both a new service AND a rare scheduled task in the same quarter warrants investigation even without any other red flag

**Reusable artifacts:**
- Rarity-analysis SPL pattern (`stats dc(ComputerName)... | where host_count <= N`) — reusable for almost any "find the needle" hunt across any artifact type
- Multi-mechanism cross-correlation pattern (Step 4) — generalize this to any set of categorical behaviors per host

**Recommended hunt cadence:** Quarterly; consider promoting Step 4 logic to a standing weekly correlation search

**References:**
- MITRE ATT&CK T1546.003: https://attack.mitre.org/techniques/T1546/003/
- MITRE ATT&CK T1543.003: https://attack.mitre.org/techniques/T1543/003/
