# Hunt Template

Use this structure for every new hunt added to this repo. It follows the **PEAK framework** (Prepare, Execute, Act, Knowledge) — developed by SpecterOps — layered with explicit MITRE ATT&CK mapping for technical precision.

---

## Hunt Metadata

| Field | Value |
|---|---|
| Hunt ID | `HUNT-###` |
| Hunt Type | Hypothesis-driven / Baseline / Model-assisted |
| MITRE ATT&CK Technique(s) | T#### |
| MITRE ATT&CK Tactic | TA#### |
| Data Sources | (e.g., Sysmon, WinEventLog, Zscaler, Entra ID Sign-in Logs) |
| Hunt Owner | Your name |
| Date | YYYY-MM-DD |
| Status | Draft / Active / Completed / Recurring |

---

## 1. PREPARE — Hypothesis

**Trigger:** What prompted this hunt? (threat intel, incident pattern, gap in detection coverage, anomaly)

**Hypothesis statement:**
> "If [adversary behavior / TTP] is occurring in our environment, then we should see [observable evidence] in [data source]."

**Scope:**
- In scope: (hosts, business units, time range)
- Out of scope: (exclusions)

---

## 2. EXECUTE — Investigation

**Step 1: Initial query / pivot point**
```spl
<initial broad query>
```

**Step 2: Narrow and enrich**
```spl
<refined query with context enrichment>
```

**Step 3: Pivot to related data sources**
```spl
<pivot query — e.g., from process events to network events>
```

**Findings log:**
| Timestamp | Host | User | Observation | Disposition |
|---|---|---|---|---|

---

## 3. ACT — Outcomes

- [ ] **True positive found** → Escalated to IR? Ticket #:
- [ ] **Detection gap identified** → New detection rule created (link to `/detection-rules`)
- [ ] **False positive baseline established** → Added to tuning exclusions
- [ ] **No findings** → Hypothesis disproven for this period

**Detection engineering follow-up:**
What new detection rule (if any) resulted from this hunt? Link it.

---

## 4. KNOWLEDGE — Documentation & Handoff

**Key takeaways:**
-

**Reusable artifacts:**
- Saved searches / lookups created
- IOCs identified (sanitized)

**Recommended hunt cadence:** One-time / Weekly / Monthly / Quarterly

**References:**
- MITRE ATT&CK: https://attack.mitre.org/techniques/T####/
