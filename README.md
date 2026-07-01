# 🎯 Threat Hunt Playbooks

A collection of hypothesis-driven and baseline/rarity-based threat hunts, structured using the **PEAK framework** (Prepare → Execute → Act → Knowledge) with explicit MITRE ATT&CK mapping. Hunts are generalized from real blue team and detection engineering experience, sanitized for public sharing.

Companion repo: [`detection-rules`](https://github.com/YOUR_USERNAME/detection-rules) — several hunts here directly reference and extend rules from that library, showing the full loop from **real-time detection → proactive hunting → new detection engineering**.

---

## 🧭 Why PEAK + ATT&CK

Most public "threat hunting" content is either:
- Pure ATT&CK technique lists with no investigative methodology, or
- Pure methodology with no concrete, runnable detection logic

This repo combines both: every hunt has a clear **hypothesis**, a **runnable SPL investigation path**, and an explicit **detection engineering feedback loop** — because a hunt that doesn't produce a reusable detection or a documented gap is a missed opportunity.

---

## 🗂️ Hunt Index

| Hunt ID | Title | Tactic(s) | Cadence |
|---|---|---|---|
| [HUNT-001](01-Identity-Credential-Abuse/HUNT-001_Impossible_Travel_Post_Spray.md) | Impossible Travel Following Password Spray | Credential Access, Initial Access | Monthly |
| [HUNT-002](02-Living-off-the-Land-Execution/HUNT-002_LOLBin_Chaining.md) | LOLBin Chains Masquerading as Admin Activity | Defense Evasion, Execution | Quarterly |
| [HUNT-003](03-Persistence-Mechanisms/HUNT-003_Persistence_Rarity_Sweep.md) | Persistence Mechanism Rarity Sweep | Persistence | Quarterly |
| [HUNT-004](04-Data-Staging-Exfiltration/HUNT-004_Archive_Staging_Before_Exfil.md) | Archive Staging Preceding Exfiltration | Collection, Exfiltration | Monthly |
| [HUNT-005](05-Cloud-Identity-Hunts/HUNT-005_OAuth_Consent_Abuse.md) | OAuth Consent Abuse & Conditional Access Gaps | Credential Access, Persistence | Monthly |

---

## 📁 Repository Structure

```
threat-hunt-playbooks/
├── 01-Identity-Credential-Abuse/
├── 02-Living-off-the-Land-Execution/
├── 03-Persistence-Mechanisms/
├── 04-Data-Staging-Exfiltration/
├── 05-Cloud-Identity-Hunts/
└── templates/
    └── HUNT_TEMPLATE.md      ← use this to add new hunts
```

---

## 🔄 The Detection Engineering Feedback Loop

Every hunt's "Act" section ends in one of four outcomes, and that's intentional — it's the same outcome taxonomy used by mature hunt teams:

```
   Hunt Hypothesis
        │
        ▼
   Investigation (SPL)
        │
        ▼
┌───────┴────────┬─────────────┬──────────────┐
▼                ▼             ▼              ▼
True Positive  Detection Gap  FP Baseline   No Findings
   │               │              │              │
   ▼               ▼              ▼              ▼
 IR Escalation  New rule in    Tuning added   Re-run on
              /detection-rules  to existing      cadence
                                  rules
```

Three hunts in this repo (HUNT-002, HUNT-004, HUNT-005) identified concrete gaps not yet covered in the `detection-rules` library — those are flagged as candidate new rules in each hunt's Act section.

---

## 🧠 Hunt Types Used in This Repo

| Type | Description | Example |
|---|---|---|
| **Hypothesis-driven** | Starts from a specific TTP or threat intel trigger | HUNT-001, HUNT-002, HUNT-004, HUNT-005 |
| **Baseline / rarity-based** | Starts from "what's normal" and hunts for statistical outliers | HUNT-003 |

---

## ⚙️ How to Use These Hunts

1. Each `.md` file is a complete, runnable playbook — copy the SPL into Splunk and adjust index/sourcetype names to your environment
2. Run **Step 1 (baseline)** queries first in every hunt before alerting on anything — most false positives are caught here
3. Use the `templates/HUNT_TEMPLATE.md` to document new hunts in the same format for consistency

---


