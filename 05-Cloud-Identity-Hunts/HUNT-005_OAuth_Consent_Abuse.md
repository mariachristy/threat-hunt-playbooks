# HUNT-005: OAuth Application Consent Abuse & Conditional Access Policy Gaps

## Hunt Metadata

| Field | Value |
|---|---|
| Hunt ID | HUNT-005 |
| Hunt Type | Hypothesis-driven |
| MITRE ATT&CK Technique(s) | T1528 (Steal Application Access Token), T1098.003 (Account Manipulation: Additional Cloud Roles), T1556.006 (Modify Authentication Process: MFA) |
| MITRE ATT&CK Tactic | TA0006 Credential Access, TA0003 Persistence |
| Data Sources | Entra ID Audit Logs, Entra ID Sign-in Logs, Microsoft Graph API logs |
| Hunt Owner | Detection Engineering |
| Status | Recurring (Monthly) |

---

## 1. PREPARE — Hypothesis

**Trigger:**
Generalized from cloud security consulting exposure to Microsoft Entra ID environments: OAuth consent phishing and rogue app registrations are an increasingly common cloud persistence technique that bypasses password-based defenses entirely (including password resets and MFA) because the attacker operates via a token, not a password. This is a known blind spot relative to identity-based detections focused on sign-in events.

**Hypothesis statement:**
> If an adversary has compromised an identity and is establishing cloud persistence, then we will observe newly registered OAuth applications or service principals requesting high-privilege Graph API scopes (Mail.Read, Files.ReadWrite.All, Directory.ReadWrite.All), particularly from non-standard publishers or with unusually broad permission grants relative to the app's stated purpose.

**Scope:**
- In scope: All OAuth app registrations and consent grants in the tenant over the trailing 90 days
- Out of scope: Pre-approved, IT-governed enterprise applications (maintained allowlist)

---

## 2. EXECUTE — Investigation

**Step 1: Enumerate all OAuth app consent grants and flag high-risk scopes**
```spl
index=azure_ad sourcetype="azure:monitor:aad:audit" OperationName IN ("Consent to application","Add app role assignment to service principal")
| eval app_name=coalesce(TargetResources{}.displayName, "unknown")
| eval scopes=mvjoin(AdditionalDetails{}.value, ",")
| eval high_risk_scope=if(match(lower(scopes), "mail\.read|mail\.readwrite|files\.readwrite\.all|directory\.readwrite\.all|user\.readwrite\.all|application\.readwrite\.all"), "Yes", "No")
| where high_risk_scope="Yes"
| table _time, InitiatedBy, app_name, scopes, high_risk_scope
| sort -_time
```

**Step 2: Check app publisher verification status and registration recency**
```spl
index=azure_ad sourcetype="azure:monitor:aad:audit" OperationName="Add service principal"
| eval app_name=TargetResources{}.displayName
| eval app_id=TargetResources{}.id
| eval publisher_verified=coalesce(AdditionalDetails{}.publisherVerification, "Unverified")
| eval days_since_registration=round((now() - _time)/86400, 0)
| join type=left app_name
    [ search index=azure_ad sourcetype="azure:monitor:aad:audit" OperationName="Consent to application"
      | eval app_name=TargetResources{}.displayName | table app_name ]
| table _time, app_name, app_id, publisher_verified, days_since_registration
| sort -_time
```

**Step 3: Pivot — cross-reference consenting users against recent risky sign-ins (from HUNT-001 methodology) or recent password resets**
```spl
| multisearch
    [ search index=azure_ad sourcetype="azure:monitor:aad:audit" OperationName="Consent to application"
      | eval event_type="oauth_consent" | eval key_user=InitiatedBy
      | table _time, event_type, key_user ]
    [ search index=azure_ad sourcetype="azure:monitor:aad" RiskLevelDuringSignIn!=none
      | eval event_type="risky_signin" | eval key_user=UserPrincipalName
      | table _time, event_type, key_user, RiskLevelDuringSignIn ]
| stats values(event_type) AS observed_events, values(RiskLevelDuringSignIn) AS risk_levels, range(_time) AS time_span BY key_user
| where "oauth_consent" IN observed_events AND "risky_signin" IN observed_events
| where time_span <= 86400
```

**Findings log:**
| Timestamp | User | App Name | Scopes Granted | Publisher Status | Disposition |
|---|---|---|---|---|---|
| *(fill in during actual hunt execution)* | | | | | |

---

## 3. ACT — Outcomes

- [ ] True positive found → revoke app consent immediately, disable service principal, force token refresh/reset for affected accounts, full audit log review for that app's API activity
- [x] **Detection gap identified** → No current detection-rules repo entry addresses OAuth/cloud app abuse (current library is endpoint/network focused). Strong candidate for a new `TA0006-Credential-Access/T1528_OAuth_Consent_Abuse.spl` rule using Entra ID Audit log scope-grant logic from Step 1
- [ ] False positive baseline → legitimate SaaS integrations requested by business units; requires a governance process (app consent approval workflow) as a long-term fix, not just detection
- [ ] No findings → maintain monthly cadence; OAuth abuse campaigns tend to come in waves tied to broader phishing trends

---

## 4. KNOWLEDGE — Documentation & Handoff

**Key takeaways:**
- OAuth/consent-based persistence is a genuine blind spot in identity programs that focus primarily on sign-in/password telemetry — this hunt category deserves dedicated attention, not just a footnote in identity hunts
- Publisher verification status (Step 2) is a fast, high-value filter — unverified publishers requesting high-risk scopes is a strong prioritization signal even without other context
- This is a good example of where detection engineering and identity governance need to meet — the long-term fix is process (consent approval workflows), not just better SPL

**Reusable artifacts:**
- High-risk scope list (Step 1) — maintain and expand this list as new Graph API permission abuse patterns emerge
- Time-boxed cross-correlation pattern (Step 3) — same reusable pattern as HUNT-004, applied to a different domain (identity vs. data exfil)

**Recommended hunt cadence:** Monthly; trigger ad-hoc after any tenant-wide phishing campaign

**References:**
- MITRE ATT&CK T1528: https://attack.mitre.org/techniques/T1528/
- MITRE ATT&CK T1098.003: https://attack.mitre.org/techniques/T1098/003/
