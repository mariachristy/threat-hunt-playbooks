# HUNT-001: Impossible Travel & Anomalous Sign-In Patterns Following Password Spray Activity

## Hunt Metadata

| Field | Value |
|---|---|
| Hunt ID | HUNT-001 |
| Hunt Type | Hypothesis-driven (post-incident follow-up) |
| MITRE ATT&CK Technique(s) | T1110.001 (Password Spraying), T1078 (Valid Accounts), T1556 (Modify Authentication Process) |
| MITRE ATT&CK Tactic | TA0006 Credential Access, TA0001 Initial Access |
| Data Sources | Entra ID Sign-in Logs, WinEventLog:Security (4624/4625), VPN logs |
| Hunt Owner | Detection Engineering |
| Status | Recurring (Monthly) |

---

## 1. PREPARE — Hypothesis

**Trigger:**
This hunt is generalized from a real pattern observed during consulting engagements: correlation searches flagged password spray activity (per [`T1110.001_Password_Spray_Detection.spl`](../../detection-rules/TA0006-Credential-Access/T1110.001_Password_Spray_Detection.spl)), but spray campaigns often have a low success rate — a handful of accounts get compromised and the activity goes quiet for days before being operationalized. The detection rule catches the noisy spray; this hunt looks for the *quiet aftermath*.

**Hypothesis statement:**
> If a password spray campaign successfully compromised one or more accounts, then those accounts will exhibit anomalous sign-in geography, device fingerprints, or MFA registration changes in the 1-14 days following the spray — even if no single sign-in event triggers a correlation rule on its own.

**Scope:**
- In scope: All accounts that appeared as "targeted_accounts" in password spray alerts over the trailing 30 days
- Out of scope: Service accounts, break-glass accounts (handled by separate hunt)

---

## 2. EXECUTE — Investigation

**Step 1: Pull the candidate account list from prior spray alerts**
```spl
index=notable source="Password Spray Attack Detection"
earliest=-30d@d latest=now
| mvexpand targeted_accounts
| dedup targeted_accounts
| table targeted_accounts, _time
| rename targeted_accounts AS account
```

**Step 2: Check successful sign-ins for those accounts and calculate geo-velocity**
```spl
index=azure_ad sourcetype="azure:monitor:aad" ResultType=0
[ search index=notable source="Password Spray Attack Detection" earliest=-30d@d
  | mvexpand targeted_accounts | dedup targeted_accounts
  | rename targeted_accounts AS UserPrincipalName | table UserPrincipalName ]
| eval country=Location.countryOrRegion
| eval lat=Location.geoCoordinates.latitude, lon=Location.geoCoordinates.longitude
| sort UserPrincipalName, _time
| streamstats current=f last(_time) AS prev_time, last(lat) AS prev_lat, last(lon) AS prev_lon BY UserPrincipalName
| eval time_diff_hours=round((_time - prev_time)/3600, 2)
| eval distance_km=if(isnotnull(prev_lat),
    round(6371 * acos(
        sin(pi()*lat/180)*sin(pi()*prev_lat/180) +
        cos(pi()*lat/180)*cos(pi()*prev_lat/180)*cos(pi()*lon/180 - pi()*prev_lon/180)
    ), 0), 0)
| eval implied_speed_kmh=if(time_diff_hours > 0, round(distance_km / time_diff_hours, 0), 0)
| where implied_speed_kmh > 900
| table _time, UserPrincipalName, country, distance_km, time_diff_hours, implied_speed_kmh, AppDisplayName, DeviceDetail.displayName
```

**Step 3: Pivot — check for MFA method changes or new device registrations on flagged accounts**
```spl
index=azure_ad sourcetype="azure:monitor:aad:audit" 
(OperationName="Update user" OR OperationName="Register security info" OR OperationName="Add registered owner to device")
[ search <output of Step 2 — flagged UserPrincipalName values> ]
| table _time, UserPrincipalName, OperationName, InitiatedBy, TargetResources
```

**Findings log:**
| Timestamp | Host/App | User | Observation | Disposition |
|---|---|---|---|---|
| *(fill in during actual hunt execution)* | | | | |

---

## 3. ACT — Outcomes

- [ ] True positive found → escalate to IR, force password reset + MFA re-registration
- [ ] Detection gap identified → consider building an automated correlation: spray alert → successful sign-in within 14 days → geo-velocity check
- [ ] False positive baseline → travelling executives, VPN exit-node hopping (corporate VPN can cause false impossible-travel)
- [x] **Detection engineering follow-up:** This hunt logic is a strong candidate to operationalize as a scheduled correlation search rather than a manual monthly hunt — see Knowledge section.

---

## 4. KNOWLEDGE — Documentation & Handoff

**Key takeaways:**
- Spray detection rules catch the loud part of the attack; the quiet follow-on compromise is where actual damage happens
- Geo-velocity math (haversine distance / time) is a reusable pattern for any "impossible travel" hunt — not just this one
- Corporate VPN egress points are the #1 source of false positives for this hunt — build an exclusion list of known corporate VPN exit IPs/ASNs

**Reusable artifacts:**
- Geo-velocity SPL pattern (Step 2) — reusable for any account-based impossible travel hunt
- Candidate list generation from prior notable events (Step 1) — reusable pattern for "hunt the aftermath" methodology

**Recommended hunt cadence:** Monthly, or trigger on-demand after any password spray alert closes

**References:**
- MITRE ATT&CK T1110.001: https://attack.mitre.org/techniques/T1110/001/
- MITRE ATT&CK T1078: https://attack.mitre.org/techniques/T1078/
