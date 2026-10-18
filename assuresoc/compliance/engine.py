"""Regulatory & insurance obligations for an incident (India-first).

* CERT-In Directions (28 Apr 2022, s.70B IT Act): listed incident types must be reported to
  CERT-In within 6 hours of being noticed.
* DPDP Act 2023 + DPDP Rules 2025: personal-data breaches must be intimated to the Data
  Protection Board and affected Data Principals; a detailed report follows (72 h window).
* Cyber-insurance: policies require prompt notice to the insurer, with evidence preserved.

These drafts accelerate reporting — they are not legal advice. Verify against the current
CERT-In reporting form, the DPDP Rules and your policy wording before submission.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Dict, List

from ..core.config import IST, OrgConfig
from ..core.models import Alert, Incident

# Subset of CERT-In Directions Annexure I incident types used by our detections.
CERTIN_TYPES = {
    "scanning": "Targeted scanning/probing of critical networks/systems",
    "compromise": "Compromise of critical systems/information",
    "unauthorised_access": "Unauthorised access of IT systems/data",
    "malicious_code": "Malicious code attacks such as spreading of virus/worm/Trojan/Bots/Spyware/Ransomware/Cryptominers",
    "phishing": "Identity Theft, spoofing and phishing attacks",
    "application": "Attacks on Application such as E-Governance, E-Commerce etc.",
    "data_breach": "Data Breach",
    "ai_ml": "Attacks or malicious/suspicious activities affecting systems/servers/software/applications "
             "related to Artificial Intelligence and Machine Learning",
}

_RULE_TO_TYPE = {
    "web_scan": "scanning",
    "phishing_lookalike": "phishing",
    "phishing_click": "phishing",
    "password_spray": "unauthorised_access",
    "brute_force": "unauthorised_access",
    "mfa_fatigue": "unauthorised_access",
    "impossible_travel": "unauthorised_access",
    "new_country_login": "unauthorised_access",
    "priv_account_shared_source": "compromise",
    "priv_account_created": "compromise",
    "lateral_new_host": "compromise",
    "exfil_volume": "data_breach",
    "web_attack": "application",
    "ai_prompt_injection": "ai_ml",
}

CERTIN_WINDOW = timedelta(hours=6)
DPDP_DETAILED_WINDOW = timedelta(hours=72)


def _types_for(alerts: List[Alert]) -> List[str]:
    keys = []
    for a in alerts:
        key = _RULE_TO_TYPE.get(a.rule_id)
        if a.rule_id == "brute_force" and not a.details.get("succeeded"):
            key = None  # failed, opportunistic guessing is not a reportable incident on its own
        if a.rule_id.startswith("edr:"):
            key = "malicious_code" if a.tactic in ("Impact", "Execution") else "compromise"
        if key and key not in keys:
            keys.append(key)
    return keys


def assess(incident: Incident, alerts: List[Alert], org: OrgConfig, now: datetime | None = None) -> Dict:
    now = now or datetime.now(timezone.utc)
    noticed = incident.first_seen
    types = _types_for(alerts)
    hosts = incident.entities.get("host", [])
    pd_systems = [h for h in hosts if h in org.personal_data_systems]
    exfil = any(a.tactic == "Exfiltration" for a in alerts)
    personal_data = bool(pd_systems) and (exfil or any(a.tactic == "Impact" for a in alerts))

    certin_deadline = noticed + CERTIN_WINDOW
    obligations = []
    if types:
        obligations.append({
            "regime": "CERT-In Directions 2022",
            "action": "Report incident to CERT-In (incident@cert-in.org.in / portal)",
            "deadline": certin_deadline.isoformat(),
            "required": "likely" if incident.priority in ("P1", "P2") else "review",
        })
    if personal_data:
        obligations.append({
            "regime": "DPDP Act 2023 / DPDP Rules 2025",
            "action": "Intimate Data Protection Board & affected Data Principals without delay; "
                      "detailed report within 72 h",
            "deadline": (noticed + DPDP_DETAILED_WINDOW).isoformat(),
            "required": "likely",
        })
    if incident.priority in ("P1", "P2"):
        obligations.append({
            "regime": "Cyber-insurance policy",
            "action": "Notify insurer/broker; preserve evidence; use panel IR vendor if mandated",
            "deadline": None,
            "required": "likely" if incident.priority == "P1" else "review",
        })
    return {
        "noticed_at": noticed.isoformat(),
        "certin_types": [CERTIN_TYPES[t] for t in types],
        "certin_deadline": certin_deadline.isoformat() if types else None,
        "certin_seconds_left": int((certin_deadline - now).total_seconds()) if types else None,
        "personal_data_at_risk": personal_data,
        "personal_data_systems": pd_systems,
        "obligations": obligations,
    }


def _ist(ts: str | datetime | None) -> str:
    if not ts:
        return "—"
    if isinstance(ts, str):
        ts = datetime.fromisoformat(ts)
    return ts.astimezone(IST).strftime("%d %b %Y, %H:%M IST")


def certin_report_md(incident: Incident, alerts: List[Alert], org: OrgConfig) -> str:
    reg = incident.regulatory
    an = incident.analysis
    ips = [ip for ip in incident.entities.get("ip", []) if not org.is_internal(ip)]
    lines = [
        f"# CERT-In Incident Report — DRAFT ({incident.id})",
        "",
        "> Auto-drafted by AssureSOC for analyst review. Verify every field against the current "
        "CERT-In incident reporting form before submission.",
        "",
        "## 1. Reporting organisation",
        f"- **Organisation:** {org.name}",
        f"- **Sector:** {org.sector}",
        "- **Point of contact:** _<name, designation, phone, email>_",
        "",
        "## 2. Incident overview",
        f"- **Incident type(s) (Annexure I):** " + ("; ".join(reg.get("certin_types", [])) or "—"),
        f"- **Date/time of occurrence (first indicator):** {_ist(incident.first_seen)}",
        f"- **Date/time noticed:** {_ist(reg.get('noticed_at'))}",
        f"- **Reporting deadline (6 h):** {_ist(reg.get('certin_deadline'))}",
        f"- **Priority / risk score:** {incident.priority} / {incident.score}",
        "",
        "## 3. Description",
        an.get("executive_summary", ""),
        "",
        "## 4. Affected systems",
    ]
    for h in incident.entities.get("host", []) or ["—"]:
        lines.append(f"- {h}" + (" (crown-jewel)" if org.criticality(h) > 1 else ""))
    lines += ["", "## 5. Accounts involved"]
    lines += [f"- {u}" for u in incident.entities.get("user", [])[:20]] or ["- —"]
    targeted = incident.related_entities.get("user", [])
    if targeted:
        lines.append(f"- Also targeted without evidence of compromise ({len(targeted)}): " + ", ".join(targeted[:25]))
    lines += ["", "## 6. Indicators of compromise"]
    lines += [f"- IP: {ip}" for ip in ips] + [f"- Domain: {d}" for d in incident.entities.get("domain", [])]
    lines += [f"- Targeted system: {h}" for h in incident.related_entities.get("host", [])]
    if not ips and not incident.entities.get("domain"):
        lines.append("- —")
    lines += ["", "## 7. Observed activity (timeline, IST)"]
    for a in alerts:
        lines.append(f"- {_ist(a.first_seen)} — **{a.title}** ({a.technique_id}): {a.description}")
    lines += ["", "## 8. Actions taken / planned"]
    for act in an.get("recommended_actions", []):
        lines.append(f"- [{act.get('priority', '')}] {act.get('action', '')}")
    lines += [
        "",
        "## 9. Personal data",
        "- Personal data potentially affected: " + ("**Yes** — DPDP intimation likely required"
                                                     if reg.get("personal_data_at_risk") else "Not indicated so far"),
        "",
        "## 10. Logs preserved",
        "- Source telemetry retained in AssureSOC evidence store (event IDs referenced per alert). "
        "CERT-In Directions require ICT logs to be maintained for 180 days within India.",
    ]
    return "\n".join(lines) + "\n"


def insurer_notice_md(incident: Incident, alerts: List[Alert], org: OrgConfig) -> str:
    an = incident.analysis
    lines = [
        f"# Cyber-Insurance Incident Notification — DRAFT ({incident.id})",
        "",
        f"**Insured:** {org.name}  ",
        "**Policy number:** _<policy no.>_  ",
        "**Broker:** _<broker / account manager>_  ",
        f"**Date of discovery:** {_ist(incident.first_seen)}  ",
        f"**Priority / risk score:** {incident.priority} / {incident.score}",
        "",
        "## Summary of event",
        an.get("executive_summary", ""),
        "",
        "## Suspected cause",
        an.get("attack_stage", "Under investigation"),
        "",
        "## Business impact (preliminary)",
        an.get("business_impact", "Under assessment"),
        "",
        "## Affected assets",
    ]
    lines += [f"- {h}" for h in incident.entities.get("host", []) + incident.related_entities.get("host", [])] or ["- —"]
    lines += [
        "",
        "## Potential loss heads to flag",
        "- Incident response & forensic investigation",
        "- Data restoration / system rebuild",
        "- Business interruption (if systems are taken offline)",
        "- Regulatory response (CERT-In / DPDP) and notification costs"
        + (" — personal data at risk" if incident.regulatory.get("personal_data_at_risk") else ""),
        "",
        "## Containment steps taken / planned",
    ]
    lines += [f"- {a.get('action', '')}" for a in an.get("recommended_actions", [])[:8]]
    lines += [
        "",
        "## Evidence preserved",
        f"- {len(alerts)} correlated detections with linked source events (AssureSOC {incident.id})",
        "- No ransom has been paid or negotiated; insurer consent will be sought before any such step.",
    ]
    return "\n".join(lines) + "\n"
