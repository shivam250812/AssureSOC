"""Core data model: normalised events, detection alerts and correlated incidents."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

# MITRE ATT&CK enterprise tactics in kill-chain order.
TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

SEVERITY_ORDER = ["low", "medium", "high", "critical"]
SEVERITY_WEIGHT = {"low": 0.2, "medium": 0.45, "high": 0.7, "critical": 0.9}


class Event(BaseModel):
    """One normalised telemetry record. Every string field may be attacker-controlled."""

    id: str
    ts: datetime
    source: str  # auth | vpn | edr | windows | email | proxy | firewall | web | waf
    action: str  # login_success | login_failure | mfa_denied | edr_alert | flow | ...
    user: Optional[str] = None
    host: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    domain: Optional[str] = None
    country: Optional[str] = None
    url: Optional[str] = None
    status: Optional[int] = None
    bytes_out: Optional[int] = None
    user_agent: Optional[str] = None
    sender: Optional[str] = None
    subject: Optional[str] = None
    signature: Optional[str] = None
    technique: Optional[str] = None
    severity: Optional[str] = None
    target_user: Optional[str] = None
    group: Optional[str] = None
    category: Optional[str] = None
    message: Optional[str] = None
    raw: Optional[str] = None


class Alert(BaseModel):
    id: str
    rule_id: str
    title: str
    description: str
    severity: str
    confidence: float
    tactic: str
    technique_id: str
    technique_name: str
    first_seen: datetime
    last_seen: datetime
    # Entities used to correlate alerts into incidents ("user", "host", "ip", "domain").
    entities: Dict[str, List[str]] = Field(default_factory=dict)
    # Context-only entities (e.g. the 30 users targeted by a spray) — shown, never linked on.
    related: Dict[str, List[str]] = Field(default_factory=dict)
    evidence: List[str] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)
    suppressed: bool = False
    suppression_reason: Optional[str] = None

    @property
    def weight(self) -> float:
        return SEVERITY_WEIGHT[self.severity] * self.confidence


class RiskFactor(BaseModel):
    label: str
    detail: str
    effect: str  # human readable, e.g. "x1.30" or "+0.70"


class Incident(BaseModel):
    id: str
    title: str
    priority: str  # P1..P4
    score: int
    status: str = "new"  # new | investigating | contained | closed
    first_seen: datetime
    last_seen: datetime
    tactics: List[str]
    techniques: List[Dict[str, str]]
    alert_ids: List[str]
    entities: Dict[str, List[str]]  # entities the evidence ties to the activity
    related_entities: Dict[str, List[str]] = Field(default_factory=dict)  # context only (e.g. spray targets)
    factors: List[RiskFactor]
    analysis: Dict[str, Any] = Field(default_factory=dict)
    analysis_source: str = "offline"
    regulatory: Dict[str, Any] = Field(default_factory=dict)
