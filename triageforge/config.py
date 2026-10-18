"""Organisation context that turns generic detections into business-aware risk."""

from __future__ import annotations

from datetime import timedelta, timezone
from typing import Dict, List

from pydantic import BaseModel, Field

IST = timezone(timedelta(hours=5, minutes=30))


class OrgConfig(BaseModel):
    name: str = "NovaPay Fintech Pvt. Ltd. (fictional)"
    sector: str = "Financial services / digital payments"
    domains: List[str] = Field(default_factory=lambda: ["novapay.example"])
    # Asset criticality multipliers — crown jewels raise incident risk.
    crown_jewels: Dict[str, float] = Field(
        default_factory=lambda: {
            "DC-01": 1.4,
            "PAY-DB-01": 1.5,
            "FILESRV-01": 1.3,
            "WEB-01": 1.2,
        }
    )
    # Systems that hold personal data (drives DPDP Act applicability).
    personal_data_systems: List[str] = Field(
        default_factory=lambda: ["PAY-DB-01", "FILESRV-01", "WEB-01"]
    )
    privileged_users: List[str] = Field(default_factory=lambda: ["adm.rahul", "adm.kavya"])
    privileged_groups: List[str] = Field(
        default_factory=lambda: ["Domain Admins", "Enterprise Admins", "Administrators"]
    )
    # Known-good sources whose alerts are suppressed (authorised internal scanner).
    allowlisted_ips: Dict[str, str] = Field(
        default_factory=lambda: {"10.0.5.10": "Authorised internal vulnerability scanner"}
    )
    internal_prefixes: List[str] = Field(default_factory=lambda: ["10.", "192.168.", "172.16."])
    work_hours: tuple = (8, 21)  # local (IST) hours considered normal

    def is_internal(self, ip: str | None) -> bool:
        return bool(ip) and any(ip.startswith(p) for p in self.internal_prefixes)

    def criticality(self, host: str | None) -> float:
        return self.crown_jewels.get(host or "", 1.0)


DEFAULT_ORG = OrgConfig()
