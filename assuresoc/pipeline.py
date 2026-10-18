"""End-to-end pipeline: events -> guard -> detections -> UEBA -> suppression -> incidents."""

from __future__ import annotations

import time
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .compliance import assess
from .core.config import DEFAULT_ORG, OrgConfig
from .core.models import Alert, Event, Incident
from .defense.guard import detect_injections
from .detection.anomaly import detect_anomalies
from .detection.correlate import build_incidents
from .detection.rules import DetectionContext, run_rules
from .intelligence.analyst import offline_analysis


class Workspace:
    """Result of one analysis run — everything the API and UI need."""

    def __init__(self, events: List[Event], alerts: List[Alert], incidents: List[Incident],
                 flagged: Dict[str, Dict[str, List[str]]], org: OrgConfig, label: str, elapsed_ms: int):
        self.events = events
        self.events_by_id = {e.id: e for e in events}
        self.alerts = alerts
        self.alerts_by_id = {a.id: a for a in alerts}
        self.incidents = incidents
        self.incidents_by_id = {i.id: i for i in incidents}
        self.flagged = flagged
        self.org = org
        self.label = label
        self.elapsed_ms = elapsed_ms
        self.created_at = datetime.now(timezone.utc)

    def alerts_for(self, inc: Incident) -> List[Alert]:
        return [self.alerts_by_id[a] for a in inc.alert_ids]

    def stats(self) -> dict:
        active = [a for a in self.alerts if not a.suppressed]
        by_priority = Counter(i.priority for i in self.incidents)
        return {
            "label": self.label,
            "events": len(self.events),
            "sources": dict(Counter(e.source for e in self.events).most_common()),
            "time_range": [self.events[0].ts.isoformat(), self.events[-1].ts.isoformat()] if self.events else None,
            "alerts": len(self.alerts),
            "suppressed": len(self.alerts) - len(active),
            "incidents": len(self.incidents),
            "by_priority": {p: by_priority.get(p, 0) for p in ("P1", "P2", "P3", "P4")},
            "queue_reduction_pct": round(100 * (1 - len(self.incidents) / len(self.alerts)), 1) if self.alerts else 0,
            "injections_neutralised": sum(len(v) for v in self.flagged.values()),
            "injection_events": len(self.flagged),
            "techniques": len({a.technique_id for a in active}),
            "elapsed_ms": self.elapsed_ms,
        }


def apply_suppressions(alerts: List[Alert], org: OrgConfig) -> None:
    for a in alerts:
        for ip in a.entities.get("ip", []):
            if ip in org.allowlisted_ips:
                a.suppressed = True
                a.suppression_reason = f"{ip}: {org.allowlisted_ips[ip]}"
                break


def analyse(events: List[Event], org: Optional[OrgConfig] = None, label: str = "upload",
            now: Optional[datetime] = None) -> Workspace:
    org = org or DEFAULT_ORG
    t0 = time.perf_counter()
    ctx = DetectionContext(events, org)
    guard_alerts, flagged = detect_injections(ctx.events)
    alerts = run_rules(ctx) + detect_anomalies(ctx) + guard_alerts
    apply_suppressions(alerts, org)
    incidents = build_incidents(alerts, org)
    by_id = {a.id: a for a in alerts}
    for inc in incidents:
        inc_alerts = [by_id[a] for a in inc.alert_ids]
        inc.regulatory = assess(inc, inc_alerts, org, now=now)
        inc.analysis = offline_analysis(inc, inc_alerts, org)
    elapsed = int((time.perf_counter() - t0) * 1000)
    return Workspace(ctx.events, alerts, incidents, flagged, org, label, elapsed)
