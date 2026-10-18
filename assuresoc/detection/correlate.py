"""Alert -> incident correlation and explainable risk scoring.

Alerts that share an entity (user, host, IP, domain) within a time window are merged with a
union-find into one incident. Each incident then gets a 0-100 risk score that is the product
of transparent factors, so an analyst can see exactly why something is P1.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from datetime import timedelta
from typing import Dict, List

from ..core.config import OrgConfig
from ..core.models import TACTIC_ORDER, Alert, Incident, RiskFactor

LINK_WINDOW = timedelta(hours=8)
HUB_LIMIT = 40  # entities linking more alerts than this are infrastructure, not evidence

# Rules that describe attempts stopped by a control (no evidence of success).
PREVENTED_RULES = {"web_attack", "web_scan", "password_spray", "ai_prompt_injection"}


class _UnionFind:
    def __init__(self, n: int):
        self.parent = list(range(n))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        self.parent[self.find(a)] = self.find(b)


def _cluster(alerts: List[Alert]) -> List[List[Alert]]:
    uf = _UnionFind(len(alerts))
    by_entity: Dict[str, List[int]] = defaultdict(list)
    for i, a in enumerate(alerts):
        for kind, values in a.entities.items():
            for v in values:
                by_entity[f"{kind}:{v}"].append(i)
    for idxs in by_entity.values():
        if len(idxs) > HUB_LIMIT:
            continue
        idxs = sorted(idxs, key=lambda i: alerts[i].first_seen)
        for prev, cur in zip(idxs, idxs[1:]):
            if alerts[cur].first_seen - alerts[prev].last_seen <= LINK_WINDOW:
                uf.union(prev, cur)
    groups: Dict[int, List[Alert]] = defaultdict(list)
    for i, a in enumerate(alerts):
        groups[uf.find(i)].append(a)
    return [sorted(g, key=lambda a: a.first_seen) for g in groups.values()]


def _merge_entities(alerts: List[Alert], include_related: bool) -> Dict[str, List[str]]:
    merged: Dict[str, Counter] = defaultdict(Counter)
    for a in alerts:
        sources = [a.entities] + ([a.related] if include_related else [])
        for src in sources:
            for k, vals in src.items():
                merged[k].update(vals)
    return {k: [v for v, _ in c.most_common()] for k, c in merged.items()}


def score(alerts: List[Alert], org: OrgConfig):
    """Return (score 0-100, priority, factors)."""
    weights = sorted((a.weight for a in alerts), reverse=True)
    strength = sum(w * 0.85 ** i for i, w in enumerate(weights))
    base = 1 - math.exp(-strength)
    factors = [RiskFactor(label="Evidence strength",
                          detail=f"{len(alerts)} alert(s), diminishing-returns sum {strength:.2f}",
                          effect=f"base {base:.2f}")]
    mult = 1.0

    tactics = {a.tactic for a in alerts}
    stage = max(TACTIC_ORDER.index(t) for t in tactics if t in TACTIC_ORDER)
    if TACTIC_ORDER[stage] in ("Exfiltration", "Impact"):
        factors.append(RiskFactor(label="Kill-chain stage", detail=f"reached {TACTIC_ORDER[stage]}", effect="x1.25"))
        mult *= 1.25
    elif TACTIC_ORDER[stage] in ("Credential Access", "Lateral Movement", "Collection", "Command and Control"):
        factors.append(RiskFactor(label="Kill-chain stage", detail=f"reached {TACTIC_ORDER[stage]}", effect="x1.10"))
        mult *= 1.10

    if len(tactics) > 1:
        b = 1 + 0.05 * (len(tactics) - 1)
        factors.append(RiskFactor(label="Tactic breadth", detail=f"{len(tactics)} ATT&CK tactics", effect=f"x{b:.2f}"))
        mult *= b

    hosts = _merge_entities(alerts, include_related=True).get("host", [])
    if hosts:
        crit_host = max(hosts, key=org.criticality)
        crit = org.criticality(crit_host)
        if crit > 1.0:
            factors.append(RiskFactor(label="Crown-jewel asset", detail=crit_host, effect=f"x{crit:.2f}"))
            mult *= crit

    users = _merge_entities(alerts, include_related=False).get("user", [])
    priv = [u for u in users if u in org.privileged_users]
    if priv:
        factors.append(RiskFactor(label="Privileged identity", detail=", ".join(priv), effect="x1.10"))
        mult *= 1.10

    if all(a.rule_id in PREVENTED_RULES or (a.rule_id == "brute_force" and not a.details.get("succeeded"))
           for a in alerts):
        factors.append(RiskFactor(label="Stopped by control", detail="only blocked/failed attempts observed",
                                  effect="x0.75"))
        mult *= 0.75

    value = min(100, round(100 * base * mult))
    priority = "P1" if value >= 80 else "P2" if value >= 55 else "P3" if value >= 30 else "P4"
    return value, priority, factors


def _title(alerts: List[Alert], entities: Dict[str, List[str]]) -> str:
    tactics = {a.tactic for a in alerts}
    rules = {a.rule_id for a in alerts}
    focus = (entities.get("user") or entities.get("host") or entities.get("ip") or ["unknown"])[0]
    if "Impact" in tactics and "Exfiltration" in tactics:
        return f"Ransomware precursor with data exfiltration — {focus}"
    if "Impact" in tactics:
        return f"Destructive activity / ransomware precursor — {focus}"
    if "Exfiltration" in tactics:
        return f"Possible data exfiltration — {focus}"
    if tactics & {"Credential Access", "Lateral Movement"} and "Initial Access" in tactics:
        return f"Account compromise — {focus}"
    if rules & {"web_attack", "web_scan"}:
        target = (_merge_entities(alerts, True).get("host") or [focus])[0]
        return f"Attack on public web application {target} from {entities.get('ip', [focus])[0]}"
    if rules == {"ueba_anomaly"}:
        return f"Unusual user behaviour — {focus}"
    top = max(alerts, key=lambda a: a.weight)
    return f"{top.title} — {focus}"


def build_incidents(alerts: List[Alert], org: OrgConfig) -> List[Incident]:
    active = [a for a in alerts if not a.suppressed]
    incidents = []
    for group in _cluster(active):
        entities = _merge_entities(group, include_related=False)
        value, priority, factors = score(group, org)
        tactics = sorted({a.tactic for a in group}, key=lambda t: TACTIC_ORDER.index(t) if t in TACTIC_ORDER else 99)
        techniques = list({a.technique_id: {"id": a.technique_id, "name": a.technique_name, "tactic": a.tactic}
                           for a in group}.values())
        incidents.append(Incident(
            id="",
            title=_title(group, entities),
            priority=priority,
            score=value,
            first_seen=group[0].first_seen,
            last_seen=max(a.last_seen for a in group),
            tactics=tactics,
            techniques=techniques,
            alert_ids=[a.id for a in group],
            entities=entities,
            related_entities={k: [v for v in vals if v not in entities.get(k, [])]
                              for k, vals in _merge_entities(group, include_related=True).items()
                              if any(v not in entities.get(k, []) for v in vals)},
            factors=factors,
        ))
    incidents.sort(key=lambda i: (-i.score, i.first_seen))
    for n, inc in enumerate(incidents, 1):
        inc.id = f"INC-{n:03d}"
    return incidents
