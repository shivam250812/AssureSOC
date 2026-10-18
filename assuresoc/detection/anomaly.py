"""UEBA: unsupervised user-behaviour anomaly detection (Isolation Forest).

Each (user, hour) bucket becomes a feature vector. The forest isolates buckets that look unlike
the rest of the organisation; we then explain every flagged bucket by the features that deviate
most from that population, so analysts see *why* — not just a score.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Dict, List, Tuple

import numpy as np

from ..core.config import IST, OrgConfig
from .rules import DetectionContext
from ..core.models import Alert, Event

FEATURES = [
    "logins_ok",
    "logins_failed",
    "mfa_denied",
    "distinct_src_ips",
    "foreign_logins",
    "off_hours_activity",
    "hours_from_usual",
    "remote_logons",
    "distinct_hosts",
]
_RELEVANT = {"login_success", "login_failure", "mfa_denied", "mfa_approved", "remote_logon"}


def _bucket_features(events: List[Event], org: OrgConfig):
    buckets: Dict[Tuple[str, object], List[Event]] = defaultdict(list)
    home: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    login_hours: Dict[str, List[float]] = defaultdict(list)
    for e in events:
        if e.action in _RELEVANT and e.user:
            buckets[(e.user, e.ts.replace(minute=0, second=0, microsecond=0))].append(e)
            if e.action == "login_success":
                local = e.ts.astimezone(IST)
                login_hours[e.user].append(local.hour + local.minute / 60)
                if e.country:
                    home[e.user][e.country] += 1
    usual_hour = {u: float(np.median(h)) for u, h in login_hours.items()}
    keys, rows = [], []
    lo, hi = org.work_hours
    for (user, hour), evs in buckets.items():
        usual = max(home[user], key=home[user].get) if home[user] else None
        local_hour = hour.astimezone(IST).hour
        ok = [e for e in evs if e.action == "login_success"]
        drift = abs(local_hour + 0.5 - usual_hour.get(user, local_hour + 0.5)) % 24
        drift = min(drift, 24 - drift)
        rows.append([
            len(ok),
            sum(e.action == "login_failure" for e in evs),
            sum(e.action == "mfa_denied" for e in evs),
            len({e.src_ip for e in evs if e.src_ip}),
            sum(1 for e in ok if e.country and usual and e.country != usual),
            1 if not (lo <= local_hour < hi) else 0,
            round(drift, 1),
            sum(e.action == "remote_logon" for e in evs),
            len({e.host for e in evs if e.host}),
        ])
        keys.append((user, hour, evs))
    return keys, np.array(rows, dtype=float)


def detect_anomalies(ctx: DetectionContext, max_alerts: int = 6, min_z: float = 3.0) -> List[Alert]:
    keys, X = _bucket_features(ctx.events, ctx.org)
    if len(X) < 50:  # not enough behaviour to learn a baseline
        return []
    from sklearn.ensemble import IsolationForest

    model = IsolationForest(n_estimators=200, contamination=0.02, random_state=42)
    model.fit(X)
    scores = model.decision_function(X)  # < 0 => outlier

    # Explain each outlier against the user's *own* history (falls back to the org baseline
    # for users with little history), so routine-but-unusual roles such as admins stay quiet.
    org_mean, org_std = X.mean(axis=0), X.std(axis=0)
    rows_by_user: Dict[str, List[int]] = defaultdict(list)
    for i, (user, _, _) in enumerate(keys):
        rows_by_user[user].append(i)

    # Candidates: the most isolated ~3% of buckets; the per-user z-test below keeps precision.
    cutoff = min(0.0, float(np.percentile(scores, 3)))
    flagged = []
    for idx in np.argsort(scores):
        if scores[idx] > cutoff or len(flagged) >= max_alerts:
            break
        user = keys[idx][0]
        authenticated = X[idx][FEATURES.index("logins_ok")] + X[idx][FEATURES.index("remote_logons")] > 0
        if not authenticated:  # failed-only activity is covered by the brute-force rules
            continue
        others = [i for i in rows_by_user[user] if i != idx]
        if len(others) >= 8:
            base = X[others]
            mean, std = base.mean(axis=0), np.maximum(base.std(axis=0), 0.75)
        else:
            mean, std = org_mean, np.maximum(org_std, 0.75)
        z = (X[idx] - mean) / std
        top = [(FEATURES[i], float(z[i]), X[idx][i]) for i in np.argsort(-z)[:3] if z[i] >= min_z]
        if top:
            flagged.append((idx, top))

    alerts = []
    for idx, top in flagged:
        user, hour, evs = keys[idx]
        evs = sorted(evs, key=lambda e: e.ts)
        why = "; ".join(f"{name.replace('_', ' ')}={val:g} ({zv:.1f}σ above baseline)" for name, zv, val in top)
        sev = "medium" if scores[idx] < -0.1 else "low"
        alerts.append(ctx.alert(
            "ueba_anomaly", "T1078", f"Anomalous behaviour for '{user}' (UEBA)",
            f"Isolation Forest flagged {user}'s activity at {hour.astimezone(IST):%d %b %H:00 IST} "
            f"(anomaly score {scores[idx]:.3f}). Drivers: {why}.",
            sev, 0.55, evs, {"user": [user]},
            details={"anomaly_score": round(float(scores[idx]), 4),
                     "drivers": [{"feature": n, "z": round(zv, 2), "value": v} for n, zv, v in top],
                     "window": f"{hour.isoformat()} +{timedelta(hours=1)}"},
        ))
    return alerts
