"""Deterministic, explainable detection rules mapped to MITRE ATT&CK.

Rules run over time-ordered normalised events. Each emits `Alert`s that cite the exact
evidence events, so every downstream AI statement can be traced back to raw telemetry.
"""

from __future__ import annotations

import math
from collections import defaultdict
from datetime import timedelta
from itertools import count
from typing import Callable, Dict, Iterable, List, Optional
from urllib.parse import urlparse

from ..core.config import OrgConfig
from ..core.models import Alert, Event

# technique id -> (tactic, name)
TECHNIQUES: Dict[str, tuple] = {
    "T1595.002": ("Reconnaissance", "Active Scanning: Vulnerability Scanning"),
    "T1566.002": ("Initial Access", "Phishing: Spearphishing Link"),
    "T1190": ("Initial Access", "Exploit Public-Facing Application"),
    "T1078": ("Initial Access", "Valid Accounts"),
    "T1078.002": ("Privilege Escalation", "Valid Accounts: Domain Accounts"),
    "T1059.001": ("Execution", "Command and Scripting Interpreter: PowerShell"),
    "T1136.002": ("Persistence", "Create Account: Domain Account"),
    "T1098": ("Persistence", "Account Manipulation"),
    "T1070.001": ("Defense Evasion", "Indicator Removal: Clear Windows Event Logs"),
    "T1110.001": ("Credential Access", "Brute Force: Password Guessing"),
    "T1110.003": ("Credential Access", "Brute Force: Password Spraying"),
    "T1621": ("Credential Access", "Multi-Factor Authentication Request Generation"),
    "T1003.001": ("Credential Access", "OS Credential Dumping: LSASS Memory"),
    "T1087": ("Discovery", "Account Discovery"),
    "T1021.001": ("Lateral Movement", "Remote Services: Remote Desktop Protocol"),
    "T1021.002": ("Lateral Movement", "Remote Services: SMB/Windows Admin Shares"),
    "T1560": ("Collection", "Archive Collected Data"),
    "T1071": ("Command and Control", "Application Layer Protocol"),
    "T1048": ("Exfiltration", "Exfiltration Over Alternative Protocol"),
    "T1486": ("Impact", "Data Encrypted for Impact"),
    "T1490": ("Impact", "Inhibit System Recovery"),
}

# Rough country centroids (lat, lon) for impossible-travel checks.
COUNTRY_COORDS = {
    "IN": (22.0, 79.0), "NL": (52.1, 5.3), "US": (39.8, -98.6), "SG": (1.35, 103.8),
    "GB": (54.0, -2.0), "DE": (51.0, 10.0), "AE": (24.0, 54.0), "JP": (36.0, 138.0),
    "AU": (-25.0, 134.0), "FR": (46.0, 2.0), "BR": (-10.0, -55.0), "HK": (22.3, 114.2),
    "CA": (56.0, -106.0), "ID": (-2.0, 118.0), "ZA": (-29.0, 24.0), "LK": (7.9, 80.7),
}

SCANNER_UA_MARKERS = ("sqlmap", "nikto", "nuclei", "masscan", "zgrab", "dirbuster", "gobuster", "wpscan")


class DetectionContext:
    def __init__(self, events: List[Event], org: OrgConfig):
        self.events = sorted(events, key=lambda e: e.ts)
        self.org = org
        self.by_action: Dict[str, List[Event]] = defaultdict(list)
        for e in self.events:
            self.by_action[e.action].append(e)
        self._ids = count(1)
        # History-based rules ("never seen before") stay quiet while the baseline is learned.
        span = (self.events[-1].ts - self.events[0].ts) if self.events else timedelta(0)
        learn = min(timedelta(days=2), span / 4)
        self.learning_until = (self.events[0].ts + learn) if self.events else None

    def learning(self, ev: Event) -> bool:
        return self.learning_until is not None and ev.ts < self.learning_until

    def alert(self, rule_id: str, technique: str, title: str, description: str, severity: str,
              confidence: float, evidence: List[Event], entities: Dict[str, Iterable[Optional[str]]],
              related: Optional[Dict[str, Iterable[str]]] = None, details: Optional[dict] = None,
              window: Optional[tuple] = None) -> Alert:
        tactic, tname = TECHNIQUES[technique]
        first, last = window or (min(e.ts for e in evidence), max(e.ts for e in evidence))
        return Alert(
            id=f"al-{next(self._ids):04d}",
            rule_id=rule_id,
            title=title,
            description=description,
            severity=severity,
            confidence=round(confidence, 2),
            tactic=tactic,
            technique_id=technique,
            technique_name=tname,
            first_seen=first,
            last_seen=last,
            entities={k: sorted({v for v in vals if v}) for k, vals in entities.items() if any(vals)},
            related={k: sorted(set(v)) for k, v in (related or {}).items() if v},
            evidence=[e.id for e in evidence][:200],
            details=details or {},
        )


def gap_clusters(items: List[Event], gap: timedelta) -> List[List[Event]]:
    """Split a time-ordered list wherever consecutive events are further apart than `gap`."""
    out, cur = [], []
    for it in items:
        if cur and it.ts - cur[-1].ts > gap:
            out.append(cur)
            cur = []
        cur.append(it)
    if cur:
        out.append(cur)
    return out


def _group(events: Iterable[Event], key: Callable[[Event], object]) -> Dict[object, List[Event]]:
    groups: Dict[object, List[Event]] = defaultdict(list)
    for e in events:
        k = key(e)
        if k is not None and k != (None, None):
            groups[k].append(e)
    return groups


def _fmt(ts) -> str:
    return ts.strftime("%H:%M UTC")


# --- Credential access ---------------------------------------------------------------------


def rule_brute_force(ctx: DetectionContext) -> List[Alert]:
    alerts = []
    successes = ctx.by_action["login_success"]
    for (user, ip), fails in _group(ctx.by_action["login_failure"], lambda e: (e.user, e.src_ip)).items():
        for burst in gap_clusters(fails, timedelta(minutes=5)):
            if len(burst) < 8:
                continue
            follow = next((s for s in successes if s.user == user and s.src_ip == ip
                           and burst[-1].ts <= s.ts <= burst[-1].ts + timedelta(minutes=30)), None)
            evidence = burst + ([follow] if follow else [])
            alerts.append(ctx.alert(
                "brute_force", "T1110.001",
                "Brute force succeeded" if follow else "Password brute force",
                f"{len(burst)} failed logins for '{user}' from {ip} between {_fmt(burst[0].ts)} and "
                f"{_fmt(burst[-1].ts)}" + (f", followed by a successful login at {_fmt(follow.ts)}." if follow else "."),
                "high" if follow else "medium", 0.9 if follow else 0.7, evidence,
                {"user": [user], "ip": [ip]}, related={"host": [burst[0].host] if burst[0].host else []},
                details={"failures": len(burst), "succeeded": bool(follow)},
            ))
    return alerts


def rule_password_spray(ctx: DetectionContext) -> List[Alert]:
    alerts = []
    for ip, fails in _group(ctx.by_action["login_failure"], lambda e: e.src_ip).items():
        for burst in gap_clusters(fails, timedelta(minutes=10)):
            users = {e.user for e in burst if e.user}
            if len(users) < 8:
                continue
            alerts.append(ctx.alert(
                "password_spray", "T1110.003", "Password spraying from single source",
                f"{ip} attempted {len(burst)} logins against {len(users)} distinct accounts "
                f"within {int((burst[-1].ts - burst[0].ts).total_seconds() // 60) + 1} minutes.",
                "high" if not ctx.org.is_internal(ip) else "medium", 0.85, burst,
                {"ip": [ip]}, related={"user": users},
                details={"attempts": len(burst), "accounts_targeted": len(users),
                         "country": burst[0].country},
            ))
    return alerts


def rule_mfa_fatigue(ctx: DetectionContext) -> List[Alert]:
    alerts = []
    approvals = ctx.by_action["mfa_approved"]
    for user, denies in _group(ctx.by_action["mfa_denied"], lambda e: e.user).items():
        for burst in gap_clusters(denies, timedelta(minutes=10)):
            if len(burst) < 4:
                continue
            approve = next((a for a in approvals if a.user == user
                            and burst[-1].ts <= a.ts <= burst[-1].ts + timedelta(minutes=15)), None)
            evidence = burst + ([approve] if approve else [])
            alerts.append(ctx.alert(
                "mfa_fatigue", "T1621",
                "MFA fatigue: push bombing accepted" if approve else "MFA push bombing",
                f"{len(burst)} MFA push requests denied by '{user}' in quick succession"
                + (f"; a push was then approved at {_fmt(approve.ts)} — likely user gave in." if approve else "."),
                "high" if approve else "medium", 0.9 if approve else 0.65, evidence,
                {"user": [user], "ip": [e.src_ip for e in evidence]},
                details={"denied": len(burst), "approved": bool(approve)},
            ))
    return alerts


# --- Initial access / valid accounts ----------------------------------------------------------


def _km(a: str, b: str) -> Optional[float]:
    if a not in COUNTRY_COORDS or b not in COUNTRY_COORDS:
        return None
    (la1, lo1), (la2, lo2) = COUNTRY_COORDS[a], COUNTRY_COORDS[b]
    p1, p2 = math.radians(la1), math.radians(la2)
    dp, dl = p2 - p1, math.radians(lo2 - lo1)
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * 6371 * math.asin(math.sqrt(h))


def rule_login_geography(ctx: DetectionContext) -> List[Alert]:
    """New-country logins and impossible travel between consecutive successful logins."""
    alerts = []
    for user, logins in _group(ctx.by_action["login_success"], lambda e: e.user).items():
        seen_countries: Dict[str, int] = defaultdict(int)
        prev: Optional[Event] = None
        for n_prior, ev in enumerate(logins):
            c = ev.country
            home = max(seen_countries, key=seen_countries.get) if seen_countries else None
            if c and prev and prev.country and c != prev.country and c != home:
                km = _km(prev.country, c)
                hours = max((ev.ts - prev.ts).total_seconds() / 3600, 1 / 60)
                if km and km / hours > 900:
                    alerts.append(ctx.alert(
                        "impossible_travel", "T1078", "Impossible travel",
                        f"'{user}' logged in from {prev.country} at {_fmt(prev.ts)} and from {c} at "
                        f"{_fmt(ev.ts)} — {int(km)} km in {hours:.1f} h ({int(km / hours)} km/h).",
                        "high", 0.85, [prev, ev], {"user": [user], "ip": [ev.src_ip]},
                        details={"from": prev.country, "to": c, "km": int(km), "kmh": int(km / hours)},
                        window=(ev.ts, ev.ts),
                    ))
            if c and seen_countries and c not in seen_countries and n_prior >= 3 and not ctx.learning(ev):
                alerts.append(ctx.alert(
                    "new_country_login", "T1078", "Login from never-seen country",
                    f"First successful login for '{user}' from {c} (history: {', '.join(sorted(seen_countries))}).",
                    "medium", 0.6, [ev], {"user": [user], "ip": [ev.src_ip]},
                    details={"country": c, "known_countries": sorted(seen_countries)},
                ))
            if c:
                seen_countries[c] += 1
            prev = ev
    return alerts


def _registrable_label(domain: str) -> str:
    parts = domain.lower().strip(".").split(".")
    return parts[-2] if len(parts) >= 2 else parts[0]


def _levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


_CONFUSABLES = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"), ("@", "a")]


def lookalike_reason(domain: Optional[str], org_domains: List[str]) -> Optional[str]:
    """Explain why `domain` impersonates one of the org's domains, or None."""
    if not domain:
        return None
    d = domain.lower().strip(".")
    if any(d == o or d.endswith("." + o) for o in org_domains):
        return None
    def normalise(text: str) -> str:
        for src, dst in _CONFUSABLES:
            text = text.replace(src, dst)
        return text

    label = _registrable_label(d)
    norm = normalise(label)
    for org in org_domains:
        brand = _registrable_label(org)
        if norm == brand:
            return f"homoglyph of {org} ('{label}' reads as '{brand}')"
        if any(brand in normalise(part) for part in d.split(".")):
            return f"embeds brand '{brand}' in an unrelated domain"
        dist = _levenshtein(label, brand)
        if len(brand) >= 5 and 0 < dist <= 2:
            return f"typo-squat of {org} (edit distance {dist})"
    return None


def _domain_of(ev: Event) -> Optional[str]:
    if ev.domain:
        return ev.domain
    if ev.url and "://" in ev.url:
        return urlparse(ev.url).hostname
    return None


def rule_phishing(ctx: DetectionContext) -> List[Alert]:
    alerts = []
    org = ctx.org.domains
    deliveries: Dict[str, List[Event]] = defaultdict(list)
    for ev in ctx.by_action["email_delivered"]:
        sender_dom = (ev.sender or "").split("@")[-1] or None
        for dom in {sender_dom, _domain_of(ev)}:
            reason = lookalike_reason(dom, org)
            if reason:
                deliveries[dom].append(ev)
                break
    for dom, evs in deliveries.items():
        alerts.append(ctx.alert(
            "phishing_lookalike", "T1566.002", "Phishing email from look-alike domain",
            f"{len(evs)} email(s) delivered from/linking to {dom} ({lookalike_reason(dom, org)}). "
            f"Subject: “{evs[0].subject or 'n/a'}”.",
            "medium", 0.75, evs, {"domain": [dom], "user": [e.user for e in evs]},
            details={"domain": dom, "recipients": sorted({e.user for e in evs if e.user})},
        ))
    clicks = _group(
        [e for e in ctx.by_action["url_click"] if lookalike_reason(_domain_of(e), org)],
        lambda e: (e.user, _domain_of(e)),
    )
    for (user, dom), evs in clicks.items():
        alerts.append(ctx.alert(
            "phishing_click", "T1566.002", "User clicked look-alike phishing link",
            f"'{user}' visited {dom} from {evs[0].host or evs[0].src_ip} at {_fmt(evs[0].ts)} "
            f"({lookalike_reason(dom, org)}). Credentials may have been entered.",
            "high", 0.85, evs, {"user": [user], "domain": [dom], "host": [evs[0].host]},
        ))
    return alerts


# --- Lateral movement & privilege -----------------------------------------------------------


def rule_remote_logons(ctx: DetectionContext) -> List[Alert]:
    alerts = []
    history: Dict[str, set] = defaultdict(set)
    recent_by_ip: Dict[str, List[Event]] = defaultdict(list)
    shared_flagged: set = set()
    for ev in ctx.by_action["remote_logon"]:
        user, host = ev.user, ev.host
        known = history[user]
        crit = ctx.org.criticality(host) > 1.0
        if host not in known and (crit or len(known) >= 2) and not ctx.learning(ev):
            alerts.append(ctx.alert(
                "lateral_new_host", "T1021.002", "Remote logon to host never accessed before",
                f"'{user}' logged on remotely to {host} from {ev.src_ip} — first time in observed history"
                + (" (crown-jewel asset)." if crit else "."),
                "high" if crit else "medium", 0.7, [ev], {"user": [user], "host": [host], "ip": [ev.src_ip]},
                details={"known_hosts": sorted(known)[:10]},
            ))
        # Privileged account used from the same source as another user's session.
        for other in recent_by_ip[ev.src_ip]:
            if other.user != user and ev.ts - other.ts <= timedelta(minutes=60) and \
                    user in ctx.org.privileged_users and ev.src_ip and (user, ev.src_ip) not in shared_flagged:
                shared_flagged.add((user, ev.src_ip))
                alerts.append(ctx.alert(
                    "priv_account_shared_source", "T1078.002",
                    "Privileged account used from another user's session",
                    f"Admin account '{user}' logged on to {host} from {ev.src_ip}, the same source "
                    f"'{other.user}' used {int((ev.ts - other.ts).total_seconds() // 60)} min earlier — "
                    f"consistent with stolen admin credentials.",
                    "high", 0.8, [other, ev], {"user": [user, other.user], "ip": [ev.src_ip], "host": [host]},
                ))
                break
        known.add(host)
        recent_by_ip[ev.src_ip].append(ev)
    return alerts


def rule_account_changes(ctx: DetectionContext) -> List[Alert]:
    alerts = []
    group_adds = ctx.by_action["group_add"]
    for created in ctx.by_action["account_created"]:
        add = next((g for g in group_adds if g.target_user == created.target_user
                    and g.group in ctx.org.privileged_groups
                    and created.ts <= g.ts <= created.ts + timedelta(hours=1)), None)
        if add:
            alerts.append(ctx.alert(
                "priv_account_created", "T1098", "New account added to privileged group",
                f"'{created.user}' created account '{created.target_user}' on {created.host} and added it to "
                f"'{add.group}' {int((add.ts - created.ts).total_seconds() // 60)} min later — likely persistence.",
                "high", 0.85, [created, add],
                {"user": [created.user, created.target_user], "host": [created.host]},
            ))
        else:
            alerts.append(ctx.alert(
                "account_created", "T1136.002", "New account created",
                f"'{created.user}' created account '{created.target_user}' on {created.host}.",
                "low", 0.4, [created], {"user": [created.user], "host": [created.host]},
            ))
    return alerts


# --- Defense evasion / impact / EDR -----------------------------------------------------------


def rule_log_cleared(ctx: DetectionContext) -> List[Alert]:
    return [
        ctx.alert(
            "audit_log_cleared", "T1070.001", "Security audit log cleared",
            f"Security event log on {ev.host} was cleared by '{ev.user}' at {_fmt(ev.ts)} — "
            f"common anti-forensics step before impact.",
            "high", 0.9, [ev], {"host": [ev.host], "user": [ev.user]},
        )
        for ev in ctx.by_action["audit_log_cleared"]
    ]


def rule_edr(ctx: DetectionContext) -> List[Alert]:
    """Promote EDR/AV sensor alerts into the pipeline (they already did endpoint detection)."""
    alerts = []
    for ev in ctx.by_action["edr_alert"]:
        tech = ev.technique if ev.technique in TECHNIQUES else "T1059.001"
        sev = ev.severity if ev.severity in ("low", "medium", "high", "critical") else "medium"
        alerts.append(ctx.alert(
            f"edr:{tech}", tech, ev.signature or "EDR detection",
            f"EDR on {ev.host} reported: {ev.signature or 'suspicious behaviour'}"
            + (f" (user '{ev.user}')." if ev.user else "."),
            sev, 0.8, [ev], {"host": [ev.host], "user": [ev.user]},
        ))
    return alerts


# --- Web / perimeter -----------------------------------------------------------------------------


def rule_web_attacks(ctx: DetectionContext) -> List[Alert]:
    alerts = []
    for ip, blocks in _group(ctx.by_action["waf_block"], lambda e: e.src_ip).items():
        for burst in gap_clusters(blocks, timedelta(minutes=15)):
            if len(burst) < 5:
                continue
            cats: Dict[str, int] = defaultdict(int)
            for e in burst:
                cats[e.category or "generic"] += 1
            injection = any(c in cats for c in ("sqli", "rce", "cmdi", "lfi", "traversal"))
            alerts.append(ctx.alert(
                "web_attack", "T1190", "Web application attack blocked by WAF",
                f"{len(burst)} WAF blocks from {ip} against {burst[0].host} "
                f"({', '.join(f'{k}: {v}' for k, v in sorted(cats.items(), key=lambda x: -x[1]))}).",
                "high" if injection and len(burst) >= 20 else "medium", 0.75, burst,
                {"ip": [ip]}, related={"host": [burst[0].host] if burst[0].host else []},
                details={"categories": dict(cats)},
            ))
    # Error bursts / scanner user-agents in raw access logs.
    reqs = [e for e in ctx.by_action["http_request"] if e.status and e.status >= 400]
    for ip, errs in _group(reqs, lambda e: e.src_ip).items():
        for burst in gap_clusters(errs, timedelta(minutes=5)):
            scanner = any(m in (e.user_agent or "").lower() for e in burst for m in SCANNER_UA_MARKERS)
            if len(burst) < 30 and not (scanner and len(burst) >= 5):
                continue
            alerts.append(ctx.alert(
                "web_scan", "T1595.002", "Automated vulnerability scanning",
                f"{len(burst)} failed HTTP requests from {ip} to {burst[0].host} in "
                f"{int((burst[-1].ts - burst[0].ts).total_seconds() // 60) + 1} min"
                + (" using a known scanner user-agent." if scanner else "."),
                "low", 0.7, burst, {"ip": [ip]}, related={"host": [burst[0].host] if burst[0].host else []},
                details={"requests": len(burst), "scanner_ua": scanner},
            ))
    return alerts


def rule_exfiltration(ctx: DetectionContext) -> List[Alert]:
    """Outbound transfer far above the host's own baseline, to a destination never seen before."""
    alerts = []
    host_hist: Dict[str, List[int]] = defaultdict(list)
    seen_dst: set = set()
    for ev in ctx.by_action["flow"]:
        if ev.bytes_out is None or ctx.org.is_internal(ev.dst_ip):
            continue
        hist = sorted(host_hist[ev.host])
        if len(hist) >= 20:
            p95 = hist[int(len(hist) * 0.95) - 1]
            threshold = max(10 * p95, 200 * 1024 ** 2)
            if ev.bytes_out > threshold:
                novel = ev.dst_ip not in seen_dst
                alerts.append(ctx.alert(
                    "exfil_volume", "T1048", "Anomalous outbound data transfer",
                    f"{ev.host} sent {ev.bytes_out / 1024 ** 3:.2f} GB to {ev.dst_ip}:{ev.dst_port} — "
                    f"{ev.bytes_out / max(p95, 1):.0f}x its 95th-percentile flow"
                    + (", to a destination never seen before." if novel else "."),
                    "high" if novel else "medium", 0.85 if novel else 0.6, [ev],
                    {"host": [ev.host], "ip": [ev.dst_ip]},
                    details={"bytes_out": ev.bytes_out, "baseline_p95": p95, "novel_destination": novel},
                ))
        host_hist[ev.host].append(ev.bytes_out)
        seen_dst.add(ev.dst_ip)
    return alerts


ALL_RULES = [
    rule_brute_force,
    rule_password_spray,
    rule_mfa_fatigue,
    rule_login_geography,
    rule_phishing,
    rule_remote_logons,
    rule_account_changes,
    rule_log_cleared,
    rule_edr,
    rule_web_attacks,
    rule_exfiltration,
]


def run_rules(ctx: DetectionContext) -> List[Alert]:
    alerts: List[Alert] = []
    for rule in ALL_RULES:
        alerts.extend(rule(ctx))
    return alerts
