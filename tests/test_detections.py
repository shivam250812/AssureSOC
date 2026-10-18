from datetime import datetime, timedelta, timezone

from triageforge.config import DEFAULT_ORG
from triageforge.detections import DetectionContext, lookalike_reason, rule_password_spray
from triageforge.models import Event

ORG = ["novapay.example"]


def test_lookalike_domains():
    assert "homoglyph" in lookalike_reason("n0vapay.example", ORG)
    assert "brand" in lookalike_reason("novapay.example.login-verify.example", ORG)  # brand hidden in subdomain
    assert "brand" in lookalike_reason("novapay-support.example", ORG)
    assert "typo-squat" in lookalike_reason("novapy.example", ORG)
    assert lookalike_reason("novapay.example", ORG) is None
    assert lookalike_reason("mail.novapay.example", ORG) is None
    assert lookalike_reason("github.com", ORG) is None
    assert lookalike_reason(None, ORG) is None


def _fail(ts, user, ip):
    return Event(id=f"e-{user}-{ts.timestamp()}", ts=ts, source="vpn", action="login_failure", user=user, src_ip=ip)


def test_password_spray_threshold():
    t0 = datetime(2026, 10, 15, 9, tzinfo=timezone.utc)
    seven = [_fail(t0 + timedelta(seconds=i * 30), f"u{i}", "203.0.113.9") for i in range(7)]
    ctx = DetectionContext(seven, DEFAULT_ORG)
    assert rule_password_spray(ctx) == []
    nine = seven + [_fail(t0 + timedelta(minutes=5, seconds=i), f"v{i}", "203.0.113.9") for i in range(2)]
    (alert,) = rule_password_spray(DetectionContext(nine, DEFAULT_ORG))
    assert alert.technique_id == "T1110.003" and alert.severity == "high"
    assert alert.entities == {"ip": ["203.0.113.9"]}  # targets are context, never correlation keys
    assert len(alert.related["user"]) == 9


def test_scenario_detections_fire(ws):
    rules = {a.rule_id for a in ws.alerts}
    expected = {"phishing_lookalike", "phishing_click", "password_spray", "mfa_fatigue", "impossible_travel",
                "new_country_login", "lateral_new_host", "priv_account_shared_source", "priv_account_created",
                "audit_log_cleared", "exfil_volume", "web_attack", "web_scan", "brute_force", "ueba_anomaly",
                "ai_prompt_injection", "edr:T1003.001", "edr:T1490"}
    assert expected <= rules


def test_no_baseline_false_positives(ws):
    lateral = [a for a in ws.alerts if a.rule_id == "lateral_new_host"]
    assert [a.entities["user"] for a in lateral] == [["priya.sharma"]]
    travel = [a for a in ws.alerts if a.rule_id == "impossible_travel"]
    assert len(travel) == 1 and travel[0].details["to"] == "NL"


def test_allowlisted_scanner_is_suppressed(ws):
    suppressed = [a for a in ws.alerts if a.suppressed]
    assert len(suppressed) == 2
    assert all(a.entities["ip"] == ["10.0.5.10"] for a in suppressed)


def test_ueba_explains_off_hours_login(ws):
    ueba = {a.entities["user"][0]: a for a in ws.alerts if a.rule_id == "ueba_anomaly"}
    assert "arjun.mehta" in ueba and "priya.sharma" in ueba
    drivers = {d["feature"] for d in ueba["arjun.mehta"].details["drivers"]}
    assert "hours_from_usual" in drivers
    assert "adm.rahul" not in ueba and "adm.kavya" not in ueba  # admins' routine stays quiet


def test_exfil_compares_against_host_baseline(ws):
    (exfil,) = [a for a in ws.alerts if a.rule_id == "exfil_volume"]
    assert exfil.entities == {"host": ["FILESRV-01"], "ip": ["203.0.113.77"]}
    assert exfil.details["novel_destination"] and exfil.details["bytes_out"] > 10 * exfil.details["baseline_p95"]
