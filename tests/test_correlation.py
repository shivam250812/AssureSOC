from datetime import timedelta

from assuresoc.compliance import certin_report_md, insurer_notice_md


def _by_rule(ws, rule):
    return next(i for i in ws.incidents if any(ws.alerts_by_id[a].rule_id == rule for a in i.alert_ids))


def test_queue_is_small_and_ranked(ws):
    assert [i.priority for i in ws.incidents] == ["P1", "P2", "P4", "P4"]
    assert ws.incidents == sorted(ws.incidents, key=lambda i: -i.score)


def test_attack_chain_is_one_incident(ws):
    p1 = ws.incidents[0]
    rules = {ws.alerts_by_id[a].rule_id for a in p1.alert_ids}
    assert {"phishing_click", "password_spray", "mfa_fatigue", "priv_account_created",
            "exfil_volume", "audit_log_cleared", "edr:T1490"} <= rules
    assert p1.tactics[0] == "Initial Access" and p1.tactics[-1] == "Impact"
    assert "Ransomware precursor" in p1.title and p1.score == 100
    assert {"FILESRV-01", "DC-01"} <= set(p1.entities["host"])
    # Spray targets are context, not compromised accounts.
    assert "aditya.rao" not in p1.entities["user"] and "aditya.rao" in p1.related_entities["user"]


def test_unrelated_attacks_on_same_server_stay_separate(ws):
    web = _by_rule(ws, "web_attack")
    ssh = _by_rule(ws, "brute_force")
    assert web.id != ssh.id
    assert {ws.alerts_by_id[a].rule_id for a in web.alert_ids} == {"web_attack", "web_scan", "ai_prompt_injection"}
    assert web.priority == "P2"
    assert any(f.label == "Stopped by control" for f in web.factors)
    assert ssh.priority == "P4"


def test_regulatory_clock(ws):
    p1 = ws.incidents[0]
    reg = p1.regulatory
    assert reg["certin_deadline"] == (p1.first_seen + timedelta(hours=6)).isoformat()
    assert reg["personal_data_at_risk"] and "FILESRV-01" in reg["personal_data_systems"]
    assert "Data Breach" in reg["certin_types"]
    assert {o["regime"].split()[0] for o in reg["obligations"]} == {"CERT-In", "DPDP", "Cyber-insurance"}
    assert reg["certin_seconds_left"] > 0
    ssh = _by_rule(ws, "brute_force")
    assert ssh.regulatory["certin_types"] == []  # failed guessing alone is not reportable
    web = _by_rule(ws, "web_attack")
    assert not web.regulatory["personal_data_at_risk"]


def test_reports_render(ws):
    p1 = ws.incidents[0]
    alerts = ws.alerts_for(p1)
    certin = certin_report_md(p1, alerts, ws.org)
    assert "CERT-In Incident Report" in certin and "203.0.113.77" in certin and "FILESRV-01 (crown-jewel)" in certin
    assert "Also targeted without evidence of compromise" in certin
    notice = insurer_notice_md(p1, alerts, ws.org)
    assert "Cyber-Insurance Incident Notification" in notice and "personal data at risk" in notice


def test_offline_analysis_is_grounded(ws):
    an = ws.incidents[0].analysis
    assert an["verdict"] == "likely_true_positive"
    assert an["recommended_actions"][0]["priority"] == "immediate"
    valid_ids = set(ws.alerts_by_id)
    for finding in an["key_findings"]:
        cited = finding.rsplit("[", 1)[1].rstrip("]")
        assert cited in valid_ids
