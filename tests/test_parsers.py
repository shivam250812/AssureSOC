import json

import pytest

from triageforge.parsers import parse_access_log, parse_any, parse_auth_log


def test_auth_log_failed_and_accepted():
    text = (
        "Oct 14 09:00:01 web-01 sshd[1]: Failed password for invalid user admin from 192.0.2.9 port 22 ssh2\n"
        "Oct 14 09:00:05 web-01 sshd[2]: Accepted publickey for deploy from 10.0.1.5 port 22 ssh2\n"
        "Oct 14 09:00:06 web-01 CRON[3]: pam_unix(cron:session): session opened\n"
    )
    events = parse_auth_log(text, year=2026)
    assert [(e.action, e.user, e.src_ip) for e in events] == [
        ("login_failure", "admin", "192.0.2.9"),
        ("login_success", "deploy", "10.0.1.5"),
    ]
    assert events[0].host == "web-01" and events[0].ts.year == 2026


def test_access_log_combined_format():
    line = '192.0.2.66 - - [14/Oct/2026:08:00:00 +0530] "GET /admin HTTP/1.1" 404 153 "-" "curl/8.0"'
    (ev,) = parse_access_log(line)
    assert ev.src_ip == "192.0.2.66" and ev.status == 404 and ev.url == "/admin"
    assert ev.user_agent == "curl/8.0"
    assert ev.ts.utcoffset().total_seconds() == 0 and ev.ts.hour == 2  # normalised to UTC


def test_jsonl_with_aliases():
    rows = [{"timestamp": "2026-10-14T10:00:00Z", "event_type": "login_failure", "username": "a", "source_ip": "1.2.3.4",
             "source": "sso", "bytes": "12"}]
    events = parse_any("\n".join(json.dumps(r) for r in rows))
    assert events[0].action == "login_failure" and events[0].user == "a"
    assert events[0].src_ip == "1.2.3.4" and events[0].bytes_out == 12


def test_samples_parse(samples):
    assert len(parse_any((samples / "auth.log").read_text())) > 70
    assert len(parse_any((samples / "access.log").read_text())) == 460
    assert len(parse_any((samples / "scenario.jsonl").read_text())) > 4000


def test_unknown_format_rejected():
    with pytest.raises(ValueError):
        parse_any("hello world\nnot a log\n")
