"""Parsers that normalise heterogeneous log formats into `Event` records.

Supported inputs (auto-detected per file):
  * JSON array / JSON Lines of already-normalised events (our schema, loose keys accepted)
  * Linux auth.log (sshd accepted / failed password lines)
  * nginx / Apache "combined" access logs
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Iterable, List, Optional

from .models import Event

_EVENT_FIELDS = set(Event.model_fields)
_ALIASES = {
    "timestamp": "ts",
    "time": "ts",
    "@timestamp": "ts",
    "username": "user",
    "account": "user",
    "hostname": "host",
    "source_ip": "src_ip",
    "client_ip": "src_ip",
    "destination_ip": "dst_ip",
    "event_type": "action",
    "useragent": "user_agent",
    "http_user_agent": "user_agent",
    "bytes": "bytes_out",
}


def _new_id(prefix: str = "ev") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _parse_ts(value) -> datetime:
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)):
        dt = datetime.fromtimestamp(value / 1000 if value > 1e12 else value, tz=timezone.utc)
    else:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def event_from_dict(d: dict) -> Event:
    data = {}
    for k, v in d.items():
        key = _ALIASES.get(k.lower(), k.lower())
        if key in _EVENT_FIELDS and v not in (None, ""):
            data[key] = v
    data["ts"] = _parse_ts(data.get("ts") or datetime.now(timezone.utc))
    data.setdefault("id", _new_id())
    data.setdefault("source", "custom")
    data.setdefault("action", "unknown")
    data.setdefault("raw", json.dumps(d, default=str)[:2000])
    for int_field in ("status", "bytes_out", "dst_port"):
        if int_field in data:
            try:
                data[int_field] = int(data[int_field])
            except (TypeError, ValueError):
                data.pop(int_field)
    return Event(**data)


# --- Linux auth.log -----------------------------------------------------------------------

_SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<msg>.*)$"
)
_FAILED_RE = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)"
)
_ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)"
)


def parse_auth_log(text: str, year: Optional[int] = None) -> List[Event]:
    year = year or datetime.now(timezone.utc).year
    events = []
    for line in text.splitlines():
        m = _SYSLOG_RE.match(line.strip())
        if not m:
            continue
        ts = datetime.strptime(
            f"{year} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S"
        ).replace(tzinfo=timezone.utc)
        msg = m["msg"]
        if fm := _FAILED_RE.search(msg):
            action, user, ip = "login_failure", fm["user"], fm["ip"]
        elif am := _ACCEPTED_RE.search(msg):
            action, user, ip = "login_success", am["user"], am["ip"]
        else:
            continue
        events.append(
            Event(
                id=_new_id(),
                ts=ts,
                source="auth",
                action=action,
                user=user,
                host=m["host"],
                src_ip=ip,
                message=msg[:500],
                raw=line[:2000],
            )
        )
    return events


# --- nginx / Apache combined access log --------------------------------------------------

_ACCESS_RE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)


def parse_access_log(text: str, host: str = "WEB-01") -> List[Event]:
    events = []
    for line in text.splitlines():
        m = _ACCESS_RE.match(line.strip())
        if not m:
            continue
        ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
        events.append(
            Event(
                id=_new_id(),
                ts=ts,
                source="web",
                action="http_request",
                host=host,
                src_ip=m["ip"],
                user=None if m["user"] == "-" else m["user"],
                url=m["path"][:2000],
                status=int(m["status"]),
                bytes_out=0 if m["size"] == "-" else int(m["size"]),
                user_agent=(m["ua"] or "")[:2000] or None,
                raw=line[:2000],
            )
        )
    return events


# --- Dispatcher -----------------------------------------------------------------------------


def parse_any(text: str, filename: str = "") -> List[Event]:
    """Detect the format of `text` and parse it. Unknown lines are skipped."""
    stripped = text.lstrip()
    if stripped.startswith("["):
        return [event_from_dict(d) for d in json.loads(stripped) if isinstance(d, dict)]
    if stripped.startswith("{"):
        out = []
        for line in stripped.splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    out.append(event_from_dict(json.loads(line)))
                except (json.JSONDecodeError, ValueError):
                    continue
        return out
    sample = "\n".join(stripped.splitlines()[:20])
    if "sshd[" in sample:
        return parse_auth_log(text)
    if _ACCESS_RE.search(sample):
        return parse_access_log(text)
    raise ValueError(
        f"Unrecognised log format in {filename or 'input'}: expected JSON/JSONL, auth.log or access log"
    )


def to_jsonl(events: Iterable[Event]) -> str:
    return "\n".join(e.model_dump_json(exclude_none=True) for e in events) + "\n"
