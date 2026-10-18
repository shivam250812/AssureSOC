"""FastAPI app: REST API + the single-page analyst console.

    uvicorn triageforge.server:app --port 8000
"""

from __future__ import annotations

import threading
from collections import defaultdict
from itertools import combinations
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import analyst, compliance
from .guard import scan_event
from .models import Incident
from .parsers import parse_any
from .pipeline import Workspace, analyse
from .scenario import generate

STATIC = Path(__file__).parent / "static"
MAX_UPLOAD_BYTES = 25 * 1024 * 1024

app = FastAPI(title="TriageForge", version="0.1.0",
              description="AI SOC copilot: telemetry -> prioritised incidents -> response & compliance")
app.mount("/static", StaticFiles(directory=STATIC), name="static")

_lock = threading.Lock()
_ws: Optional[Workspace] = None


def _workspace() -> Workspace:
    if _ws is None:
        raise HTTPException(409, "No data loaded yet — load the demo scenario or upload logs.")
    return _ws


def _incident(inc_id: str) -> Incident:
    ws = _workspace()
    inc = ws.incidents_by_id.get(inc_id)
    if not inc:
        raise HTTPException(404, f"Unknown incident {inc_id}")
    return inc


def _summary(inc: Incident) -> dict:
    return {
        "id": inc.id, "title": inc.analysis.get("title") or inc.title, "priority": inc.priority,
        "score": inc.score, "status": inc.status, "first_seen": inc.first_seen, "last_seen": inc.last_seen,
        "tactics": inc.tactics, "alerts": len(inc.alert_ids), "analysis_source": inc.analysis_source,
        "certin_deadline": inc.regulatory.get("certin_deadline"),
        "personal_data_at_risk": inc.regulatory.get("personal_data_at_risk"),
        "entities": {k: v[:4] for k, v in inc.entities.items()},
    }


def _graph(ws: Workspace, inc: Incident) -> dict:
    """Entity graph: nodes are users/hosts/IPs/domains, edges join entities seen in one alert."""
    weights: Dict[tuple, List[str]] = defaultdict(list)
    nodes: Dict[str, dict] = {}
    for a in ws.alerts_for(inc):
        ents = [(k, v) for k, vals in a.entities.items() for v in vals[:6]]
        ents += [(k, v) for k, vals in a.related.items() if k == "host" for v in vals[:3]]
        for k, v in ents:
            node = nodes.setdefault(f"{k}:{v}", {"id": f"{k}:{v}", "kind": k, "label": v, "alerts": 0,
                                                 "crown_jewel": k == "host" and ws.org.criticality(v) > 1,
                                                 "external": k == "ip" and not ws.org.is_internal(v)})
            node["alerts"] += 1
        for (k1, v1), (k2, v2) in combinations(sorted(set(ents)), 2):
            weights[(f"{k1}:{v1}", f"{k2}:{v2}")].append(a.technique_id)
    edges = [{"source": s, "target": t, "techniques": sorted(set(tt))} for (s, t), tt in weights.items()]
    return {"nodes": list(nodes.values()), "edges": edges}


# --- Status & ingestion ---------------------------------------------------------------------


@app.get("/api/status")
def status():
    return {
        "ai_enabled": analyst.ai_enabled(),
        "model": analyst.MODEL if analyst.ai_enabled() else "offline analyst",
        "workspace": _ws.stats() if _ws else None,
    }


@app.post("/api/demo")
def load_demo():
    global _ws
    with _lock:
        _ws = analyse(generate(), label="Demo: NovaPay Fintech (synthetic)")
    return _ws.stats()


@app.post("/api/upload")
async def upload(files: List[UploadFile] = File(...)):
    global _ws
    events, total = [], 0
    for f in files:
        data = await f.read()
        total += len(data)
        if total > MAX_UPLOAD_BYTES:
            raise HTTPException(413, "Upload limit is 25 MB per analysis")
        try:
            events.extend(parse_any(data.decode("utf-8", errors="replace"), f.filename or ""))
        except (ValueError, KeyError) as e:
            raise HTTPException(400, f"{f.filename}: {e}") from e
    if not events:
        raise HTTPException(400, "No parsable events found in the uploaded files")
    with _lock:
        _ws = analyse(events, label=", ".join(f.filename or "upload" for f in files))
    return _ws.stats()


# --- Incidents ----------------------------------------------------------------------------


@app.get("/api/incidents")
def list_incidents():
    ws = _workspace()
    return {"stats": ws.stats(), "incidents": [_summary(i) for i in ws.incidents]}


@app.get("/api/incidents/{inc_id}")
def get_incident(inc_id: str):
    ws = _workspace()
    inc = _incident(inc_id)
    alerts = ws.alerts_for(inc)
    evidence = {}
    for a in alerts:
        for eid in a.evidence[:8]:
            ev = ws.events_by_id.get(eid)
            if ev:
                evidence[eid] = {**ev.model_dump(mode="json", exclude_none=True),
                                 "injection_fields": ws.flagged.get(eid) or scan_event(ev) or None}
    # Refresh the regulatory clock on every view.
    inc.regulatory = compliance.assess(inc, alerts, ws.org)
    return {
        "incident": inc.model_dump(mode="json"),
        "alerts": [a.model_dump(mode="json") for a in alerts],
        "evidence": evidence,
        "graph": _graph(ws, inc),
        "ai_enabled": analyst.ai_enabled(),
    }


class StatusUpdate(BaseModel):
    status: str


@app.patch("/api/incidents/{inc_id}")
def update_incident(inc_id: str, body: StatusUpdate):
    if body.status not in ("new", "investigating", "contained", "closed"):
        raise HTTPException(400, "status must be new | investigating | contained | closed")
    inc = _incident(inc_id)
    inc.status = body.status
    return _summary(inc)


@app.post("/api/incidents/{inc_id}/analyze")
def analyze_with_ai(inc_id: str):
    ws = _workspace()
    inc = _incident(inc_id)
    if not analyst.ai_enabled():
        raise HTTPException(503, "Claude is not configured — set ANTHROPIC_API_KEY. Offline analysis is shown.")
    alerts = ws.alerts_for(inc)
    context, neutralised = analyst.incident_context(inc, alerts, ws.events_by_id, ws.org)
    try:
        result = analyst.claude_analysis(context)
    except analyst.AnalystUnavailable as e:
        raise HTTPException(503, str(e)) from e
    result.setdefault("_meta", {})["neutralised_fields"] = neutralised
    # Claude writes the narrative; risk score and priority stay deterministic and auditable.
    inc.analysis = result
    inc.analysis_source = "claude"
    return {"incident": inc.model_dump(mode="json")}


class Question(BaseModel):
    question: str
    history: List[Dict[str, str]] = []


@app.post("/api/incidents/{inc_id}/ask")
def ask(inc_id: str, body: Question):
    ws = _workspace()
    inc = _incident(inc_id)
    if not body.question.strip():
        raise HTTPException(400, "Empty question")
    alerts = ws.alerts_for(inc)
    context = analyst.incident_context(inc, alerts, ws.events_by_id, ws.org)[0] if analyst.ai_enabled() else None
    stream = analyst.ask(body.question[:4000], body.history, context, inc, alerts)
    return StreamingResponse(stream, media_type="text/plain; charset=utf-8")


@app.get("/api/incidents/{inc_id}/report/{kind}", response_class=PlainTextResponse)
def report(inc_id: str, kind: str):
    ws = _workspace()
    inc = _incident(inc_id)
    alerts = ws.alerts_for(inc)
    if kind == "certin":
        body = compliance.certin_report_md(inc, alerts, ws.org)
    elif kind == "insurer":
        body = compliance.insurer_notice_md(inc, alerts, ws.org)
    else:
        raise HTTPException(404, "report kind must be certin | insurer")
    return PlainTextResponse(body, media_type="text/markdown; charset=utf-8",
                             headers={"Content-Disposition": f'inline; filename="{inc.id}-{kind}.md"'})


@app.get("/api/incidents/{inc_id}/iocs")
def iocs(inc_id: str):
    ws = _workspace()
    inc = _incident(inc_id)
    out = []
    for ip in inc.entities.get("ip", []):
        if not ws.org.is_internal(ip):
            out.append({"type": "ipv4-addr", "value": ip})
    for d in inc.entities.get("domain", []):
        out.append({"type": "domain-name", "value": d})
    return {"incident": inc.id, "indicators": out,
            "techniques": [t["id"] for t in inc.techniques]}


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")
