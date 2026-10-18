import pytest
from fastapi.testclient import TestClient

from assuresoc import server


@pytest.fixture()
def client():
    server._ws = None
    return TestClient(server.app)


def test_requires_data_first(client):
    assert client.get("/api/status").json()["workspace"] is None
    assert client.get("/api/incidents").status_code == 409


def test_demo_flow(client):
    stats = client.post("/api/demo").json()
    assert stats["events"] > 4000 and stats["incidents"] >= 3 and stats["by_priority"]["P1"] == 1
    assert stats["injection_events"] > 0

    incidents = client.get("/api/incidents").json()["incidents"]
    top = incidents[0]
    assert top["priority"] == "P1" and top["certin_deadline"] and top["personal_data_at_risk"]

    detail = client.get(f"/api/incidents/{top['id']}").json()
    assert len(detail["alerts"]) == top["alerts"]
    assert detail["graph"]["nodes"] and detail["graph"]["edges"]
    assert detail["incident"]["regulatory"]["certin_seconds_left"] > 0

    certin = client.get(f"/api/incidents/{top['id']}/report/certin")
    assert certin.status_code == 200 and certin.text.startswith("# CERT-In Incident Report")
    assert client.get(f"/api/incidents/{top['id']}/report/insurer").status_code == 200
    assert client.get(f"/api/incidents/{top['id']}/report/other").status_code == 404

    iocs = client.get(f"/api/incidents/{top['id']}/iocs").json()
    assert {"type": "ipv4-addr", "value": "203.0.113.77"} in iocs["indicators"]
    assert all(not i["value"].startswith("10.") for i in iocs["indicators"])

    assert client.patch(f"/api/incidents/{top['id']}", json={"status": "contained"}).json()["status"] == "contained"
    assert client.patch(f"/api/incidents/{top['id']}", json={"status": "bogus"}).status_code == 400


def test_injected_evidence_is_flagged_for_ui(client):
    client.post("/api/demo")
    web = next(i for i in client.get("/api/incidents").json()["incidents"] if "web application" in i["title"])
    detail = client.get(f"/api/incidents/{web['id']}").json()
    flagged = [e for e in detail["evidence"].values() if e.get("injection_fields")]
    assert flagged and "user_agent" in flagged[0]["injection_fields"]


def test_offline_ask_and_analyze(client):
    client.post("/api/demo")
    res = client.post("/api/incidents/INC-001/ask", json={"question": "What should I do first?", "history": []})
    assert res.status_code == 200 and "Immediate actions" in res.text
    assert client.post("/api/incidents/INC-001/analyze").status_code == 503  # no credentials in tests
    assert client.get("/api/incidents/INC-999").status_code == 404


def test_upload_real_log_formats(client, samples):
    files = [("files", ("auth.log", (samples / "auth.log").read_bytes())),
             ("files", ("access.log", (samples / "access.log").read_bytes()))]
    stats = client.post("/api/upload", files=files).json()
    assert stats["sources"] == {"web": 460, "auth": 81}
    titles = [i["title"] for i in client.get("/api/incidents").json()["incidents"]]
    assert any("192.0.2.66" in t for t in titles)          # scanner + injection UA
    assert any("root" in t for t in titles)                 # SSH brute force
    assert any("198.51.100.250" in t or "spray" in t.lower() for t in titles)  # username spray
    assert stats["injection_events"] == 60


def test_upload_rejects_garbage(client):
    res = client.post("/api/upload", files=[("files", ("x.txt", b"nothing to see here\n"))])
    assert res.status_code == 400


def test_index_served(client):
    res = client.get("/")
    assert res.status_code == 200 and "AssureSOC" in res.text
