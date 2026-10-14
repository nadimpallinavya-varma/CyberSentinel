import os
os.environ["DATABASE_URL"] = "sqlite:///./test_cybersentinel.db"
from fastapi.testclient import TestClient
from app.main import app
from app.db import Base, engine

client = TestClient(app)

def setup_module():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    client.__enter__()

def teardown_module():
    client.__exit__(None, None, None)

def test_health_and_normal_demo():
    assert client.get("/health").json()["status"] == "ok"
    result = client.post("/api/demo/normal").json()
    assert result["events_created"] == 1
    assert result["incidents"] == []

def test_demo_preflight_allows_frontend_origin():
    response = client.options(
        "/api/demo/brute_force",
        headers={
            "Origin": "http://localhost:8080",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:8080"
    assert "POST" in response.headers["access-control-allow-methods"]
    assert "content-type" in response.headers["access-control-allow-headers"].lower()

def test_brute_force_creates_incident():
    before_events = client.get("/api/stats").json()["events"]
    result = client.post("/api/demo/brute_force").json()
    assert result["events_created"] == 5
    assert any(x["detection_rule"] == "AUTH-FAILURE-SEQUENCE" for x in result["incidents"])
    after = client.get("/api/stats").json()
    assert after["events"] >= before_events + 5
    assert after["active_incidents"] >= 1

def test_success_after_failures_and_status_update():
    result = client.post("/api/demo/success_after_failures").json()
    incident = next(x for x in result["incidents"] if x["detection_rule"] == "AUTH-SUCCESS-AFTER-FAILURES")
    updated = client.patch(f"/api/incidents/{incident['id']}", json={"status": "acknowledged", "analyst_notes": "Reviewed evidence."})
    assert updated.status_code == 200
    assert updated.json()["status"] == "acknowledged"
    resolved = client.patch(f"/api/incidents/{incident['id']}", json={"status": "resolved"})
    assert resolved.json()["status"] == "resolved"
