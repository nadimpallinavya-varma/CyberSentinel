import os
os.environ["DATABASE_URL"] = "sqlite:///./test_cybersentinel.db"
os.environ["WAZUH_API_KEY"] = "test-wazuh-key"
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

def test_metrics_endpoint_exposes_bounded_cybersentinel_metrics():
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "cybersentinel_http_requests_total" in response.text
    assert "cybersentinel_security_events_processed_total" in response.text
    assert "192.0.2.44" not in response.text
    assert "username" not in response.text

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

WAZUH_SAMPLE = {
    "timestamp": "2026-01-01T12:00:00Z",
    "rule": {"id": "5712", "level": 10, "description": "Multiple authentication failures detected"},
    "agent": {"id": "001", "name": "demo-agent", "ip": "192.0.2.88"},
    "data": {"srcip": "192.0.2.88", "dstuser": "demo-user"},
    "is_demo": True,
}

def test_wazuh_requires_api_key():
    response = client.post("/api/integrations/wazuh/alerts", json=WAZUH_SAMPLE)
    assert response.status_code == 401

def test_wazuh_rejects_invalid_payload():
    response = client.post("/api/integrations/wazuh/alerts", headers={"X-Wazuh-API-Key": "test-wazuh-key"}, json={"rule": {"id": "5712"}})
    assert response.status_code == 422

def test_wazuh_alert_creates_incident_and_duplicate_is_suppressed():
    headers = {"X-Wazuh-API-Key": "test-wazuh-key"}
    first = client.post("/api/integrations/wazuh/alerts", headers=headers, json=WAZUH_SAMPLE)
    assert first.status_code == 200
    first_body = first.json()
    assert first_body["duplicate"] is False
    assert first_body["incident"]["detection_rule"] == "WAZUH-5712"
    assert first_body["incident"]["severity"] == "high"
    second = client.post("/api/integrations/wazuh/alerts", headers=headers, json=WAZUH_SAMPLE)
    assert second.status_code == 200
    assert second.json()["duplicate"] is True
    assert second.json()["incident"]["id"] == first_body["incident"]["id"]
