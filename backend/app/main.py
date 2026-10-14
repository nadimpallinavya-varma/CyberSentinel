from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from .config import settings
from .db import Base, engine, get_db
from .detection import detect
from .models import Asset, Incident, SecurityEvent
from .schemas import AssetCreate, AssetOut, DemoResponse, EventIn, IncidentOut, IncidentStatusUpdate
from .metrics import metrics_response, observe_request, record_detection, record_security_event, record_wazuh_alert
from .schemas import WazuhAlert, WazuhIngestResponse

app = FastAPI(title="CyberSentinel API", version="0.2.0", description="Explainable security event detection and incident response API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["Content-Type", "Accept", "Authorization"],
)
app.middleware("http")(observe_request)


@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)


@app.get("/health")
def health(db: Session = Depends(get_db)):
    db.execute(select(1))
    return {"status": "ok", "database": "reachable"}


@app.get("/metrics", include_in_schema=False)
def metrics():
    return metrics_response()


@app.get("/api/stats")
def stats(db: Session = Depends(get_db)):
    return {"events": db.scalar(select(func.count(SecurityEvent.id))) or 0, "active_incidents": db.scalar(select(func.count(Incident.id)).where(Incident.status != "resolved")) or 0, "assets": db.scalar(select(func.count(Asset.id))) or 0}


@app.post("/api/assets", response_model=AssetOut, status_code=201)
def create_asset(payload: AssetCreate, db: Session = Depends(get_db)):
    asset = Asset(**payload.model_dump())
    db.add(asset); db.commit(); db.refresh(asset)
    return asset


@app.get("/api/assets", response_model=list[AssetOut])
def list_assets(db: Session = Depends(get_db)):
    return db.scalars(select(Asset).order_by(Asset.name)).all()


@app.post("/api/events", response_model=list[IncidentOut])
def ingest_event(payload: EventIn, db: Session = Depends(get_db)):
    if not db.get(Asset, payload.asset_id):
        raise HTTPException(404, "Asset not found")
    event = SecurityEvent(event_type=payload.event_type, username=payload.username, source_ip=payload.source_ip, asset_id=payload.asset_id, success=payload.success, is_demo=payload.is_demo, occurred_at=payload.occurred_at or datetime.now(timezone.utc), metadata_json=payload.metadata)
    db.add(event); db.flush(); incidents = detect(db, event); db.commit()
    record_security_event(event.event_type, event.is_demo)
    return incidents


@app.get("/api/incidents", response_model=list[IncidentOut])
def list_incidents(status: str | None = Query(default=None), db: Session = Depends(get_db)):
    query = select(Incident).order_by(Incident.created_at.desc())
    if status: query = query.where(Incident.status == status)
    return db.scalars(query).all()


@app.get("/api/incidents/{incident_id}", response_model=IncidentOut)
def get_incident(incident_id: int, db: Session = Depends(get_db)):
    incident = db.get(Incident, incident_id)
    if not incident: raise HTTPException(404, "Incident not found")
    return incident


@app.patch("/api/incidents/{incident_id}", response_model=IncidentOut)
def update_incident(incident_id: int, payload: IncidentStatusUpdate, db: Session = Depends(get_db)):
    incident = db.get(Incident, incident_id)
    if not incident: raise HTTPException(404, "Incident not found")
    incident.status = payload.status
    if payload.analyst_notes is not None: incident.analyst_notes = payload.analyst_notes
    db.commit(); db.refresh(incident)
    return incident


@app.post("/api/demo/{scenario}", response_model=DemoResponse)
def run_demo(scenario: str, db: Session = Depends(get_db)):
    if scenario not in {"normal", "brute_force", "burst", "success_after_failures"}: raise HTTPException(400, "Unknown demo scenario")
    asset = db.scalar(select(Asset).where(Asset.name == "Demo Auth Service"))
    if not asset:
        asset = Asset(name="Demo Auth Service", kind="authentication_service", environment="demo"); db.add(asset); db.flush()
    now = datetime.now(timezone.utc); username = "admin@demo.local"; ip = "192.0.2.44"
    specs = {"normal": [(True, username)], "brute_force": [(False, username)] * settings.failed_login_threshold, "burst": [(False, f"user{i}@demo.local") for i in range(settings.burst_threshold)], "success_after_failures": [(False, username)] * settings.failed_login_threshold + [(True, username)]}[scenario]
    found = []
    for i, (success, user) in enumerate(specs):
        event = SecurityEvent(event_type="authentication", username=user, source_ip=ip, asset_id=asset.id, success=success, is_demo=True, occurred_at=now - timedelta(seconds=len(specs) - i), metadata_json={"scenario": scenario})
        db.add(event); db.flush(); found.extend(detect(db, event))
        record_security_event(event.event_type, event.is_demo)
    db.commit()
    unique = {i.id: i for i in found}
    return DemoResponse(scenario=scenario, events_created=len(specs), incidents=list(unique.values()))


@app.get("/api/reports/summary")
def report_summary(db: Session = Depends(get_db)):
    rows = db.execute(select(Incident.severity, func.count(Incident.id)).group_by(Incident.severity)).all()
    return {"generated_at": datetime.now(timezone.utc), "events": db.scalar(select(func.count(SecurityEvent.id))) or 0, "incidents_by_severity": {severity: count for severity, count in rows}}


def _wazuh_severity(level: int) -> str:
    if level >= 12: return "critical"
    if level >= 8: return "high"
    if level >= 5: return "medium"
    return "low"


def _wazuh_fingerprint(alert: WazuhAlert, source_ip: str) -> str:
    stable = "|".join([alert.rule.id, str(alert.rule.level), alert.timestamp.isoformat(), alert.agent.id, source_ip, alert.rule.description])
    return hashlib.sha256(stable.encode()).hexdigest()


@app.post("/api/integrations/wazuh/alerts", response_model=WazuhIngestResponse)
def ingest_wazuh_alert(alert: WazuhAlert, x_wazuh_api_key: str | None = Header(default=None, alias="X-Wazuh-API-Key"), db: Session = Depends(get_db)):
    configured = settings.wazuh_api_key
    if not configured or not x_wazuh_api_key or not hmac.compare_digest(x_wazuh_api_key, configured):
        raise HTTPException(status_code=401, detail="Invalid Wazuh integration credentials")
    source_ip = str(alert.data.get("srcip") or alert.agent.ip or "0.0.0.0")
    fingerprint = _wazuh_fingerprint(alert, source_ip)
    asset_name = f"Wazuh Agent {alert.agent.name}"
    asset = db.scalar(select(Asset).where(Asset.name == asset_name))
    if not asset:
        asset = Asset(name=asset_name, kind="wazuh_agent", environment="integration")
        db.add(asset); db.flush()
    event = SecurityEvent(event_type="wazuh_alert", username=str(alert.data.get("dstuser") or alert.agent.name), source_ip=source_ip, asset_id=asset.id, success=False, is_demo=alert.is_demo, occurred_at=alert.timestamp, metadata_json={"wazuh_rule_id": alert.rule.id, "wazuh_level": alert.rule.level, "agent_id": alert.agent.id, "agent_name": alert.agent.name, "fingerprint": fingerprint, "description": alert.rule.description})
    db.add(event); db.flush(); record_wazuh_alert()
    duplicate = db.scalar(select(Incident).where(Incident.detection_rule == f"WAZUH-{alert.rule.id}", Incident.evidence["fingerprint"].as_string() == fingerprint))
    if duplicate:
        db.commit()
        return WazuhIngestResponse(event_id=event.id, duplicate=True, incident=duplicate)
    description = alert.rule.description.lower()
    if any(word in description for word in ("brute", "authentication", "login")):
        title = "Wazuh authentication threat"
    elif "unauthorized" in description or "access" in description:
        title = "Wazuh unauthorized access alert"
    else:
        title = "Wazuh security alert"
    severity = _wazuh_severity(alert.rule.level)
    incident = Incident(title=title, severity=severity, status="investigating", source_ip=source_ip, asset_id=asset.id, detection_rule=f"WAZUH-{alert.rule.id}", evidence={"fingerprint": fingerprint, "wazuh_rule_id": alert.rule.id, "wazuh_level": alert.rule.level, "agent_id": alert.agent.id, "agent_name": alert.agent.name, "description": alert.rule.description, "event_ids": [event.id]}, analyst_notes="")
    db.add(incident); db.flush(); record_detection(f"WAZUH-{alert.rule.id}", severity); db.commit()
    return WazuhIngestResponse(event_id=event.id, duplicate=False, incident=incident)
