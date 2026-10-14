from datetime import datetime, timedelta, timezone
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from .config import settings
from .db import Base, engine, get_db
from .detection import detect
from .models import Asset, Incident, SecurityEvent
from .schemas import AssetCreate, AssetOut, DemoResponse, EventIn, IncidentOut, IncidentStatusUpdate

app = FastAPI(title="CyberSentinel API", version="0.2.0", description="Explainable security event detection and incident response API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["Content-Type", "Accept", "Authorization"],
)


@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)


@app.get("/health")
def health(db: Session = Depends(get_db)):
    db.execute(select(1))
    return {"status": "ok", "database": "reachable"}


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
    db.commit()
    unique = {i.id: i for i in found}
    return DemoResponse(scenario=scenario, events_created=len(specs), incidents=list(unique.values()))


@app.get("/api/reports/summary")
def report_summary(db: Session = Depends(get_db)):
    rows = db.execute(select(Incident.severity, func.count(Incident.id)).group_by(Incident.severity)).all()
    return {"generated_at": datetime.now(timezone.utc), "events": db.scalar(select(func.count(SecurityEvent.id))) or 0, "incidents_by_severity": {severity: count for severity, count in rows}}
