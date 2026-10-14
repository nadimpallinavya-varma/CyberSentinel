from datetime import datetime, timedelta, timezone
from sqlalchemy import select
from sqlalchemy.orm import Session
from .config import settings
from .models import Incident, SecurityEvent


def detect(db: Session, event: SecurityEvent) -> list[Incident]:
    since = event.occurred_at - timedelta(seconds=settings.burst_window_seconds)
    recent = db.scalars(select(SecurityEvent).where(SecurityEvent.source_ip == event.source_ip, SecurityEvent.occurred_at >= since)).all()
    failures = [e for e in recent if not e.success and e.username == event.username]
    same_source = [e for e in recent if not e.success]
    rules: list[tuple[str, str, str, list[SecurityEvent]]] = []
    if len(failures) >= settings.failed_login_threshold:
        rules.append(("AUTH-FAILURE-SEQUENCE", "Repeated failed-login pattern", "high", failures))
    if len(same_source) >= settings.burst_threshold:
        rules.append(("AUTH-VELOCITY", "Suspicious authentication burst", "high", same_source))
    if event.success and len(failures) >= settings.failed_login_threshold:
        rules.append(("AUTH-SUCCESS-AFTER-FAILURES", "Successful login after repeated failures", "critical", failures + [event]))
    incidents = []
    for rule, title, severity, evidence_events in rules:
        duplicate_cutoff = datetime.now(timezone.utc) - timedelta(minutes=settings.deduplication_window_minutes)
        duplicate = db.scalar(select(Incident).where(Incident.detection_rule == rule, Incident.source_ip == event.source_ip, Incident.created_at >= duplicate_cutoff))
        if duplicate:
            continue
        incident = Incident(title=title, severity=severity, status="investigating", source_ip=event.source_ip, asset_id=event.asset_id, detection_rule=rule, evidence={"event_ids": [e.id for e in evidence_events], "count": len(evidence_events), "explanation": _explanation(rule, len(evidence_events))})
        db.add(incident)
        incidents.append(incident)
    if incidents:
        db.flush()
    return incidents


def _explanation(rule: str, count: int) -> str:
    if rule == "AUTH-VELOCITY":
        return f"{count} failed authentication events from one source within {settings.burst_window_seconds} seconds."
    if rule == "AUTH-SUCCESS-AFTER-FAILURES":
        return f"A successful authentication followed {count - 1} failed attempts for the same identity."
    return f"{count} failed authentication attempts for the same identity exceeded the threshold of {settings.failed_login_threshold}."
