from datetime import datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


class AssetCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    kind: str = "web_application"
    environment: str = "demo"


class AssetOut(AssetCreate):
    id: int
    model_config = ConfigDict(from_attributes=True)


class EventIn(BaseModel):
    event_type: str = "authentication"
    username: str = Field(min_length=1, max_length=160)
    source_ip: str = Field(min_length=7, max_length=64)
    asset_id: int
    success: bool = False
    is_demo: bool = False
    occurred_at: datetime | None = None
    metadata: dict = Field(default_factory=dict)


class IncidentStatusUpdate(BaseModel):
    status: Literal["acknowledged", "investigating", "resolved"]
    analyst_notes: str | None = Field(default=None, max_length=4000)


class IncidentOut(BaseModel):
    id: int
    title: str
    severity: str
    status: str
    source_ip: str
    asset_id: int
    detection_rule: str
    evidence: dict
    analyst_notes: str
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class DemoResponse(BaseModel):
    scenario: str
    events_created: int
    incidents: list[IncidentOut]
