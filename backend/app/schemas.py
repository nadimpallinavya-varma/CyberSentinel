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


class WazuhRule(BaseModel):
    id: str = Field(min_length=1, max_length=40)
    level: int = Field(ge=0, le=16)
    description: str = Field(min_length=1, max_length=500)


class WazuhAgent(BaseModel):
    id: str = Field(min_length=1, max_length=40)
    name: str = Field(min_length=1, max_length=120)
    ip: str | None = Field(default=None, max_length=64)


class WazuhAlert(BaseModel):
    timestamp: datetime
    rule: WazuhRule
    agent: WazuhAgent
    data: dict = Field(default_factory=dict)
    full_log: str | None = Field(default=None, max_length=4000)
    is_demo: bool = False


class WazuhIngestResponse(BaseModel):
    event_id: int
    duplicate: bool
    incident: IncidentOut | None = None
