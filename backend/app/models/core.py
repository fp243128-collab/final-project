from sqlmodel import SQLModel, Field
from typing import Optional
from datetime import datetime, timezone

def utc_now():
    return datetime.now(timezone.utc)

class ThreatEvent(SQLModel, table=True):
    id: str = Field(primary_key=True)
    time: datetime = Field(default_factory=utc_now)
    type: str
    source: str
    severity: str
    status: str

class CSPMFinding(SQLModel, table=True):
    id: str = Field(primary_key=True)
    time: datetime = Field(default_factory=utc_now)
    finding: str
    severity: str
    resource: str
    rule_id: str
    status: str = Field(default="Open")

class PipelineRun(SQLModel, table=True):
    id: str = Field(primary_key=True)
    time: datetime = Field(default_factory=utc_now)
    commit_sha: str
    branch: str
    developer: str
    status: str
    sast_status: str
    secret_status: str
    dependency_status: str
    container_status: str

class SystemMetric(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    time: datetime = Field(default_factory=utc_now)
    cpu_usage: float
    memory_usage: float
    network_rx: float
    network_tx: float
    api_latency: float

class SystemStats(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    threats: int
    critical: int
    risk_score: int
    cloud_security_score: int
    threats_trend: str
    threats_trend_value: str
    critical_trend: str
    critical_trend_value: str
    cloud_trend: str
    cloud_trend_value: str

class Alert(SQLModel, table=True):
    id: str = Field(primary_key=True)
    time: datetime = Field(default_factory=utc_now)
    title: str
    severity: str
    source: str
    message: str
    status: str = Field(default="Active")

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True, unique=True)
    name: str
    hashed_password: str
    created_at: datetime = Field(default_factory=utc_now)

