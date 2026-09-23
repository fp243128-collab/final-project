from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import Session, select
from app.database import get_session, init_db
from app.models.core import SystemStats, ThreatEvent
import contextlib

@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize the database on startup
    init_db()
    yield

app = FastAPI(title="SentinelX API", lifespan=lifespan)

# Configure CORS so the Next.js frontend can communicate with FastAPI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/overview")
async def get_overview(session: Session = Depends(get_session)):
    # Fetch stats from DB
    stats = session.exec(select(SystemStats)).first()
    # Fetch events from DB (most recent first)
    events = session.exec(select(ThreatEvent).order_by(ThreatEvent.time.desc()).limit(10)).all()
    
    # If no stats yet (not seeded), return empty
    if not stats:
        return {"stats": {}, "trends": {}, "recent_events": [], "threat_distribution": []}

    return {
        "stats": {
            "threats": stats.threats,
            "critical": stats.critical,
            "risk_score": stats.risk_score,
            "cloud_security_score": stats.cloud_security_score,
        },
        "trends": {
            "threats": {"direction": stats.threats_trend, "value": stats.threats_trend_value},
            "critical": {"direction": stats.critical_trend, "value": stats.critical_trend_value},
            "cloud_security_score": {"direction": stats.cloud_trend, "value": stats.cloud_trend_value},
        },
        "threat_distribution": [
            {"label": "Brute Force", "count": 55},
            {"label": "Port Scan", "count": 38},
            {"label": "DoS", "count": 27},
            {"label": "Anomaly", "count": 22},
        ],
        "recent_events": [
            {
                "id": evt.id,
                "time": evt.time.strftime("%H:%M"),
                "type": evt.type,
                "source": evt.source,
                "severity": evt.severity,
                "status": evt.status,
            }
            for evt in events
        ]
    }

from pydantic import BaseModel

class NetworkEvent(BaseModel):
    packet_size: float
    duration: float
    failed_logins: int
    unique_ports_accessed: int
    bytes_sent: float
    source_ip: str
    destination: str

from app.ml.predict import analyze_event
from datetime import datetime, timezone
import uuid

@app.get("/api/threats")
async def get_threats(session: Session = Depends(get_session)):
    events = session.exec(select(ThreatEvent).order_by(ThreatEvent.time.desc()).limit(50)).all()
    return [
        {
            "id": evt.id,
            "time": evt.time.strftime("%H:%M:%S"),
            "type": evt.type,
            "source": evt.source,
            "destination": evt.destination if hasattr(evt, 'destination') else "Unknown",
            "severity": evt.severity,
            "status": evt.status,
            "confidence": getattr(evt, 'confidence', 95.0) # Mock confidence if missing
        }
        for evt in events
    ]

@app.post("/api/threats/analyze")
async def analyze_threat(event: NetworkEvent, session: Session = Depends(get_session)):
    analysis = analyze_event(event.dict())
    
    if "error" in analysis:
        return analysis

    # Create new threat event based on ML prediction
    new_event = ThreatEvent(
        id=f"THR-{str(uuid.uuid4())[:8]}",
        time=datetime.now(timezone.utc),
        type=analysis["prediction"],
        source=event.source_ip,
        severity=analysis["severity"],
        status="Open"
    )
    
    # In a real system, we might only log if severity > LOW. For demo, we log all.
    if analysis["severity"] != "LOW":
        session.add(new_event)
        
        # Update system stats
        stats = session.exec(select(SystemStats)).first()
        if stats:
            stats.threats += 1
            if analysis["severity"] == "CRITICAL":
                stats.critical += 1
            session.add(stats)
            
        session.commit()
    
    return {
        "event": event,
        "analysis": analysis,
        "logged": analysis["severity"] != "LOW"
    }

from app.models.core import CSPMFinding
from app.cspm.scanner import run_cspm_scan

@app.get("/api/cspm")
async def get_cspm_findings(session: Session = Depends(get_session)):
    findings = session.exec(select(CSPMFinding).order_by(CSPMFinding.severity.desc())).all()
    stats = session.exec(select(SystemStats)).first()
    
    score = stats.cloud_security_score if stats else 100
    
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        if f.severity in severity_counts:
            severity_counts[f.severity] += 1
            
    return {
        "score": score,
        "counts": severity_counts,
        "findings": [
            {
                "id": f.id,
                "finding": f.finding,
                "severity": f.severity,
                "resource": f.resource,
                "rule_id": f.rule_id,
                "status": f.status
            }
            for f in findings
        ]
    }

@app.post("/api/cspm/scan")
async def trigger_cspm_scan():
    run_cspm_scan()
    return {"status": "success", "message": "CSPM Scan completed"}

from app.models.core import PipelineRun
from app.devsecops.service import simulate_pipeline_run, seed_initial_runs

@app.on_event("startup")
def on_startup():
    # Keep the existing init_db if any, and call seed_initial_runs
    seed_initial_runs()

@app.get("/api/devsecops/runs")
async def get_pipeline_runs(session: Session = Depends(get_session)):
    runs = session.exec(select(PipelineRun).order_by(PipelineRun.time.desc())).all()
    return {
        "runs": [
            {
                "id": r.id,
                "time": r.time,
                "commit_sha": r.commit_sha,
                "branch": r.branch,
                "developer": r.developer,
                "status": r.status,
                "sast_status": r.sast_status,
                "secret_status": r.secret_status,
                "dependency_status": r.dependency_status,
                "container_status": r.container_status
            }
            for r in runs
        ]
    }

@app.post("/api/devsecops/webhook")
async def trigger_pipeline_webhook():
    run = simulate_pipeline_run()
    return {"status": "success", "run": run}
