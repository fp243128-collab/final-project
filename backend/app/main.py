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
        ],
        "risk_trend": [
            {"date": "Mon", "score": 65},
            {"date": "Tue", "score": 68},
            {"date": "Wed", "score": 75},
            {"date": "Thu", "score": 72},
            {"date": "Fri", "score": 85},
            {"date": "Sat", "score": 78},
            {"date": "Sun", "score": 74}
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

from app.models.core import PipelineRun, Alert
from app.devsecops.service import simulate_pipeline_run, seed_initial_runs
from app.monitoring.service import get_and_generate_latest_metrics, seed_historical_metrics
import uuid
import random
from datetime import datetime, timezone, timedelta
from app.database import engine

def seed_alerts(session: Session):
    existing = session.exec(select(Alert)).first()
    if existing:
        return
    now = datetime.now(timezone.utc)
    alerts = [
        Alert(id=f"ALT-{str(uuid.uuid4())[:8]}", time=now - timedelta(minutes=2), title="Port scan detected", severity="Critical", source="AI IDS", message="Repeated connection attempts across multiple ports from IP 192.168.1.105."),
        Alert(id=f"ALT-{str(uuid.uuid4())[:8]}", time=now - timedelta(minutes=5), title="Brute force detected", severity="High", source="AI IDS", message="Multiple failed login attempts to SSH from unknown external IP."),
        Alert(id=f"ALT-{str(uuid.uuid4())[:8]}", time=now - timedelta(minutes=18), title="Public resource", severity="Medium", source="CSPM", message="S3 Bucket 'production-assets' allows public read access."),
    ]
    session.add_all(alerts)
    session.commit()

@app.on_event("startup")
def on_startup():
    with Session(engine) as session:
        seed_alerts(session)
    # Keep the existing init_db if any, and call seed_initial_runs
    seed_initial_runs()
    seed_historical_metrics()

@app.get("/api/monitoring/metrics")
async def get_metrics(session: Session = Depends(get_session)):
    metrics = get_and_generate_latest_metrics(session)
    return {
        "metrics": [
            {
                "time": m.time.isoformat(),
                "cpu_usage": m.cpu_usage,
                "memory_usage": m.memory_usage,
                "network_rx": m.network_rx,
                "network_tx": m.network_tx,
                "api_latency": m.api_latency
            }
            for m in metrics
        ]
    }

@app.get("/api/monitoring/health")
async def get_health():
    import random
    return {
        "uptime": "99.98%",
        "active_containers": 12,
        "error_rate": f"{round(random.uniform(0.1, 1.5), 2)}%",
        "status": "Healthy"
    }

class AssistantQuery(BaseModel):
    prompt: str

from app.assistant.service import query_assistant

@app.post("/api/assistant/query")
async def ask_assistant(query: AssistantQuery):
    response = query_assistant(query.prompt)
    return {"response": response}

@app.get("/api/resources")
async def get_resources():
    return {
        "resources": [
            {"id": "aws-s3-prod-assets", "provider": "AWS", "type": "S3 Bucket", "compliance": "Non-Compliant", "risk": "High"},
            {"id": "aws-ec2-api-web", "provider": "AWS", "type": "EC2 Instance", "compliance": "Compliant", "risk": "Low"},
            {"id": "aws-rds-main-db", "provider": "AWS", "type": "RDS Database", "compliance": "Compliant", "risk": "Medium"},
            {"id": "gcp-storage-logs", "provider": "GCP", "type": "Cloud Storage", "compliance": "Compliant", "risk": "Low"},
        ]
    }

@app.get("/api/reports")
async def get_reports():
    return {
        "reports": [
            {"id": "rep-001", "name": "Monthly Executive Summary", "date": "2026-09-01", "type": "Summary"},
            {"id": "rep-002", "name": "PCI-DSS Compliance Audit", "date": "2026-08-15", "type": "Compliance"},
            {"id": "rep-003", "name": "Q3 Infrastructure Risk", "date": "2026-07-01", "type": "Risk"},
        ]
    }

@app.get("/api/audit-logs")
async def get_audit_logs():
    return {
        "logs": [
            {"id": "log-1", "time": "2026-09-24 10:15:00", "user": "admin@sentinelx.io", "action": "Resolved Alert ALT-54321", "status": "Success"},
            {"id": "log-2", "time": "2026-09-24 09:45:12", "user": "system", "action": "Automated CSPM Scan Completed", "status": "Success"},
            {"id": "log-3", "time": "2026-09-24 08:30:00", "user": "jdoe@sentinelx.io", "action": "Failed Login Attempt", "status": "Failure"},
            {"id": "log-4", "time": "2026-09-23 16:20:00", "user": "admin@sentinelx.io", "action": "Blocked IP 10.0.0.19", "status": "Success"},
        ]
    }

@app.get("/api/settings")
async def get_settings():
    return {
        "integrations": [
            {"name": "AWS", "status": "Connected", "last_sync": "10 mins ago"},
            {"name": "Google Cloud", "status": "Connected", "last_sync": "1 hour ago"},
            {"name": "Azure", "status": "Disconnected", "last_sync": "N/A"},
            {"name": "Slack", "status": "Connected", "last_sync": "Active"},
        ]
    }

@app.get("/api/alerts")
async def get_alerts(session: Session = Depends(get_session)):
    alerts = session.exec(select(Alert).order_by(Alert.time.desc())).all()
    return {"alerts": alerts}

@app.post("/api/alerts/resolve/{alert_id}")
async def resolve_alert(alert_id: str, session: Session = Depends(get_session)):
    alert = session.get(Alert, alert_id)
    if alert:
        alert.status = "Resolved"
        session.add(alert)
        session.commit()
    return {"status": "success"}

@app.get("/api/risk")
async def get_risk():
    return {
        "overall_risk": 74,
        "breakdown": {
            "threat_risk": 32,
            "cloud_risk": 24,
            "iam_risk": 9,
            "infra_risk": 14
        },
        "top_assets": [
            {"name": "production-api", "score": 91},
            {"name": "production-db", "score": 76},
            {"name": "public-assets", "score": 73}
        ]
    }

@app.get("/api/analytics")
async def get_analytics():
    # Generate mock historical trend data
    now = datetime.now(timezone.utc)
    trend = []
    for i in range(30, 0, -1):
        t = now - timedelta(days=i)
        trend.append({
            "date": t.strftime("%Y-%m-%d"),
            "critical": random.randint(0, 5),
            "high": random.randint(2, 10),
            "medium": random.randint(5, 20)
        })
    return {
        "trend": trend,
        "severity_distribution": [
            {"name": "Critical", "value": 12},
            {"name": "High", "value": 35},
            {"name": "Medium", "value": 89},
            {"name": "Low", "value": 124}
        ]
    }

@app.get("/api/monitoring/health")
async def get_health():
    import random
    return {
        "uptime": "99.98%",
        "active_containers": 12,
        "error_rate": f"{round(random.uniform(0.1, 1.5), 2)}%",
        "status": "Healthy"
    }

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
