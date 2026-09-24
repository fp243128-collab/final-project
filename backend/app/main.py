from fastapi import FastAPI, Depends, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import Session, select
from app.database import get_session, init_db
from app.models.core import SystemStats, ThreatEvent
import contextlib
import json
import asyncio
from typing import List

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_text(json.dumps(message))
            except Exception:
                self.disconnect(connection)

ws_manager = ConnectionManager()

@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize the database on startup
    init_db()
    yield

app = FastAPI(title="SentinelX API", lifespan=lifespan)

# Configure CORS so the Next.js frontend (local or deployed) can communicate with FastAPI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

import hashlib
import secrets
from app.models.core import User

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

from pydantic import BaseModel, EmailStr
from fastapi import HTTPException, status

class RegisterRequest(BaseModel):
    name: str
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

@app.post("/api/auth/register")
async def register(req: RegisterRequest, session: Session = Depends(get_session)):
    clean_email = req.email.strip().lower()
    if not clean_email or not req.password:
        raise HTTPException(status_code=400, detail="Email and password are required")
    
    # Check if user already exists
    existing = session.exec(select(User).where(User.email == clean_email)).first()
    if existing:
        raise HTTPException(status_code=400, detail="An account with this email already exists")
    
    new_user = User(
        name=req.name.strip() or "Security Analyst",
        email=clean_email,
        hashed_password=hash_password(req.password)
    )
    session.add(new_user)
    session.commit()
    session.refresh(new_user)
    
    # Return auth token and user profile
    token = secrets.token_hex(24)
    return {
        "status": "success",
        "message": "Account created successfully",
        "token": token,
        "user": {
            "id": new_user.id,
            "name": new_user.name,
            "email": new_user.email
        }
    }

@app.post("/api/auth/login")
async def login(req: LoginRequest, session: Session = Depends(get_session)):
    clean_email = req.email.strip().lower()
    hashed = hash_password(req.password)
    
    user = session.exec(select(User).where(User.email == clean_email, User.hashed_password == hashed)).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    token = secrets.token_hex(24)
    return {
        "status": "success",
        "message": "Login successful",
        "token": token,
        "user": {
            "id": user.id,
            "name": user.name,
            "email": user.email
        }
    }

@app.get("/api/auth/users")
async def get_all_users(session: Session = Depends(get_session)):
    users = session.exec(select(User)).all()
    return {
        "total": len(users),
        "users": [{"id": u.id, "email": u.email, "name": u.name, "created_at": str(u.created_at)} for u in users]
    }



@app.websocket("/ws/live")
async def websocket_live_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        # Initial greeting and ping loop
        await websocket.send_text(json.dumps({
            "type": "CONNECTION_ESTABLISHED",
            "message": "Connected to SentinelX real-time security stream"
        }))
        while True:
            data = await websocket.receive_text()
            # Echo or heartbeat
            await websocket.send_text(json.dumps({"type": "PONG", "payload": data}))
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)

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
        await ws_manager.broadcast({
            "type": "NEW_THREAT",
            "threat": {
                "id": new_event.id,
                "type": new_event.type,
                "source": new_event.source,
                "severity": new_event.severity,
                "confidence": analysis.get("confidence", 95.0),
                "time": new_event.time.strftime("%H:%M:%S")
            }
        })
    
    return {
        "event": event,
        "analysis": analysis,
        "logged": analysis["severity"] != "LOW"
    }

@app.get("/api/threats/model")
async def get_model_details():
    """Returns AI Intrusion Detection Model evaluation metrics, parameters, and feature importances."""
    return {
        "model_name": "Random Forest Intrusion Detector (RF-IDS)",
        "version": "1.0.4",
        "status": "ACTIVE",
        "algorithm": "RandomForestClassifier(n_estimators=100, criterion='gini', random_state=42)",
        "metrics": {
            "accuracy": 94.2,
            "precision": 93.8,
            "recall": 92.9,
            "f1_score": 93.3,
            "latency_ms": 1.2
        },
        "features": [
            {"name": "bytes_sent", "importance": 37.4, "description": "Outbound byte transfer rate (flags data exfiltration & DoS floods)"},
            {"name": "packet_size", "importance": 29.2, "description": "Average packet payload size (distinguishes SYN probes from large payloads)"},
            {"name": "failed_logins", "importance": 15.2, "description": "Sequential authentication failure counter (identifies Brute Force)"},
            {"name": "unique_ports_accessed", "importance": 14.8, "description": "Unique port destinations per 10s window (detects Port Scanners)"},
            {"name": "duration", "importance": 3.4, "description": "Connection session lifespan in seconds"}
        ],
        "classes": ["Normal", "Port Scan", "Brute Force", "DoS"],
        "dataset": "CIC-IDS2017 & Synthetic Flow Vectors (10,000 samples, 80/20 train/test split)",
        "confusion_matrix": [
            {"actual": "Normal", "predicted_normal": 1180, "predicted_attack": 20},
            {"actual": "Port Scan", "predicted_normal": 12, "predicted_attack": 288},
            {"actual": "Brute Force", "predicted_normal": 18, "predicted_attack": 282},
            {"actual": "DoS", "predicted_normal": 8, "predicted_attack": 192}
        ]
    }

@app.post("/api/threats/simulate")
async def simulate_live_traffic_burst(session: Session = Depends(get_session)):
    """Simulates an incoming network traffic vector to trigger real-time AI ML detection and broadcast."""
    import random
    scenarios = [
        {
            "name": "SSH Brute Force Flood",
            "event": NetworkEvent(
                packet_size=125.0,
                duration=4.5,
                failed_logins=random.randint(15, 60),
                unique_ports_accessed=1,
                bytes_sent=random.uniform(400, 650),
                source_ip=f"198.51.100.{random.randint(10, 250)}",
                destination="10.0.1.50:22"
            )
        },
        {
            "name": "Nmap Horizontal Port Scan",
            "event": NetworkEvent(
                packet_size=64.0,
                duration=0.8,
                failed_logins=0,
                unique_ports_accessed=random.randint(80, 500),
                bytes_sent=random.uniform(150, 300),
                source_ip=f"203.0.113.{random.randint(10, 250)}",
                destination="10.0.1.0/24"
            )
        },
        {
            "name": "High Volume HTTP DoS Attack",
            "event": NetworkEvent(
                packet_size=1480.0,
                duration=12.0,
                failed_logins=0,
                unique_ports_accessed=1,
                bytes_sent=random.uniform(12000, 25000),
                source_ip=f"45.33.32.{random.randint(10, 250)}",
                destination="10.0.1.100:80"
            )
        }
    ]
    chosen = random.choice(scenarios)
    result = await analyze_threat(chosen["event"], session)
    return {
        "status": "success",
        "scenario": chosen["name"],
        "analysis": result["analysis"]
    }

from app.models.core import CSPMFinding
from app.cspm.scanner import run_cspm_scan, remediate_finding

@app.get("/api/cspm")
async def get_cspm_findings(session: Session = Depends(get_session)):
    findings = session.exec(select(CSPMFinding).order_by(CSPMFinding.severity.desc())).all()
    stats = session.exec(select(SystemStats)).first()
    
    score = stats.cloud_security_score if stats else 100
    
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        if f.status == "Open" and f.severity in severity_counts:
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

class RemediationRequest(BaseModel):
    finding_id: str

@app.post("/api/cspm/remediate")
async def apply_cspm_remediation(req: RemediationRequest, session: Session = Depends(get_session)):
    result = remediate_finding(req.finding_id, session)
    if result.get("status") == "success":
        await ws_manager.broadcast({
            "type": "CSPM_REMEDIATED",
            "finding_id": req.finding_id,
            "new_score": result.get("new_score")
        })
    return result

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
    init_db()
    with Session(engine) as session:
        seed_alerts(session)
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
async def ask_assistant(query: AssistantQuery, session: Session = Depends(get_session)):
    result = query_assistant(query.prompt, session=session)
    return result

@app.get("/api/assistant/status")
async def assistant_status():
    import os
    k = (os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or os.getenv("GOOGLE_GENAI_API_KEY") or "").strip()
    return {
        "gemini_api_key_configured": bool(k),
        "key_length": len(k) if k else 0,
        "key_prefix": k[:6] + "..." if len(k) >= 6 else None
    }


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
        await ws_manager.broadcast({
            "type": "ALERT_RESOLVED",
            "alert_id": alert_id
        })
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

from app.devsecops.service import trigger_pipeline_scan

@app.post("/api/devsecops/webhook")
async def trigger_pipeline_webhook():
    result = trigger_pipeline_scan(developer="devsecops-ci@sentinelx.ai", branch="main")
    return {"status": "success", "run": result["run"], "sast_details": result["sast_details"]}
