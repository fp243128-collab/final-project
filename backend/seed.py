from sqlmodel import Session, select
from app.database import engine, init_db
from app.models.core import ThreatEvent, SystemStats
from datetime import datetime, timedelta, timezone
import uuid

def seed():
    init_db()
    with Session(engine) as session:
        # Check if already seeded
        if session.exec(select(SystemStats)).first():
            print("Database already seeded.")
            return

        print("Seeding database...")
        
        # Seed Stats
        stats = SystemStats(
            threats=142,
            critical=12,
            risk_score=78,
            cloud_security_score=85,
            threats_trend="up",
            threats_trend_value="15%",
            critical_trend="down",
            critical_trend_value="3",
            cloud_trend="up",
            cloud_trend_value="5%"
        )
        session.add(stats)
        
        # Seed Threat Events
        now = datetime.now(timezone.utc)
        events = [
            ThreatEvent(id=f"EVT-{uuid.uuid4().hex[:6].upper()}", time=now - timedelta(minutes=5), type="SQL Injection", source="45.33.12.9", severity="CRITICAL", status="Open"),
            ThreatEvent(id=f"EVT-{uuid.uuid4().hex[:6].upper()}", time=now - timedelta(minutes=18), type="Port Scan", source="10.0.0.45", severity="HIGH", status="Investigate"),
            ThreatEvent(id=f"EVT-{uuid.uuid4().hex[:6].upper()}", time=now - timedelta(minutes=45), type="Anomaly", source="192.168.1.100", severity="MEDIUM", status="Open"),
            ThreatEvent(id=f"EVT-{uuid.uuid4().hex[:6].upper()}", time=now - timedelta(minutes=120), type="Brute Force", source="External", severity="CRITICAL", status="Resolved"),
        ]
        session.add_all(events)
        
        session.commit()
        print("Seeding complete.")

if __name__ == "__main__":
    seed()
