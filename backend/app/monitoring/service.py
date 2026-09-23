import random
import time
from datetime import datetime, timezone, timedelta
from app.models.core import SystemMetric
from sqlmodel import Session, select
from app.database import engine

def generate_metric_point() -> SystemMetric:
    return SystemMetric(
        time=datetime.now(timezone.utc),
        cpu_usage=round(random.uniform(20.0, 65.0), 2),
        memory_usage=round(random.uniform(40.0, 85.0), 2),
        network_rx=round(random.uniform(10.0, 100.0), 2),
        network_tx=round(random.uniform(5.0, 50.0), 2),
        api_latency=round(random.uniform(20.0, 150.0), 2)
    )

def seed_historical_metrics():
    with Session(engine) as session:
        existing = session.exec(select(SystemMetric)).first()
        if existing:
            return
            
        now = datetime.now(timezone.utc)
        metrics = []
        # Generate 30 points, one for every minute historically
        for i in range(30, 0, -1):
            m = generate_metric_point()
            m.time = now - timedelta(minutes=i)
            metrics.append(m)
            
        session.add_all(metrics)
        session.commit()

def get_and_generate_latest_metrics(session: Session):
    # First add a new point for right now
    new_point = generate_metric_point()
    session.add(new_point)
    session.commit()
    
    # Retrieve the last 30 points
    recent = session.exec(
        select(SystemMetric)
        .order_by(SystemMetric.time.desc())
        .limit(30)
    ).all()
    
    # Return ascending for charts
    return list(reversed(recent))
