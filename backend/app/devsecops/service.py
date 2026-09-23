import uuid
import random
from datetime import datetime, timezone
from app.models.core import PipelineRun
from sqlmodel import Session, select
from app.database import engine

def simulate_pipeline_run():
    # Randomly select a scenario
    scenarios = [
        {
            "status": "PASSED",
            "sast_status": "PASSED",
            "secret_status": "PASSED",
            "dependency_status": "PASSED",
            "container_status": "PASSED"
        },
        {
            "status": "PASSED WITH WARNINGS",
            "sast_status": "PASSED",
            "secret_status": "PASSED",
            "dependency_status": "WARNING",
            "container_status": "PASSED"
        },
        {
            "status": "FAILED",
            "sast_status": "PASSED",
            "secret_status": "FAILED",
            "dependency_status": "PASSED",
            "container_status": "PASSED"
        },
        {
            "status": "FAILED",
            "sast_status": "FAILED",
            "secret_status": "PASSED",
            "dependency_status": "WARNING",
            "container_status": "FAILED"
        }
    ]
    
    scenario = random.choice(scenarios)
    
    developers = ["alice@sentinelx.ai", "bob@sentinelx.ai", "charlie@sentinelx.ai", "system"]
    branches = ["main", "feature/auth", "hotfix/api-bug", "develop"]
    
    new_run = PipelineRun(
        id=f"RUN-{str(uuid.uuid4())[:8].upper()}",
        time=datetime.now(timezone.utc),
        commit_sha=str(uuid.uuid4())[:7],
        branch=random.choice(branches),
        developer=random.choice(developers),
        status=scenario["status"],
        sast_status=scenario["sast_status"],
        secret_status=scenario["secret_status"],
        dependency_status=scenario["dependency_status"],
        container_status=scenario["container_status"]
    )
    
    with Session(engine) as session:
        session.add(new_run)
        session.commit()
        session.refresh(new_run)
        
    return new_run.dict()

def seed_initial_runs():
    with Session(engine) as session:
        existing = session.exec(select(PipelineRun)).first()
        if existing:
            return
            
    for _ in range(5):
        simulate_pipeline_run()

if __name__ == "__main__":
    seed_initial_runs()
    print("Initial DevSecOps pipeline runs seeded.")
