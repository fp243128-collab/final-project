import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine
from app.main import app
from app.database import get_session
from app.ml.predict import analyze_event
from app.cspm.scanner import run_cspm_scan, remediate_finding
from app.assistant.service import query_assistant

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/api/monitoring/health")
    assert response.status_code == 200
    data = response.json()
    assert "uptime" in data
    assert data["status"] == "Healthy"

def test_ml_prediction_brute_force():
    # Simulate high failed logins
    sample = {
        "packet_size": 120.0,
        "duration": 5.0,
        "failed_logins": 25.0,
        "unique_ports_accessed": 1.0,
        "bytes_sent": 500.0
    }
    result = analyze_event(sample)
    assert result["prediction"] in ["Brute Force", "Port Scan", "DoS", "Normal"]
    assert "confidence" in result
    assert "severity" in result

def test_cspm_scan_and_remediation():
    # Test triggering scan
    scan_resp = client.post("/api/cspm/scan")
    assert scan_resp.status_code == 200
    
    # Verify findings exist
    get_resp = client.get("/api/cspm")
    assert get_resp.status_code == 200
    findings = get_resp.json()["findings"]
    assert len(findings) > 0
    
    # Test auto-remediation on first finding
    target_id = findings[0]["id"]
    rem_resp = client.post("/api/cspm/remediate", json={"finding_id": target_id})
    assert rem_resp.status_code == 200
    rem_data = rem_resp.json()
    assert rem_data["status"] == "success"
    assert rem_data["new_status"] == "Resolved"

def test_assistant_query():
    # Test AI assistant with DB telemetry context
    response = client.post("/api/assistant/query", json={"prompt": "Explain why public S3 buckets are dangerous"})
    assert response.status_code == 200
    data = response.json()
    assert "response" in data
    assert "S3" in data["response"] or "Bucket" in data["response"]
    assert "engine" in data

def test_devsecops_pipeline_trigger():
    response = client.post("/api/devsecops/webhook")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "run" in data
    assert "sast_details" in data
    assert data["sast_details"]["engine"] == "Bandit SAST v1.9"

def test_alerts_endpoint():
    response = client.get("/api/alerts")
    assert response.status_code == 200
    data = response.json()
    assert "alerts" in data
