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

def test_auth_register_and_login():
    import uuid
    test_email = f"analyst_{uuid.uuid4().hex[:6]}@sentinelx.io"
    test_pass = "Security123!"

    # 1. Register
    reg_resp = client.post("/api/auth/register", json={
        "name": "Alex Mercer",
        "email": test_email,
        "password": test_pass
    })
    assert reg_resp.status_code == 200
    reg_data = reg_resp.json()
    assert reg_data["status"] == "success"
    assert "token" in reg_data
    assert reg_data["user"]["email"] == test_email

    # 2. Duplicate registration should fail
    dup_resp = client.post("/api/auth/register", json={
        "name": "Alex Mercer",
        "email": test_email,
        "password": test_pass
    })
    assert dup_resp.status_code == 400

    # 3. Successful Login
    login_resp = client.post("/api/auth/login", json={
        "email": test_email,
        "password": test_pass
    })
    assert login_resp.status_code == 200
    login_data = login_resp.json()
    assert login_data["status"] == "success"
    assert "token" in login_data
    assert login_data["user"]["name"] == "Alex Mercer"

    # 4. Failed Login with wrong password
    bad_login = client.post("/api/auth/login", json={
        "email": test_email,
        "password": "WrongPassword!"
    })
    assert bad_login.status_code == 401

