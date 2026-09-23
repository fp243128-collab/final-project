import uuid
import random
from datetime import datetime, timezone
from app.models.core import CSPMFinding, SystemStats
from sqlmodel import Session, select
from app.database import engine

def run_cspm_scan():
    findings_to_generate = [
        {
            "finding": "S3 bucket publicly accessible",
            "severity": "CRITICAL",
            "resource": "s3://production-assets-main",
            "rule_id": "S3_PUBLIC_ACCESS_001"
        },
        {
            "finding": "SSH open to 0.0.0.0/0",
            "severity": "HIGH",
            "resource": "sg-prod-web-01",
            "rule_id": "EC2_SG_SSH_OPEN_001"
        },
        {
            "finding": "IAM user lacks MFA",
            "severity": "HIGH",
            "resource": "arn:aws:iam::123456789012:user/admin-bot",
            "rule_id": "IAM_MFA_DISABLED_001"
        },
        {
            "finding": "EBS encryption disabled",
            "severity": "MEDIUM",
            "resource": "vol-049df61146c4d7901",
            "rule_id": "EC2_EBS_UNENCRYPTED_001"
        },
        {
            "finding": "S3 Bucket Versioning Disabled",
            "severity": "LOW",
            "resource": "s3://temp-upload-buffer",
            "rule_id": "S3_VERSIONING_DISABLED_001"
        },
    ]

    new_findings = []
    
    with Session(engine) as session:
        # Clear existing simulated findings for the demo
        existing = session.exec(select(CSPMFinding)).all()
        for f in existing:
            session.delete(f)
            
        for template in findings_to_generate:
            finding = CSPMFinding(
                id=f"CSPM-{str(uuid.uuid4())[:8]}",
                time=datetime.now(timezone.utc),
                finding=template["finding"],
                severity=template["severity"],
                resource=template["resource"],
                rule_id=template["rule_id"],
                status="Open"
            )
            session.add(finding)
            new_findings.append(finding)
            
        # Update cloud security score randomly between 70 and 85
        stats = session.exec(select(SystemStats)).first()
        if stats:
            stats.cloud_security_score = random.randint(70, 85)
            session.add(stats)

        session.commit()
    
    return [f.dict() for f in new_findings]

if __name__ == "__main__":
    run_cspm_scan()
    print("CSPM Scan completed and findings recorded.")
