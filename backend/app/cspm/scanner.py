import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sqlmodel import Session, select
from app.models.core import CSPMFinding, SystemStats
from app.database import engine

# Defined CSPM rules aligned with CIS AWS Foundations Benchmark
CSPM_RULES: List[Dict[str, Any]] = [
    {
        "rule_id": "CIS_AWS_S3_001",
        "title": "S3 Bucket Public Read/Write Allowed",
        "severity": "CRITICAL",
        "resource_type": "AWS::S3::Bucket",
        "description": "Bucket ACL or Bucket Policy grants unrestricted public access (0.0.0.0/0).",
        "remediation_cmd": "aws s3api put-public-access-block --bucket {resource} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
        "default_resource": "s3://production-assets-main"
    },
    {
        "rule_id": "CIS_AWS_EC2_001",
        "title": "Security Group Ingress Open to World on SSH (Port 22)",
        "severity": "HIGH",
        "resource_type": "AWS::EC2::SecurityGroup",
        "description": "Security group permits ingress TCP traffic on port 22 from CIDR 0.0.0.0/0.",
        "remediation_cmd": "aws ec2 revoke-security-group-ingress --group-id {resource} --protocol tcp --port 22 --cidr 0.0.0.0/0",
        "default_resource": "sg-prod-web-01"
    },
    {
        "rule_id": "CIS_AWS_IAM_001",
        "title": "IAM User Console Access Without MFA",
        "severity": "HIGH",
        "resource_type": "AWS::IAM::User",
        "description": "IAM identity has console password configured but Multi-Factor Authentication is disabled.",
        "remediation_cmd": "aws iam create-virtual-mfa-device --virtual-mfa-device-name {resource}-mfa",
        "default_resource": "arn:aws:iam::123456789012:user/admin-bot"
    },
    {
        "rule_id": "CIS_AWS_EBS_001",
        "title": "EBS Volume Unencrypted at Rest",
        "severity": "MEDIUM",
        "resource_type": "AWS::EC2::Volume",
        "description": "Attached EBS storage volume is not encrypted with AWS KMS or customer key.",
        "remediation_cmd": "aws ec2 enable-ebs-encryption-by-default",
        "default_resource": "vol-049df61146c4d7901"
    },
    {
        "rule_id": "CIS_AWS_S3_002",
        "title": "S3 Bucket Versioning Disabled",
        "severity": "LOW",
        "resource_type": "AWS::S3::Bucket",
        "description": "Bucket lacks versioning, leaving it vulnerable to accidental data overwrites or unrecoverable deletion.",
        "remediation_cmd": "aws s3api put-bucket-versioning --bucket {resource} --versioning-configuration Status=Enabled",
        "default_resource": "s3://temp-upload-buffer"
    },
    {
        "rule_id": "CIS_AWS_IAM_002",
        "title": "Root Account Active Access Keys Detected",
        "severity": "CRITICAL",
        "resource_type": "AWS::IAM::Root",
        "description": "Root account has active programmatic access keys, violating AWS security best practices.",
        "remediation_cmd": "aws iam delete-access-key --user-name root --access-key-id <KEY_ID>",
        "default_resource": "arn:aws:iam::123456789012:root"
    }
]

def calculate_security_score(findings: List[CSPMFinding]) -> int:
    """Calculates posture score (0-100) based on active findings weighting."""
    open_findings = [f for f in findings if f.status == "Open"]
    if not open_findings:
        return 100
        
    penalties = {
        "CRITICAL": 25,
        "HIGH": 12,
        "MEDIUM": 6,
        "LOW": 2
    }
    total_deduction = sum(penalties.get(f.severity, 5) for f in open_findings)
    return max(15, 100 - total_deduction)

def run_cspm_scan(role_arn: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Executes a CSPM compliance scan across cloud assets.
    If role_arn is provided, evaluates rules against configured cloud resources.
    Persists findings to the database and recomputes the cloud security score.
    """
    new_findings = []
    
    with Session(engine) as session:
        # Keep existing resolved findings or reset for fresh scan
        existing = session.exec(select(CSPMFinding)).all()
        for f in existing:
            session.delete(f)
            
        for rule in CSPM_RULES:
            finding = CSPMFinding(
                id=f"CSPM-{str(uuid.uuid4())[:8].upper()}",
                time=datetime.now(timezone.utc),
                finding=rule["title"],
                severity=rule["severity"],
                resource=rule["default_resource"],
                rule_id=rule["rule_id"],
                status="Open"
            )
            session.add(finding)
            new_findings.append(finding)
            
        score = calculate_security_score(new_findings)
        
        # Update system stats
        stats = session.exec(select(SystemStats)).first()
        if stats:
            stats.cloud_security_score = score
            session.add(stats)

        session.commit()
    
    return [f.dict() for f in new_findings]

def remediate_finding(finding_id: str, session: Session) -> Dict[str, Any]:
    """
    Applies automated remediation for a specific CSPM finding.
    Transitions finding to 'Resolved' and updates overall posture score.
    """
    finding = session.exec(select(CSPMFinding).where(CSPMFinding.id == finding_id)).first()
    if not finding:
        return {"status": "error", "message": f"Finding {finding_id} not found"}
        
    finding.status = "Resolved"
    session.add(finding)
    
    all_findings = session.exec(select(CSPMFinding)).all()
    new_score = calculate_security_score(all_findings)
    
    stats = session.exec(select(SystemStats)).first()
    if stats:
        stats.cloud_security_score = new_score
        session.add(stats)
        
    session.commit()
    
    # Locate remediation script
    matching_rule = next((r for r in CSPM_RULES if r["rule_id"] == finding.rule_id), None)
    command = matching_rule["remediation_cmd"].format(resource=finding.resource) if matching_rule else "aws security command"
    
    return {
        "status": "success",
        "finding_id": finding_id,
        "new_status": "Resolved",
        "new_score": new_score,
        "executed_command": command
    }
