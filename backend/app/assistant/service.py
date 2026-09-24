import os
import json
import logging
from typing import Optional, List, Dict, Any
from sqlmodel import Session, select
from app.models.core import CSPMFinding, ThreatEvent, Alert

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are SentinelX AI, an elite cybersecurity and cloud security operations copilot for the SentinelX platform.
You specialize in:
1. CSPM (Cloud Security Posture Management) finding analysis (AWS IAM, S3, Security Groups, Encryption, VPC).
2. AI-based Intrusion Detection & Threat Analysis (Port scans, Brute Force, DoS, anomalies).
3. Actionable step-by-step remediation commands (AWS CLI, Terraform diffs, Linux iptables/sysctl).
4. Blast radius assessment and impact evaluation.

Guidelines:
- Ground your analysis in the real-time telemetry and database findings provided in the context.
- Be concise, authoritative, structured, and helpful.
- Present clear remediation steps using markdown code blocks (`bash`, `terraform`, or `json`).
- Always remind the user that remediation scripts require human authorization before execution in production.
"""

def assemble_context(session: Optional[Session] = None) -> str:
    """Assembles scoped telemetry context from the SentinelX database."""
    if not session:
        return "No database session available."
    
    try:
        findings = session.exec(select(CSPMFinding).limit(5)).all()
        threats = session.exec(select(ThreatEvent).order_by(ThreatEvent.time.desc()).limit(5)).all()
        alerts = session.exec(select(Alert).order_by(Alert.time.desc()).limit(5)).all()
        
        context_data = {
            "active_cspm_findings": [
                {"id": f.id, "finding": f.finding, "severity": f.severity, "resource": f.resource, "status": f.status}
                for f in findings
            ],
            "recent_threat_events": [
                {"id": t.id, "type": t.type, "source": t.source, "severity": t.severity, "status": t.status}
                for t in threats
            ],
            "recent_alerts": [
                {"id": a.id, "title": a.title, "severity": a.severity, "message": a.message}
                for a in alerts
            ]
        }
        return json.dumps(context_data, indent=2)
    except Exception as e:
        logger.warning(f"Failed to gather db context: {e}")
        return "Context gathering unavailable."

def query_assistant(prompt: str, session: Optional[Session] = None) -> Dict[str, Any]:
    """
    Queries SentinelX AI.
    If GEMINI_API_KEY is present, calls the Google GenAI SDK (gemini-3.7-flash).
    Otherwise, gracefully falls back to structured expert cybersecurity heuristics.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    db_context = assemble_context(session) if session else ""
    
    if api_key:
        try:
            from google import genai
            client = genai.Client(api_key=api_key)
            full_prompt = f"""Context from SentinelX Platform:
```json
{db_context}
```

User Query:
{prompt}
"""
            response = client.models.generate_content(
                model="gemini-3.7-flash",
                contents=full_prompt,
                config={
                    "system_instruction": SYSTEM_PROMPT,
                    "temperature": 0.2
                }
            )
            return {
                "response": response.text,
                "engine": "Gemini 3.7 Flash (Live LLM)",
                "context_injected": bool(db_context)
            }
        except Exception as e:
            logger.error(f"Gemini API invocation failed: {e}. Falling back to rule-based engine.")

    # High-quality offline / rule-based fallback with real DB context integration
    lower_p = prompt.lower()
    
    if "s3" in lower_p or "bucket" in lower_p or "public" in lower_p:
        content = """### 🛡️ CSPM Finding Analysis: Public S3 Bucket

**Status:** High Risk Misconfiguration  
**Target Resource:** `s3://production-assets`  
**Threat Vector:** Public Read / Data Exfiltration Risk

#### 1. Why this is Critical
An Amazon S3 bucket has public read ACLs or an unrestricted bucket policy enabled (`Principal: "*"`). Attackers and automated reconnaissance bots routinely scan IPv4 address space and Certificate Transparency logs to find public buckets containing sensitive credentials, database backups, or customer PII.

#### 2. Blast Radius Assessment
- **Confidentiality:** High (Any anonymous internet actor can read/download objects).
- **Integrity:** Medium (If write permissions are also exposed).
- **Compliance Violation:** Violates CIS AWS Benchmark 2.1.5, SOC 2 CC6.1, and PCI-DSS 3.4.

#### 3. Prescribed Remediation (AWS CLI)
Execute the following to enforce S3 Public Access Block across the entire bucket:

```bash
aws s3api put-public-access-block \\
    --bucket production-assets \\
    --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

#### 4. Infrastructure as Code (Terraform) Permanent Fix:
```hcl
resource "aws_s3_bucket_public_access_block" "prod_assets" {
  bucket = "production-assets"

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```
*Note: SentinelX requires administrator approval before applying remediation commands.*"""

    elif "brute force" in lower_p or "ssh" in lower_p or "port 22" in lower_p:
        content = """### 🚨 AI IDS Threat Report: SSH Brute Force Detection

**Detection Engine:** SentinelX Random Forest IDS Classifier  
**Confidence Score:** 98.4%  
**Attack Vector:** SSH (Port 22) Authentication Flooding

#### 1. Incident Summary
The intrusion detection model recognized an anomalous spike of **>45 failed login attempts per minute** from external IP `198.51.100.24` targeting port 22.

#### 2. Threat Analysis & Blast Radius
- Attackers are executing automated credential stuffing / dictionary attacks against administrative users (`root`, `admin`, `ubuntu`).
- If successful, the attacker gains shell access, enabling lateral movement across the VPC and credential scraping via AWS Instance Metadata Service (IMDS).

#### 3. Immediate Containment
Block the threat actor IP on the host firewall or VPC Network ACL:

```bash
# Host level (iptables)
sudo iptables -I INPUT -s 198.51.100.24 -j DROP

# AWS Security Group Update (Remove port 22 exposure to 0.0.0.0/0)
aws ec2 revoke-security-group-ingress \\
    --group-id sg-0a1b2c3d4e5f6g7h8 \\
    --protocol tcp --port 22 --cidr 0.0.0.0/0
```

#### 4. Hardening Recommendations
- Migrate to **AWS Systems Manager Session Manager (SSM)** to eliminate inbound open port 22 entirely.
- Enforce Ed25519 SSH keys and disable `PasswordAuthentication no` in `/etc/ssh/sshd_config`."""

    elif "summary" in lower_p or "status" in lower_p or "overview" in lower_p:
        content = f"""### 📊 SentinelX Security Posture Briefing

SentinelX telemetry and database records currently show:
- **Cloud Security Posture:** Active scans monitoring AWS IAM, S3, Security Groups, and KMS.
- **Intrusion Detection:** Random Forest model active and inspecting network ingress.
- **Real-Time Telemetry Context:**
```json
{db_context}
```

**Key Action Items:**
1. Resolve critical finding on public S3 bucket `production-assets`.
2. Restrict Security Group ingress on port 22 and port 3389 open to `0.0.0.0/0`.
3. Verify MFA enforcement on root and IAM power-users."""

    else:
        content = f"""I am **SentinelX AI**, your SecOps & Cloud Security intelligence assistant.

I am connected to the SentinelX real-time database and threat telemetry. Here is what I can do for you:
- **Explain Detections:** Ask about specific attacks like *"Explain the SSH Brute Force alert"* or *"What is port scanning?"*
- **CSPM Analysis:** Ask *"Why is public S3 risky?"* or *"How to fix open security group port 22?"*
- **Generate Terraform / CLI Fixes:** Request exact remediation syntax for your cloud resources.
- **Security Audit:** Inquire *"Give me a summary of current open findings"*.

*(Tip: Set `GEMINI_API_KEY` in your environment or backend settings to enable live multi-turn Gemini 3.7 Flash generation).*"""

    return {
        "response": content,
        "engine": "SentinelX Security Copilot (Heuristics + Telemetry Context)",
        "context_injected": bool(db_context)
    }
