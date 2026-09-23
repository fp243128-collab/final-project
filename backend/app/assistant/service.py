import time

def query_assistant(prompt: str) -> str:
    """
    Simulates an LLM assistant responding to user prompts about security events.
    In a production system, this would construct a prompt with context (e.g. recent findings)
    and call an LLM API like Anthropic Claude or OpenAI GPT-4.
    """
    prompt = prompt.lower()
    time.sleep(1.5) # Simulate network latency
    
    if "s3" in prompt or "bucket" in prompt or "public" in prompt:
        return """### CSPM Finding: Public S3 Bucket

The alert indicates that an S3 bucket (`production-assets`) has a bucket policy or ACL allowing **public read access**.

**Why this is risky:**
Public buckets can be crawled and scraped by automated tools. If this bucket contains sensitive customer data, PII, or internal credentials, it constitutes a critical data breach.

**Recommended Remediation:**
You should immediately block public access at the account or bucket level unless this bucket is explicitly hosting public web assets.

To fix this via AWS CLI:
```bash
aws s3api put-public-access-block \\
    --bucket production-assets \\
    --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```
"""
    elif "brute force" in prompt or "ssh" in prompt:
        return """### Threat Analysis: SSH Brute Force

The AI IDS detected a **brute force attack** on SSH (port 22).

**What happened:**
Multiple failed login attempts were detected from an unknown external IP address in a short time frame. This suggests an automated bot attempting to guess passwords or SSH keys.

**Impact:**
If an attacker guesses a weak credential, they gain shell access to the server, allowing them to pivot internally or install malware.

**Recommended Remediation:**
1. Block the offending IP address.
2. Ensure SSH is not exposed to the public internet (use a VPN or AWS Systems Manager Session Manager).
3. Disable password authentication entirely (use key-based auth only).

To block via iptables (Linux):
```bash
sudo iptables -A INPUT -s <OFFENDING_IP> -j DROP
```
"""
    else:
        return """I am **SentinelX AI**, your security operations assistant.

I can help you:
- **Explain alerts:** Ask me about specific threat detections or CSPM findings.
- **Provide remediations:** I can draft exact CLI commands or Terraform blocks to fix misconfigurations.
- **Analyze trends:** Ask me about security trends in your environment.

*(Note: This is a simulated response for the FYP demonstration. I have parsed your prompt and provided a generic response. Try asking about the "S3 bucket" or "Brute force" alerts to see targeted remediation!)*
"""
