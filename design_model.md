# AI-Powered Cloud Security & Threat Detection Platform
## Complete UI/UX + Functional Design Model

**Document purpose:** This document is the single product/design specification for building the FYP with Antigravity. It defines the system architecture, pages, UI/UX, navigation, components, user flows, backend behavior, AI threat detection, CSPM scanning, risk scoring, monitoring, DevSecOps, database concepts, security controls, and implementation phases.

---

## Table of Contents

1. Project Identity · 2. Core System Architecture · 3. High-Level Product Flow · 4. UI/UX Design System
5. Login · 6. Security Overview/Home · 7. Threat Detection · 8. Threat Details · 9. CSPM Cloud Security
10. CSPM Finding Details · 11. Cloud Resources · 12. Risk Center · 13. Alert Center · 14. Analytics
15. Monitoring · 16. DevSecOps Center · 17. CI/CD Run Details · 18. Reports · 19. Settings
20. Users & RBAC · 21. Audit Logs · 22. AI/ML Engine · **22A. AI Assistant (LLM Layer)** · 23. AI Model Page · 24. Feature Importance
25. CSPM Engine · 26. Cloud Account Connection (real IAM role flow) · **26A. Log Ingestion & Monitoring Pipeline**
27. Database Model · 28. API Architecture
29. Real-Time Data Flow · 30. Asynchronous Processing · 31. Security Architecture · 32. DevSecOps Pipeline (real tools)
33. Infrastructure as Code · 34. Docker Architecture · 35. Observability · 36. Notification Engine
37. User Journeys · 38–40. Demonstration Scenarios · 41. Dashboard KPI Definitions · 42–44. Empty/Loading/Error States
45. Responsive Design · 46. Navigation Structure · 47. Component Library · 48–50. Folder Structures (Next.js/FastAPI/ML)
51. Development Phases · 52. MVP vs Advanced Features · 53. Recommended Technology Stack
54. FYP Research Questions · 55. FYP Objectives · 56. Final Product Graph · 57. Antigravity Build Instruction
58. Antigravity UI/UX Rules · 59. Final FYP Story · 60. Definition of Done
61. Non-Functional Requirements · 62. Testing Strategy · 63. Demo Data Seeding

---

# 1. Project Identity

## Proposed Product Name
**SentinelX — AI-Powered Cloud Security & Threat Detection Platform**

Alternative names:
- CloudSentinel AI
- SecureOps AI
- ThreatGuard
- SentinelCloud
- CyberShield AI

Use **SentinelX** throughout the UI unless a different name is selected later.

## One-Line Description

> A cloud-native security platform that combines AI-powered intrusion detection, Cloud Security Posture Management (CSPM), centralized risk scoring, security monitoring, and DevSecOps automation in one dashboard.

## Main FYP Areas

1. Artificial Intelligence / Machine Learning
2. Cybersecurity
3. Cloud Security
4. DevSecOps
5. Cloud Monitoring
6. Infrastructure as Code
7. Web Application Development

---

# 2. Core System Architecture

This is a real AWS integration, not a simulated one. That has one big consequence for the
architecture: SentinelX does not poll the customer's AWS account on a timer as its primary
detection path — polling alone is too slow and too easy to miss short-lived events. Instead
it is **event-driven first, polling second**: AWS pushes security-relevant events to
SentinelX in near real time via EventBridge, and a scheduled CSPM scan (polling via boto3)
runs on top of that to catch configuration drift that doesn't generate an event.

```text
┌──────────────────────────┐
│      USER / ANALYST      │
└─────────────┬─────────────┘
              │ HTTPS
              ▼
┌───────────────────────────────────┐
│         NEXT.JS FRONTEND           │
│  App Router, Server Components,    │
│  Server Actions for mutations,     │
│  WebSocket/SSE client for live UI  │
└─────────────┬───────────────────────┘
              │ REST + WebSocket (auth via httpOnly cookie / short-lived JWT)
              ▼
┌───────────────────────────────────┐
│          FASTAPI GATEWAY           │
│  Auth (OAuth2/JWT) · RBAC          │
│  Rate limiting · Request routing   │
└─────────────┬───────────────────────┘
              │
   ┌──────────┼───────────────────────────────────┐
   ▼          ▼                                    ▼
┌────────┐ ┌────────────────┐              ┌──────────────────┐
│ Threat │ │  CSPM Service   │              │  AI Assistant API │
│  API   │ │ (boto3 scans)   │              │ (LLM: findings Q&A,│
└───┬────┘ └────────┬────────┘              │ remediation text) │
    │               │                        └────────┬──────────┘
    │               │                                 │
    ▼               ▼                                 │
┌─────────────────────────────────────────┐           │
│         AWS CUSTOMER ACCOUNT              │           │
│  (connected via cross-account IAM role)   │           │
│                                            │           │
│  CloudTrail ── GuardDuty ── AWS Config     │           │
│  VPC Flow Logs ── Security Hub ── IAM      │           │
└──────────────┬─────────────────────────────┘           │
               │ EventBridge rule (near real-time push)   │
               ▼                                          │
┌───────────────────────────────────┐                     │
│         AMAZON SQS QUEUE            │                     │
│   (buffers bursts, guarantees       │                     │
│    at-least-once delivery)          │                     │
└─────────────┬───────────────────────┘                     │
              ▼                                             │
┌───────────────────────────────────┐                       │
│      CELERY WORKERS (Python)        │                       │
│  Normalize event → feature vector   │                       │
└──────┬─────────────────┬────────────┘                       │
       ▼                 ▼                                    │
┌─────────────┐   ┌──────────────────┐                        │
│  ML ENGINE   │   │   CSPM RULES     │                        │
│ RandomForest │   │ IAM / S3 / SG    │                        │
│ / IsolationF │   │ Encryption / MFA │                        │
└──────┬───────┘   └────────┬─────────┘                        │
       └─────────┬──────────┘                                  │
                  ▼                                             │
        ┌──────────────────┐          ┌──────────────────┐     │
        │   RISK ENGINE     │──────────▶ ALERT ENGINE     │◀────┘
        │ Severity Scoring  │          │ Email / In-App   │
        └────────┬─────────┘          │ Webhook / Slack   │
                  │                    └────────┬─────────┘
                  ▼                             │
        ┌─────────────────────────────────────────┐
        │                DATA LAYER                 │
        │   PostgreSQL (system of record)            │
        │   Redis (cache, Celery broker, pub/sub)    │
        └─────────────────────┬───────────────────────┘
                              │ pub/sub → WebSocket
                              ▼
        ┌───────────────────────────────────────────┐
        │             SECURITY DASHBOARD              │
        │ Threats • CSPM • Risk • Cloud • Alerts      │
        │ Analytics • Reports • DevSecOps • AI Chat   │
        └───────────────────────────────────────────┘


                  DEVSECOPS / DELIVERY PIPELINE
                  ─────────────────────────────

 GitHub → GitHub Actions → Lint → Bandit (SAST) → pip-audit (deps) → Gitleaks (secrets)
                      ↓
                 Docker Build
                      ↓
                Trivy (image scan)
                      ↓
             Checkov (Terraform scan)
                      ↓
             Terraform Apply → AWS
                      ↓
      GitHub Actions webhook → SentinelX /api/devsecops/pipeline-runs
                      ↓
            Prometheus / Grafana (infra metrics)
                      ↓
              SentinelX Monitoring page
```

**Why event-driven, concretely:** a scheduled scan that runs every 15 minutes can miss a
public S3 bucket that was flipped public and back within that window, and it can't tell you
*when* GuardDuty actually raised a finding versus when SentinelX happened to notice it. EventBridge
solves this: CloudTrail, GuardDuty, Config, and Security Hub can all emit directly to an
EventBridge bus, and an EventBridge rule forwards matching events to an SQS queue that Celery
workers consume. Polling (a scheduled `boto3` CSPM scan) still exists, but as a baseline
sweep and drift-catcher, not the primary detection path.

---

# 3. High-Level Product Flow

```text
LOGIN
  ↓
OVERVIEW DASHBOARD
  ↓
┌─────────────────────────────────────────────────────────────┐
│                                                             │
├── Security Overview                                         │
├── Threat Detection                                          │
├── Threat Details                                            │
├── CSPM Cloud Security                                       │
├── Cloud Resources                                           │
├── Risk Center                                               │
├── Alerts                                                    │
├── Analytics                                                 │
├── Monitoring                                                │
├── DevSecOps                                                 │
├── Reports                                                   │
└── Settings                                                  │
```

---

# 4. UI/UX Design System

## Visual Direction

The application should look like a premium **light** enterprise SaaS security platform —
Cloudflare Dashboard, AWS Security Hub, Microsoft Defender, Datadog. Not a hacker terminal,
not a sci-fi HUD.

**Theme policy — the default and ONLY theme is Light Enterprise SaaS. There is no dark mode
in v1.** Any component generated with a dark/black background is a defect, not a stylistic
variant.

Design characteristics:

- Light-first interface (see color table below)
- High information density without feeling cluttered
- Flat surfaces, no glass/blur effects, no gradients on backgrounds or cards
- Strong hierarchy
- Security-focused visual language expressed through color-coded severity, not darkness
- Thin (1px) solid borders
- Compact tables
- Interactive charts
- Minimal, purposeful transitions — no decorative micro-animations
- Responsive desktop layout
- Tablet support
- Mobile can provide monitoring and alert views

## Required Color System (exact hex — do not substitute)

```text
Page background:        #FFFFFF   (pure white)
Card/container surface: #FFFFFF   (pure white — separated from page by the 1px border below, not by a shade difference)
Borders/dividers:       #E2E8F0   (Slate 200, 1px solid only)

Primary/accent:         #2563EB   (royal blue)

Success:                #16A34A
Warning:                #D97706
Critical:                #DC2626
Info:                    #0284C7

Text primary:            #0F172A   (Slate 900)
Text secondary:          #64748B   (Slate 500)

Sidebar:                 #0F172A background with white text,
                          OR #FFFFFF background with slate borders
                          (navy background anywhere ELSE is not allowed)
```

Forbidden: any background darker than `#1E293B` outside the sidebar/topbar, dark-mode media
queries or toggles, neon/glowing shadows, gradients, glassmorphism/backdrop-blur. The only
allowed shadow is `0 1px 3px 0 rgba(0, 0, 0, 0.05)`.

Use red only for genuine CRITICAL severity. Do not make the entire application red.

## Typography

Use a professional modern font such as:

- Inter
- Manrope
- IBM Plex Sans

For technical/log data:

- JetBrains Mono

## Layout

Desktop:

```text
┌────────────────────────────────────────────────────────────────────────┐
│ LOGO     Search                     Notifications    User Profile      │
├──────────────┬─────────────────────────────────────────────────────────┤
│              │                                                         │
│ Sidebar      │                    MAIN CONTENT                         │
│              │                                                         │
│ Overview     │                                                         │
│ Threats      │                                                         │
│ CSPM         │                                                         │
│ Resources    │                                                         │
│ Risk         │                                                         │
│ Alerts       │                                                         │
│ Analytics    │                                                         │
│ Monitoring   │                                                         │
│ DevSecOps    │                                                         │
│ Reports      │                                                         │
│ Settings     │                                                         │
│              │                                                         │
└──────────────┴─────────────────────────────────────────────────────────┘
```

---

# 5. PAGE 01 — LOGIN

## Purpose

Authenticate administrators/security analysts.

## UI

```text
┌────────────────────────────────────────────────────────────┐
│                         SENTINELX                           │
│                                                            │
│                AI CLOUD SECURITY PLATFORM                  │
│                                                            │
│             ┌──────────────────────────────┐               │
│             │ Email                        │               │
│             └──────────────────────────────┘               │
│             ┌──────────────────────────────┐               │
│             │ Password                  ◉   │               │
│             └──────────────────────────────┘               │
│                                                            │
│             [ Sign In ]                                    │
│                                                            │
│             Forgot password?                               │
│                                                            │
│             Secure authentication • RBAC                   │
└────────────────────────────────────────────────────────────┘
```

## Features

- Email/password authentication
- Optional MFA
- Session management
- Password reset
- Login audit logging
- Account lockout/rate limiting

## Function

Successful login creates a secure session/token and redirects to the Overview page.

---

# 6. PAGE 02 — SECURITY OVERVIEW / HOME

## Purpose

The main command center.

This is the page that should immediately communicate the security state of the entire environment.

## UI

```text
┌────────────────────────────────────────────────────────────────────────┐
│ Security Overview                              Last updated: 10:42 PM │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│ ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌─────────────────────┐ │
│ │ Threats    │ │ Critical   │ │ Risk Score │ │ Cloud Security     │ │
│ │    127     │ │     8      │ │   74/100   │ │      82%            │ │
│ └────────────┘ └────────────┘ └────────────┘ └─────────────────────┘ │
│                                                                        │
│ ┌──────────────────────────────┐ ┌───────────────────────────────────┐ │
│ │ Threat Distribution          │ │ Security Risk Trend               │ │
│ │                              │ │                                   │ │
│ │ Brute Force     42           │ │          ╭───╮                    │ │
│ │ Port Scan       29           │ │      ╭───╯   ╰──╮                 │ │
│ │ DoS              21          │ │  ╭───╯           ╰──             │ │
│ │ Anomaly          17          │ │                                   │ │
│ └──────────────────────────────┘ └───────────────────────────────────┘ │
│                                                                        │
│ ┌────────────────────────────────────────────────────────────────────┐ │
│ │ Recent Critical Events                                             │ │
│ │ Time       Type          Source         Severity       Status       │ │
│ │ 22:41      Port Scan     10.0.0.23      Critical       Open         │ │
│ │ 22:38      Brute Force   10.0.0.19      High           Investigate   │ │
│ └────────────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────────┘
```

## Features

- Total threats
- Critical threats
- Overall risk score
- Cloud security posture score
- Threat distribution
- Risk trend
- Recent events
- Open alerts
- Resource health
- Security recommendations

## Interactions

Clicking:

- Threats → Threat Detection
- Critical → filtered critical threats
- Risk Score → Risk Center
- Cloud Security → CSPM
- Event → Threat Details

---

# 7. PAGE 03 — THREAT DETECTION

## Purpose

Display AI-detected network/security events.

## UI

```text
┌─────────────────────────────────────────────────────────────────────┐
│ Threat Detection                                                    │
├─────────────────────────────────────────────────────────────────────┤
│ [Search] [Severity ▼] [Attack Type ▼] [Time ▼] [Export]           │
│                                                                     │
│ AI Detection Status: ● ACTIVE                                      │
│ Model: Random Forest v1.0       Accuracy: 94.2%                    │
│                                                                     │
│ ┌─────────────────────────────────────────────────────────────────┐ │
│ │ ID │ Attack │ Source │ Destination │ Confidence │ Severity     │ │
│ ├─────────────────────────────────────────────────────────────────┤ │
│ │ #1 │ Port    │ 10... │ Server-01   │ 97%        │ CRITICAL     │ │
│ │ #2 │ Brute   │ 10... │ SSH         │ 91%        │ HIGH         │ │
│ │ #3 │ DoS     │ 10... │ API         │ 89%        │ HIGH         │ │
│ └─────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

## Features

- Real-time event feed
- ML classification
- Confidence score
- Severity
- Attack category
- Source IP
- Destination
- Timestamp
- Filtering
- Search
- Export

## ML Flow

```text
Raw Network Event
       ↓
Feature Extraction
       ↓
Data Normalization
       ↓
Random Forest
       ↓
Prediction
       ↓
Confidence
       ↓
Severity Mapping
       ↓
Risk Engine
       ↓
Alert
```

---

# 8. PAGE 04 — THREAT DETAILS

## Purpose

Provide complete forensic information for one threat.

## UI

```text
┌──────────────────────────────────────────────────────────────┐
│ ← Back to Threats                                            │
│                                                              │
│ PORT SCANNING DETECTED                      CRITICAL         │
│ Threat ID: THR-000127                                       │
│                                                              │
│ ┌────────────────┐ ┌────────────────┐ ┌────────────────────┐ │
│ │ Confidence     │ │ Risk           │ │ Status             │ │
│ │ 97.4%          │ │ 91/100         │ │ Investigating      │ │
│ └────────────────┘ └────────────────┘ └────────────────────┘ │
│                                                              │
│ SOURCE                                                       │
│ IP: 10.0.0.23                                               │
│ Country: Unknown                                            │
│                                                              │
│ DESTINATION                                                  │
│ Server: production-api                                      │
│ Port: 22, 80, 443, 8080                                    │
│                                                              │
│ AI ANALYSIS                                                  │
│ Model: Random Forest                                        │
│ Prediction: Port Scan                                      │
│ Confidence: 97.4%                                          │
│                                                              │
│ [Investigate] [Mark Resolved] [Block Source]                │
└──────────────────────────────────────────────────────────────┘
```

## Functions

- Investigate
- Assign analyst
- Add notes
- Change status
- Mark resolved
- Create alert
- Export evidence

---

# 9. PAGE 05 — CSPM CLOUD SECURITY

## Purpose

Audit cloud infrastructure for security misconfigurations.

## UI

```text
┌────────────────────────────────────────────────────────────────────┐
│ Cloud Security Posture                                             │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│ Overall Security Score: 82/100                                    │
│                                                                    │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐              │
│ │ Critical │ │ High     │ │ Medium   │ │ Low      │              │
│ │    3     │ │    7     │ │   12     │ │    5     │              │
│ └──────────┘ └──────────┘ └──────────┘ └──────────┘              │
│                                                                    │
│ [Run Full Scan] [AWS ▼] [Export Report]                           │
│                                                                    │
│ ┌────────────────────────────────────────────────────────────────┐ │
│ │ Finding                         Severity      Resource           │ │
│ │ S3 bucket publicly accessible   CRITICAL      bucket-prod       │ │
│ │ SSH open to 0.0.0.0/0          HIGH          sg-prod           │ │
│ │ IAM user lacks MFA              HIGH          user-admin        │ │
│ │ EBS encryption disabled         MEDIUM        volume-22         │ │
│ └────────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────┘
```

## CSPM Checks

### IAM

- MFA enabled
- Root account security
- Excessive permissions
- Wildcard permissions
- Inactive credentials
- Password policy

### S3

- Public access
- Encryption
- Versioning
- Logging
- Bucket policy
- Access control

### Security Groups

- SSH exposure
- RDP exposure
- Wide-open ports
- 0.0.0.0/0 rules

### EC2

- Public IP
- Security group exposure
- Encryption
- Unused resources
- Metadata configuration

### Cloud Logging

- CloudTrail
- Monitoring
- Audit logging

---

# 10. PAGE 06 — CSPM FINDING DETAILS

## Purpose

Explain exactly why a cloud configuration is insecure and how to remediate it.

## UI

```text
┌──────────────────────────────────────────────────────────────┐
│ Finding: Public S3 Bucket                                    │
│                                                              │
│ Severity: CRITICAL                                          │
│ Resource: production-assets                                  │
│ Rule: S3_PUBLIC_ACCESS_001                                  │
│                                                              │
│ WHY THIS IS A PROBLEM                                       │
│ The bucket allows public access.                             │
│                                                              │
│ CURRENT CONFIGURATION                                        │
│ Public Access: ENABLED                                      │
│ Encryption: ENABLED                                         │
│ Versioning: ENABLED                                         │
│                                                              │
│ RECOMMENDATION                                               │
│ Disable public access unless explicitly required.             │
│                                                              │
│ [Mark Remediated] [Create Ticket]                            │
└──────────────────────────────────────────────────────────────┘
```

## Function

Each finding should have:

- Rule ID
- Description
- Evidence
- Severity
- Resource
- Compliance category
- Remediation
- Status

---

# 11. PAGE 07 — CLOUD RESOURCES

## Purpose

Show discovered cloud infrastructure.

## UI

```text
┌──────────────────────────────────────────────────────────────┐
│ Cloud Resources                                               │
├──────────────────────────────────────────────────────────────┤
│ [AWS ▼] [Region ▼] [Type ▼] [Status ▼]                      │
│                                                              │
│ EC2 INSTANCES                                                 │
│                                                              │
│ Name           Status      CPU       Security      Risk       │
│ API-Server     Running     42%       Healthy       31         │
│ DB-Server      Running     68%       Warning       54         │
│ Test-Server   Stopped      0%        Healthy       12         │
│                                                              │
│ S3 BUCKETS                                                    │
│ production-assets      Private       Encrypted                │
│ logs-bucket             Private       Encrypted                │
└──────────────────────────────────────────────────────────────┘
```

## Features

- Resource inventory
- Resource status
- CPU
- Memory where available
- Network
- Security posture
- Risk score
- Region
- Tags
- Resource details

---

# 12. PAGE 08 — RISK CENTER

## Purpose

Centralize all security risk into one scoring system.

## UI

```text
┌──────────────────────────────────────────────────────────────┐
│ Risk Center                                                  │
│                                                              │
│                    ┌──────────────┐                          │
│                    │   74 / 100   │                          │
│                    │ Overall Risk │                          │
│                    └──────────────┘                          │
│                                                              │
│ Threat Risk             32                                     │
│ Cloud Risk              24                                     │
│ IAM Risk                 9                                     │
│ Infrastructure Risk     14                                     │
│                                                              │
│ TOP RISK ASSETS                                             │
│ 1. production-api       91                                   │
│ 2. production-db        76                                   │
│ 3. public-assets        73                                   │
└──────────────────────────────────────────────────────────────┘
```

## Risk Formula

Use a transparent formula rather than an unexplained AI score.

Example:

```text
Risk Score =
Threat Severity × Threat Confidence
+ Asset Criticality
+ Exposure
+ Vulnerability Weight
+ Cloud Misconfiguration Weight
```

Normalize to:

```text
0–29     LOW
30–59    MEDIUM
60–79    HIGH
80–100   CRITICAL
```

The exact weights should be configurable in Settings → Risk Configuration, but ship with these
defaults so the formula is computable from day one instead of blocking on a design decision:

```text
Threat Severity weight        : 0.35
Threat Confidence multiplier  : 0.0–1.0 (raw ML confidence, not separately weighted)
Asset Criticality weight      : 0.20   (Critical=100, High=70, Medium=40, Low=15)
Exposure weight               : 0.20   (public-facing=100, internal=40, isolated=10)
Vulnerability weight          : 0.15   (from matched CVE CVSS score, scaled 0–100)
Cloud Misconfiguration weight : 0.10   (CSPM rule severity, scaled 0–100)

Risk Score = (Threat Severity × Threat Confidence × 0.35)
           + (Asset Criticality × 0.20)
           + (Exposure × 0.20)
           + (Vulnerability × 0.15)
           + (Cloud Misconfiguration × 0.10)
```

A finding with no threat/CVE component (pure CSPM misconfiguration) simply zeroes the Threat and
Vulnerability terms and re-normalizes the remaining weights so the score still lands on 0–100.

---

# 13. PAGE 09 — ALERT CENTER

## Purpose

Central place for active security alerts.

## UI

```text
┌──────────────────────────────────────────────────────────────┐
│ Alert Center                                                  │
├──────────────────────────────────────────────────────────────┤
│ [All] [Critical] [High] [Medium] [Resolved]                 │
│                                                              │
│ 🔴 Critical  Port scan detected      2 min ago              │
│ 🟠 High      Brute force detected    5 min ago              │
│ 🟡 Medium    Public resource         18 min ago             │
│                                                              │
│ [Acknowledge] [Investigate] [Resolve]                        │
└──────────────────────────────────────────────────────────────┘
```

## Alert Sources

- AI IDS
- CSPM
- Resource health
- Budget anomaly
- CI/CD security scan
- Container vulnerability scan

---

# 14. PAGE 10 — ANALYTICS

## Purpose

Provide historical security analysis.

## UI

Charts:

1. Threats over time
2. Threat types
3. Severity distribution
4. Risk trend
5. Cloud security score
6. Top attacking IPs
7. Most affected assets
8. CSPM findings over time

Filters:

- Last 24 hours
- 7 days
- 30 days
- Custom date

## Research Value

Analytics allows the FYP to demonstrate measurable changes rather than only showing a static dashboard.

---

# 15. PAGE 11 — MONITORING

## Purpose

Infrastructure and application health monitoring.

## Architecture

```text
AWS / EC2 / Docker / Application
             ↓
       Exporters/Agents
             ↓
        Prometheus
             ↓
          Grafana
             ↓
       SentinelX API
             ↓
        Dashboard
```

## Metrics

- CPU
- Memory
- Disk
- Network
- API latency
- Request rate
- Error rate
- Container health
- Server uptime

---

# 16. PAGE 12 — DEVSECOPS CENTER

## Purpose

Show the security status of the software delivery pipeline.

## UI

```text
┌──────────────────────────────────────────────────────────────┐
│ DevSecOps Pipeline                                           │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│ GitHub                                                       │
│   ↓                                                          │
│ Build ✓                                                      │
│   ↓                                                          │
│ Unit Tests ✓                                                 │
│   ↓                                                          │
│ SAST ✓                                                       │
│   ↓                                                          │
│ Dependency Scan ✓                                            │
│   ↓                                                          │
│ Secret Scan ✓                                                │
│   ↓                                                          │
│ Docker Build ✓                                               │
│   ↓                                                          │
│ Container Scan ⚠                                             │
│   ↓                                                          │
│ Deploy ✓                                                      │
│                                                              │
│ Pipeline Status: PASSED WITH WARNINGS                        │
└──────────────────────────────────────────────────────────────┘
```

## Security Tools

Possible implementation:

- GitHub Actions
- Semgrep
- Trivy
- Gitleaks
- OWASP dependency scanning
- Docker
- Terraform
- Checkov
- Prometheus
- Grafana

---

# 17. PAGE 13 — CI/CD RUN DETAILS

## Purpose

Show individual pipeline execution.

## Information

- Commit SHA
- Branch
- Developer
- Start time
- Duration
- Build result
- Test result
- Security findings
- Docker image
- Deployment environment

## Example

```text
Pipeline #142

Commit:
a83f1d9

Branch:
main

Security:
SAST          ✓
Secrets       ✓
Dependencies  ✓
Container     ⚠ 2 HIGH

Deployment:
AWS Production ✓
```

---

# 18. PAGE 14 — REPORTS

## Purpose

Generate professional security reports for the FYP demonstration.

## Report Types

- Security overview
- Threat report
- CSPM report
- Risk report
- Compliance report
- DevSecOps report

## Export

- PDF
- CSV
- JSON

## Report Structure

```text
Executive Summary
↓
Security Score
↓
Threat Summary
↓
Cloud Findings
↓
Risk Analysis
↓
Recommendations
↓
Technical Evidence
```

---

# 19. PAGE 15 — SETTINGS

Sections:

```text
Profile
Authentication
Users & Roles
Cloud Accounts
Detection Model
Risk Configuration
Alert Settings
Integrations
API Keys
System Preferences
Audit Logs
```

---

# 20. PAGE 16 — USERS & RBAC

## Roles

### Administrator

Full access.

### Security Analyst

- Threats
- CSPM
- Alerts
- Analytics
- Reports

### DevOps Engineer

- Resources
- Monitoring
- DevSecOps
- Deployment status

### Viewer

Read-only dashboards.

## RBAC Flow

```text
Login
 ↓
Identity
 ↓
Role
 ↓
Permission
 ↓
Resource
 ↓
Allow / Deny
```

---

# 21. PAGE 17 — AUDIT LOGS

Every sensitive operation should be logged.

Example:

```text
Timestamp     User        Action                  Result
22:41         admin       Started CSPM scan       SUCCESS
22:38         analyst     Resolved threat         SUCCESS
22:20         admin       Changed IAM policy      SUCCESS
21:59         viewer      Exported report         SUCCESS
```

Log:

- Login
- Logout
- Scan
- Configuration changes
- Threat updates
- User changes
- Report exports
- API actions

---

# 22. AI / ML ENGINE

There are two genuinely different AI components in SentinelX, and conflating them is a common
mistake: a **classifier/anomaly detector** (traditional ML, trained offline, runs inference on
every event) and an **AI assistant** (an LLM, called on-demand, explains things in language and
suggests fixes). Section 22 covers the first; §22A covers the second.

## Primary Objective

Classify network/security events sourced from VPC Flow Log features, and flag statistical
anomalies in CloudTrail event volume/pattern per account (e.g. a sudden burst of
`ListBuckets`/`GetObject` calls from an unfamiliar IP — classic recon behavior).

## Model choice, and why two models

- **Random Forest (supervised)** — trained on a labeled public dataset, classifies known
  attack *types* (port scan, DDoS, brute force) from flow-level features. Good precision on
  patterns the training data actually contains.
- **Isolation Forest (unsupervised)** — trained on the *customer's own* historical CloudTrail
  volume, catches "this doesn't look like this account's normal behavior" even for attack
  patterns not in any public dataset. This is what makes the detection feel account-specific
  rather than generic.

Running both and letting the Risk Engine combine their outputs is more honest than claiming
one model handles everything a real SOC needs.

## Dataset

For the supervised model, use one public cybersecurity dataset and document its limitations
in the FYP report:

- CIC-IDS2017
- UNSW-NB15
- CIC-DDoS2019

For the unsupervised model, there is no public dataset — it trains on each connected
account's own ingested CloudTrail/flow-log history (minimum ~7 days of baseline before it
starts flagging anomalies; state this cold-start limitation explicitly).

## Pipeline

```text
Supervised (Random Forest):
Dataset → Cleaning → Feature Selection → Train/Test Split → Normalization
  → Training → Validation → Evaluation → Model Export (joblib/ONNX)
  → FastAPI Inference Service → Threat API

Unsupervised (Isolation Forest), per connected account:
Ingested CloudTrail events (§26A) → rolling feature window
  (event count, distinct IPs, distinct API calls, off-hours ratio)
  → Isolation Forest re-fit on a schedule (e.g. nightly)
  → real-time scoring of each new event against the current model
  → anomaly score → Risk Engine
```

## Evaluation Metrics

Do not report accuracy alone. Use:

- Accuracy, Precision, Recall, F1-score
- Confusion matrix
- ROC-AUC where appropriate
- Inference latency
- For the unsupervised model: false-positive rate against a manually reviewed sample, since
  there's no ground-truth label — this is the honest metric to report in the FYP.

---

# 22A. AI ASSISTANT (LLM LAYER)

This is the actual "how does AI assistance help" answer, separate from the ML classifiers
above. The assistant is an LLM (e.g. Claude, via the Messages API) called with structured
context assembled by the backend — it never sees the customer's raw AWS credentials, and it
never makes AWS API calls itself.

## What it actually does

1. **Finding explanation** — given a CSPM finding or threat event as structured JSON, generate
   a plain-language explanation: what happened, why it's risky, what the likely blast radius
   is. This replaces a wall of raw JSON with something an analyst can read in five seconds.
2. **Remediation drafting** — generate the specific fix: a corrected IAM policy JSON, the
   exact `aws s3api put-bucket-policy` command, or a Terraform diff — scoped to the one
   resource in question, not generic advice.
3. **Natural-language querying** — "show me all critical findings from the last 7 days on
   production" gets translated into a structured filter against `/api/findings`, not into a
   raw SQL query the LLM writes itself (never let the LLM generate or run SQL directly against
   production — that's a prompt-injection/SQLi risk surface with no upside).
4. **Alert triage summary** — daily/weekly digest that groups related alerts into a narrative
   ("these 6 alerts are all the same misconfigured security group being hit repeatedly").

## Architecture

```text
Frontend (AI Assistant panel / chat)
     │
     ▼
POST /api/assistant/query
     │
     ▼
Backend assembles context:
  - the specific finding(s)/event(s) in scope (fetched from Postgres,
    NOT sent as "all data")
  - a fixed system prompt describing SentinelX's data model
     │
     ▼
Anthropic Messages API call (server-side only, API key never reaches the client)
     │
     ▼
Response parsed, (optionally) rendered as structured cards, stored in
`ai_assistant_messages` for audit/history
```

## Guardrails (state these explicitly — they're gradeable FYP design decisions)

- The assistant is read/advise-only in v1: it can draft a remediation, it cannot execute one.
  A human clicks "Apply" before any AWS write call happens.
- Every prompt sent to the LLM is logged (prompt + response) for audit, same as any other
  privileged action in the system.
- Context sent to the LLM is scoped to the specific findings/events the user is looking at —
  never a full database dump — both for cost and for not leaking unrelated customer data into
  a single prompt.

---

# 23. AI MODEL PAGE

Add a dedicated page so the FYP demonstrates the research component.

## UI

```text
┌──────────────────────────────────────────────────────────────┐
│ AI Detection Model                                           │
├──────────────────────────────────────────────────────────────┤
│ Model: Random Forest                                         │
│ Version: 1.0                                                 │
│ Status: ● Active                                             │
│                                                              │
│ Accuracy       94.2%                                         │
│ Precision      93.8%                                         │
│ Recall         92.9%                                         │
│ F1 Score       93.3%                                         │
│                                                              │
│ [Confusion Matrix]                                           │
│ [Feature Importance]                                         │
│ [Model Information]                                          │
└──────────────────────────────────────────────────────────────┘
```

---

# 24. FEATURE IMPORTANCE

For Random Forest, display important features.

Example:

```text
Feature Importance

Destination Port      ████████████████
Flow Duration         ████████████
Packet Length         ██████████
Flow Bytes/s          ████████
Packet Rate           ███████
Source Bytes          █████
```

This improves explainability.

---

# 25. CSPM ENGINE

## Rule-Based Architecture

```text
Cloud Account
     ↓
Resource Discovery
     ↓
Configuration Extraction
     ↓
Security Rules
     ↓
Finding
     ↓
Severity
     ↓
Risk Engine
     ↓
Dashboard
```

## Example Rule

```text
RULE: S3_PUBLIC_ACCESS

IF bucket.public_access == true
THEN
    severity = CRITICAL
    risk = 90
    recommendation = "Disable public access"
```

Rules should be stored separately from scanner code.

---

# 26. CLOUD ACCOUNT CONNECTION (REAL IMPLEMENTATION)

> **Practical note for building this as a real project:** use a dedicated AWS account (AWS
> Organizations lets you create one free) for both "SentinelX's own account" and a separate
> "test customer account" — never your only/personal AWS account. You'll be building against
> the AWS Free Tier / your $200 promotional credit; the services used here (CloudTrail,
> GuardDuty, Config, EventBridge, SQS) all have free-tier allowances that comfortably cover
> development and a demo. Keep GuardDuty and Config enabled only in the test account you're
> actively working in, mainly so findings don't pile up somewhere you forgot about.

## First Version

Support AWS first. Avoid attempting AWS + Azure + GCP simultaneously.

## How a real customer actually connects their AWS account

Long-lived AWS access keys are never used — not stored, not requested, not accepted from the
user. This is the same cross-account role pattern every real security vendor (Wiz, Orca,
Datadog Cloud Security) uses:

```text
1. User clicks "Connect AWS Account" in SentinelX
2. SentinelX generates a unique ExternalId (random UUID) for this connection
   and a one-click "Launch CloudFormation Stack" link, pre-filled with:
     - SentinelXAccountId  (SentinelX's own AWS account ID)
     - ExternalId          (prevents the "confused deputy" problem)
     - a least-privilege IAM policy (read-only + the specific write actions
       SentinelX needs, e.g. tagging a resource as "remediated")
3. User runs the CloudFormation stack in THEIR AWS account (Console or CLI).
   This creates an IAM Role with a trust policy that only allows
   SentinelX's account, with that exact ExternalId, to assume it.
4. User pastes the resulting Role ARN back into SentinelX.
5. SentinelX backend calls sts:AssumeRole with the ExternalId to get
   short-lived credentials (default 1 hour), never stores them, and
   re-assumes the role every time it needs to call AWS.
6. SentinelX immediately does a "connection test": sts:GetCallerIdentity +
   one cheap read call (e.g. iam:ListAccountAliases) to confirm the role
   works before marking the account as Connected.
```

Trust policy created by the CloudFormation stack (illustrative):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::<SENTINELX_ACCOUNT_ID>:root" },
    "Action": "sts:AssumeRole",
    "Condition": { "StringEquals": { "sts:ExternalId": "<PER_CONNECTION_UUID>" } }
  }]
}
```

## AWS services actually used, and what each is for

| Service | Purpose | Access pattern |
|---|---|---|
| STS | Assume the customer's cross-account role | Called per-job, short-lived creds |
| IAM | Read policies/users/roles for CSPM rules (MFA, unused keys, wildcard policies) | Scheduled scan (boto3) |
| S3 | Bucket ACL/policy/encryption checks | Scheduled scan (boto3) |
| EC2 / Security Groups | Open ports, unrestricted ingress checks | Scheduled scan (boto3) |
| CloudTrail | Source of "who did what" management-plane events | Event-driven (EventBridge → SQS) |
| GuardDuty | Managed threat-detection findings (recon, credential compromise, crypto-mining) | Event-driven (EventBridge → SQS) |
| AWS Config | Configuration-change history + compliance rules | Event-driven (EventBridge) + scheduled baseline pull |
| VPC Flow Logs | Network-level traffic features for the ML engine | CloudWatch Logs → Kinesis Firehose → S3 → batch ingest |
| Security Hub | Aggregated findings from GuardDuty/Inspector/Config in one place | Read via boto3, optional if GuardDuty+Config are wired directly |

## Security principle

Least privilege — the IAM policy attached to the role is scoped to exactly the API calls
listed above (mostly `Describe*`/`List*`/`Get*`, plus narrow, explicit write actions such as
tagging). Nothing broader is granted "just in case." Every `AssumeRole` call, and every API
call made with the resulting credentials, is written to `audit_logs` with the target account
ID, so a customer can see exactly what SentinelX did in their account and when.

---

# 26A. LOG INGESTION & MONITORING PIPELINE (REAL IMPLEMENTATION)

This is the section that answers "how does it actually monitor the cloud and read logs."

## Event-driven path (the primary one)

```text
AWS account (customer's)
  │
  ├── CloudTrail  ──┐
  ├── GuardDuty    ──┼──▶ EventBridge Rule (per connected account)
  ├── AWS Config   ──┘         │
  │                            ▼
  │                    Amazon SQS Queue (one per account or shared, partitioned by account_id)
  │                            │
  │                            ▼
  │                    Celery worker pool (Python, boto3 + pydantic)
  │                       1. Verify event authenticity / dedupe by event ID
  │                       2. Normalize into SentinelX's internal event schema
  │                       3. Write to `threat_events` / `security_findings`
  │                       4. Publish to Redis pub/sub → WebSocket → dashboard
  │                       5. If it matches an ML feature shape, enqueue for
  │                          inference (see §22)
```

## High-volume path (VPC Flow Logs)

Flow logs are far higher volume than CloudTrail/GuardDuty, so they are **not** pushed through
EventBridge directly. Instead:

```text
VPC Flow Logs → CloudWatch Logs → Kinesis Data Firehose
                                        │
                                        ▼
                              S3 (partitioned by date/hour)
                                        │
                                        ▼
                        Scheduled batch job (every 1–5 min)
                        reads new S3 objects, extracts ML
                        features (bytes, ports, packet rate,
                        flow duration), enqueues for inference
```

## Scheduled/polling path (CSPM baseline)

```text
Celery Beat (scheduler) → every N hours per connected account:
  assume role → boto3 calls across IAM/S3/EC2/SG → evaluate CSPM rules (§25)
  → diff against last scan → new/resolved findings → risk engine → dashboard
```

## Why both event-driven AND polling exist

Event-driven catches things *as they happen* (a new GuardDuty finding, an IAM policy change).
Polling catches things that don't generate a discrete event but represent ongoing risk (a
bucket that has been public for three months with no new CloudTrail event to trigger on). A
production security platform needs both; relying on only one is the single biggest realism
gap in a "detects threats" claim that only polls.

---

# 27. DATABASE MODEL

Suggested PostgreSQL entities:

```text
users
roles
permissions
cloud_accounts
cloud_resources
security_findings
threat_events
risk_scores
alerts
audit_logs
pipeline_runs
model_versions
notifications
reports
```

Relationship concept:

```text
User
 ├── Audit Logs
 ├── Alerts
 └── Reports

Cloud Account
 └── Cloud Resources
       └── Security Findings

Threat Event
 └── Risk Score
       └── Alert

Pipeline Run
 └── Security Findings
```

---

# 28. API ARCHITECTURE

Recommended backend:

**Python + FastAPI**

## API Groups

```text
/api/auth
/api/users
/api/threats
/api/threats/{id}
/api/cspm
/api/cspm/scan
/api/findings
/api/resources
/api/risk
/api/alerts
/api/analytics
/api/monitoring
/api/devsecops
/api/reports
/api/settings
/api/audit
```

## Example

```text
POST /api/cspm/scan

Response:

{
  "scan_id": "SCAN-001",
  "status": "completed",
  "findings": 27,
  "critical": 3,
  "high": 7,
  "medium": 12,
  "low": 5
}
```

---

# 29. REAL-TIME DATA FLOW

Real-time updates are not optional polish here — they're what makes "monitoring" true instead
of a page the user has to keep refreshing.

```text
AWS event (CloudTrail/GuardDuty/Config via EventBridge → SQS, §26A)
     ↓
Celery worker: normalize → write to PostgreSQL
     ↓
ML inference (§22) → anomaly/classification score
     ↓
Risk Engine → severity + risk delta
     ↓
Worker publishes a compact event on Redis pub/sub channel `events:{account_id}`
     ↓
FastAPI WebSocket endpoint (one connection per authenticated session,
subscribed to the channels for that user's accounts) pushes the event
     ↓
Next.js Client Component (React Query cache) merges it into the live
list/table — no full page refresh, no polling loop on the frontend
```

If the WebSocket connection drops, the frontend falls back to a short-interval REST poll
until it reconnects, so the dashboard degrades gracefully instead of silently going stale.

---

# 30. ASYNCHRONOUS PROCESSING

Long operations should not block the API.

Use a queue/background worker architecture.

```text
Frontend
   ↓
API
   ↓
Job Queue
   ↓
Worker
   ├── ML Processing
   ├── CSPM Scan
   ├── Report Generation
   └── Resource Discovery
   ↓
Database
   ↓
Frontend
```

Possible technologies:

- Redis
- Celery
- RQ
- FastAPI background tasks for lightweight jobs

For the FYP, Redis + Celery is a good advanced architecture if implementation time allows.

---

# 31. SECURITY ARCHITECTURE

Security is not only the subject of the application; the application itself must be secured.

Implement:

- HTTPS
- Authentication
- RBAC
- Password hashing
- MFA as an optional extension
- JWT/session security
- Input validation
- Rate limiting
- CORS configuration
- Secure headers
- SQL injection prevention through ORM/parameterized queries
- Secrets management
- Audit logging
- Least-privilege cloud IAM
- Dependency scanning
- Container scanning

---

# 32. DEVSECOPS PIPELINE (REAL TOOLS, REAL WIRING)

"DevSecOps monitoring" only means something if SentinelX actually receives real scan results,
not a fabricated pass/fail. The mechanism: a GitHub Actions workflow runs real open-source
scanners and, as its last step, POSTs the results to SentinelX's API — SentinelX is a
*consumer* of pipeline results, not the thing running the pipeline.

```text
Developer
    ↓
Git Push / Pull Request
    ↓
GitHub Actions workflow (.github/workflows/security.yml)
    ↓
┌───────────────────────────────────────────────────┐
│ ruff (lint)                                        │
│ pytest (unit tests)                                │
│ bandit -r app/ -f json          (Python SAST)       │
│ pip-audit -f json               (dependency scan)   │
│ gitleaks detect --report-format json (secret scan)  │
└──────────────────────┬──────────────────────────────┘
                       ↓
                  Docker Build
                       ↓
       trivy image --format json <image>   (container scan)
                       ↓
       checkov -d infra/ --output json     (Terraform/IaC scan)
                       ↓
                Terraform Apply → AWS
                       ↓
     Final workflow step: POST all JSON results to
     SentinelX  →  POST /api/devsecops/pipeline-runs
     (this is the ONE integration point — an HTTPS call
      with a per-repo API token, nothing more exotic)
                       ↓
       SentinelX parses findings from each tool's JSON,
       stores them against this pipeline_run, feeds
       CRITICAL/HIGH findings into the Risk Engine
                       ↓
                  Health Checks (post-deploy)
                       ↓
              Prometheus / Grafana (infra metrics, scraped
              separately — not part of the security payload)
                       ↓
              SentinelX DevSecOps page + Monitoring page
```

## Example webhook payload (`POST /api/devsecops/pipeline-runs`)

```json
{
  "repo": "sentinelx/backend",
  "commit_sha": "a1b2c3d",
  "status": "completed",
  "findings": {
    "bandit": [{"severity": "medium", "rule": "B608", "file": "app/db.py", "line": 42}],
    "pip_audit": [{"package": "requests", "installed": "2.25.0", "cve": "CVE-2023-32681"}],
    "gitleaks": [],
    "trivy": [{"severity": "high", "cve": "CVE-2024-1234", "pkg": "libssl"}],
    "checkov": [{"severity": "high", "check": "CKV_AWS_20", "resource": "aws_s3_bucket.logs"}]
  }
}
```

Each tool already outputs real JSON in this shape (or close to it) — the backend's job is a
thin parser per tool, not a generic "understand any scanner" abstraction. Build one parser per
tool, tested against that tool's real sample output.

---

# 33. INFRASTRUCTURE AS CODE

Use Terraform for infrastructure.

Possible resources:

```text
VPC
├── Public Subnet
├── Private Subnet
├── Security Groups
├── EC2
├── Load Balancer
├── RDS
├── S3
└── IAM
```

Do not manually configure production infrastructure if the same infrastructure can be represented in Terraform.

---

# 34. DOCKER ARCHITECTURE

Services:

```text
docker-compose

frontend
backend
ml-service
worker
postgres
redis
prometheus
grafana
```

Development:

```text
React
 ↓
FastAPI
 ├── ML Service
 ├── CSPM
 └── Risk Engine
 ↓
PostgreSQL
Redis
```

---

# 35. OBSERVABILITY

Use three observability concepts:

## Metrics

Prometheus

## Visualization

Grafana

## Logs

Application/container logs.

Optional advanced addition:

- OpenTelemetry

Monitor:

- API latency
- Error rate
- Request count
- CPU
- Memory
- Container health
- ML inference latency
- CSPM scan duration

---

# 36. NOTIFICATION ENGINE

Alert channels:

- In-app
- Email
- Webhook
- Telegram as optional extension

Trigger examples:

```text
IF severity == CRITICAL
→ immediate alert

IF risk_score > 80
→ immediate alert

IF cloud_security_score < threshold
→ alert

IF pipeline security scan fails
→ alert
```

---

# 37. USER JOURNEYS

## Security Analyst

```text
Login
 ↓
Overview
 ↓
Critical Alert
 ↓
Threat Details
 ↓
Investigate
 ↓
Review AI Evidence
 ↓
Assign / Resolve
 ↓
Report
```

## Cloud Security Analyst

```text
Login
 ↓
CSPM
 ↓
Run Scan
 ↓
Findings
 ↓
Critical Finding
 ↓
Remediation
 ↓
Rescan
 ↓
Security Score Improves
```

## DevOps Engineer

```text
Login
 ↓
DevSecOps
 ↓
Pipeline
 ↓
Security Finding
 ↓
Open Finding
 ↓
Fix Code
 ↓
Push Commit
 ↓
Pipeline
 ↓
Scan Passes
 ↓
Deploy
```

---

# 38. IMPORTANT DEMONSTRATION SCENARIO 1 — AI ATTACK DETECTION

For the final FYP demo:

```text
1. Generate/replay a controlled security-event dataset
2. Send event to Threat API
3. Feature extraction occurs
4. ML model predicts attack type
5. Confidence is calculated
6. Severity is assigned
7. Risk engine calculates risk
8. Alert is generated
9. Dashboard updates
10. Analyst opens Threat Details
11. Analyst investigates/resolves event
```

Do this using a controlled lab/test environment and synthetic or authorized traffic.

---

# 39. DEMONSTRATION SCENARIO 2 — CSPM

```text
1. Connect test AWS account
2. Run CSPM scan
3. Discover resources
4. Evaluate security rules
5. Detect intentionally configured test misconfiguration
6. Create finding
7. Calculate risk
8. Show remediation
9. Fix configuration
10. Run scan again
11. Show finding resolved
12. Security score changes
```

This creates an excellent before/after demonstration.

---

# 40. DEMONSTRATION SCENARIO 3 — DEVSECOPS

```text
1. Developer commits vulnerable/test code
2. GitHub Actions starts
3. SAST runs
4. Secret scan runs
5. Dependency scan runs
6. Docker image builds
7. Container scanner runs
8. Pipeline identifies finding
9. Developer fixes issue
10. Push again
11. Pipeline passes
12. Deployment proceeds
```

---

# 41. DASHBOARD KPI DEFINITIONS

Do not create random numbers in the final product.

Every KPI should come from actual data.

## Threats

Number of detected threat events within selected time range.

## Critical

Number of unresolved critical events.

## Risk Score

Calculated from active security risk factors.

## Cloud Security Score

Calculated from CSPM findings and configured weighting.

## Open Alerts

Number of unresolved alerts.

## Resource Health

Percentage of monitored resources meeting health thresholds.

---

# 42. EMPTY STATES

Every page needs a useful empty state.

Example:

```text
No threats detected

Your environment currently has no
detected security events for this period.

[Change Time Range]
```

CSPM:

```text
No findings

Your latest scan did not identify
security misconfigurations.

[Run New Scan]
```

Do not leave empty pages blank.

---

# 43. LOADING STATES

Use skeleton loaders for:

- Dashboard cards
- Tables
- Charts
- Resource lists

For scans:

```text
CSPM SCAN IN PROGRESS

Discovering resources       ✓
Checking IAM                ✓
Checking S3                 ●
Checking Security Groups    ○
Generating findings         ○

Estimated status: Running
```

---

# 44. ERROR STATES

Example:

```text
Unable to load cloud resources

The AWS connection could not be reached.

Possible causes:
• Credentials expired
• Permission denied
• AWS service unavailable

[Retry] [View Connection]
```

---

# 45. RESPONSIVE DESIGN

Desktop is the primary target.

Tablet:

- Collapsible sidebar
- Responsive cards
- Horizontal table scrolling

Mobile:

Prioritize:

- Alerts
- Threats
- Risk score
- Critical findings
- Monitoring

Avoid trying to display every large analytics chart on mobile.

---

# 46. NAVIGATION STRUCTURE

```text
SENTINELX

Overview

Security
├── Threat Detection
├── Alerts
├── Risk Center
└── Analytics

Cloud Security
├── CSPM
├── Findings
└── Cloud Resources

Operations
├── Monitoring
├── DevSecOps
└── Pipeline Runs

Intelligence
├── AI Model
└── Reports

Administration
├── Users & Roles
├── Audit Logs
└── Settings
```

---

# 47. COMPONENT LIBRARY

Create reusable components rather than designing each page independently.

Components:

```text
AppShell
Sidebar
Topbar
StatCard
RiskScoreCard
ThreatBadge
SeverityBadge
StatusBadge
DataTable
SearchBar
FilterBar
ChartCard
ThreatCard
FindingCard
AlertItem
ResourceCard
ScanProgress
PipelineStep
Timeline
Modal
Drawer
ConfirmationDialog
Toast
EmptyState
ErrorState
Skeleton
```

---

# 48. FRONTEND FOLDER STRUCTURE (NEXT.JS APP ROUTER)

```text
src/
├── app/
│   ├── (auth)/
│   │   └── login/page.tsx
│   ├── (dashboard)/
│   │   ├── layout.tsx              ← shared sidebar/topbar
│   │   ├── overview/page.tsx
│   │   ├── threats/
│   │   │   ├── page.tsx
│   │   │   └── [id]/page.tsx
│   │   ├── cspm/
│   │   │   ├── page.tsx
│   │   │   └── [findingId]/page.tsx
│   │   ├── resources/page.tsx
│   │   ├── risk/page.tsx
│   │   ├── alerts/page.tsx
│   │   ├── analytics/page.tsx
│   │   ├── monitoring/page.tsx
│   │   ├── devsecops/
│   │   │   ├── page.tsx
│   │   │   └── runs/[id]/page.tsx
│   │   ├── assistant/page.tsx      ← AI chat panel (§22A)
│   │   ├── reports/page.tsx
│   │   ├── settings/
│   │   │   └── cloud-accounts/page.tsx  ← connect AWS flow (§26)
│   │   └── audit-logs/page.tsx
│   └── api/                        ← Next.js route handlers ONLY for things
│                                      that must run server-side (e.g. setting
│                                      the httpOnly auth cookie); everything
│                                      else calls the FastAPI backend directly
├── components/
│   ├── ui/                         ← shared primitives (table, badge, card)
│   └── charts/
├── lib/
│   ├── api-client.ts                ← typed fetch wrapper for FastAPI
│   └── websocket.ts
├── hooks/
├── stores/                          ← Zustand or React Query cache config
├── types/                           ← generated from the FastAPI OpenAPI schema
└── styles/
```

Server Components fetch initial page data directly from FastAPI on the server (no
loading-spinner flash on first paint); Client Components take over for the WebSocket-driven
live updates (new threats, alert counts). Types under `types/` are generated from FastAPI's
OpenAPI schema (e.g. via `openapi-typescript`) so frontend and backend can't silently drift
apart on a field name or type.

---

# 49. BACKEND FOLDER STRUCTURE

```text
backend/
├── app/
│   ├── api/
│   ├── core/
│   ├── models/
│   ├── schemas/
│   ├── services/
│   │   ├── threat/
│   │   ├── cspm/
│   │   ├── risk/
│   │   ├── alerts/
│   │   ├── cloud/
│   │   └── reports/
│   ├── workers/
│   ├── database/
│   └── main.py
├── tests/
├── requirements.txt
└── Dockerfile
```

---

# 50. ML SERVICE STRUCTURE

```text
ml-service/
├── data/
├── notebooks/
├── models/
├── training/
├── inference/
├── preprocessing/
├── evaluation/
├── api/
└── requirements.txt
```

Never mix model training code directly into the main production API.

---

# 51. DEVELOPMENT PHASES

## Phase 1 — UI Foundation

Build:

- Login
- App shell
- Sidebar
- Topbar
- Dashboard
- Theme
- Component system

Use realistic mock data initially.

## Phase 2 — Backend

Build:

- Authentication
- Users
- Threat APIs
- CSPM APIs
- Risk APIs
- Alerts
- PostgreSQL

## Phase 3 — AI

Build:

- Dataset preprocessing
- Model training
- Evaluation
- Model export
- Inference API
- Threat integration

## Phase 4 — CSPM

Build:

- AWS connection
- Resource discovery
- Security rules
- Findings
- Remediation
- Rescan

## Phase 5 — DevSecOps

Build:

- GitHub Actions
- SAST
- Secret scanning
- Dependency scanning
- Docker
- Trivy
- Terraform scanning

## Phase 6 — Monitoring

Build:

- Prometheus
- Grafana
- Application metrics
- Cloud metrics

## Phase 7 — Production Integration

Connect:

```text
Frontend
+
Backend
+
ML
+
CSPM
+
Risk
+
Alerts
+
Monitoring
+
DevSecOps
```

## Phase 8 — Testing

Test:

- Unit tests
- API tests
- Integration tests
- Security tests
- ML evaluation
- UI testing
- Performance testing

## Phase 9 — Deployment

Recommended initial deployment:

```text
AWS
 ├── Frontend
 ├── Backend
 ├── ML Service
 ├── PostgreSQL
 ├── Redis
 ├── Prometheus
 └── Grafana
```

---

# 52. MVP VS ADVANCED FEATURES

## MVP — Must Have

```text
✓ Login
✓ Dashboard
✓ Threat Detection
✓ Random Forest model
✓ Threat Details
✓ CSPM AWS scanner
✓ IAM/S3/Security Group checks
✓ Risk Engine
✓ Alerts
✓ PostgreSQL
✓ Docker
✓ GitHub Actions
✓ Basic monitoring
```

## Advanced

```text
○ Real-time WebSocket events
○ Redis/Celery
○ MFA
○ Telegram alerts
○ Multi-cloud
○ Kubernetes
○ ArgoCD
○ Automated remediation
○ OpenTelemetry
○ Explainable AI
○ AI-generated security summaries
```

Do not make advanced features mandatory for the first working version.

---

# 53. RECOMMENDED TECHNOLOGY STACK

```text
Frontend:
Next.js (App Router) + TypeScript
Tailwind CSS
Recharts / Apache ECharts
React Query (server-state cache) + Zustand (light UI state)

Backend:
Python
FastAPI (async)
Pydantic v2 (schemas/validation)
SQLAlchemy 2.0 (async) + Alembic (migrations)

AI / ML:
Python, scikit-learn, Pandas, NumPy   (Random Forest + Isolation Forest, §22)
Anthropic API (Claude)                (AI Assistant / LLM layer, §22A)

Database:
PostgreSQL

Cache / Queue / Pub-Sub:
Redis  (Celery broker + WebSocket pub/sub)

Workers:
Celery (event processing, scheduled CSPM scans)
Celery Beat (scheduler for polling jobs)

Cloud:
AWS — cross-account IAM role (STS AssumeRole), never long-lived keys

Cloud SDK:
Boto3

Real-time AWS ingestion:
Amazon EventBridge → Amazon SQS       (CloudTrail / GuardDuty / Config events)
CloudWatch Logs → Kinesis Data Firehose → S3   (VPC Flow Logs, high volume)

Containers:
Docker

IaC:
Terraform

CI/CD:
GitHub Actions

DevSecOps scanners (real, wired via webhook — §32):
Bandit (SAST) · pip-audit (deps) · Gitleaks (secrets)
Trivy (container) · Checkov (IaC)

Monitoring:
Prometheus + Grafana (infra metrics)
Sentry (app error tracking) — optional but cheap to add and genuinely useful

Reverse Proxy:
Nginx

Version Control:
Git + GitHub
```

---

# 54. FYP RESEARCH QUESTIONS

Potential research questions:

### RQ1
How effectively can a Random Forest classifier identify common network attack patterns from network-flow features?

### RQ2
How can automated CSPM rules identify common cloud misconfigurations in AWS environments?

### RQ3
Can combining AI-based threat detection and CSPM findings into a unified risk engine provide a more useful security overview?

### RQ4
How can DevSecOps security gates reduce the likelihood of vulnerable code and container images reaching deployment?

### RQ5
What is the performance overhead of real-time threat inference in a cloud-native security monitoring architecture?

---

# 55. FYP OBJECTIVES

1. Design a cloud-native cybersecurity monitoring platform.
2. Develop an ML-based network threat classification component.
3. Develop an AWS CSPM scanner.
4. Create a transparent security risk scoring engine.
5. Develop a centralized security dashboard.
6. Integrate security alerts and historical analytics.
7. Implement DevSecOps security checks in CI/CD.
8. Containerize the application.
9. Monitor application and infrastructure health.
10. Evaluate the ML model and complete system performance.

---

# 56. FINAL PRODUCT GRAPH

The final product should visually communicate this architecture:

```text
                             SENTINELX
                 AI CLOUD SECURITY PLATFORM

                                  │
                                  ▼
                     ┌─────────────────────┐
                     │   REACT DASHBOARD   │
                     └──────────┬──────────┘
                                │
                                ▼
                     ┌─────────────────────┐
                     │      API GATEWAY    │
                     │ Auth • RBAC • Rate  │
                     └──────────┬──────────┘
                                │
             ┌──────────────────┼──────────────────┐
             │                  │                  │
             ▼                  ▼                  ▼
      ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
      │ THREAT API  │    │    CSPM     │    │ MONITORING  │
      └──────┬──────┘    └──────┬──────┘    └──────┬──────┘
             │                  │                  │
             ▼                  ▼                  ▼
      ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
      │ ML ENGINE   │    │ CSPM RULES  │    │ PROMETHEUS  │
      │ RandomForest│    │ AWS Security│    │ + Grafana   │
      └──────┬──────┘    └──────┬──────┘    └──────┬──────┘
             │                  │                  │
             └──────────────────┼──────────────────┘
                                ▼
                     ┌─────────────────────┐
                     │     RISK ENGINE     │
                     │ Severity + Exposure │
                     │ Asset Criticality   │
                     └──────────┬──────────┘
                                │
                 ┌──────────────┴──────────────┐
                 ▼                             ▼
        ┌─────────────────┐          ┌─────────────────┐
        │  ALERT ENGINE   │          │    POSTGRESQL   │
        │ Email/Webhook   │          │ Security Data   │
        └────────┬────────┘          └─────────────────┘
                 │
                 ▼
        ┌─────────────────────────────────────────┐
        │          SECURITY OPERATIONS            │
        │ Threats • CSPM • Risk • Alerts          │
        │ Analytics • Monitoring • Reports        │
        └─────────────────────────────────────────┘


                       DEVSECOPS
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
          GitHub                    Terraform
              │                         │
              ▼                         ▼
       GitHub Actions              AWS Infrastructure
              │
       ┌──────┼────────┐
       ▼      ▼        ▼
      SAST  Secrets  Dependencies
              │
              ▼
           Docker
              │
              ▼
           Trivy
              │
              ▼
           Deploy
              │
              ▼
        Monitoring
```

---

# 57. ANTIGRAVITY BUILD INSTRUCTION

Use this document as the master product specification.

Do not attempt to implement the entire platform in one generation.

Build incrementally.

## First Generation

Create only:

```text
Authentication UI
App Shell
Sidebar
Topbar
Dashboard
Threat Detection
CSPM
Risk Center
Alerts
Resources
Analytics
Monitoring
DevSecOps
Reports
Settings
```

Use realistic mock data and fully functional navigation.

## Second Generation

Implement backend APIs.

## Third Generation

Connect PostgreSQL.

## Fourth Generation

Connect ML inference.

## Fifth Generation

Connect AWS CSPM.

## Sixth Generation

Connect monitoring.

## Seventh Generation

Connect DevSecOps pipeline.

## Eighth Generation

Deploy and test.

---

# 58. IMPORTANT ANTIGRAVITY UI/UX RULES

1. Do not create generic SaaS UI.
2. Make it look like a real Security Operations Center platform.
3. Keep information hierarchy extremely clear.
4. Use consistent spacing and typography.
5. Use reusable components.
6. Every button should have a meaningful function.
7. Every table row should be interactive where appropriate.
8. Every chart should be backed by data.
9. Do not use fake random numbers once backend integration starts.
10. Do not hardcode security scores in production.
11. Clearly distinguish Critical, High, Medium, Low.
12. Never use red for normal UI decoration.
13. Provide loading, empty, success, and error states.
14. Use confirmation dialogs for destructive operations.
15. Keep security findings explainable.
16. Never expose cloud secrets in the frontend.
17. Never claim that an event is an attack solely because of a UI label; preserve model confidence and evidence.
18. Use accessible contrast and keyboard navigation.
19. Make the dashboard responsive.
20. Prefer a polished enterprise cybersecurity aesthetic over flashy animation.

---

# 59. FINAL FYP STORY

The complete story of the project is:

```text
                 SECURITY EVENTS
                       │
                       ▼
                AI THREAT DETECTION
                       │
                       ▼
                 THREAT ANALYSIS
                       │
                       ▼
                 RISK ENGINE
                       │
                       ▼
                  ALERT SYSTEM
                       │
                       ▼
                 SECURITY SOC
                       │
                       │
      ┌────────────────┴────────────────┐
      │                                 │
      ▼                                 ▼
 CLOUD SECURITY                    DEVSECOPS
      │                                 │
      ▼                                 ▼
    CSPM                         Secure CI/CD
      │                                 │
      ▼                                 ▼
Misconfiguration                 Vulnerability
 Detection                        Detection
      │                                 │
      └────────────────┬────────────────┘
                       ▼
                UNIFIED RISK VIEW
                       │
                       ▼
             CLOUD SECURITY PLATFORM
```

The key FYP innovation is **integration**: instead of treating AI IDS, cloud security scanning, risk analysis, monitoring, and DevSecOps as unrelated projects, SentinelX presents them as connected security signals feeding a common risk and operations layer.

---

# 60. DEFINITION OF DONE

The FYP can be considered functionally complete when a user can:

```text
✓ Log in
✓ View security posture
✓ View detected threats
✓ Open threat details
✓ See ML prediction/confidence
✓ Run an AWS CSPM scan
✓ View cloud findings
✓ View resource inventory
✓ See unified risk score
✓ Receive/view alerts
✓ View historical analytics
✓ View infrastructure metrics
✓ View DevSecOps pipeline status
✓ View security scan results
✓ Generate a security report
✓ Review audit logs
✓ Manage authorized users/roles
```

And the final demonstration can prove:

```text
ATTACK EVENT
     ↓
AI DETECTION
     ↓
RISK CALCULATION
     ↓
ALERT
     ↓
DASHBOARD
     ↓
ANALYST INVESTIGATION

AND

CLOUD MISCONFIGURATION
     ↓
CSPM SCAN
     ↓
SECURITY FINDING
     ↓
RISK SCORE
     ↓
REMEDIATION
     ↓
RESCAN
     ↓
RESOLVED

AND

VULNERABLE CODE
     ↓
CI/CD
     ↓
SECURITY SCANS
     ↓
FINDING
     ↓
FIX
     ↓
PIPELINE PASS
     ↓
DEPLOYMENT
```

---

# 61. NON-FUNCTIONAL REQUIREMENTS

These were implicit in earlier sections (latency, uptime mentioned once each) but a build spec
needs actual numbers to test against, not adjectives like "fast" or "reliable."

```text
Dashboard initial load           < 2.5s  (p95, on mock/seeded data)
API response time                < 300ms (p95, excluding scan/report jobs)
CSPM full account scan           < 90s   for a demo-sized account (~50 resources)
ML inference (single event)      < 150ms
WebSocket event-to-UI latency    < 1s
Concurrent demo users supported  10+     (FYP defense, not production SaaS scale)
Uptime target                    99% during evaluation window (not a 24/7 SLA)
Data retention (events/findings) 90 days rolling, configurable
Password hashing                 bcrypt/argon2, never plaintext or reversible encryption
Session expiry                   Access token 15min, refresh token 7 days
```

State these numbers explicitly in the FYP report/demo — "handles X in under Yms" is a concrete,
gradeable claim; "the system is fast" is not.

---

# 62. TESTING STRATEGY

Phase 8 mentions test categories; this expands them into an actual pyramid so Antigravity
generates real test files alongside features rather than skipping tests until the end.

## Test Pyramid

```text
        ┌───────────────┐
        │   E2E (few)   │   Playwright — the 3 demo scenarios in §38–40,
        └───────┬───────┘   run end-to-end against seeded data before every demo
        ┌───────▼───────┐
        │ Integration    │   API + DB + ML service, pytest — one suite per
        │ (moderate)     │   API group in §28 (/auth, /cspm, /threats, /risk...)
        └───────┬───────┘
        ┌───────▼───────┐
        │  Unit (many)   │   Risk formula math, RBAC permission checks,
        │                │   CSPM rule evaluation, React component rendering
        └───────────────┘
```

## Tooling

```text
Backend unit/integration : pytest + pytest-asyncio + httpx test client
Frontend unit             : Jest + React Testing Library
E2E                        : Playwright (covers login → action → assertion)
ML model evaluation        : scikit-learn metrics (§22) run as a CI job, not a UI test
Security testing            : OWASP ZAP baseline scan against the running app in CI
Load/perf smoke test        : k6 or locust against §61 targets before the final demo
```

## What must have a test before it's considered "done"

- Risk Score formula (§12) — unit tests covering LOW/MEDIUM/HIGH/CRITICAL boundaries and the
  zero-weight-component case (pure CSPM finding, pure threat finding).
- RBAC permission matrix (§20) — every role × every protected route, allow and deny cases.
- Each CSPM rule (§25) — one test fixture per rule with a known-bad and a known-good resource.
- Auth flow — expired token, invalid credentials, lockout after repeated failures.
- The 3 demo scenarios (§38–40) as Playwright E2E tests, so the live defense demo is literally
  running a test suite the supervisor can watch pass.

## Coverage target

Aim for 70%+ on backend business logic (risk engine, CSPM rules, RBAC) and don't chase 100% —
prioritize the modules above over incidental UI glue code.

---

# 63. DEMO DATA SEEDING

The Antigravity build instruction (§57) says "use realistic mock data" — this section makes that
concrete and repeatable so the same demo works every time in front of a supervisor, not just once
while data happened to look right.

## Seed script responsibilities

```text
seed.py (or seed.ts)
  ├── Creates demo org + 4 users, one per role in §20
  ├── Inserts ~150 threat_events spread across the last 30 days,
  │     weighted so Critical/High are rare and Low/Medium are common (realistic ratio)
  ├── Inserts a demo AWS account with ~50 mock cloud_resources
  │     (a few intentionally misconfigured: 1 public S3 bucket, 1 open SSH SG, 1 IAM user w/o MFA)
  ├── Pre-computes risk_scores for every asset using the §12 formula (not random numbers)
  ├── Inserts a handful of resolved + open alerts, and 2–3 completed pipeline_runs
  └── Is idempotent — safe to re-run before every demo/rehearsal without duplicating rows
```

## Why this matters for the FYP specifically

Rule 9 in §58 says "do not use fake random numbers once backend integration starts." A seed
script that runs the real Risk Engine / CSPM Rules / RBAC logic against synthetic-but-realistic
input satisfies that rule during development and gives you a scripted, reliable demo — re-run
`seed.py` the morning of the defense and the numbers in the Dashboard, Risk Center, and Threat
Detection pages will match exactly what you rehearsed with.

---

This is the complete product model to use as the source of truth while building SentinelX.
