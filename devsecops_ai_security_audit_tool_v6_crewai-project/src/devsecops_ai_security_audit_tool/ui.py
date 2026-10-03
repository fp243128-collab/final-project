from __future__ import annotations

import re
import os
import threading
import time
from datetime import datetime
from urllib.parse import urlparse

import streamlit as st

from devsecops_ai_security_audit_tool.crew import DevsecopsAiSecurityAuditToolCrew


st.set_page_config(
    page_title="Sentinel // Security Audit",
    page_icon="◈",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Space+Grotesk:wght@400;500;600;700&display=swap');
    :root { --ink:#17212b; --muted:#667381; --panel:#ffffff; --line:#d8e0e7; --cyan:#087f73; --amber:#a96400; --red:#c93636; }
    .stApp { background:#f5f7f9; color:var(--ink); }
    .stApp, .stApp p, .stApp span, .stApp div, .stApp label,
    [data-testid="stMarkdownContainer"], [data-testid="stMarkdownContainer"] p,
    [data-testid="stMarkdownContainer"] li, [data-testid="stMarkdownContainer"] td,
    [data-testid="stMarkdownContainer"] th { color:var(--ink); }
    .stApp h1, .stApp h2, .stApp h3, .stApp h4, .stApp h5, .stApp h6 { color:var(--ink) !important; }
    [data-testid="stHeader"] { height:0 !important; min-height:0 !important; background:transparent; overflow:hidden; }
    [data-testid="stToolbar"] { display:none !important; }
    [data-testid="stAppDeployButton"] { display:none !important; }
    [data-testid="stMainMenu"] { display:none !important; }
    [data-testid="stSidebar"] { background:#ffffff; border-right:1px solid var(--line); }
    [data-testid="stSidebarHeader"] { height:2.25rem !important; min-height:2.25rem !important; margin-bottom:0 !important; }
    [data-testid="stSidebar"] p,
    [data-testid="stSidebar"] h1,
    [data-testid="stSidebar"] h2,
    [data-testid="stSidebar"] h3,
    [data-testid="stSidebar"] label,
    [data-testid="stSidebar"] input { font-family:'Space Grotesk', sans-serif; }
    [data-testid="stSidebar"][aria-expanded="false"] {
        width:0 !important;
        min-width:0 !important;
        flex:0 0 0 !important;
        border:0 !important;
    }
    [data-testid="stMainBlockContainer"] {
        padding-top:.75rem !important;
    }
    body, h1, h2, h3, p, label, input, textarea, select { font-family:'Space Grotesk', sans-serif; }
    .hero h1 { letter-spacing:-.045em; font-size:clamp(2.2rem, 5vw, 4.8rem); line-height:.98; margin:0 !important; padding:0 !important; max-width:850px; }
    .stMarkdown h1 { font-size:clamp(1.55rem, 3vw, 2.4rem); line-height:1.08; letter-spacing:-.025em; margin-top:1rem; }
    .stMarkdown h2 { font-size:clamp(1.2rem, 2.3vw, 1.7rem); line-height:1.15; margin-top:1.3rem; }
    .stMarkdown h3 { font-size:1.05rem; line-height:1.2; margin-top:1rem; }
    h2 { letter-spacing:-.025em; }
    code, .mono { font-family:'DM Mono', monospace !important; }
    .eyebrow { color:var(--cyan); font-family:'DM Mono', monospace; font-size:.72rem; letter-spacing:.13em; text-transform:uppercase; }
    .hero { padding:.35rem 0 1.4rem; }
    .hero-copy { max-width:720px; color:#586775; font-size:1.04rem; line-height:1.65; margin-top:1rem; }
    .panel { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:1.2rem 1.35rem; box-shadow:0 8px 24px rgba(23,33,43,.06); }
    .panel-label { color:var(--muted); font-family:'DM Mono', monospace; font-size:.7rem; letter-spacing:.1em; text-transform:uppercase; margin-bottom:.85rem; }
    .metric { min-height:112px; }
    .metric-value { color:var(--ink); font-size:clamp(1.35rem, 2.5vw, 2.15rem); font-weight:600; letter-spacing:-.03em; margin-top:.45rem; overflow-wrap:anywhere; }
    .metric-note { color:var(--muted); font-size:.78rem; margin-top:.15rem; }
    .metric-row-gap { display:block !important; width:100%; height:18px !important; min-height:18px !important; margin:0 !important; }
    .status-dot { display:inline-block; width:8px; height:8px; border-radius:50%; background:var(--cyan); box-shadow:0 0 14px var(--cyan); margin-right:7px; }
    .status-dot.idle { background:var(--muted); box-shadow:none; }
    .rail-title { color:var(--ink); font-size:1.05rem; font-weight:600; margin:0 0 .25rem; }
    .rail-copy { color:var(--muted); font-size:.82rem; line-height:1.5; }
    .sidebar-footer { border-top:1px solid var(--line); margin-top:1.25rem; padding-top:1rem; color:var(--muted); font-family:'DM Mono', monospace; font-size:.68rem; letter-spacing:.08em; text-transform:uppercase; }
    .sidebar-footer strong { color:var(--cyan); font-family:'Space Grotesk', sans-serif; font-size:.82rem; letter-spacing:0; text-transform:none; }
    .finding { border-left:3px solid var(--amber); padding:.75rem 1rem; background:#fffaf1; margin:.55rem 0; border-radius:0 5px 5px 0; }
    .finding strong { color:var(--amber); }
    .live-head { display:flex; align-items:center; gap:.75rem; margin-bottom:.65rem; }
    .live-active { color:var(--cyan); font-family:'DM Mono', monospace; font-size:.78rem; }
    .live-count { color:var(--muted); font-family:'DM Mono', monospace; font-size:.72rem; margin-left:auto; }
    .timeline-row, .tool-row { display:flex; align-items:center; gap:.7rem; border-bottom:1px solid var(--line); padding:.65rem 0; font-size:.86rem; }
    .timeline-row:last-child, .tool-row:last-child { border-bottom:0; }
    .timeline-marker { width:20px; color:var(--muted); text-align:center; font-family:'DM Mono', monospace; }
    .timeline-row.done .timeline-marker { color:var(--cyan); }
    .timeline-row.current .timeline-marker { color:var(--amber); }
    .timeline-row.current { color:var(--amber); }
    .tool-row { justify-content:space-between; }
    .tool-detail { color:var(--muted); font-size:.74rem; margin-top:.18rem; }
    .tool-state { font-family:'DM Mono', monospace; font-size:.62rem; letter-spacing:.08em; }
    .tool-state.complete { color:var(--cyan); }
    .tool-state.running { color:var(--amber); }
    .tool-state.queued { color:var(--muted); }
    .risk-grid { display:grid; gap:.9rem; }
    .risk-row { display:grid; grid-template-columns:86px minmax(80px, 1fr) 42px; align-items:center; gap:.75rem; }
    .risk-name { font-family:'DM Mono', monospace; font-size:.72rem; text-transform:uppercase; }
    .risk-track { height:10px; background:#e5ebf0; border-radius:99px; overflow:hidden; }
    .risk-fill { height:100%; border-radius:99px; min-width:2px; }
    .risk-number { text-align:right; font-family:'DM Mono', monospace; font-size:.78rem; color:var(--ink); }
    .severity-strip { display:grid; grid-template-columns:repeat(4, minmax(0, 1fr)); gap:.6rem; }
    .severity-cell { border:1px solid var(--line); border-radius:6px; padding:.75rem .8rem; background:#f8fafb; }
    .severity-cell .label { font-family:'DM Mono', monospace; font-size:.64rem; text-transform:uppercase; color:var(--muted); }
    .severity-cell .value { font-size:1.45rem; font-weight:600; margin-top:.3rem; }
    [data-testid="stTabs"] [role="tablist"] { gap:.25rem; border-bottom:1px solid var(--line); }
    [data-testid="stTabs"] [role="tab"] { color:var(--muted); border-radius:5px 5px 0 0; padding:.55rem .8rem; }
    [data-testid="stTabs"] [role="tab"]:hover { color:var(--ink); background:#eef4f5; }
    [data-testid="stTabs"] [role="tab"][aria-selected="true"] { color:var(--cyan); background:#e5f3f1; }
    [data-testid="stTabs"] button[aria-label*="scroll"],
    [data-testid="stTabs"] button[aria-label*="Scroll"] { color:var(--cyan); background:#e5f3f1; border:1px solid var(--line); border-radius:5px; }
    @media (max-width: 900px) {
        [data-testid="stSidebar"] { min-width:220px; max-width:220px; }
        .hero { padding-top:.35rem; }
        .hero-copy { font-size:.92rem; }
        .panel { padding:1rem; }
        .metric { min-height:96px; }
        .metric-value { font-size:1.4rem; }
    }
    @media (max-width: 640px) {
        [data-testid="stSidebar"] { display:none; }
        .risk-row { grid-template-columns:72px minmax(60px, 1fr) 30px; gap:.45rem; }
    }
    .stButton > button { background:var(--cyan); border:0; color:#ffffff; font-family:'Space Grotesk', sans-serif; font-weight:700; border-radius:5px; min-height:2.65rem; }
    .stButton > button:hover { background:#0a6b61; color:#ffffff; }
    [data-testid="stFormSubmitButton"] > button { background:var(--cyan) !important; color:#ffffff !important; border:0 !important; border-radius:5px; min-height:2.65rem; font-weight:700; }
    [data-testid="stFormSubmitButton"] > button:hover { background:#0a6b61 !important; color:#ffffff !important; }
    .stDownloadButton > button { border:1px solid var(--line); background:#ffffff; color:var(--ink); border-radius:5px; }
    div[data-baseweb="input"], [data-testid="stTextInputRootElement"] { background:#ffffff !important; border-color:var(--line) !important; }
    [data-testid="stTextInputField"] { background:#ffffff !important; color:var(--ink) !important; -webkit-text-fill-color:var(--ink) !important; }
    [data-testid="stTextInputField"]::placeholder { color:#7b8792 !important; opacity:1; }
    [data-testid="stSelectbox"] [data-baseweb="select"] > div { background:#ffffff !important; border-color:var(--line) !important; color:var(--ink) !important; }
    [data-testid="stSelectbox"] [data-baseweb="select"] span,
    [data-testid="stSelectbox"] [data-baseweb="select"] svg { color:var(--ink) !important; fill:var(--ink) !important; }
    [data-testid="stSelectbox"] [role="group"] { background:#ffffff !important; border:1px solid var(--line) !important; border-radius:6px !important; box-shadow:none !important; }
    [data-testid="stSelectbox"] [role="group"] input { background:#ffffff !important; color:var(--ink) !important; -webkit-text-fill-color:var(--ink) !important; }
    [data-testid="stSelectbox"] [role="group"]:focus-within { border-color:var(--cyan) !important; box-shadow:0 0 0 2px rgba(8,127,115,.14) !important; }
    [data-baseweb="popover"] [role="listbox"], [data-baseweb="menu"] { background:#ffffff !important; color:var(--ink) !important; border:1px solid var(--line) !important; }
    [data-baseweb="popover"] [role="option"], [data-baseweb="menu"] li { color:var(--ink) !important; background:#ffffff !important; }
    [data-baseweb="popover"] [role="option"]:hover, [data-baseweb="menu"] li:hover { background:#e5f3f1 !important; }
    .stTextInput label, .stCheckbox label { color:#344451; }
    input, textarea, select { color:var(--ink) !important; }
    [data-testid="stRadio"] label, [data-testid="stCheckbox"] label { color:var(--ink) !important; }
    [data-testid="stCheckbox"] input, [data-testid="stRadio"] input { accent-color:var(--cyan); }
    [data-testid="stSidebar"] .rail-copy, [data-testid="stSidebar"] .panel-label { color:var(--muted) !important; }
    hr { border-color:var(--line); }
    </style>
    """,
    unsafe_allow_html=True,
)


def target_is_valid(target: str) -> bool:
    candidate = target.strip()
    parsed = urlparse(candidate if "://" in candidate else f"https://{candidate}")
    return bool(parsed.netloc and " " not in candidate)


def severity_counts(report: str) -> dict[str, int]:
    return {
        severity: len(re.findall(rf"\b{severity}\b", report, flags=re.IGNORECASE))
        for severity in ("Critical", "High", "Medium", "Low")
    }


def clean_report_markdown(report: str) -> str:
    """Remove model wrapper fences so headings and tables render as Markdown."""
    cleaned = report.strip()
    cleaned = re.sub(r"^```(?:markdown|md|text)?\s*", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    return cleaned.strip()


def clean_visual_symbols(text: str) -> str:
    symbols = "🔍🌐🔐🔒⚠️🚨🔴🟠🟡🔵⚪🔑🗝️📊🛡️✅❌📡🧭"
    return re.sub(f"[{re.escape(symbols)}]", "", text).replace("  ", " ").strip()


def render_structured_report(report: str) -> None:
    cleaned = clean_report_markdown(report)
    sections = re.split(r"(?=^##\s+)", cleaned, flags=re.MULTILINE)
    sections = [section.strip() for section in sections if section.strip()]
    if len(sections) <= 1:
        st.markdown(cleaned)
        return

    labels = []
    bodies = []
    for section in sections:
        heading_match = re.match(r"^##\s+(.+?)\s*$", section, flags=re.MULTILINE)
        if heading_match:
            labels.append(clean_visual_symbols(heading_match.group(1).replace("**", "")).strip()[:34] or "Section")
            body = re.sub(r"^##\s+.+?$", "", section, count=1, flags=re.MULTILINE).strip()
            bodies.append(clean_visual_symbols(body))
        else:
            labels.append("Overview")
            bodies.append(section)

    tabs = st.tabs(labels)
    for tab, body in zip(tabs, bodies):
        with tab:
            st.markdown(body)


def render_metric(label: str, value: str, note: str) -> None:
    st.markdown(
        f'<div class="panel metric"><div class="panel-label">{label}</div>'
        f'<div class="metric-value">{value}</div><div class="metric-note">{note}</div></div>',
        unsafe_allow_html=True,
    )


PIPELINE = [
    ("Network reconnaissance", "DNS, IP, ASN, SPF/DMARC, Shodan services", "target_reconnaissance_agent"),
    ("Web application inspection", "Headers, cookies, TLS, scraping", "web_application_security_inspector"),
    ("Endpoint discovery", "Sensitive paths, metadata, technology fingerprinting", "deep_endpoint_discovery_and_metadata_analyst"),
    ("DoS resilience testing", "Rate limits, methods, payloads, CDN/WAF", "dos_resilience_and_http_attack_tester"),
    ("Injection testing", "SQL injection, XSS, open redirects", "sql_injection_and_input_vulnerability_tester"),
    ("Authentication testing", "Login, sessions, enumeration, lockout", "authentication_and_session_security_tester"),
    ("CVE and OWASP analysis", "CVE research, CVSS, attack chains", "vulnerability_analyst"),
    ("Executive report", "Risk dashboard and remediation roadmap", "security_audit_report_generator"),
]

TOOL_CATALOG = [
    (0, "DNS / IP Recon", "Records, ASN, geolocation, SPF and DMARC"),
    (0, "Shodan InternetDB", "Ports, services, CPEs and known CVEs"),
    (1, "HTTP Headers", "Security header presence and severity"),
    (1, "Cookie Analyzer", "Secure, HttpOnly, SameSite and JWT checks"),
    (1, "SSL / TLS Inspector", "Certificate health and expiry"),
    (1, "Website Scraper", "Technology, forms, links and disclosures"),
    (2, "Endpoint Discovery", "Sensitive paths and exposed files"),
    (2, "Metadata Extractor", "Technology fingerprints and secret patterns"),
    (3, "Rate Limit Tester", "HTTP attack and resilience behavior"),
    (4, "SQL Injection Tester", "SQLi, XSS and open redirect probes"),
    (5, "Authentication Tester", "Login, sessions and enumeration"),
    (6, "Exa CVE Research", "Technology vulnerability intelligence"),
    (6, "URL Reader", "Source context for analysis"),
]


def create_run_state() -> dict:
    return {
        "status": "queued",
        "completed": 0,
        "active": PIPELINE[0][0],
        "stage_index": 0,
        "mode": "guided",
        "target": "",
        "provider": "grok",
        "events": [],
        "report": "",
        "reports": {},
        "error": None,
        "stop_requested": False,
        "started": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "lock": threading.Lock(),
    }


def task_progress_callback(run_state: dict, task_output) -> None:
    description = getattr(task_output, "description", "") or ""
    text = description.lower()
    completed_index = 0
    for index, (title, _, agent_name) in enumerate(PIPELINE):
        if agent_name.replace("_", " ") in text or any(word in text for word in title.lower().split()[:2]):
            completed_index = index
            break
    with run_state["lock"]:
        run_state["completed"] = max(run_state["completed"], completed_index + 1)
        next_index = min(run_state["completed"], len(PIPELINE) - 1)
        run_state["active"] = PIPELINE[next_index][0]
        run_state["events"].append({"time": datetime.now().strftime("%H:%M:%S"), "label": PIPELINE[completed_index][0], "status": "complete"})


def run_audit(run_state: dict, target: str, provider: str) -> None:
    os.environ["AI_PROVIDER"] = provider
    with run_state["lock"]:
        run_state["status"] = "running"
    try:
        crew_instance = DevsecopsAiSecurityAuditToolCrew()
        crew_instance.progress_sink = lambda output: task_progress_callback(run_state, output)
        result = crew_instance.crew().kickoff(inputs={"target": target})
        with run_state["lock"]:
            run_state["report"] = getattr(result, "raw", str(result))
            run_state["status"] = "complete"
            run_state["completed"] = len(PIPELINE)
            run_state["active"] = "Assessment complete"
    except Exception as error:
        with run_state["lock"]:
            run_state["status"] = "failed"
            run_state["error"] = str(error)


def run_guided_stage(run_state: dict, stage_index: int) -> None:
    os.environ["AI_PROVIDER"] = run_state["provider"]
    with run_state["lock"]:
        run_state["status"] = "running"
        run_state["active"] = PIPELINE[stage_index][0]
        run_state["completed"] = stage_index
    try:
        crew_instance = DevsecopsAiSecurityAuditToolCrew()
        crew_instance.progress_sink = lambda output: task_progress_callback(run_state, output)
        result = crew_instance.stage_crew(stage_index, list(run_state["reports"].values())).kickoff(
            inputs={"target": run_state["target"]}
        )
        report = getattr(result, "raw", str(result))
        with run_state["lock"]:
            run_state["report"] = report
            run_state["reports"][PIPELINE[stage_index][0]] = report
            run_state["status"] = "complete"
            run_state["completed"] = stage_index + 1
            run_state["active"] = PIPELINE[stage_index][0]
    except Exception as error:
        with run_state["lock"]:
            run_state["status"] = "failed"
            run_state["error"] = str(error)


def run_remaining_stages(run_state: dict) -> None:
    """Run only stages that have not already completed in guided mode."""
    with run_state["lock"]:
        start_index = run_state["completed"]
        run_state["mode"] = "all"
        run_state["status"] = "running"
        run_state["stop_requested"] = False
    for stage_index in range(start_index, len(PIPELINE)):
        with run_state["lock"]:
            if run_state["stop_requested"]:
                run_state["status"] = "stopped"
                run_state["active"] = "Assessment paused"
                return
        run_guided_stage(run_state, stage_index)
        with run_state["lock"]:
            if run_state["status"] == "failed":
                return
    with run_state["lock"]:
        run_state["status"] = "complete"
        run_state["active"] = "Assessment complete"


def stop_assessment(run_state: dict) -> None:
    with run_state["lock"]:
        run_state["stop_requested"] = True
        if run_state["status"] in {"queued", "complete"}:
            run_state["status"] = "stopped"
            run_state["active"] = "Assessment paused"


def start_guided_stage(run_state: dict, stage_index: int) -> None:
    with run_state["lock"]:
        run_state["stage_index"] = stage_index
        run_state["status"] = "queued"
        run_state["report"] = ""
        run_state["error"] = None
    threading.Thread(target=run_guided_stage, args=(run_state, stage_index), daemon=True).start()


def render_live_session(run_state: dict) -> None:
    with run_state["lock"]:
        status = run_state["status"]
        completed = run_state["completed"]
        active = run_state["active"]
        events = list(run_state["events"])
        error = run_state["error"]
    if status == "queued":
        return
    st.markdown("### Live session")
    progress = completed / len(PIPELINE)
    status_label = {"running": "LIVE", "complete": "COMPLETE", "stopped": "PAUSED", "failed": "FAILED"}.get(status, status.upper())
    st.markdown(f'<div class="live-head"><span class="status-dot"></span><strong>{status_label}</strong><span class="live-active">{active}</span><span class="live-count">{completed}/{len(PIPELINE)} stages</span></div>', unsafe_allow_html=True)
    st.progress(progress, text=f"{active} · {completed} of {len(PIPELINE)} stages complete")
    timeline, tools = st.columns([1.1, 1.9], gap="large")
    with timeline:
        st.markdown('<div class="panel"><div class="panel-label">Session timeline</div>', unsafe_allow_html=True)
        for index, (title, _, _) in enumerate(PIPELINE):
            done = index < completed
            current = title == active and status == "running"
            marker = "✓" if done else ("●" if current else "○")
            css = "done" if done else ("current" if current else "queued")
            st.markdown(f'<div class="timeline-row {css}"><span class="timeline-marker">{marker}</span><span>{title}</span></div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
    with tools:
        st.markdown('<div class="panel"><div class="panel-label">Tool activity</div>', unsafe_allow_html=True)
        for stage, title, detail in TOOL_CATALOG:
            done = stage < completed
            current = stage == completed and status == "running"
            state = "COMPLETE" if done else ("RUNNING" if current else "QUEUED")
            st.markdown(f'<div class="tool-row"><div><strong>{title}</strong><div class="tool-detail">{detail}</div></div><span class="tool-state {state.lower()}">{state}</span></div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
    if events:
        st.caption(" · ".join(f'{event["time"]}  {event["label"]}' for event in events[-4:]))
    if error:
        st.error(error)
    if status == "stopped" or (status == "complete" and run_state["mode"] == "guided"):
        next_index = completed
        if next_index < len(PIPELINE):
            st.markdown("#### Continue assessment")
            one_col, all_col, stop_col = st.columns(3, gap="small")
            with one_col:
                if st.button("One-by-one", key=f"next_{next_index}", use_container_width=True):
                    run_state["mode"] = "guided"
                    start_guided_stage(run_state, next_index)
                    st.rerun()
            with all_col:
                if st.button("Run all remaining tasks", key=f"all_{next_index}", use_container_width=True):
                    threading.Thread(target=run_remaining_stages, args=(run_state,), daemon=True).start()
                    st.rerun()
            with stop_col:
                if st.button("Stop assessment", key=f"stop_{next_index}", use_container_width=True):
                    stop_assessment(run_state)
                    st.rerun()
        else:
            st.success("All assessment stages are complete. Review each section below.")


def render_risk_graph(report: str) -> None:
    counts = severity_counts(report) if report else {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    st.markdown("### Risk graph")
    max_count = max(counts.values(), default=1) or 1
    colors = {"Critical": "#ff6b6b", "High": "#ffc857", "Medium": "#65e6d2", "Low": "#8793a5"}
    rows = []
    for label, count in counts.items():
        width = round((count / max_count) * 100) if count else 0
        rows.append(
            f'<div class="risk-row"><span class="risk-name" style="color:{colors[label]}">{label}</span>'
            f'<div class="risk-track"><div class="risk-fill" style="width:{width}%;background:{colors[label]}"></div></div>'
            f'<span class="risk-number">{count}</span></div>'
        )
    st.markdown(f'<div class="panel"><div class="panel-label">Findings by severity</div><div class="risk-grid">{"".join(rows)}</div></div>', unsafe_allow_html=True)


if "report" not in st.session_state:
    st.session_state.report = ""
if "target" not in st.session_state:
    st.session_state.target = ""
if "scan_started" not in st.session_state:
    st.session_state.scan_started = None
if "run_state" not in st.session_state:
    st.session_state.run_state = None

with st.sidebar:
    st.markdown('<div class="rail-title">AI security audit</div>', unsafe_allow_html=True)
    st.markdown('<div class="rail-copy">Coordinate reconnaissance, inspection, and remediation intelligence from one focused workspace.</div>', unsafe_allow_html=True)
    st.divider()
    st.markdown('<div class="panel-label">Pipeline</div>', unsafe_allow_html=True)
    for index, (name, detail, _) in enumerate(PIPELINE, 1):
        st.markdown(f"**{index:02d}  {name}**  \n<span class='rail-copy'>{detail}</span>", unsafe_allow_html=True)
    provider_options = ("gemini", "grok", "openai")
    configured_provider = os.getenv("AI_PROVIDER", "gemini").lower()
    if configured_provider not in provider_options:
        configured_provider = "gemini"
    provider = st.selectbox(
        "AI provider",
        options=provider_options,
        index=provider_options.index(configured_provider),
        format_func=lambda name: {"gemini": "Google Gemini", "grok": "xAI Grok", "openai": "OpenAI"}[name],
    )
    os.environ["AI_PROVIDER"] = provider
    st.divider()
    st.markdown('<div class="panel-label">Operator note</div>', unsafe_allow_html=True)
    st.markdown('<div class="rail-copy">Only scan assets you own or have explicit authorization to test. Active checks may generate traffic.</div>', unsafe_allow_html=True)
    st.markdown('<div class="sidebar-footer"><strong>Workspace</strong><br>Local session · Protected</div>', unsafe_allow_html=True)

st.markdown('<div class="hero"><h1>See the attack surface<br>before attackers do.</h1><div class="hero-copy">A calm, evidence-first interface for turning a target into a prioritized security brief. Launch the existing CrewAI pipeline, then review the signal without losing the thread.</div></div>', unsafe_allow_html=True)

with st.form("assessment_form"):
    target = st.text_input("Target", value=st.session_state.target, placeholder="https://app.example.com or example.com")
    authorized = st.checkbox("I have authorization to test this target", value=False)
    assessment_mode = st.radio(
        "Assessment mode",
        options=("guided", "all"),
        format_func=lambda value: "One-by-one guided assessment" if value == "guided" else "Run all assessments",
        horizontal=True,
        help="Guided mode spends credits one task at a time and waits for your decision before continuing.",
    )
    submitted = st.form_submit_button("Launch assessment", use_container_width=True)

if submitted:
    st.session_state.target = target.strip()
    if not target_is_valid(target):
        st.error("Enter a valid domain, IP address, or URL.")
    elif not authorized:
        st.error("Confirm that you are authorized to test this target before launching.")
    else:
        st.session_state.scan_started = datetime.now().strftime("%Y-%m-%d %H:%M")
        st.session_state.report = ""
        st.session_state.run_state = create_run_state()
        st.session_state.run_state["target"] = target.strip()
        st.session_state.run_state["provider"] = provider
        st.session_state.run_state["mode"] = assessment_mode
        if assessment_mode == "guided":
            start_guided_stage(st.session_state.run_state, 0)
        else:
            threading.Thread(
                target=run_audit,
                args=(st.session_state.run_state, target.strip(), provider),
                daemon=True,
            ).start()

if st.session_state.run_state:
    @st.fragment(run_every=1)
    def live_dashboard():
        render_live_session(st.session_state.run_state)
        if st.session_state.run_state["status"] == "complete":
            st.session_state.report = st.session_state.run_state["report"]

    live_dashboard()

report = st.session_state.report or (st.session_state.run_state or {}).get("report", "")
counts = severity_counts(report) if report else {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

st.markdown("### Assessment pulse")
metric_row_one = st.columns(2, gap="medium")
with metric_row_one[0]:
    render_metric("Overall state", "READY" if not report else "REVIEW", "Awaiting target" if not report else "Report generated")
with metric_row_one[1]:
    render_metric("Critical", str(counts["Critical"]), "Immediate attention")
st.markdown('<div class="metric-row-gap">&nbsp;</div>', unsafe_allow_html=True)
metric_row_two = st.columns(2, gap="medium")
with metric_row_two[0]:
    render_metric("High", str(counts["High"]), "Priority remediation")
with metric_row_two[1]:
    render_metric("Last run", st.session_state.scan_started or "--", "Local session")

st.markdown("### Findings desk")
if report:
    severity_cells = []
    for label, color in (("Critical", "#ff6b6b"), ("High", "#ffc857"), ("Medium", "#65e6d2"), ("Low", "#8793a5")):
        severity_cells.append(f'<div class="severity-cell"><div class="label" style="color:{color}">{label}</div><div class="value">{counts[label]}</div></div>')
    st.markdown(f'<div class="panel"><div class="panel-label">Severity mix</div><div class="severity-strip">{"".join(severity_cells)}</div></div>', unsafe_allow_html=True)
    st.download_button("Download markdown report", report, file_name="security-audit-report.md", use_container_width=True)
    st.markdown('<div class="panel"><div class="panel-label">Executive output</div>', unsafe_allow_html=True)
    render_structured_report(report)
    st.markdown('</div>', unsafe_allow_html=True)
    render_risk_graph(report)
    if st.session_state.run_state and st.session_state.run_state.get("mode") == "guided":
        saved_reports = st.session_state.run_state.get("reports", {})
        if saved_reports:
            st.markdown("### Assessment sections")
            for section_name, section_report in saved_reports.items():
                with st.expander(section_name, expanded=section_name == st.session_state.run_state.get("active")):
                    render_structured_report(section_report)
else:
    st.markdown('<div class="panel"><span class="status-dot idle"></span><strong>No assessment loaded</strong><p class="rail-copy">Enter an authorized target above to populate the report workspace. The live result will appear here with severity counts and a downloadable markdown report.</p></div>', unsafe_allow_html=True)
