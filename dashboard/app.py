"""
AI Code Reviewer — Interactive Command Center Dashboard

Works in two modes:
  ONLINE  — FastAPI is running → shows live audit data
  OFFLINE — FastAPI is not running → shows demo data with a banner

Run (standalone, no API needed):
    streamlit run dashboard/app.py

Run (with live API):
    # Terminal 1: uvicorn api.main:app --reload --port 8000
    # Terminal 2: streamlit run dashboard/app.py
"""

from __future__ import annotations

import os
import random
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import pandas as pd
import plotly.express as px
import streamlit as st

# ── Try importing httpx; fall back gracefully ─────────────────
try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False

# ─── Config ───────────────────────────────────────────────────
API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")
REFRESH_INTERVAL = 15
API_TIMEOUT = 3.0   # short so offline detection is fast

st.set_page_config(
    page_title="AI Code Reviewer",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
  .api-offline {background:#1e1010;border:1px solid #7f1d1d;border-radius:8px;
    padding:12px 16px;color:#fca5a5;margin-bottom:12px;}
  .api-online  {background:#0d1f16;border:1px solid #14532d;border-radius:8px;
    padding:12px 16px;color:#86efac;margin-bottom:12px;}
  .stDataFrame {font-size:13px;}
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────
# API connectivity helpers
# ─────────────────────────────────────────────────────────────

def _check_api_online() -> bool:
    """Return True if the FastAPI server responds to /health."""
    if not _HTTPX_AVAILABLE:
        return False
    try:
        r = httpx.get(f"{API_BASE_URL}/health", timeout=API_TIMEOUT)
        return r.status_code == 200
    except Exception:
        return False


@st.cache_data(ttl=5)
def api_online() -> bool:
    return _check_api_online()


def api_get(path: str) -> Any:
    """GET wrapper — returns None silently when offline."""
    if not _HTTPX_AVAILABLE or not api_online():
        return None
    try:
        r = httpx.get(f"{API_BASE_URL}{path}", timeout=API_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


def api_post(path: str, params: dict | None = None) -> Any:
    """POST wrapper — returns None silently when offline."""
    if not _HTTPX_AVAILABLE or not api_online():
        return None
    try:
        r = httpx.post(f"{API_BASE_URL}{path}", params=params, timeout=API_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────
# Demo data — shown when the API is offline
# ─────────────────────────────────────────────────────────────

def _make_demo_finding(sev: str, rule_id: str, agent: str, fname: str, line: int) -> dict:
    titles = {
        "SEC-001": "Hardcoded Secret detected",
        "SEC-002": "SQL Injection risk",
        "SEC-003": "XSS vulnerability",
        "QA-001":  "High cyclomatic complexity",
        "QA-003":  "Lint violation",
        "SEC-007": "Vulnerable dependency (CVE)",
    }
    return {
        "finding_id": f"demo-{rule_id}-{line}",
        "rule_id": rule_id,
        "agent_id": agent,
        "severity": sev,
        "title": titles.get(rule_id, rule_id),
        "description": f"Demo finding for {rule_id}. Run the API to see real results.",
        "owasp_category": "A03:2021 – Injection",
        "suppressed": False,
        "location": {"file": fname, "line_start": line, "code_snippet": f"# line {line}"},
        "evidence": {"tool_name": "demo", "raw_output": "{}", "command_run": "demo"},
        "patch": None,
    }


def _demo_audits() -> list[dict]:
    statuses = ["PASSED", "PASSED", "BLOCKED", "PASSED", "ERROR", "BLOCKED", "PASSED"]
    repos = ["owner/webapp", "owner/api-service", "owner/cli-tool"]
    now = datetime.now(timezone.utc)
    audits = []
    for i, st_val in enumerate(statuses):
        ts = (now - timedelta(hours=i * 3)).isoformat()
        f_list = []
        if st_val == "BLOCKED":
            f_list = [
                _make_demo_finding("CRITICAL", "SEC-001", "agent_b", "auth.py", 42),
                _make_demo_finding("HIGH",     "SEC-002", "agent_b", "db.py",   17),
                _make_demo_finding("MEDIUM",   "QA-001",  "agent_a", "utils.py", 5),
            ]
        elif st_val == "PASSED":
            f_list = [_make_demo_finding("LOW", "QA-003", "agent_a", "main.py", 10)]
        audits.append({
            "audit_id": f"demo-audit-{i:03d}",
            "pr_number": 100 + i,
            "repo_full_name": repos[i % len(repos)],
            "head_sha": f"abc{i:05d}def",
            "overall_status": st_val,
            "started_at": ts,
            "completed_at": ts,
            "findings": f_list,
            "agent_metrics": [
                {"agent_id": "agent_a", "files_scanned": 3, "duration_seconds": 1.2,
                 "lines_analyzed": 150, "tool_calls": [], "error": None},
                {"agent_id": "agent_b", "files_scanned": 3, "duration_seconds": 4.7,
                 "lines_analyzed": 150, "tool_calls": [], "error": None},
            ],
            "compliance_report": {
                "markdown_report": "## Demo Report\n\nRun the API for real OWASP analysis."
            },
        })
    return audits


def _demo_cost() -> dict:
    return {
        "total_calls": 14,
        "total_tokens": 28400,
        "total_cost_usd": 0.2130,
        "by_model": {
            "gpt-4o": {"calls": 10, "tokens": 21000, "cost_usd": 0.1575},
            "gpt-4o-mini": {"calls": 4, "tokens": 7400, "cost_usd": 0.0555},
        },
        "by_agent": {
            "agent_c": {"calls": 14, "tokens": 28400, "cost_usd": 0.2130},
        },
    }


def _demo_token_records() -> list[dict]:
    now = datetime.now(timezone.utc)
    records = []
    for i in range(14):
        ts = (now - timedelta(minutes=i * 20)).isoformat()
        tok = random.randint(800, 2400)
        records.append({
            "timestamp": ts,
            "audit_id": f"demo-audit-{i % 7:03d}",
            "agent_id": "agent_c",
            "model": "gpt-4o" if i % 3 != 0 else "gpt-4o-mini",
            "prompt_tokens": int(tok * 0.7),
            "completion_tokens": int(tok * 0.3),
            "total_tokens": tok,
            "cost_usd": round(tok / 1000 * 0.005, 5),
            "latency_ms": random.randint(900, 3200),
        })
    return records


# ─────────────────────────────────────────────────────────────
# Data loaders — live or demo
# ─────────────────────────────────────────────────────────────

@st.cache_data(ttl=REFRESH_INTERVAL)
def load_audits(limit: int = 200) -> tuple[list[dict], bool]:
    """Returns (audits, is_live)."""
    r = api_get(f"/audits?limit={limit}")
    if r and isinstance(r, dict):
        return r.get("results", []), True
    return _demo_audits(), False


@st.cache_data(ttl=REFRESH_INTERVAL)
def load_audit(audit_id: str) -> dict | None:
    if not audit_id.startswith("demo-"):
        return api_get(f"/audits/{audit_id}")
    # Return from demo set
    for a in _demo_audits():
        if a["audit_id"] == audit_id:
            return a
    return None


@st.cache_data(ttl=REFRESH_INTERVAL)
def load_cost_summary() -> dict:
    r = api_get("/telemetry/cost")
    return r if isinstance(r, dict) and r else _demo_cost()


@st.cache_data(ttl=REFRESH_INTERVAL)
def load_token_records() -> list[dict]:
    r = api_get("/telemetry/tokens?limit=200")
    if r and isinstance(r, dict):
        return r.get("records", [])
    return _demo_token_records()


# ─────────────────────────────────────────────────────────────
# Metric aggregation
# ─────────────────────────────────────────────────────────────

def compute_metrics(audits: list[dict]) -> dict:
    if not audits:
        return dict(total=0, passed=0, blocked=0, error=0,
                    pass_rate=0.0, critical=0, high=0, time_saved=0.0)
    total = len(audits)
    passed  = sum(1 for a in audits if a.get("overall_status") == "PASSED")
    blocked = sum(1 for a in audits if a.get("overall_status") == "BLOCKED")
    error   = sum(1 for a in audits if a.get("overall_status") == "ERROR")
    all_f   = [f for a in audits for f in a.get("findings", [])]
    return dict(
        total=total, passed=passed, blocked=blocked, error=error,
        pass_rate=passed / total * 100 if total else 0.0,
        critical=sum(1 for f in all_f if f.get("severity") == "CRITICAL"),
        high=sum(1 for f in all_f if f.get("severity") == "HIGH"),
        time_saved=round(total * 42 / 60, 1),
    )


# ─────────────────────────────────────────────────────────────
# Sidebar
# ─────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("## 🔐 AI Code Reviewer")
    st.markdown("`v2.0.0` · Autonomous DevSecOps Agent")
    st.divider()

    page = st.radio("Navigate", [
        "📊 Dashboard",
        "🔍 Audit Details",
        "🤖 Agent Traces",
        "💰 Cost Dashboard",
        "⚙️ Settings & Setup",
    ])
    st.divider()

    repo_filter = st.text_input("Filter by repo", "")
    if st.toggle("Auto-refresh", value=False):
        st.caption(f"Refreshing every {REFRESH_INTERVAL}s")
        time.sleep(REFRESH_INTERVAL)
        st.rerun()
    if st.button("🔄 Refresh Now"):
        st.cache_data.clear()
        st.rerun()

# ─── Load data ───────────────────────────────────────────────
audits_raw, is_live = load_audits()
if repo_filter:
    audits_raw = [a for a in audits_raw
                  if repo_filter.lower() in a.get("repo_full_name", "").lower()]

metrics = compute_metrics(audits_raw)

# ─── API status banner ────────────────────────────────────────
if is_live:
    st.markdown('<div class="api-online">✅ <b>API Online</b> — showing live data '
                f'from <code>{API_BASE_URL}</code></div>', unsafe_allow_html=True)
else:
    st.markdown(
        '<div class="api-offline">⚠️ <b>API Offline</b> — FastAPI is not running. '
        'Showing <b>demo data</b>.<br>'
        'Start the API: <code>uvicorn api.main:app --reload --port 8000</code>'
        '</div>', unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════
# PAGE — Dashboard
# ══════════════════════════════════════════════════════════════
if page == "📊 Dashboard":
    st.title("🔐 AI Code Security Review — Command Center")
    src_label = "live" if is_live else "demo"
    st.caption(f"Last updated: {datetime.now().strftime('%H:%M:%S')} · "
               f"{len(audits_raw)} audits ({src_label})")

    # KPIs
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("Total PRs",       metrics["total"])
    c2.metric("Pass Rate",       f"{metrics['pass_rate']:.1f}%")
    c3.metric("Blocked",         metrics["blocked"])
    c4.metric("🔴 Critical",     metrics["critical"])
    c5.metric("🟠 High",         metrics["high"])
    c6.metric("⏱️ Hours Saved",  metrics["time_saved"])

    st.divider()
    col_l, col_r = st.columns(2)

    with col_l:
        st.subheader("PR Status Distribution")
        s = pd.Series(
            [a.get("overall_status", "UNKNOWN") for a in audits_raw]
        ).value_counts().reset_index()
        s.columns = ["Status", "Count"]
        cmap = {"PASSED": "#22c55e", "BLOCKED": "#ef4444", "ERROR": "#6b7280",
                "PENDING": "#eab308", "RUNNING": "#3b82f6", "OVERRIDDEN": "#a855f7"}
        fig = px.pie(s, values="Count", names="Status",
                     color="Status", color_discrete_map=cmap, hole=0.4)
        fig.update_layout(height=280, margin=dict(t=0, b=0))
        st.plotly_chart(fig, use_container_width=True)

    with col_r:
        st.subheader("Findings by Severity")
        all_f = [f for a in audits_raw for f in a.get("findings", [])]
        if all_f:
            sv = pd.Series(
                [f.get("severity", "UNKNOWN") for f in all_f]
            ).value_counts().reset_index()
            sv.columns = ["Severity", "Count"]
            cmap2 = {"CRITICAL": "#ef4444", "HIGH": "#f97316",
                     "MEDIUM": "#eab308", "LOW": "#3b82f6", "INFO": "#6b7280"}
            fig2 = px.bar(sv, x="Severity", y="Count",
                          color="Severity", color_discrete_map=cmap2)
            fig2.update_layout(height=280, margin=dict(t=0, b=0), showlegend=False)
            st.plotly_chart(fig2, use_container_width=True)
        else:
            st.info("No findings yet.")

    # Audit table
    st.subheader("📋 Recent Audits")
    if audits_raw:
        rows = [{
            "Audit ID":   a.get("audit_id", "")[:12] + "…",
            "Repo":       a.get("repo_full_name", ""),
            "PR #":       f"#{a.get('pr_number')}",
            "Status":     a.get("overall_status", ""),
            "Findings":   len(a.get("findings", [])),
            "Started":    (a.get("started_at") or "")[:19].replace("T", " "),
        } for a in audits_raw[:50]]
        df = pd.DataFrame(rows)

        def _color(val: str) -> str:
            return {"PASSED": "color:#22c55e", "BLOCKED": "color:#ef4444",
                    "ERROR": "color:#6b7280", "RUNNING": "color:#3b82f6"}.get(val, "")

        st.dataframe(df.style.map(_color, subset=["Status"]),
                     use_container_width=True, hide_index=True)
    else:
        st.info("No audit data yet. Trigger a PR to start.")


# ══════════════════════════════════════════════════════════════
# PAGE — Audit Details
# ══════════════════════════════════════════════════════════════
elif page == "🔍 Audit Details":
    st.title("🔍 Audit Details")

    if not audits_raw:
        st.info("No audits available.")
        st.stop()

    opts = {
        f"PR #{a.get('pr_number')} | {a.get('repo_full_name')} | {a.get('overall_status')}": a.get("audit_id")
        for a in audits_raw[:60]
    }
    sel   = st.selectbox("Select audit:", list(opts.keys()))
    a_id  = opts.get(sel or "", "")
    audit = load_audit(a_id) if a_id else None

    if not audit:
        st.warning("Select an audit above.")
        st.stop()

    # Action buttons (disabled in demo mode)
    bc1, bc2, _ = st.columns([1, 1, 4])
    with bc1:
        if st.button("🔄 Re-run", disabled=not is_live):
            if api_post(f"/audits/{a_id}/rerun"):
                st.success("Re-run queued!")
                st.cache_data.clear()
    with bc2:
        if audit.get("overall_status") == "BLOCKED":
            if st.button("⚡ Override", disabled=not is_live):
                st.session_state["ovr_id"] = a_id

    if not is_live:
        st.caption("⚠️ Re-run and Override require the API to be running.")

    if st.session_state.get("ovr_id") == a_id:
        with st.form("ovr_form"):
            reason = st.text_area("Override reason (min 10 chars):")
            if st.form_submit_button("Confirm"):
                if len(reason.strip()) >= 10:
                    api_post(f"/audits/{a_id}/override",
                             params={"reason": reason.strip()})
                    st.success("Override applied.")
                    del st.session_state["ovr_id"]
                    st.cache_data.clear()
                else:
                    st.error("Reason too short.")

    # Summary
    status = audit.get("overall_status", "?")
    icon   = "🟢" if status == "PASSED" else ("🔴" if status == "BLOCKED" else "🟡")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Status",   f"{icon} {status}")
    m2.metric("PR",       f"#{audit.get('pr_number')}")
    m3.metric("Findings", len(audit.get("findings", [])))
    m4.metric("Commit",   (audit.get("head_sha") or "")[:8])

    # Findings list
    findings = audit.get("findings", [])
    if findings:
        st.subheader(f"🔎 Findings ({len(findings)})")
        for f in findings:
            sev  = f.get("severity", "INFO")
            ico  = {"CRITICAL": "🔴", "HIGH": "🟠",
                    "MEDIUM": "🟡", "LOW": "🔵"}.get(sev, "⚪")
            patched = bool(f.get("patch") and f.get("patch", {}).get("test_passed"))
            label   = f"{ico} [{sev}] {f.get('rule_id')} — {f.get('title','')}"
            if patched:
                label += " ✅"
            with st.expander(label):
                lc1, lc2 = st.columns(2)
                loc = f.get("location", {})
                with lc1:
                    st.write(f"**File:** `{loc.get('file')}:{loc.get('line_start')}`")
                    st.write(f"**Agent:** `{f.get('agent_id')}`")
                    st.write(f"**OWASP:** {f.get('owasp_category', 'N/A')}")
                with lc2:
                    st.write(f"**Tool:** `{f.get('evidence', {}).get('tool_name')}`")
                    st.write(f"**Rule:** `{f.get('rule_id')}`")
                st.write(f.get("description", ""))
                st.code(loc.get("code_snippet", ""), language="python")
                with st.expander("🔧 Raw Tool Output"):
                    st.code(f.get("evidence", {}).get("raw_output", "{}"), language="json")
                if patched:
                    st.success(f"✅ Verified patch — coverage: "
                               f"{f['patch'].get('coverage_pct', 0):.1f}%")
                    st.code(f["patch"]["patch_diff"], language="diff")
    else:
        st.success("✅ No findings — this PR is clean!")

    cr = audit.get("compliance_report") or {}
    if cr.get("markdown_report"):
        st.subheader("📋 OWASP Compliance Report")
        st.markdown(cr["markdown_report"])


# ══════════════════════════════════════════════════════════════
# PAGE — Agent Traces
# ══════════════════════════════════════════════════════════════
elif page == "🤖 Agent Traces":
    st.title("🤖 Agent Decision Traces")
    st.caption("Raw MCP tool outputs per agent with OTel span context")

    if not audits_raw:
        st.info("No audits yet.")
        st.stop()

    opts = {
        f"PR #{a.get('pr_number')} | {a.get('repo_full_name')}": a.get("audit_id")
        for a in audits_raw[:60]
    }
    sel   = st.selectbox("Select audit:", list(opts.keys()))
    a_id  = opts.get(sel or "", "")
    audit = load_audit(a_id) if a_id else None

    if not audit:
        st.stop()

    agent_meta = {
        "agent_a": ("🔧", "Code Quality  —  ruff · radon · AST"),
        "agent_b": ("🛡️", "Security  —  MCP: Bandit · Semgrep · Trivy"),
        "agent_c": ("🔨", "Patch Engine  —  LLM + Docker sandbox"),
    }

    for m in audit.get("agent_metrics", []):
        aid       = m.get("agent_id", "")
        emo, name = agent_meta.get(aid, ("🤖", aid))
        with st.expander(f"{emo} {aid.upper()} — {name}", expanded=True):
            mc1, mc2, mc3, mc4 = st.columns(4)
            mc1.metric("Files Scanned",   m.get("files_scanned", 0))
            mc2.metric("Duration",        f"{m.get('duration_seconds', 0):.2f}s")
            mc3.metric("Lines Analyzed",  m.get("lines_analyzed", 0))
            mc4.metric("Status", "✅ OK" if not m.get("error") else "❌ Error")

            if m.get("error"):
                st.error(m["error"])

            tool_calls = m.get("tool_calls", [])
            if tool_calls:
                st.markdown(f"**MCP Tool Calls ({len(tool_calls)}):**")
                for tc in tool_calls:
                    st.json(tc)
            else:
                st.caption("No MCP call log recorded for this agent.")

            agent_findings = [
                f for f in audit.get("findings", [])
                if f.get("agent_id") == aid
            ]
            if agent_findings:
                st.markdown(f"**Findings from this agent ({len(agent_findings)}):**")
                for f in agent_findings[:15]:
                    sev = f.get("severity", "INFO")
                    ico = {"CRITICAL": "🔴", "HIGH": "🟠",
                           "MEDIUM": "🟡", "LOW": "🔵"}.get(sev, "⚪")
                    st.markdown(
                        f"{ico} `{f.get('rule_id')}` · "
                        f"`{f.get('evidence', {}).get('tool_name', '')}` → "
                        f"**{f.get('title', '')}**"
                    )


# ══════════════════════════════════════════════════════════════
# PAGE — Cost Dashboard
# ══════════════════════════════════════════════════════════════
elif page == "💰 Cost Dashboard":
    st.title("💰 LLM Token & Cost Dashboard")
    src = "live" if is_live else "demo"
    st.caption(f"OpenTelemetry-traced token consumption · source: **{src}**")

    cost    = load_cost_summary()
    records = load_token_records()

    # KPIs
    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Total LLM Calls",   cost.get("total_calls", 0))
    k2.metric("Total Tokens",       f"{cost.get('total_tokens', 0):,}")
    k3.metric("Total Cost (USD)",   f"${cost.get('total_cost_usd', 0.0):.4f}")
    avg = cost.get("total_cost_usd", 0) / max(cost.get("total_calls", 1), 1)
    k4.metric("Avg Cost / Call",    f"${avg:.4f}")

    st.divider()
    cl, cr = st.columns(2)

    with cl:
        st.subheader("💸 Cost by Model")
        by_model = cost.get("by_model", {})
        if by_model:
            df_m = pd.DataFrame([
                {"Model": k, "Calls": v["calls"],
                 "Tokens": v["tokens"], "Cost ($)": v["cost_usd"]}
                for k, v in by_model.items()
            ])
            fig_m = px.bar(df_m, x="Model", y="Cost ($)", color="Model",
                           text_auto=".4f")
            fig_m.update_layout(height=300, showlegend=False,
                                margin=dict(t=20, b=0))
            st.plotly_chart(fig_m, use_container_width=True)
            st.dataframe(df_m, hide_index=True, use_container_width=True)

    with cr:
        st.subheader("🤖 Cost by Agent")
        by_agent = cost.get("by_agent", {})
        if by_agent:
            df_a = pd.DataFrame([
                {"Agent": k, "Calls": v["calls"],
                 "Tokens": v["tokens"], "Cost ($)": v["cost_usd"]}
                for k, v in by_agent.items()
            ])
            cmap_a = {"agent_a": "#3b82f6", "agent_b": "#ef4444", "agent_c": "#22c55e"}
            fig_a  = px.pie(df_a, values="Cost ($)", names="Agent",
                            color="Agent", color_discrete_map=cmap_a, hole=0.4)
            fig_a.update_layout(height=300, margin=dict(t=20, b=0))
            st.plotly_chart(fig_a, use_container_width=True)

    st.subheader("📈 Token Usage Over Time")
    if records:
        df_r = pd.DataFrame(records)
        df_r["timestamp"] = pd.to_datetime(df_r["timestamp"])
        df_r = df_r.sort_values("timestamp")

        fig_t = px.line(df_r, x="timestamp", y="total_tokens",
                        color="model", markers=True,
                        title="Tokens per LLM call")
        fig_t.update_layout(height=280, margin=dict(t=30, b=0))
        st.plotly_chart(fig_t, use_container_width=True)

        fig_c = px.scatter(df_r, x="timestamp", y="cost_usd",
                           size="total_tokens", color="agent_id",
                           hover_data=["model", "latency_ms"],
                           title="Cost per call  (bubble = token count)")
        fig_c.update_layout(height=280, margin=dict(t=30, b=0))
        st.plotly_chart(fig_c, use_container_width=True)

        cols = ["timestamp", "audit_id", "agent_id", "model",
                "prompt_tokens", "completion_tokens", "cost_usd", "latency_ms"]
        st.subheader("📋 Call Log")
        st.dataframe(df_r[cols].head(100), hide_index=True,
                     use_container_width=True)
    else:
        st.info("No token records yet.")

    st.divider()
    ls_proj = os.getenv("LANGCHAIN_PROJECT", "ai-code-reviewer")
    st.markdown(
        f"**LangSmith traces:** [smith.langchain.com/projects/{ls_proj}]"
        f"(https://smith.langchain.com/projects/{ls_proj})"
    )


# ══════════════════════════════════════════════════════════════
# PAGE — Settings & Setup
# ══════════════════════════════════════════════════════════════
elif page == "⚙️ Settings & Setup":
    st.title("⚙️ Settings & Setup Guide")

    # Live status card
    if is_live:
        st.success(f"✅ API reachable at `{API_BASE_URL}`")
        health = api_get("/health")
        if health:
            st.json(health)
        ready = api_get("/readiness")
        if ready:
            st.json(ready)
    else:
        st.error(f"❌ API not reachable at `{API_BASE_URL}`")
        st.markdown("""
### How to start the full stack

**Step 1 — Install dependencies**
```powershell
pip install -r requirements.txt
```

**Step 2 — Copy the env file and add your keys**
```powershell
copy .env.example .env
# Open .env and set GITHUB_TOKEN and OPENAI_API_KEY
```

**Step 3 — Start Redis (requires Docker Desktop)**
```powershell
docker run -d --name redis -p 6379:6379 redis:7-alpine
```

**Step 4 — Start the FastAPI server**
```powershell
# Open a NEW terminal in this folder
uvicorn api.main:app --reload --port 8000
```

**Step 5 — Refresh this dashboard**

Click **🔄 Refresh Now** in the sidebar — the banner will turn green.

---

> **No Docker / Redis?** The API also starts without Redis:
> set `USE_REDIS_STORE=false` in `.env` and skip Step 3.
""")

    st.divider()
    st.subheader("Spec Reference")
    st.markdown("""
| Section | Rules | Tools |
|---|---|---|
| `quality_rules` | QA-001 → QA-006 | Agent A: ruff, radon, AST |
| `security_rules` | SEC-001 → SEC-010 | Agent B: Bandit, Semgrep, Trivy |
| `patch_rules` | PATCH-001 → PATCH-003 | Agent C: LLM + Docker sandbox |
| `pr_policy` | auto-approve / block | Orchestrator |
| `anti_hallucination` | zero-hallucination | All agents |
""")
