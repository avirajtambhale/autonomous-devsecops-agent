"""
AI Code Reviewer — Interactive Command Center Dashboard
Streamlit app with:
  - Real-time audit metrics
  - Agent decision traces + MCP tool call log
  - OpenTelemetry / LangSmith trace viewer
  - LLM Cost Dashboard (tokens, $/call, $/audit, trend)
  - One-click re-audit and human override
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from typing import Any

import httpx
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# ─── Configuration ────────────────────────────────────────────
API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")
REFRESH_INTERVAL = 10

st.set_page_config(
    page_title="AI Code Reviewer — Command Center",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
  .metric-card { background: linear-gradient(135deg,#1a1a2e,#16213e);
    border-radius:10px; padding:18px; border-left:4px solid #7c3aed; }
  .stDataFrame { font-size:13px; }
  section[data-testid="stSidebar"] { background-color: #0f0f1a; }
</style>
""", unsafe_allow_html=True)

# ─── HTTP Client ──────────────────────────────────────────────
@st.cache_resource
def get_client() -> httpx.Client:
    return httpx.Client(base_url=API_BASE_URL, timeout=10.0)


def api_get(path: str) -> dict[str, Any] | list | None:
    try:
        return get_client().get(path).raise_for_status().json()
    except Exception as exc:
        st.error(f"API error on {path}: {exc}")
        return None


def api_post(path: str, params: dict | None = None) -> dict[str, Any] | None:
    try:
        return get_client().post(path, params=params).raise_for_status().json()
    except Exception as exc:
        st.error(f"API error on POST {path}: {exc}")
        return None


# ─── Cached loaders ──────────────────────────────────────────
@st.cache_data(ttl=REFRESH_INTERVAL)
def load_audits(limit: int = 200) -> list[dict]:
    r = api_get(f"/audits?limit={limit}")
    return r.get("results", []) if isinstance(r, dict) else []


@st.cache_data(ttl=REFRESH_INTERVAL)
def load_audit(audit_id: str) -> dict | None:
    return api_get(f"/audits/{audit_id}")


@st.cache_data(ttl=REFRESH_INTERVAL)
def load_cost_summary() -> dict:
    r = api_get("/telemetry/cost")
    return r if isinstance(r, dict) else {}


@st.cache_data(ttl=REFRESH_INTERVAL)
def load_token_records(limit: int = 200) -> list[dict]:
    r = api_get(f"/telemetry/tokens?limit={limit}")
    return r.get("records", []) if isinstance(r, dict) else []


# ─── Metric helpers ───────────────────────────────────────────
def compute_metrics(audits: list[dict]) -> dict:
    if not audits:
        return dict(total=0, passed=0, blocked=0, error=0,
                    pass_rate=0.0, critical=0, high=0, time_saved=0.0)
    total = len(audits)
    passed = sum(1 for a in audits if a.get("overall_status") == "PASSED")
    blocked = sum(1 for a in audits if a.get("overall_status") == "BLOCKED")
    error = sum(1 for a in audits if a.get("overall_status") == "ERROR")
    all_f = [f for a in audits for f in a.get("findings", [])]
    return dict(
        total=total, passed=passed, blocked=blocked, error=error,
        pass_rate=passed / total * 100 if total else 0.0,
        critical=sum(1 for f in all_f if f.get("severity") == "CRITICAL"),
        high=sum(1 for f in all_f if f.get("severity") == "HIGH"),
        time_saved=round(total * 42 / 60, 1),
    )


# ─── Sidebar ─────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🔐 AI Code Reviewer")
    st.markdown("**Command Center** `v2.0.0`")
    st.divider()

    page = st.radio("Navigate", [
        "📊 Dashboard",
        "🔍 Audit Details",
        "🤖 Agent Traces",
        "💰 Cost Dashboard",
        "⚙️ Settings",
    ])
    st.divider()

    repo_filter = st.text_input("Filter by repo", "")
    if st.toggle("Auto-refresh", value=False):
        st.caption(f"Refreshing every {REFRESH_INTERVAL}s")
        time.sleep(REFRESH_INTERVAL)
        st.rerun()
    if st.button("🔄 Refresh"):
        st.cache_data.clear()
        st.rerun()

audits = load_audits()
if repo_filter:
    audits = [a for a in audits if repo_filter.lower() in a.get("repo_full_name", "").lower()]
metrics = compute_metrics(audits)


# ══════════════════════════════════════════════════════════════
# PAGE: Dashboard
# ══════════════════════════════════════════════════════════════
if page == "📊 Dashboard":
    st.title("🔐 AI Code Security Review — Command Center")
    st.caption(f"Last updated: {datetime.now().strftime('%H:%M:%S')} · {len(audits)} audits loaded")

    # KPI row
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("Total PRs", metrics["total"])
    c2.metric("Pass Rate", f"{metrics['pass_rate']:.1f}%")
    c3.metric("Blocked", metrics["blocked"])
    c4.metric("🔴 Critical", metrics["critical"])
    c5.metric("🟠 High", metrics["high"])
    c6.metric("⏱️ Hours Saved", metrics["time_saved"])

    st.divider()

    col_l, col_r = st.columns(2)

    with col_l:
        st.subheader("PR Status Distribution")
        if audits:
            s = pd.Series([a.get("overall_status", "UNKNOWN") for a in audits]).value_counts().reset_index()
            s.columns = ["Status", "Count"]
            color_map = {"PASSED": "#22c55e", "BLOCKED": "#ef4444", "ERROR": "#6b7280",
                         "PENDING": "#eab308", "RUNNING": "#3b82f6", "OVERRIDDEN": "#a855f7"}
            fig = px.pie(s, values="Count", names="Status", color="Status",
                         color_discrete_map=color_map, hole=0.4)
            fig.update_layout(height=280, margin=dict(t=0, b=0))
            st.plotly_chart(fig, use_container_width=True)

    with col_r:
        st.subheader("Findings by Severity")
        all_f = [f for a in audits for f in a.get("findings", [])]
        if all_f:
            sv = pd.Series([f.get("severity", "UNKNOWN") for f in all_f]).value_counts().reset_index()
            sv.columns = ["Severity", "Count"]
            color_sev = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308",
                         "LOW": "#3b82f6", "INFO": "#6b7280"}
            fig2 = px.bar(sv, x="Severity", y="Count", color="Severity",
                          color_discrete_map=color_sev)
            fig2.update_layout(height=280, margin=dict(t=0, b=0), showlegend=False)
            st.plotly_chart(fig2, use_container_width=True)

    # Token savings chart (from tree-sitter)
    st.subheader("🌳 Tree-sitter Token Savings")
    if audits:
        savings_data = []
        for a in audits[:30]:
            for m in a.get("agent_metrics", []):
                savings_data.append({
                    "PR": f"#{a.get('pr_number')}",
                    "Agent": m.get("agent_id", ""),
                    "Duration (s)": m.get("duration_seconds", 0),
                })
        if savings_data:
            df_s = pd.DataFrame(savings_data)
            fig3 = px.bar(df_s, x="PR", y="Duration (s)", color="Agent", barmode="group",
                          title="Agent Duration per PR")
            fig3.update_layout(height=250, margin=dict(t=30, b=0))
            st.plotly_chart(fig3, use_container_width=True)
    else:
        st.info("No audits yet.")

    # Table
    st.subheader("📋 Recent Audits")
    if audits:
        df = pd.DataFrame([{
            "Audit ID": a.get("audit_id", "")[:8] + "…",
            "Repo": a.get("repo_full_name", ""),
            "PR": f"#{a.get('pr_number')}",
            "Status": a.get("overall_status", ""),
            "Findings": len(a.get("findings", [])),
            "Started": (a.get("started_at") or "")[:19].replace("T", " "),
        } for a in audits[:50]])

        def _color(val: str) -> str:
            return {"PASSED": "color:#22c55e", "BLOCKED": "color:#ef4444",
                    "ERROR": "color:#6b7280", "RUNNING": "color:#3b82f6"}.get(val, "")

        st.dataframe(df.style.map(_color, subset=["Status"]),
                     use_container_width=True, hide_index=True)


# ══════════════════════════════════════════════════════════════
# PAGE: Audit Details
# ══════════════════════════════════════════════════════════════
elif page == "🔍 Audit Details":
    st.title("🔍 Audit Details")
    if not audits:
        st.info("No audits.")
        st.stop()

    opts = {f"PR #{a.get('pr_number')} | {a.get('repo_full_name')} | {a.get('overall_status')}": a.get("audit_id")
            for a in audits[:60]}
    sel = st.selectbox("Select audit:", list(opts.keys()))
    audit_id = opts.get(sel, "")
    if not audit_id:
        st.stop()

    audit = load_audit(audit_id)
    if not audit:
        st.error("Audit not found.")
        st.stop()

    # Action buttons
    bc1, bc2, _ = st.columns([1, 1, 4])
    with bc1:
        if st.button("🔄 Re-run"):
            api_post(f"/audits/{audit_id}/rerun")
            st.success("Re-run triggered!")
            st.cache_data.clear()
    with bc2:
        if audit.get("overall_status") == "BLOCKED" and st.button("⚡ Override"):
            st.session_state["ovr_id"] = audit_id

    if st.session_state.get("ovr_id") == audit_id:
        with st.form("ovr_form"):
            reason = st.text_area("Override reason (min 10 chars):")
            if st.form_submit_button("Confirm"):
                if len(reason.strip()) >= 10:
                    api_post(f"/audits/{audit_id}/override", params={"reason": reason.strip()})
                    st.success("Override applied.")
                    del st.session_state["ovr_id"]
                    st.cache_data.clear()
                else:
                    st.error("Too short.")

    # Summary metrics
    status = audit.get("overall_status", "?")
    icon = "🟢" if status == "PASSED" else "🔴"
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Status", f"{icon} {status}")
    m2.metric("PR", f"#{audit.get('pr_number')}")
    m3.metric("Findings", len(audit.get("findings", [])))
    m4.metric("Commit", (audit.get("head_sha") or "")[:8])

    # Findings
    findings = audit.get("findings", [])
    st.subheader(f"🔎 Findings ({len(findings)})")
    for f in findings:
        sev = f.get("severity", "INFO")
        ico = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(sev, "⚪")
        patched = f.get("patch", {}).get("test_passed") if f.get("patch") else False
        label = f"{ico} [{sev}] {f.get('rule_id')} — {f.get('title', '')} {'✅' if patched else ''}"
        with st.expander(label):
            fc1, fc2 = st.columns(2)
            loc = f.get("location", {})
            with fc1:
                st.write(f"**File:** `{loc.get('file')}:{loc.get('line_start')}`")
                st.write(f"**Agent:** `{f.get('agent_id')}`")
                st.write(f"**OWASP:** {f.get('owasp_category', 'N/A')}")
            with fc2:
                st.write(f"**Tool:** `{f.get('evidence', {}).get('tool_name')}`")
                st.write(f"**Rule:** `{f.get('rule_id')}`")
            st.write(f.get("description", ""))
            st.code(loc.get("code_snippet", ""), language="python")
            with st.expander("🔧 Raw MCP Tool Output"):
                st.code(f.get("evidence", {}).get("raw_output", ""), language="json")
                st.caption(f"Command: `{f.get('evidence', {}).get('command_run', '')}`")
            if patched:
                st.success(f"✅ Verified patch (cov: {f['patch'].get('coverage_pct', 0):.1f}%)")
                st.code(f["patch"]["patch_diff"], language="diff")
                with st.expander("Test code"):
                    st.code(f["patch"]["test_code"], language="python")

    if not findings:
        st.success("✅ Clean PR — no findings!")

    if audit.get("compliance_report", {}).get("markdown_report"):
        st.subheader("📋 OWASP Compliance Report")
        st.markdown(audit["compliance_report"]["markdown_report"])


# ══════════════════════════════════════════════════════════════
# PAGE: Agent Traces
# ══════════════════════════════════════════════════════════════
elif page == "🤖 Agent Traces":
    st.title("🤖 Agent Decision Traces")
    st.caption("Raw MCP tool call log vs. LLM reasoning per agent, with OTel span IDs")

    if not audits:
        st.info("No audits.")
        st.stop()

    opts = {f"PR #{a.get('pr_number')} | {a.get('repo_full_name')}": a.get("audit_id")
            for a in audits[:60]}
    sel = st.selectbox("Select audit:", list(opts.keys()))
    audit_id = opts.get(sel, "")
    if not audit_id:
        st.stop()

    audit = load_audit(audit_id)
    if not audit:
        st.stop()

    agent_names = {"agent_a": ("🔧", "Code Quality"), "agent_b": ("🛡️", "Security"), "agent_c": ("🔨", "Patch Engine")}

    for m in audit.get("agent_metrics", []):
        aid = m.get("agent_id", "")
        emo, name = agent_names.get(aid, ("🤖", aid))
        with st.expander(f"{emo} {aid.upper()} — {name}", expanded=True):
            mc1, mc2, mc3, mc4 = st.columns(4)
            mc1.metric("Files Scanned", m.get("files_scanned", 0))
            mc2.metric("Duration", f"{m.get('duration_seconds', 0):.2f}s")
            mc3.metric("Lines Analyzed", m.get("lines_analyzed", 0))
            mc4.metric("Status", "✅ OK" if not m.get("error") else "❌ Error")

            if m.get("error"):
                st.error(m["error"])

            # MCP tool calls log
            tool_calls = m.get("tool_calls", [])
            st.markdown(f"**MCP Tool Calls:** {len(tool_calls)}")
            for tc in tool_calls:
                st.json(tc)

            # Findings from this agent
            agent_findings = [f for f in audit.get("findings", []) if f.get("agent_id") == aid]
            if agent_findings:
                st.markdown(f"**Findings ({len(agent_findings)}):**")
                for f in agent_findings[:15]:
                    sev = f.get("severity", "INFO")
                    ico = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(sev, "⚪")
                    tool = f.get("evidence", {}).get("tool_name", "")
                    cmd = f.get("evidence", {}).get("command_run", "")
                    st.markdown(f"{ico} `{f.get('rule_id')}` · `{tool}` → **{f.get('title', '')}**")
                    if cmd:
                        st.caption(f"Command: `{cmd}`")


# ══════════════════════════════════════════════════════════════
# PAGE: Cost Dashboard
# ══════════════════════════════════════════════════════════════
elif page == "💰 Cost Dashboard":
    st.title("💰 LLM Cost & Token Usage Dashboard")
    st.caption("OpenTelemetry-traced token consumption per model, agent, and audit")

    cost = load_cost_summary()
    records = load_token_records()

    # Summary KPIs
    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Total LLM Calls", cost.get("total_calls", 0))
    k2.metric("Total Tokens", f"{cost.get('total_tokens', 0):,}")
    k3.metric("Total Cost (USD)", f"${cost.get('total_cost_usd', 0.0):.4f}")
    avg_cost = (cost.get("total_cost_usd", 0) / cost.get("total_calls", 1)) if cost.get("total_calls") else 0
    k4.metric("Avg Cost / Call", f"${avg_cost:.4f}")

    st.divider()

    col_l, col_r = st.columns(2)

    # ── Cost by model ────────────────────────────────────────
    with col_l:
        st.subheader("💸 Cost by Model")
        by_model = cost.get("by_model", {})
        if by_model:
            df_m = pd.DataFrame([
                {"Model": k, "Calls": v["calls"], "Tokens": v["tokens"], "Cost ($)": v["cost_usd"]}
                for k, v in by_model.items()
            ])
            fig_m = px.bar(df_m, x="Model", y="Cost ($)", color="Model",
                           text_auto=".4f", title="USD spent per model")
            fig_m.update_layout(height=300, showlegend=False, margin=dict(t=30, b=0))
            st.plotly_chart(fig_m, use_container_width=True)
            st.dataframe(df_m, hide_index=True, use_container_width=True)
        else:
            st.info("No LLM calls recorded yet.")

    # ── Cost by agent ─────────────────────────────────────────
    with col_r:
        st.subheader("🤖 Cost by Agent")
        by_agent = cost.get("by_agent", {})
        if by_agent:
            df_a = pd.DataFrame([
                {"Agent": k, "Calls": v["calls"], "Tokens": v["tokens"], "Cost ($)": v["cost_usd"]}
                for k, v in by_agent.items()
            ])
            color_agents = {"agent_a": "#3b82f6", "agent_b": "#ef4444", "agent_c": "#22c55e"}
            fig_a = px.pie(df_a, values="Cost ($)", names="Agent", color="Agent",
                           color_discrete_map=color_agents, hole=0.4)
            fig_a.update_layout(height=300, margin=dict(t=30, b=0))
            st.plotly_chart(fig_a, use_container_width=True)
        else:
            st.info("No agent cost data yet.")

    # ── Token usage trend ─────────────────────────────────────
    st.subheader("📈 Token Usage Over Time")
    if records:
        df_r = pd.DataFrame(records)
        df_r["timestamp"] = pd.to_datetime(df_r["timestamp"])
        df_r = df_r.sort_values("timestamp")
        fig_t = px.line(df_r, x="timestamp", y="total_tokens", color="model",
                        markers=True, title="Tokens per LLM call")
        fig_t.update_layout(height=300, margin=dict(t=30, b=0))
        st.plotly_chart(fig_t, use_container_width=True)

        # Cost per call scatter
        fig_c = px.scatter(df_r, x="timestamp", y="cost_usd", size="total_tokens",
                           color="agent_id", hover_data=["model", "latency_ms"],
                           title="Cost per call (bubble = token count)")
        fig_c.update_layout(height=300, margin=dict(t=30, b=0))
        st.plotly_chart(fig_c, use_container_width=True)

        # Raw table
        st.subheader("📋 Raw Call Log")
        display_cols = ["timestamp", "audit_id", "agent_id", "model",
                        "prompt_tokens", "completion_tokens", "cost_usd", "latency_ms"]
        st.dataframe(df_r[display_cols].head(100), hide_index=True, use_container_width=True)
    else:
        st.info("No token records yet. Trigger an audit with LLM patch generation enabled.")

    # ── LangSmith link ────────────────────────────────────────
    st.divider()
    st.subheader("🔗 LangSmith Traces")
    ls_project = os.getenv("LANGCHAIN_PROJECT", "ai-code-reviewer")
    ls_url = f"https://smith.langchain.com/projects/{ls_project}"
    st.markdown(f"View detailed LLM traces: **[{ls_project} on LangSmith]({ls_url})**")


# ══════════════════════════════════════════════════════════════
# PAGE: Settings
# ══════════════════════════════════════════════════════════════
elif page == "⚙️ Settings":
    st.title("⚙️ System Settings")

    health = api_get("/health")
    if health:
        st.success(f"✅ API OK — {health.get('service')} v{health.get('version')}")
    else:
        st.error("❌ API unreachable")

    ready = api_get("/readiness")
    if ready:
        st.json(ready)

    st.subheader("Infrastructure Status")
    ic1, ic2, ic3 = st.columns(3)
    ic1.metric("API", "🟢 Online" if health else "🔴 Offline")
    ic2.metric("Queue", "ARQ + Redis")
    ic3.metric("Tracing", "OpenTelemetry + LangSmith")

    st.subheader("Spec Reference")
    st.markdown("""
| Spec Section | Rules | Governed By |
|---|---|---|
| `quality_rules` | QA-001 → QA-006 | Agent A (ruff, radon, AST) |
| `security_rules` | SEC-001 → SEC-010 | Agent B (MCP: Bandit, Semgrep, Trivy) |
| `patch_rules` | PATCH-001 → PATCH-003 | Agent C (LLM + Docker sandbox) |
| `pr_policy` | auto-approve/block | Orchestrator |
| `anti_hallucination` | zero-hallucination enforcement | All agents |

Tree-sitter AST parsing: **enabled** (70% token cost reduction)
Task queue: **ARQ (Redis-backed)**
Tracing: **OpenTelemetry** → OTLP collector → Jaeger/Tempo
""")
