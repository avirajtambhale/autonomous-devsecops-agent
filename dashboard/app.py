"""
AI Code Reviewer — Command Center Dashboard  v2.1
=================================================
FIXED:
  - Nested st.expander crash (StreamlitAPIException line 466)
  - Raw tool output shown in st.container / st.code (not nested expander)

MODES:
  ONLINE  → FastAPI running at API_BASE_URL  → live audit data
  OFFLINE → API unreachable                  → realistic demo data

LIVE DATA CONFIG:
  Set API_BASE_URL in Streamlit Cloud Secrets:
    API_BASE_URL = "https://your-api.railway.app"

LOCAL RUN:
  streamlit run dashboard/app.py
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

try:
    import httpx
    _HTTPX = True
except ImportError:
    _HTTPX = False

# ── Config ────────────────────────────────────────────────────
API_BASE_URL    = os.getenv("API_BASE_URL", "http://localhost:8000")
REFRESH_TTL     = 15     # seconds between cache refresh
API_TIMEOUT     = 2.5    # fail-fast so offline detection is instant
ONLINE_CHECK_TTL = 5     # seconds between liveness probes

# ── Page config ───────────────────────────────────────────────
st.set_page_config(
    page_title="AI Code Reviewer · DevSecOps Agent",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        "Get Help": "https://github.com/avirajtambhale/autonomous-devsecops-agent",
        "Report a bug": "https://github.com/avirajtambhale/autonomous-devsecops-agent/issues",
        "About": "# 🔐 Autonomous DevSecOps Agent\nProduction-grade AI code review.",
    },
)

# ── Premium CSS ───────────────────────────────────────────────
st.markdown("""
<style>
  /* Sidebar */
  section[data-testid="stSidebar"] {background:#0a0a1a;}
  /* Metric cards */
  [data-testid="metric-container"] {
    background:linear-gradient(135deg,#1a1a2e,#16213e);
    border:1px solid #2d2d4e; border-radius:10px; padding:12px;
  }
  /* Tables */
  .stDataFrame {font-size:13px;}
  /* Banner */
  .banner-online  {background:#052e16;border:1px solid #16a34a;
    border-radius:8px;padding:10px 16px;color:#86efac;margin-bottom:8px;}
  .banner-offline {background:#1c0505;border:1px solid #b91c1c;
    border-radius:8px;padding:10px 16px;color:#fca5a5;margin-bottom:8px;}
  /* Section headers */
  h2 {border-bottom:1px solid #2d2d4e; padding-bottom:4px;}
</style>
""", unsafe_allow_html=True)

# ═════════════════════════════════════════════════════════════
# API CLIENT  (online / offline detection)
# ═════════════════════════════════════════════════════════════

@st.cache_data(ttl=ONLINE_CHECK_TTL)
def _api_online() -> bool:
    if not _HTTPX:
        return False
    try:
        r = httpx.get(f"{API_BASE_URL}/health", timeout=API_TIMEOUT)
        return r.status_code == 200
    except Exception:
        return False


def api_get(path: str) -> Any:
    if not _HTTPX or not _api_online():
        return None
    try:
        r = httpx.get(f"{API_BASE_URL}{path}", timeout=API_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


def api_post(path: str, params: dict | None = None) -> Any:
    if not _HTTPX or not _api_online():
        return None
    try:
        r = httpx.post(f"{API_BASE_URL}{path}", params=params, timeout=API_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


# ═════════════════════════════════════════════════════════════
# DEMO DATA
# ═════════════════════════════════════════════════════════════

def _demo_finding(sev: str, rule: str, agent: str, fname: str, line: int) -> dict:
    _titles = {
        "SEC-001": "Hardcoded API key in source code",
        "SEC-002": "SQL injection via f-string query",
        "SEC-003": "XSS: unescaped user input in template",
        "SEC-007": "CVE-2024-1234 in requests==2.28.0",
        "QA-001":  "Cyclomatic complexity 14 > threshold 10",
        "QA-003":  "E501 line too long (102 > 100 chars)",
    }
    _owasp = {
        "SEC-001": "A02:2021 – Cryptographic Failures",
        "SEC-002": "A03:2021 – Injection",
        "SEC-003": "A03:2021 – Injection",
        "SEC-007": "A06:2021 – Vulnerable Components",
        "QA-001":  "N/A",
        "QA-003":  "N/A",
    }
    _snippets = {
        "SEC-001": 'API_KEY = "sk-prod-abc123xyz789"',
        "SEC-002": 'cursor.execute(f"SELECT * FROM users WHERE id={uid}")',
        "SEC-003": 'return render_template("page.html", name=request.args["name"])',
        "SEC-007": "requests==2.28.0",
        "QA-001":  "def process_order(cart, user, promo, tax, ship, gift):",
        "QA-003":  "x = some_very_long_variable_name + another_very_long_variable_name  # noqa",
    }
    return {
        "finding_id": f"demo-{rule}-{line}",
        "rule_id": rule,
        "agent_id": agent,
        "severity": sev,
        "title": _titles.get(rule, rule),
        "description": (
            f"**{_titles.get(rule, rule)}** detected at `{fname}:{line}`. "
            "This is demo data — connect the API for real analysis."
        ),
        "owasp_category": _owasp.get(rule, "N/A"),
        "suppressed": False,
        "location": {
            "file": fname, "line_start": line,
            "code_snippet": _snippets.get(rule, f"# line {line}"),
        },
        "evidence": {
            "tool_name": {"agent_b": "bandit", "agent_a": "ruff"}.get(agent, "demo"),
            "raw_output": '{"test_id": "' + rule + '", "severity": "' + sev + '"}',
            "command_run": f"bandit -r {fname} --format json",
        },
        "patch": {
            "patch_diff": (
                f"--- a/{fname}\n+++ b/{fname}\n"
                f"@@ -{line},1 +{line},1 @@\n"
                f"-{_snippets.get(rule, '# old')}\n"
                f"+# FIXED: use environment variable or parameterized query\n"
                f"+import os\n+SAFE_VALUE = os.environ.get('CONFIG_KEY', '')"
            ),
            "test_code": (
                "import os, pytest\n"
                "def test_fix():\n"
                "    assert os.environ.get('CONFIG_KEY') is not None or True\n"
            ),
            "test_passed": sev in ("CRITICAL", "HIGH"),
            "coverage_pct": 87.3 if sev in ("CRITICAL", "HIGH") else None,
            "confidence_score": 0.91 if sev in ("CRITICAL", "HIGH") else 0.72,
        } if sev in ("CRITICAL", "HIGH") else None,
    }


def _demo_audits() -> list[dict]:
    statuses = ["PASSED", "BLOCKED", "PASSED", "PASSED", "BLOCKED", "PASSED", "ERROR"]
    repos    = ["owner/webapp", "owner/api-service", "owner/cli-tool"]
    now      = datetime.now(timezone.utc)
    result   = []
    for i, status in enumerate(statuses):
        ts       = (now - timedelta(hours=i * 4)).isoformat()
        findings: list[dict] = []
        if status == "BLOCKED":
            findings = [
                _demo_finding("CRITICAL", "SEC-001", "agent_b", "src/auth.py",    42),
                _demo_finding("HIGH",     "SEC-002", "agent_b", "src/models.py",  17),
                _demo_finding("MEDIUM",   "QA-001",  "agent_a", "src/utils.py",    5),
                _demo_finding("LOW",      "QA-003",  "agent_a", "src/helpers.py", 88),
            ]
        elif status == "PASSED":
            findings = [_demo_finding("LOW", "QA-003", "agent_a", "src/main.py", 10)]
        result.append({
            "audit_id":       f"demo-audit-{i:03d}",
            "pr_number":      100 + i,
            "repo_full_name": repos[i % len(repos)],
            "head_sha":       f"a{i}b{i}c{i}d{i}e{i}f{i}",
            "overall_status": status,
            "started_at":     ts,
            "completed_at":   ts,
            "findings":       findings,
            "agent_metrics": [
                {"agent_id": "agent_a", "files_scanned": 4,
                 "duration_seconds": 1.4, "lines_analyzed": 312, "tool_calls": [], "error": None},
                {"agent_id": "agent_b", "files_scanned": 4,
                 "duration_seconds": 5.2, "lines_analyzed": 312, "tool_calls": [], "error": None},
                {"agent_id": "agent_c", "files_scanned": 0,
                 "duration_seconds": 8.7, "lines_analyzed": 0,   "tool_calls": [], "error": None},
            ],
            "compliance_report": {
                "markdown_report": (
                    "## 🛡️ OWASP Top 10 Compliance Report\n\n"
                    f"**PR #{100+i}** · `{repos[i % len(repos)]}` · "
                    f"Status: **{status}**\n\n"
                    "| Category | Status |\n|---|---|\n"
                    "| A01 Broken Access Control | ✅ Pass |\n"
                    "| A02 Cryptographic Failures | "
                    + ("❌ 1 finding" if status == "BLOCKED" else "✅ Pass") + " |\n"
                    "| A03 Injection | "
                    + ("❌ 1 finding" if status == "BLOCKED" else "✅ Pass") + " |\n"
                    "| A04-A10 | ✅ Pass |\n\n"
                    "*Demo data — connect the API for real OWASP analysis.*"
                ),
            },
        })
    return result


def _demo_cost() -> dict:
    return {
        "total_calls": 14, "total_tokens": 28_400, "total_cost_usd": 0.2130,
        "by_model": {
            "gpt-4o":      {"calls": 10, "tokens": 21_000, "cost_usd": 0.1575},
            "gpt-4o-mini": {"calls":  4, "tokens":  7_400, "cost_usd": 0.0555},
        },
        "by_agent": {
            "agent_c": {"calls": 14, "tokens": 28_400, "cost_usd": 0.2130},
        },
    }


def _demo_tokens() -> list[dict]:
    now = datetime.now(timezone.utc)
    return [
        {
            "timestamp":         (now - timedelta(minutes=i * 18)).isoformat(),
            "audit_id":          f"demo-audit-{i % 7:03d}",
            "agent_id":          "agent_c",
            "model":             "gpt-4o" if i % 3 != 0 else "gpt-4o-mini",
            "prompt_tokens":     random.randint(600, 1800),
            "completion_tokens": random.randint(200, 600),
            "total_tokens":      random.randint(800, 2400),
            "cost_usd":          round(random.uniform(0.004, 0.025), 5),
            "latency_ms":        random.randint(900, 3200),
        }
        for i in range(14)
    ]


# ═════════════════════════════════════════════════════════════
# DATA LOADERS
# ═════════════════════════════════════════════════════════════

@st.cache_data(ttl=REFRESH_TTL)
def load_audits(limit: int = 200) -> tuple[list[dict], bool]:
    r = api_get(f"/audits?limit={limit}")
    if r and isinstance(r, dict) and "results" in r:
        return r["results"], True
    return _demo_audits(), False


@st.cache_data(ttl=REFRESH_TTL)
def load_audit(audit_id: str) -> dict | None:
    if not audit_id.startswith("demo-"):
        return api_get(f"/audits/{audit_id}")
    return next((a for a in _demo_audits() if a["audit_id"] == audit_id), None)


@st.cache_data(ttl=REFRESH_TTL)
def load_cost() -> dict:
    r = api_get("/telemetry/cost")
    return r if (r and isinstance(r, dict)) else _demo_cost()


@st.cache_data(ttl=REFRESH_TTL)
def load_tokens() -> list[dict]:
    r = api_get("/telemetry/tokens?limit=200")
    return r.get("records", []) if (r and isinstance(r, dict)) else _demo_tokens()


def compute_metrics(audits: list[dict]) -> dict:
    if not audits:
        return dict(total=0, passed=0, blocked=0, error=0,
                    pass_rate=0.0, critical=0, high=0, patched=0, time_saved=0.0)
    total   = len(audits)
    passed  = sum(1 for a in audits if a.get("overall_status") == "PASSED")
    blocked = sum(1 for a in audits if a.get("overall_status") == "BLOCKED")
    error   = sum(1 for a in audits if a.get("overall_status") == "ERROR")
    all_f   = [f for a in audits for f in a.get("findings", [])]
    patched = sum(1 for f in all_f if f.get("patch") and f["patch"].get("test_passed"))
    return dict(
        total=total, passed=passed, blocked=blocked, error=error,
        pass_rate=passed / total * 100 if total else 0.0,
        critical=sum(1 for f in all_f if f.get("severity") == "CRITICAL"),
        high=sum(1 for f in all_f if f.get("severity") == "HIGH"),
        patched=patched,
        time_saved=round(total * 42 / 60, 1),
    )


# ═════════════════════════════════════════════════════════════
# SIDEBAR
# ═════════════════════════════════════════════════════════════

with st.sidebar:
    st.image(
        "https://img.icons8.com/fluency/96/security-shield-green.png",
        width=56,
    )
    st.markdown("## AI Code Reviewer")
    st.markdown("**Autonomous DevSecOps Agent** `v2.1`")
    st.divider()

    page = st.radio(
        "Navigate",
        ["📊 Dashboard", "🔍 Audit Details",
         "🤖 Agent Traces", "💰 Cost Dashboard", "⚙️ Settings"],
        label_visibility="collapsed",
    )
    st.divider()

    repo_filter = st.text_input("🔍 Filter by repo", "")

    col_a, col_b = st.columns(2)
    with col_a:
        if st.button("🔄 Refresh", use_container_width=True):
            st.cache_data.clear()
            st.rerun()
    with col_b:
        auto = st.toggle("Auto", value=False, help="Auto-refresh every 15s")
    if auto:
        time.sleep(REFRESH_TTL)
        st.rerun()

    st.divider()
    live = _api_online()
    if live:
        st.success("API Online", icon="✅")
    else:
        st.warning("API Offline", icon="⚠️")
    st.caption(f"`{API_BASE_URL}`")

# ── Load data ─────────────────────────────────────────────────
audits_raw, is_live = load_audits()
if repo_filter:
    audits_raw = [
        a for a in audits_raw
        if repo_filter.lower() in a.get("repo_full_name", "").lower()
    ]
metrics = compute_metrics(audits_raw)
src_lbl = "🟢 live" if is_live else "🟡 demo"

# ── Top banner ────────────────────────────────────────────────
if is_live:
    st.markdown(
        f'<div class="banner-online">✅ <b>API Online</b> · live data '
        f'from <code>{API_BASE_URL}</code></div>',
        unsafe_allow_html=True,
    )
else:
    st.markdown(
        '<div class="banner-offline">⚠️ <b>API Offline</b> · showing demo data · '
        'start API: <code>uvicorn api.main:app --reload --port 8000</code> · '
        'or set <code>API_BASE_URL</code> in Streamlit secrets</div>',
        unsafe_allow_html=True,
    )


# ═════════════════════════════════════════════════════════════
# PAGE — Dashboard
# ═════════════════════════════════════════════════════════════
if page == "📊 Dashboard":
    st.title("🔐 AI Code Security Review — Command Center")
    st.caption(f"{datetime.now().strftime('%H:%M:%S')} · {len(audits_raw)} audits · {src_lbl}")

    # ── KPI row ──────────────────────────────────────────────
    k1, k2, k3, k4, k5, k6, k7 = st.columns(7)
    k1.metric("Total PRs",      metrics["total"])
    k2.metric("✅ Passed",       metrics["passed"])
    k3.metric("❌ Blocked",      metrics["blocked"])
    k4.metric("Pass Rate",      f"{metrics['pass_rate']:.0f}%")
    k5.metric("🔴 Critical",    metrics["critical"])
    k6.metric("🩹 Auto-patched", metrics["patched"])
    k7.metric("⏱ Hours Saved",  metrics["time_saved"])

    st.divider()
    col_l, col_r = st.columns(2)

    with col_l:
        st.subheader("PR Status")
        s = (pd.Series([a.get("overall_status", "?") for a in audits_raw])
               .value_counts().reset_index())
        s.columns = ["Status", "Count"]
        cmap = {"PASSED": "#22c55e", "BLOCKED": "#ef4444", "ERROR": "#6b7280",
                "PENDING": "#eab308", "RUNNING": "#3b82f6", "OVERRIDDEN": "#a855f7"}
        fig = px.pie(s, values="Count", names="Status", color="Status",
                     color_discrete_map=cmap, hole=0.45)
        fig.update_layout(height=260, margin=dict(t=0, b=0, l=0, r=0),
                          legend=dict(orientation="h", y=-0.15))
        st.plotly_chart(fig, use_container_width=True)

    with col_r:
        st.subheader("Findings by Severity")
        all_f = [f for a in audits_raw for f in a.get("findings", [])]
        if all_f:
            sv = (pd.Series([f.get("severity", "?") for f in all_f])
                    .value_counts().reset_index())
            sv.columns = ["Severity", "Count"]
            cmap2 = {"CRITICAL": "#ef4444", "HIGH": "#f97316",
                     "MEDIUM":   "#eab308", "LOW":  "#3b82f6", "INFO": "#6b7280"}
            fig2 = px.bar(sv, x="Severity", y="Count",
                          color="Severity", color_discrete_map=cmap2)
            fig2.update_layout(height=260, margin=dict(t=0, b=0), showlegend=False)
            st.plotly_chart(fig2, use_container_width=True)
        else:
            st.info("No findings yet.")

    # ── Audit table ──────────────────────────────────────────
    st.subheader("📋 Recent Audits")
    if audits_raw:
        df = pd.DataFrame([{
            "ID":       a["audit_id"][:10] + "…",
            "Repo":     a.get("repo_full_name", ""),
            "PR":       f"#{a.get('pr_number')}",
            "Status":   a.get("overall_status", ""),
            "Findings": len(a.get("findings", [])),
            "Patched":  sum(1 for f in a.get("findings", [])
                           if f.get("patch") and f["patch"].get("test_passed")),
            "Started":  (a.get("started_at") or "")[:19].replace("T", " "),
        } for a in audits_raw[:50]])

        def _c(v: str) -> str:
            return {"PASSED": "color:#22c55e", "BLOCKED": "color:#ef4444",
                    "ERROR":  "color:#6b7280", "RUNNING": "color:#3b82f6"}.get(v, "")

        st.dataframe(df.style.map(_c, subset=["Status"]),
                     use_container_width=True, hide_index=True)
    else:
        st.info("Trigger a GitHub PR to see audits here.")


# ═════════════════════════════════════════════════════════════
# PAGE — Audit Details
# ═════════════════════════════════════════════════════════════
elif page == "🔍 Audit Details":
    st.title("🔍 Audit Details")

    if not audits_raw:
        st.info("No audits available.")
        st.stop()

    opts = {
        f"PR #{a.get('pr_number')} · {a.get('repo_full_name')} · {a.get('overall_status')}":
        a.get("audit_id")
        for a in audits_raw[:60]
    }
    sel   = st.selectbox("Select audit", list(opts.keys()))
    a_id  = opts.get(sel or "", "")
    audit = load_audit(a_id) if a_id else None

    if not audit:
        st.warning("Select an audit above.")
        st.stop()

    # ── Action bar ───────────────────────────────────────────
    ab1, ab2, ab3 = st.columns([1, 1, 4])
    with ab1:
        if st.button("🔄 Re-run", disabled=not is_live, use_container_width=True):
            if api_post(f"/audits/{a_id}/rerun"):
                st.success("Re-queued!")
                st.cache_data.clear()
    with ab2:
        if audit.get("overall_status") == "BLOCKED":
            if st.button("⚡ Override", disabled=not is_live, use_container_width=True):
                st.session_state["ovr_id"] = a_id
    if not is_live:
        st.caption("Re-run and Override require the API to be online.")

    if st.session_state.get("ovr_id") == a_id:
        with st.form("ovr_form"):
            reason = st.text_area("Override reason (min 10 chars):")
            if st.form_submit_button("✅ Confirm Override"):
                if len(reason.strip()) >= 10:
                    api_post(f"/audits/{a_id}/override",
                             params={"reason": reason.strip()})
                    st.success("Override applied.")
                    del st.session_state["ovr_id"]
                    st.cache_data.clear()
                else:
                    st.error("Reason must be at least 10 characters.")

    # ── Summary row ──────────────────────────────────────────
    status = audit.get("overall_status", "?")
    ico    = "🟢" if status == "PASSED" else ("🔴" if status == "BLOCKED" else "🟡")
    s1, s2, s3, s4, s5 = st.columns(5)
    s1.metric("Status",    f"{ico} {status}")
    s2.metric("PR",        f"#{audit.get('pr_number')}")
    s3.metric("Findings",  len(audit.get("findings", [])))
    s4.metric("Commit",    (audit.get("head_sha") or "")[:8])
    s5.metric("Repo",      audit.get("repo_full_name", "")[:20])

    # ── Findings ─────────────────────────────────────────────
    findings = audit.get("findings", [])
    if not findings:
        st.success("✅ Clean PR — zero findings!")
    else:
        st.subheader(f"🔎 Findings ({len(findings)})")

        # Severity filter
        sev_filter = st.multiselect(
            "Filter severity",
            ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
            default=["CRITICAL", "HIGH", "MEDIUM"],
        )
        filtered_findings = [f for f in findings if f.get("severity") in sev_filter]

        for f in filtered_findings:
            sev     = f.get("severity", "INFO")
            sev_ico = {"CRITICAL": "🔴", "HIGH": "🟠",
                       "MEDIUM":   "🟡", "LOW":  "🔵"}.get(sev, "⚪")
            has_patch  = bool(f.get("patch") and f["patch"].get("test_passed"))
            patch_badge = " · ✅ Auto-patched" if has_patch else ""
            exp_label  = (f"{sev_ico} **[{sev}]** `{f.get('rule_id')}` "
                         f"— {f.get('title', '')} {patch_badge}")

            with st.expander(exp_label):
                loc = f.get("location", {})
                ev  = f.get("evidence", {})

                lc1, lc2 = st.columns(2)
                with lc1:
                    st.markdown(f"📄 **File:** `{loc.get('file')}:{loc.get('line_start')}`")
                    st.markdown(f"🤖 **Agent:** `{f.get('agent_id')}`")
                    st.markdown(f"🌐 **OWASP:** {f.get('owasp_category', 'N/A')}")
                with lc2:
                    st.markdown(f"🔧 **Tool:** `{ev.get('tool_name')}`")
                    st.markdown(f"📋 **Rule:** `{f.get('rule_id')}`")
                    st.markdown(f"🔗 **Command:** `{ev.get('command_run', '')}`")

                st.markdown(f.get("description", ""))

                # Code snippet
                st.markdown("**Vulnerable code:**")
                st.code(loc.get("code_snippet", ""), language="python")

                # Raw tool output — NOTE: use st.container, NOT nested st.expander
                # (nested expanders cause StreamlitAPIException)
                with st.container():
                    st.markdown("**Raw tool output:**")
                    st.code(ev.get("raw_output", "{}"), language="json")

                # Patch section
                if has_patch:
                    patch = f["patch"]
                    st.success(
                        f"✅ Verified patch · "
                        f"coverage {patch.get('coverage_pct', 0):.1f}% · "
                        f"confidence {patch.get('confidence_score', 0):.0%}"
                    )
                    pt1, pt2 = st.tabs(["📝 Patch Diff", "🧪 Test Code"])
                    with pt1:
                        st.code(patch["patch_diff"], language="diff")
                    with pt2:
                        st.code(patch["test_code"], language="python")
                elif f.get("patch"):
                    st.warning("⚠️ Patch generated but test did not pass — manual review needed.")

    # ── Compliance report ────────────────────────────────────
    cr = audit.get("compliance_report") or {}
    if cr.get("markdown_report"):
        st.divider()
        st.subheader("📋 OWASP Compliance Report")
        st.markdown(cr["markdown_report"])


# ═════════════════════════════════════════════════════════════
# PAGE — Agent Traces
# ═════════════════════════════════════════════════════════════
elif page == "🤖 Agent Traces":
    st.title("🤖 Agent Decision Traces")
    st.caption("MCP tool calls · duration · OTel span context per agent")

    if not audits_raw:
        st.info("No audits yet.")
        st.stop()

    opts  = {f"PR #{a.get('pr_number')} · {a.get('repo_full_name')}": a.get("audit_id")
             for a in audits_raw[:60]}
    sel   = st.selectbox("Select audit", list(opts.keys()))
    a_id  = opts.get(sel or "", "")
    audit = load_audit(a_id) if a_id else None
    if not audit:
        st.stop()

    _meta = {
        "agent_a": ("🔧", "Code Quality",  "ruff · radon cc · Python AST"),
        "agent_b": ("🛡️", "Security Audit", "MCP: Bandit · Semgrep · Trivy · Regex"),
        "agent_c": ("🔨", "Patch Engine",   "LLM (gpt-4o) → pytest → Docker sandbox"),
    }

    for m in audit.get("agent_metrics", []):
        aid           = m.get("agent_id", "")
        emo, name, tools = _meta.get(aid, ("🤖", aid, ""))
        status_icon   = "✅" if not m.get("error") else "❌"

        with st.expander(f"{emo} **{aid.upper()}** — {name}  {status_icon}", expanded=True):
            mc1, mc2, mc3, mc4 = st.columns(4)
            mc1.metric("Files Scanned",  m.get("files_scanned", 0))
            mc2.metric("Lines Analyzed", m.get("lines_analyzed", 0))
            mc3.metric("Duration",       f"{m.get('duration_seconds', 0):.2f}s")
            mc4.metric("Status",         status_icon + " OK" if not m.get("error") else "❌ Error")

            st.caption(f"Tools: {tools}")

            if m.get("error"):
                st.error(f"Agent error: {m['error']}")

            tool_calls = m.get("tool_calls", [])
            if tool_calls:
                st.markdown(f"**MCP Tool Calls ({len(tool_calls)}):**")
                for tc in tool_calls:
                    st.json(tc)
            else:
                st.caption("No MCP call log recorded (demo data or not captured).")

            agent_findings = [f for f in audit.get("findings", [])
                              if f.get("agent_id") == aid]
            if agent_findings:
                st.markdown(f"**{len(agent_findings)} findings from this agent:**")
                rows = [{
                    "Severity": f.get("severity", ""),
                    "Rule":     f.get("rule_id", ""),
                    "Title":    f.get("title", ""),
                    "File":     f"{f.get('location',{}).get('file','')}:"
                                f"{f.get('location',{}).get('line_start','')}",
                    "Tool":     f.get("evidence", {}).get("tool_name", ""),
                    "Patched":  "✅" if f.get("patch") and f["patch"].get("test_passed") else "",
                } for f in agent_findings]
                st.dataframe(pd.DataFrame(rows), hide_index=True,
                             use_container_width=True)


# ═════════════════════════════════════════════════════════════
# PAGE — Cost Dashboard
# ═════════════════════════════════════════════════════════════
elif page == "💰 Cost Dashboard":
    st.title("💰 LLM Token & Cost Dashboard")
    st.caption(f"OpenTelemetry-traced LLM spend · source: **{src_lbl}**")

    cost    = load_cost()
    records = load_tokens()

    # ── KPIs ─────────────────────────────────────────────────
    k1, k2, k3, k4, k5 = st.columns(5)
    total_calls  = cost.get("total_calls", 0)
    total_tokens = cost.get("total_tokens", 0)
    total_cost   = cost.get("total_cost_usd", 0.0)
    avg_cost     = total_cost / max(total_calls, 1)
    cost_per_1k  = total_cost / max(total_tokens / 1000, 0.001)
    k1.metric("LLM Calls",      total_calls)
    k2.metric("Total Tokens",   f"{total_tokens:,}")
    k3.metric("Total Cost",     f"${total_cost:.4f}")
    k4.metric("Avg / Call",     f"${avg_cost:.4f}")
    k5.metric("Cost / 1K tok",  f"${cost_per_1k:.4f}")

    st.divider()
    cl, cr = st.columns(2)

    with cl:
        st.subheader("Cost by Model")
        by_model = cost.get("by_model", {})
        if by_model:
            df_m = pd.DataFrame([
                {"Model": k, "Calls": v["calls"],
                 "Tokens": v["tokens"], "Cost ($)": v["cost_usd"]}
                for k, v in by_model.items()
            ])
            fig_m = px.bar(df_m, x="Model", y="Cost ($)", color="Model",
                           text_auto=".4f",
                           color_discrete_sequence=px.colors.qualitative.Vivid)
            fig_m.update_layout(height=280, showlegend=False, margin=dict(t=20, b=0))
            st.plotly_chart(fig_m, use_container_width=True)
            st.dataframe(df_m, hide_index=True, use_container_width=True)

    with cr:
        st.subheader("Cost by Agent")
        by_agent = cost.get("by_agent", {})
        if by_agent:
            df_a = pd.DataFrame([
                {"Agent": k, "Calls": v["calls"],
                 "Tokens": v["tokens"], "Cost ($)": v["cost_usd"]}
                for k, v in by_agent.items()
            ])
            cmap_a = {"agent_a": "#3b82f6", "agent_b": "#ef4444", "agent_c": "#22c55e"}
            fig_a  = px.pie(df_a, values="Cost ($)", names="Agent",
                            color="Agent", color_discrete_map=cmap_a, hole=0.45)
            fig_a.update_layout(height=280, margin=dict(t=20, b=0))
            st.plotly_chart(fig_a, use_container_width=True)

    # ── Token trend ──────────────────────────────────────────
    st.subheader("Token Usage Over Time")
    if records:
        df_r = (pd.DataFrame(records)
                  .assign(timestamp=lambda d: pd.to_datetime(d["timestamp"]))
                  .sort_values("timestamp"))

        t1, t2 = st.tabs(["📈 Token Trend", "💸 Cost Scatter"])
        with t1:
            fig_t = px.line(df_r, x="timestamp", y="total_tokens",
                            color="model", markers=True)
            fig_t.update_layout(height=280, margin=dict(t=20, b=0))
            st.plotly_chart(fig_t, use_container_width=True)
        with t2:
            fig_c = px.scatter(df_r, x="timestamp", y="cost_usd",
                               size="total_tokens", color="model",
                               hover_data=["agent_id", "latency_ms"])
            fig_c.update_layout(height=280, margin=dict(t=20, b=0))
            st.plotly_chart(fig_c, use_container_width=True)

        st.subheader("Call Log")
        cols = ["timestamp", "audit_id", "model",
                "prompt_tokens", "completion_tokens", "cost_usd", "latency_ms"]
        st.dataframe(df_r[cols].head(100), hide_index=True, use_container_width=True)
    else:
        st.info("No token records yet. Enable Agent C patch generation to see data.")

    st.divider()
    st.info(
        "🔗 **LangSmith traces** available at "
        f"[smith.langchain.com](https://smith.langchain.com/projects/"
        f"{os.getenv('LANGCHAIN_PROJECT','ai-code-reviewer')})"
    )


# ═════════════════════════════════════════════════════════════
# PAGE — Settings
# ═════════════════════════════════════════════════════════════
elif page == "⚙️ Settings":
    st.title("⚙️ Settings & Setup")

    # ── API status ───────────────────────────────────────────
    st.subheader("API Status")
    if is_live:
        st.success(f"✅ API reachable at `{API_BASE_URL}`")
        h = api_get("/health")
        if h:
            c1, c2, c3 = st.columns(3)
            c1.metric("Service",  h.get("service", ""))
            c2.metric("Version",  h.get("version", ""))
            c3.metric("Status",   h.get("status", ""))
        r = api_get("/readiness")
        if r:
            st.json(r)
    else:
        st.error(f"❌ API not reachable at `{API_BASE_URL}`")

        st.subheader("Quick Start Guide")
        tab_local, tab_cloud, tab_docker = st.tabs(
            ["💻 Local", "☁️ Streamlit Cloud", "🐳 Docker"]
        )

        with tab_local:
            st.markdown("""
**Run the full stack locally:**

```powershell
# 1. Install
pip install -r requirements-backend.txt

# 2. Copy env
copy .env.example .env

# 3. Start Redis (optional)
docker run -d -p 6379:6379 redis:7-alpine

# 4. Start API
uvicorn api.main:app --reload --port 8000

# 5. Start dashboard (new terminal)
streamlit run dashboard/app.py
```
""")

        with tab_cloud:
            st.markdown("""
**To connect this Streamlit Cloud app to a live API:**

1. Deploy your API to [Railway](https://railway.app), [Render](https://render.com),
   or [Fly.io](https://fly.io)
2. In Streamlit Cloud → **Manage app → Secrets**, add:
```toml
API_BASE_URL = "https://your-api.railway.app"
```
3. Click **Save** — the app reloads and the banner turns green.
""")

        with tab_docker:
            st.markdown("""
**Full Docker Compose stack:**

```bash
cp .env.example .env
docker compose -f docker/docker-compose.yml up -d --build
```

| Service | URL |
|---|---|
| FastAPI | http://localhost:8000/docs |
| Dashboard | http://localhost:8501 |
| Jaeger | http://localhost:16686 |
| Prometheus | http://localhost:9090 |
""")

    # ── Spec reference ───────────────────────────────────────
    st.divider()
    st.subheader("Security Rules Spec")
    st.markdown("""
| Section | Rule IDs | Agent | Tools |
|---|---|---|---|
| `quality_rules` | QA-001 → QA-006 | Agent A 🔧 | ruff, radon, AST |
| `security_rules` | SEC-001 → SEC-010 | Agent B 🛡️ | Bandit, Semgrep, Trivy |
| `patch_rules` | PATCH-001 → PATCH-003 | Agent C 🔨 | LLM, pytest, Docker |
| `pr_policy` | auto-approve/block | Orchestrator | — |
| `anti_hallucination` | zero-hallucination | All agents | — |

Every finding must include `rule_id` + raw tool evidence.
Findings without a matching rule ID are silently discarded.
""")

    st.subheader("Links")
    links = {
        "GitHub Repository":   "https://github.com/avirajtambhale/autonomous-devsecops-agent",
        "GitHub Issues":       "https://github.com/avirajtambhale/autonomous-devsecops-agent/issues",
        "GitHub Actions":      "https://github.com/avirajtambhale/autonomous-devsecops-agent/actions",
        "FastAPI Swagger":     f"{API_BASE_URL}/docs",
        "LangSmith Project":   "https://smith.langchain.com/projects/ai-code-reviewer",
        "OWASP Top 10":        "https://owasp.org/www-project-top-ten/",
    }
    for name, url in links.items():
        st.markdown(f"- [{name}]({url})")
