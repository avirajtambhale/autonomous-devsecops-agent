"""
Autonomous DevSecOps Agent — Command Center Dashboard  v2.2
============================================================
FIXES in v2.2:
  - ZERO nested expanders (StreamlitAPIException fully resolved)
  - Raw tool output in st.code block, NOT inside any expander
  - Patch diff shown in st.tabs, NOT inside any expander
  - packages.txt blank (fixes apt-get comment errors)

PREMIUM FEATURES:
  - 5 pages: Dashboard, Audit Details, Agent Traces, Cost, Settings
  - Live data when API_BASE_URL is set in Streamlit secrets
  - Offline demo mode with realistic OWASP data, patches, CVEs
  - Token cost tracking per model and agent
  - Severity filter, auto-refresh, repo filter
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
API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")
REFRESH_TTL  = 15
API_TIMEOUT  = 2.5

st.set_page_config(
    page_title="AI Code Reviewer · DevSecOps",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        "Get Help": "https://github.com/avirajtambhale/autonomous-devsecops-agent",
        "Report a bug": "https://github.com/avirajtambhale/autonomous-devsecops-agent/issues",
        "About": "**AI Code Reviewer v2.2** — Autonomous DevSecOps Agent",
    },
)

st.markdown("""
<style>
[data-testid="metric-container"] {
    background: linear-gradient(135deg,#1a1a2e,#16213e);
    border: 1px solid #2d2d4e; border-radius: 10px; padding: 14px;
}
.banner-on  { background:#052e16; border:1px solid #16a34a; border-radius:8px;
              padding:10px 16px; color:#86efac; margin-bottom:8px; }
.banner-off { background:#1c0505; border:1px solid #b91c1c; border-radius:8px;
              padding:10px 16px; color:#fca5a5; margin-bottom:8px; }
section[data-testid="stSidebar"] { background:#080818; }
</style>
""", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════
# API CLIENT
# ═══════════════════════════════════════════════════════════════

@st.cache_data(ttl=5)
def _online() -> bool:
    if not _HTTPX:
        return False
    try:
        return httpx.get(f"{API_BASE_URL}/health", timeout=API_TIMEOUT).status_code == 200
    except Exception:
        return False


def _get(path: str) -> Any:
    if not _HTTPX or not _online():
        return None
    try:
        r = httpx.get(f"{API_BASE_URL}{path}", timeout=API_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


def _post(path: str, params: dict | None = None) -> Any:
    if not _HTTPX or not _online():
        return None
    try:
        r = httpx.post(f"{API_BASE_URL}{path}", params=params, timeout=API_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════
# DEMO DATA
# ═══════════════════════════════════════════════════════════════

def _finding(sev: str, rule: str, agent: str, path: str, line: int) -> dict:
    T = {
        "SEC-001": "Hardcoded API key in source code",
        "SEC-002": "SQL injection via f-string query",
        "SEC-003": "XSS: unescaped user input in template",
        "SEC-007": "CVE-2024-45231 in requests==2.28.0 (HIGH)",
        "QA-001":  "Cyclomatic complexity 14 > threshold 10",
        "QA-003":  "E501 line too long (108 > 100 chars)",
    }
    S = {
        "SEC-001": 'API_KEY = "sk-prod-abc123xyz"  # hardcoded',
        "SEC-002": 'cursor.execute(f"SELECT * FROM users WHERE id={uid}")',
        "SEC-003": 'return render_template("p.html", name=request.args["name"])',
        "SEC-007": "requests==2.28.0",
        "QA-001":  "def process_order(cart, user, promo, tax, ship):",
        "QA-003":  "x = very_long_var + another_very_long_var  # line too long here",
    }
    OWASP = {
        "SEC-001": "A02:2021 – Cryptographic Failures",
        "SEC-002": "A03:2021 – Injection",
        "SEC-003": "A03:2021 – Injection",
        "SEC-007": "A06:2021 – Vulnerable Components",
    }
    return {
        "finding_id":    f"demo-{rule}-{line}",
        "rule_id":       rule,
        "agent_id":      agent,
        "severity":      sev,
        "title":         T.get(rule, rule),
        "description":   f"{T.get(rule, rule)} at `{path}:{line}`.",
        "owasp_category": OWASP.get(rule, "N/A"),
        "suppressed":    False,
        "location":      {"file": path, "line_start": line, "code_snippet": S.get(rule, "")},
        "evidence":      {
            "tool_name":   {"agent_b": "bandit", "agent_a": "ruff"}.get(agent, "trivy"),
            "raw_output":  f'{{"test_id":"{rule}","severity":"{sev}","line":{line}}}',
            "command_run": f"bandit -r {path} --format json",
        },
        "patch": {
            "patch_diff": (
                f"--- a/{path}\n+++ b/{path}\n"
                f"@@ -{line},3 +{line},4 @@\n"
                f"-{S.get(rule,'# old code')}\n"
                f"+import os\n"
                f"+# FIXED: use environment variable\n"
                f"+SAFE_VALUE = os.environ.get('{rule.replace('-','_')}_VALUE', '')"
            ),
            "test_code": (
                "import os\nimport pytest\n\n"
                "def test_no_hardcoded_secret():\n"
                "    src = open('src/auth.py').read()\n"
                "    assert 'sk-prod' not in src\n"
                "    assert 'API_KEY =' not in src\n"
            ),
            "test_passed":      True,
            "coverage_pct":     88.4,
            "confidence_score": 0.93,
        } if sev in ("CRITICAL", "HIGH") else None,
    }


def _audits() -> list[dict]:
    STATUSES = ["PASSED", "BLOCKED", "PASSED", "PASSED", "BLOCKED", "PASSED", "ERROR"]
    REPOS    = ["owner/webapp", "owner/api-service", "owner/cli-tool"]
    now      = datetime.now(timezone.utc)
    result   = []
    for i, status in enumerate(STATUSES):
        ts       = (now - timedelta(hours=i * 4)).isoformat()
        findings = (
            [
                _finding("CRITICAL", "SEC-001", "agent_b", "src/auth.py",   42),
                _finding("HIGH",     "SEC-002", "agent_b", "src/models.py", 17),
                _finding("MEDIUM",   "QA-001",  "agent_a", "src/utils.py",   5),
                _finding("LOW",      "QA-003",  "agent_a", "src/views.py",  88),
            ]
            if status == "BLOCKED"
            else [_finding("LOW", "QA-003", "agent_a", "src/main.py", 10)]
            if status == "PASSED"
            else []
        )
        result.append({
            "audit_id":       f"demo-{i:03d}",
            "pr_number":      100 + i,
            "repo_full_name": REPOS[i % len(REPOS)],
            "head_sha":       f"a{i}b{i}c{i}d{i}e{i}f{i}",
            "overall_status": status,
            "started_at":     ts,
            "completed_at":   ts,
            "findings":       findings,
            "agent_metrics": [
                {"agent_id": "agent_a", "files_scanned": 4, "duration_seconds": 1.4,
                 "lines_analyzed": 312, "tool_calls": [], "error": None},
                {"agent_id": "agent_b", "files_scanned": 4, "duration_seconds": 5.2,
                 "lines_analyzed": 312, "tool_calls": [], "error": None},
                {"agent_id": "agent_c", "files_scanned": 0, "duration_seconds": 8.7,
                 "lines_analyzed": 0,   "tool_calls": [], "error": None},
            ],
            "compliance_report": {
                "markdown_report": (
                    f"## OWASP Report — PR #{100+i}\n\n"
                    "| Category | Result |\n|---|---|\n"
                    "| A01 Broken Access Control | ✅ Pass |\n"
                    f"| A02 Crypto Failures | {'❌ 1 finding' if status=='BLOCKED' else '✅ Pass'} |\n"
                    f"| A03 Injection | {'❌ 1 finding' if status=='BLOCKED' else '✅ Pass'} |\n"
                    "| A04–A10 | ✅ Pass |\n"
                ),
            },
        })
    return result


def _cost() -> dict:
    return {
        "total_calls": 14, "total_tokens": 28_400, "total_cost_usd": 0.2130,
        "by_model": {
            "gpt-4o":      {"calls": 10, "tokens": 21_000, "cost_usd": 0.1575},
            "gpt-4o-mini": {"calls":  4, "tokens":  7_400, "cost_usd": 0.0555},
        },
        "by_agent": {"agent_c": {"calls": 14, "tokens": 28_400, "cost_usd": 0.2130}},
    }


def _tokens() -> list[dict]:
    now = datetime.now(timezone.utc)
    return [
        {
            "timestamp":         (now - timedelta(minutes=i * 18)).isoformat(),
            "audit_id":          f"demo-{i % 7:03d}",
            "model":             "gpt-4o" if i % 3 != 0 else "gpt-4o-mini",
            "agent_id":          "agent_c",
            "prompt_tokens":     random.randint(600, 1800),
            "completion_tokens": random.randint(200, 600),
            "total_tokens":      random.randint(800, 2400),
            "cost_usd":          round(random.uniform(0.004, 0.025), 5),
            "latency_ms":        random.randint(900, 3200),
        }
        for i in range(14)
    ]


# ═══════════════════════════════════════════════════════════════
# DATA LOADERS
# ═══════════════════════════════════════════════════════════════

@st.cache_data(ttl=REFRESH_TTL)
def load_audits() -> tuple[list[dict], bool]:
    r = _get("/audits?limit=200")
    if r and isinstance(r, dict) and "results" in r:
        return r["results"], True
    return _audits(), False


@st.cache_data(ttl=REFRESH_TTL)
def load_audit(aid: str) -> dict | None:
    if not aid.startswith("demo-"):
        return _get(f"/audits/{aid}")
    return next((a for a in _audits() if a["audit_id"] == aid), None)


@st.cache_data(ttl=REFRESH_TTL)
def load_cost() -> dict:
    r = _get("/telemetry/cost")
    return r if (r and isinstance(r, dict)) else _cost()


@st.cache_data(ttl=REFRESH_TTL)
def load_tokens() -> list[dict]:
    r = _get("/telemetry/tokens?limit=200")
    return r.get("records", []) if (r and isinstance(r, dict)) else _tokens()


def metrics(audits: list[dict]) -> dict:
    if not audits:
        return dict(total=0, passed=0, blocked=0, error=0,
                    pass_rate=0.0, crit=0, high=0, patched=0, saved=0.0)
    total   = len(audits)
    passed  = sum(1 for a in audits if a.get("overall_status") == "PASSED")
    blocked = sum(1 for a in audits if a.get("overall_status") == "BLOCKED")
    error   = sum(1 for a in audits if a.get("overall_status") == "ERROR")
    all_f   = [f for a in audits for f in a.get("findings", [])]
    patched = sum(1 for f in all_f
                  if f.get("patch") and f["patch"].get("test_passed"))
    return dict(
        total=total, passed=passed, blocked=blocked, error=error,
        pass_rate=passed / total * 100 if total else 0.0,
        crit=sum(1 for f in all_f if f.get("severity") == "CRITICAL"),
        high=sum(1 for f in all_f if f.get("severity") == "HIGH"),
        patched=patched,
        saved=round(total * 42 / 60, 1),
    )


# ═══════════════════════════════════════════════════════════════
# SIDEBAR
# ═══════════════════════════════════════════════════════════════

with st.sidebar:
    st.markdown("## 🔐 AI Code Reviewer")
    st.markdown("`v2.2` · Autonomous DevSecOps Agent")
    st.divider()

    page = st.radio(
        "Navigate",
        ["📊 Dashboard", "🔍 Audit Details",
         "🤖 Agent Traces", "💰 Cost Dashboard", "⚙️ Settings"],
        label_visibility="collapsed",
    )
    st.divider()

    repo_filter = st.text_input("🔍 Filter by repo", "")
    ca, cb = st.columns(2)
    with ca:
        if st.button("🔄 Refresh", use_container_width=True):
            st.cache_data.clear(); st.rerun()
    with cb:
        auto = st.toggle("Auto", help="Refresh every 15s")
    if auto:
        time.sleep(REFRESH_TTL); st.rerun()

    st.divider()
    live = _online()
    st.success("API Online", icon="✅") if live else st.warning("API Offline", icon="⚠️")
    st.caption(f"`{API_BASE_URL}`")


# ─── Load + filter ────────────────────────────────────────────
audits_raw, is_live = load_audits()
if repo_filter:
    audits_raw = [a for a in audits_raw
                  if repo_filter.lower() in a.get("repo_full_name", "").lower()]
m       = metrics(audits_raw)
src_lbl = "🟢 live" if is_live else "🟡 demo"

# ─── Top banner ───────────────────────────────────────────────
if is_live:
    st.markdown(
        f'<div class="banner-on">✅ <b>API Online</b> · live data from '
        f'<code>{API_BASE_URL}</code></div>', unsafe_allow_html=True)
else:
    st.markdown(
        '<div class="banner-off">⚠️ <b>API Offline</b> · demo data shown · '
        'set <code>API_BASE_URL</code> in Streamlit secrets for live data</div>',
        unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════
# PAGE 1 — Dashboard
# ═══════════════════════════════════════════════════════════════
if page == "📊 Dashboard":
    st.title("🔐 AI Code Security Review — Command Center")
    st.caption(f"{datetime.now().strftime('%H:%M:%S')} · {len(audits_raw)} audits · {src_lbl}")

    # KPIs
    k1,k2,k3,k4,k5,k6,k7 = st.columns(7)
    k1.metric("Total PRs",     m["total"])
    k2.metric("✅ Passed",      m["passed"])
    k3.metric("❌ Blocked",     m["blocked"])
    k4.metric("Pass Rate",     f"{m['pass_rate']:.0f}%")
    k5.metric("🔴 Critical",   m["crit"])
    k6.metric("🩹 Patched",    m["patched"])
    k7.metric("⏱ Hours Saved", m["saved"])

    st.divider()
    cl, cr = st.columns(2)

    with cl:
        st.subheader("PR Status")
        s = (pd.Series([a.get("overall_status","?") for a in audits_raw])
               .value_counts().reset_index())
        s.columns = ["Status","Count"]
        cmap = {"PASSED":"#22c55e","BLOCKED":"#ef4444","ERROR":"#6b7280",
                "PENDING":"#eab308","RUNNING":"#3b82f6","OVERRIDDEN":"#a855f7"}
        fig = px.pie(s, values="Count", names="Status", color="Status",
                     color_discrete_map=cmap, hole=0.45)
        fig.update_layout(height=260, margin=dict(t=0,b=0,l=0,r=0),
                          legend=dict(orientation="h",y=-0.18))
        st.plotly_chart(fig, use_container_width=True)

    with cr:
        st.subheader("Findings by Severity")
        all_f = [f for a in audits_raw for f in a.get("findings",[])]
        if all_f:
            sv = (pd.Series([f.get("severity","?") for f in all_f])
                    .value_counts().reset_index())
            sv.columns = ["Severity","Count"]
            cmap2 = {"CRITICAL":"#ef4444","HIGH":"#f97316",
                     "MEDIUM":"#eab308","LOW":"#3b82f6","INFO":"#6b7280"}
            fig2 = px.bar(sv, x="Severity", y="Count",
                          color="Severity", color_discrete_map=cmap2)
            fig2.update_layout(height=260, margin=dict(t=0,b=0), showlegend=False)
            st.plotly_chart(fig2, use_container_width=True)
        else:
            st.info("No findings yet.")

    st.subheader("📋 Recent Audits")
    if audits_raw:
        df = pd.DataFrame([{
            "ID":      a["audit_id"][:10]+"…",
            "Repo":    a.get("repo_full_name",""),
            "PR":      f"#{a.get('pr_number')}",
            "Status":  a.get("overall_status",""),
            "Issues":  len(a.get("findings",[])),
            "Patched": sum(1 for f in a.get("findings",[])
                          if f.get("patch") and f["patch"].get("test_passed")),
            "Started": (a.get("started_at") or "")[:19].replace("T"," "),
        } for a in audits_raw[:50]])

        def _c(v: str) -> str:
            return {"PASSED":"color:#22c55e","BLOCKED":"color:#ef4444",
                    "ERROR":"color:#6b7280","RUNNING":"color:#3b82f6"}.get(v,"")

        st.dataframe(df.style.map(_c, subset=["Status"]),
                     use_container_width=True, hide_index=True)
    else:
        st.info("Trigger a GitHub PR to see real audits here.")


# ═══════════════════════════════════════════════════════════════
# PAGE 2 — Audit Details
# NOTE: NO nested expanders — raw output in st.code, patch in st.tabs
# ═══════════════════════════════════════════════════════════════
elif page == "🔍 Audit Details":
    st.title("🔍 Audit Details")

    if not audits_raw:
        st.info("No audits available."); st.stop()

    opts = {
        f"PR #{a.get('pr_number')} · {a.get('repo_full_name')} · {a.get('overall_status')}":
        a.get("audit_id") for a in audits_raw[:60]
    }
    sel   = st.selectbox("Select audit", list(opts.keys()))
    a_id  = opts.get(sel or "", "")
    audit = load_audit(a_id) if a_id else None
    if not audit:
        st.warning("Select an audit above."); st.stop()

    # Action bar
    ab1, ab2, _ = st.columns([1, 1, 5])
    with ab1:
        if st.button("🔄 Re-run", disabled=not is_live, use_container_width=True):
            if _post(f"/audits/{a_id}/rerun"):
                st.success("Re-queued!"); st.cache_data.clear()
    with ab2:
        if audit.get("overall_status") == "BLOCKED":
            if st.button("⚡ Override", disabled=not is_live, use_container_width=True):
                st.session_state["ovr"] = a_id
    if not is_live:
        st.caption("Re-run / Override need the API running.")

    if st.session_state.get("ovr") == a_id:
        with st.form("ovr_form"):
            reason = st.text_area("Override reason (min 10 chars):")
            if st.form_submit_button("✅ Confirm"):
                if len(reason.strip()) >= 10:
                    _post(f"/audits/{a_id}/override",
                          params={"reason": reason.strip()})
                    st.success("Override applied.")
                    del st.session_state["ovr"]
                    st.cache_data.clear()
                else:
                    st.error("Too short.")

    # Summary
    status = audit.get("overall_status","?")
    ico    = "🟢" if status=="PASSED" else ("🔴" if status=="BLOCKED" else "🟡")
    s1,s2,s3,s4 = st.columns(4)
    s1.metric("Status",   f"{ico} {status}")
    s2.metric("PR",       f"#{audit.get('pr_number')}")
    s3.metric("Findings", len(audit.get("findings",[])))
    s4.metric("Commit",   (audit.get("head_sha") or "")[:8])

    # Findings
    findings = audit.get("findings", [])
    if not findings:
        st.success("✅ Clean PR — zero findings!")
    else:
        st.subheader(f"🔎 Findings ({len(findings)})")
        sev_filter = st.multiselect(
            "Filter severity",
            ["CRITICAL","HIGH","MEDIUM","LOW","INFO"],
            default=["CRITICAL","HIGH","MEDIUM"],
        )
        shown = [f for f in findings if f.get("severity") in sev_filter]

        SEV_ICO = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵","INFO":"⚪"}

        for f in shown:
            sev        = f.get("severity","INFO")
            has_patch  = bool(f.get("patch") and f["patch"].get("test_passed"))
            badge      = " · ✅ Auto-patched" if has_patch else ""
            label      = (f"{SEV_ICO.get(sev,'⚪')} **[{sev}]** "
                         f"`{f.get('rule_id')}` — {f.get('title','')}{badge}")
            loc = f.get("location", {})
            ev  = f.get("evidence", {})

            # ── OUTER EXPANDER (one level only) ──────────────
            with st.expander(label):
                c1, c2 = st.columns(2)
                with c1:
                    st.markdown(f"📄 **File** `{loc.get('file')}:{loc.get('line_start')}`")
                    st.markdown(f"🤖 **Agent** `{f.get('agent_id')}`")
                    st.markdown(f"🌐 **OWASP** {f.get('owasp_category','N/A')}")
                with c2:
                    st.markdown(f"🔧 **Tool** `{ev.get('tool_name')}`")
                    st.markdown(f"📋 **Rule** `{f.get('rule_id')}`")
                    st.markdown(f"⌨️ **Command** `{ev.get('command_run','')}`")

                st.markdown(f.get("description",""))

                # Vulnerable code — plain st.code (no expander)
                st.markdown("**Vulnerable code:**")
                st.code(loc.get("code_snippet",""), language="python")

                # Raw output — plain st.code (NOT nested expander)
                st.markdown("**Raw tool output:**")
                st.code(ev.get("raw_output","{}"), language="json")

                # Patch — st.tabs (NOT nested expander)
                if has_patch:
                    patch = f["patch"]
                    st.success(
                        f"✅ Patch verified · "
                        f"coverage {patch.get('coverage_pct',0):.1f}% · "
                        f"confidence {patch.get('confidence_score',0):.0%}"
                    )
                    t1, t2 = st.tabs(["📝 Patch Diff", "🧪 Test Code"])
                    with t1:
                        st.code(patch["patch_diff"], language="diff")
                    with t2:
                        st.code(patch["test_code"], language="python")
                elif f.get("patch"):
                    st.warning("Patch generated but test did not pass — review manually.")
            # ── END OUTER EXPANDER ───────────────────────────

    cr = audit.get("compliance_report") or {}
    if cr.get("markdown_report"):
        st.divider()
        st.subheader("📋 OWASP Compliance Report")
        st.markdown(cr["markdown_report"])


# ═══════════════════════════════════════════════════════════════
# PAGE 3 — Agent Traces
# ═══════════════════════════════════════════════════════════════
elif page == "🤖 Agent Traces":
    st.title("🤖 Agent Decision Traces")
    st.caption("Per-agent MCP tool calls · duration · findings table")

    if not audits_raw:
        st.info("No audits yet."); st.stop()

    opts  = {f"PR #{a.get('pr_number')} · {a.get('repo_full_name')}":
             a.get("audit_id") for a in audits_raw[:60]}
    sel   = st.selectbox("Select audit", list(opts.keys()))
    a_id  = opts.get(sel or "", "")
    audit = load_audit(a_id) if a_id else None
    if not audit: st.stop()

    AGENTS = {
        "agent_a": ("🔧", "Code Quality",  "ruff · radon cc · Python AST"),
        "agent_b": ("🛡️", "Security Audit", "MCP: Bandit · Semgrep · Trivy · regex"),
        "agent_c": ("🔨", "Patch Engine",   "LLM (gpt-4o) → pytest → Docker sandbox"),
    }

    for m_row in audit.get("agent_metrics", []):
        aid          = m_row.get("agent_id","")
        emo, nm, tls = AGENTS.get(aid, ("🤖", aid, ""))
        ok           = not m_row.get("error")

        # OUTER EXPANDER only — no nesting inside
        with st.expander(f"{emo} **{aid.upper()}** — {nm}  {'✅' if ok else '❌'}",
                         expanded=True):
            mc1,mc2,mc3,mc4 = st.columns(4)
            mc1.metric("Files",   m_row.get("files_scanned",0))
            mc2.metric("Lines",   m_row.get("lines_analyzed",0))
            mc3.metric("Duration",f"{m_row.get('duration_seconds',0):.2f}s")
            mc4.metric("Status",  "✅ OK" if ok else "❌ Error")
            st.caption(f"Tools: {tls}")

            if m_row.get("error"):
                st.error(f"Error: {m_row['error']}")

            calls = m_row.get("tool_calls",[])
            if calls:
                st.markdown(f"**MCP Tool Calls ({len(calls)}):**")
                for c in calls:
                    st.json(c)
            else:
                st.caption("No MCP call log (demo mode or not captured).")

            af = [f for f in audit.get("findings",[]) if f.get("agent_id")==aid]
            if af:
                st.markdown(f"**{len(af)} findings:**")
                st.dataframe(pd.DataFrame([{
                    "Sev":     f.get("severity",""),
                    "Rule":    f.get("rule_id",""),
                    "Title":   f.get("title",""),
                    "File":    f"{f.get('location',{}).get('file','')}:"
                               f"{f.get('location',{}).get('line_start','')}",
                    "Tool":    f.get("evidence",{}).get("tool_name",""),
                    "Patched": "✅" if f.get("patch") and f["patch"].get("test_passed") else "",
                } for f in af]), hide_index=True, use_container_width=True)


# ═══════════════════════════════════════════════════════════════
# PAGE 4 — Cost Dashboard
# ═══════════════════════════════════════════════════════════════
elif page == "💰 Cost Dashboard":
    st.title("💰 LLM Token & Cost Dashboard")
    st.caption(f"OpenTelemetry-traced LLM spend · {src_lbl}")

    cost_data = load_cost()
    recs      = load_tokens()

    k1,k2,k3,k4,k5 = st.columns(5)
    tc = cost_data.get("total_calls",0)
    tt = cost_data.get("total_tokens",0)
    tu = cost_data.get("total_cost_usd",0.0)
    k1.metric("LLM Calls",     tc)
    k2.metric("Total Tokens",  f"{tt:,}")
    k3.metric("Total Cost",    f"${tu:.4f}")
    k4.metric("Avg / Call",    f"${tu/max(tc,1):.4f}")
    k5.metric("Cost / 1K tok", f"${tu/max(tt/1000,0.001):.4f}")

    st.divider()
    cl2, cr2 = st.columns(2)

    with cl2:
        st.subheader("Cost by Model")
        bm = cost_data.get("by_model",{})
        if bm:
            df_m = pd.DataFrame([{"Model":k,"Calls":v["calls"],
                                   "Tokens":v["tokens"],"Cost ($)":v["cost_usd"]}
                                  for k,v in bm.items()])
            fig_m = px.bar(df_m, x="Model", y="Cost ($)", color="Model",
                           text_auto=".4f",
                           color_discrete_sequence=px.colors.qualitative.Vivid)
            fig_m.update_layout(height=280, showlegend=False, margin=dict(t=20,b=0))
            st.plotly_chart(fig_m, use_container_width=True)
            st.dataframe(df_m, hide_index=True, use_container_width=True)

    with cr2:
        st.subheader("Cost by Agent")
        ba = cost_data.get("by_agent",{})
        if ba:
            df_a = pd.DataFrame([{"Agent":k,"Cost ($)":v["cost_usd"]}
                                  for k,v in ba.items()])
            fig_a = px.pie(df_a, values="Cost ($)", names="Agent", hole=0.45,
                           color_discrete_sequence=["#3b82f6","#ef4444","#22c55e"])
            fig_a.update_layout(height=280, margin=dict(t=20,b=0))
            st.plotly_chart(fig_a, use_container_width=True)

    st.subheader("Token Usage Over Time")
    if recs:
        df_r = (pd.DataFrame(recs)
                  .assign(timestamp=lambda d: pd.to_datetime(d["timestamp"]))
                  .sort_values("timestamp"))
        t1, t2 = st.tabs(["📈 Token Trend", "💸 Cost Scatter"])
        with t1:
            fig_t = px.line(df_r, x="timestamp", y="total_tokens",
                            color="model", markers=True)
            fig_t.update_layout(height=270, margin=dict(t=20,b=0))
            st.plotly_chart(fig_t, use_container_width=True)
        with t2:
            fig_c = px.scatter(df_r, x="timestamp", y="cost_usd",
                               size="total_tokens", color="model",
                               hover_data=["agent_id","latency_ms"])
            fig_c.update_layout(height=270, margin=dict(t=20,b=0))
            st.plotly_chart(fig_c, use_container_width=True)
        cols = ["timestamp","audit_id","model","prompt_tokens",
                "completion_tokens","cost_usd","latency_ms"]
        st.subheader("Call Log")
        st.dataframe(df_r[cols].head(100), hide_index=True,
                     use_container_width=True)
    else:
        st.info("No records yet. Enable Agent C to see cost data.")

    st.divider()
    ls = os.getenv("LANGCHAIN_PROJECT","ai-code-reviewer")
    st.info(f"🔗 LangSmith: [smith.langchain.com/projects/{ls}]"
            f"(https://smith.langchain.com/projects/{ls})")


# ═══════════════════════════════════════════════════════════════
# PAGE 5 — Settings
# ═══════════════════════════════════════════════════════════════
elif page == "⚙️ Settings":
    st.title("⚙️ Settings & Setup Guide")

    if is_live:
        st.success(f"✅ API reachable at `{API_BASE_URL}`")
        h = _get("/health")
        if h:
            c1,c2,c3 = st.columns(3)
            c1.metric("Service", h.get("service",""))
            c2.metric("Version", h.get("version",""))
            c3.metric("Status",  h.get("status",""))
        r = _get("/readiness")
        if r: st.json(r)
    else:
        st.error(f"❌ API offline at `{API_BASE_URL}`")

        tab_l, tab_c, tab_d = st.tabs(["💻 Local", "☁️ Streamlit Cloud", "🐳 Docker"])

        with tab_l:
            st.code("""# 1. Install backend deps
pip install -r requirements-backend.txt

# 2. Copy env
copy .env.example .env   # add GITHUB_TOKEN + OPENAI_API_KEY

# 3. Redis (optional)
docker run -d -p 6379:6379 redis:7-alpine

# 4. Start API
uvicorn api.main:app --reload --port 8000

# 5. Dashboard (new terminal)
streamlit run dashboard/app.py""", language="bash")

        with tab_c:
            st.markdown("""
**Connect live data to Streamlit Cloud:**

1. Deploy API to Railway / Render / Fly.io
2. **Streamlit Cloud → Manage app → Secrets** → add:
```toml
API_BASE_URL = "https://your-api.railway.app"
```
3. Save — banner turns green automatically.
""")

        with tab_d:
            st.code("""cp .env.example .env
docker compose -f docker/docker-compose.yml up -d --build""", language="bash")
            st.markdown("""
| Service | URL |
|---|---|
| FastAPI | http://localhost:8000/docs |
| Dashboard | http://localhost:8501 |
| Jaeger | http://localhost:16686 |
| Prometheus | http://localhost:9090 |
""")

    st.divider()
    st.subheader("Security Rules Quick Reference")
    st.markdown("""
| Rule | Description | Agent | Severity |
|---|---|---|---|
| QA-001 | Cyclomatic complexity > 10 | A | HIGH |
| QA-002 | Function > 60 lines | A | MEDIUM |
| QA-003 | Lint violations (ruff) | A | MEDIUM |
| SEC-001 | Hardcoded secrets | B | CRITICAL |
| SEC-002 | SQL injection | B | CRITICAL |
| SEC-003 | XSS vulnerability | B | HIGH |
| SEC-007 | Vulnerable dependency CVE | B | CRITICAL |
| PATCH-001 | Test coverage ≥ 80% | C | HIGH |
| PATCH-002 | No regressions | C | CRITICAL |

**Zero-hallucination**: every finding needs `rule_id` + raw tool evidence.
""")

    st.divider()
    st.subheader("🔗 Links")
    for name, url in {
        "GitHub Repository":  "https://github.com/avirajtambhale/autonomous-devsecops-agent",
        "GitHub Issues":      "https://github.com/avirajtambhale/autonomous-devsecops-agent/issues",
        "GitHub Actions CI":  "https://github.com/avirajtambhale/autonomous-devsecops-agent/actions",
        "LangSmith Project":  "https://smith.langchain.com/projects/ai-code-reviewer",
        "OWASP Top 10":       "https://owasp.org/www-project-top-ten/",
        "Semgrep Rules":      "https://semgrep.dev/r",
        "Generate GitHub PAT":"https://github.com/settings/tokens/new",
    }.items():
        st.markdown(f"- [{name}]({url})")
