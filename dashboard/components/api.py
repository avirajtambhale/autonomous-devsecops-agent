"""
Shared API client + demo-data fallback used by all dashboard pages.
Works in two modes:
  ONLINE  — FastAPI running at API_BASE_URL  → returns live data
  OFFLINE — API not reachable               → returns demo data
"""

from __future__ import annotations

import os
import random
from datetime import datetime, timedelta, timezone
from typing import Any

import streamlit as st

API_BASE_URL: str = os.getenv("API_BASE_URL", "http://localhost:8000")
_TIMEOUT: float = 2.5          # seconds before marking as offline
_OFFLINE_TTL: int = 5          # seconds between liveness re-checks

# ── Try importing httpx ───────────────────────────────────────
try:
    import httpx as _httpx
    _HTTPX = True
except ImportError:
    _HTTPX = False


# ─────────────────────────────────────────────────────────────
# Connectivity
# ─────────────────────────────────────────────────────────────

@st.cache_data(ttl=_OFFLINE_TTL)
def api_online() -> bool:
    if not _HTTPX:
        return False
    try:
        r = _httpx.get(f"{API_BASE_URL}/health", timeout=_TIMEOUT)
        return r.status_code == 200
    except Exception:
        return False


def api_get(path: str) -> Any:
    if not _HTTPX or not api_online():
        return None
    try:
        r = _httpx.get(f"{API_BASE_URL}{path}", timeout=_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


def api_post(path: str, params: dict | None = None) -> Any:
    if not _HTTPX or not api_online():
        return None
    try:
        r = _httpx.post(f"{API_BASE_URL}{path}", params=params, timeout=_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────
# Status banner (call at top of every page)
# ─────────────────────────────────────────────────────────────

def status_banner() -> bool:
    """Render API status banner. Returns True if online."""
    live = api_online()
    if live:
        st.success(
            f"✅ **API Online** — live data from `{API_BASE_URL}`",
            icon=None,
        )
    else:
        st.warning(
            "⚠️ **API Offline** — showing demo data.  "
            "Start the API: `uvicorn api.main:app --reload --port 8000`",
        )
    return live


# ─────────────────────────────────────────────────────────────
# Data loaders
# ─────────────────────────────────────────────────────────────

@st.cache_data(ttl=15)
def load_audits(limit: int = 200) -> tuple[list[dict], bool]:
    r = api_get(f"/audits?limit={limit}")
    if r and isinstance(r, dict) and "results" in r:
        return r["results"], True
    return _demo_audits(), False


@st.cache_data(ttl=15)
def load_audit(audit_id: str) -> dict | None:
    if audit_id.startswith("demo-"):
        return next((a for a in _demo_audits() if a["audit_id"] == audit_id), None)
    return api_get(f"/audits/{audit_id}")


@st.cache_data(ttl=15)
def load_cost_summary() -> dict:
    r = api_get("/telemetry/cost")
    return r if (r and isinstance(r, dict)) else _demo_cost()


@st.cache_data(ttl=15)
def load_token_records() -> list[dict]:
    r = api_get("/telemetry/tokens?limit=200")
    if r and isinstance(r, dict):
        return r.get("records", [])
    return _demo_token_records()


# ─────────────────────────────────────────────────────────────
# Demo data
# ─────────────────────────────────────────────────────────────

def _demo_finding(sev: str, rule: str, agent: str, fname: str, line: int) -> dict:
    titles = {
        "SEC-001": "Hardcoded secret detected",
        "SEC-002": "SQL injection risk",
        "SEC-003": "XSS vulnerability",
        "SEC-007": "Vulnerable dependency (CVE)",
        "QA-001":  "Cyclomatic complexity > 10",
        "QA-003":  "Lint violation",
    }
    return {
        "finding_id": f"demo-{rule}-{line}",
        "rule_id": rule,
        "agent_id": agent,
        "severity": sev,
        "title": titles.get(rule, rule),
        "description": f"Demo finding — run the API to see real results.",
        "owasp_category": "A03:2021 – Injection",
        "suppressed": False,
        "location": {"file": fname, "line_start": line,
                     "code_snippet": f"# vulnerable code at line {line}"},
        "evidence": {"tool_name": "demo", "raw_output": "{}",
                     "command_run": "demo_scan()"},
        "patch": None,
    }


def _demo_audits() -> list[dict]:
    statuses = ["PASSED", "BLOCKED", "PASSED", "PASSED",
                "BLOCKED", "PASSED", "ERROR"]
    repos    = ["owner/webapp", "owner/api-service", "owner/cli-tool"]
    now      = datetime.now(timezone.utc)
    result   = []
    for i, st_val in enumerate(statuses):
        ts = (now - timedelta(hours=i * 4)).isoformat()
        findings: list[dict] = []
        if st_val == "BLOCKED":
            findings = [
                _demo_finding("CRITICAL", "SEC-001", "agent_b", "auth.py",    42),
                _demo_finding("HIGH",     "SEC-002", "agent_b", "models.py",  17),
                _demo_finding("MEDIUM",   "QA-001",  "agent_a", "utils.py",    5),
            ]
        elif st_val == "PASSED":
            findings = [_demo_finding("LOW", "QA-003", "agent_a", "main.py", 10)]
        result.append({
            "audit_id":       f"demo-audit-{i:03d}",
            "pr_number":      100 + i,
            "repo_full_name": repos[i % len(repos)],
            "head_sha":       f"abc{i:05d}ef",
            "overall_status": st_val,
            "started_at":     ts,
            "completed_at":   ts,
            "findings":       findings,
            "agent_metrics": [
                {"agent_id": "agent_a", "files_scanned": 3,
                 "duration_seconds": 1.2, "lines_analyzed": 150,
                 "tool_calls": [], "error": None},
                {"agent_id": "agent_b", "files_scanned": 3,
                 "duration_seconds": 4.7, "lines_analyzed": 150,
                 "tool_calls": [], "error": None},
            ],
            "compliance_report": {
                "markdown_report": "## Demo OWASP Report\n\nStart the API for real analysis."
            },
        })
    return result


def _demo_cost() -> dict:
    return {
        "total_calls": 14,
        "total_tokens": 28_400,
        "total_cost_usd": 0.2130,
        "by_model": {
            "gpt-4o":      {"calls": 10, "tokens": 21_000, "cost_usd": 0.1575},
            "gpt-4o-mini": {"calls": 4,  "tokens":  7_400, "cost_usd": 0.0555},
        },
        "by_agent": {
            "agent_c": {"calls": 14, "tokens": 28_400, "cost_usd": 0.2130},
        },
    }


def _demo_token_records() -> list[dict]:
    now = datetime.now(timezone.utc)
    return [
        {
            "timestamp":          (now - timedelta(minutes=i * 18)).isoformat(),
            "audit_id":           f"demo-audit-{i % 7:03d}",
            "agent_id":           "agent_c",
            "model":              "gpt-4o" if i % 3 != 0 else "gpt-4o-mini",
            "prompt_tokens":      int(random.randint(600, 1800)),
            "completion_tokens":  int(random.randint(200, 600)),
            "total_tokens":       int(random.randint(800, 2400)),
            "cost_usd":           round(random.uniform(0.004, 0.025), 5),
            "latency_ms":         random.randint(900, 3200),
        }
        for i in range(14)
    ]
