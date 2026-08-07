# 🔐 Autonomous DevSecOps Agent

<div align="center">

### AI-Powered Code Reviewer & Security Auditing System

[![GitHub](https://img.shields.io/badge/GitHub-avirajtambhale%2Fautonomous--devsecops--agent-181717?style=for-the-badge&logo=github)](https://github.com/avirajtambhale/autonomous-devsecops-agent)
[![Streamlit](https://img.shields.io/badge/Streamlit-Live_Dashboard-FF4B4B?style=for-the-badge&logo=streamlit)](http://localhost:8501)
[![FastAPI](https://img.shields.io/badge/FastAPI-Webhook_Gateway-009688?style=for-the-badge&logo=fastapi)](http://localhost:8000/docs)

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python)](https://python.org)
[![Redis](https://img.shields.io/badge/Redis-ARQ_Queue-DC382D?logo=redis)](https://redis.io)
[![OpenTelemetry](https://img.shields.io/badge/OTel-Tracing-425CC7?logo=opentelemetry)](https://opentelemetry.io)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

</div>

> **Production-grade autonomous code review** with 3-agent orchestration,
> Tree-sitter AST differential parsing (−70% LLM token cost), Redis task queue,
> OpenTelemetry tracing, and a Streamlit command-center dashboard with live cost tracking.

---

## ⚡ Run in 30 Seconds

```powershell
git clone https://github.com/avirajtambhale/autonomous-devsecops-agent.git
cd autonomous-devsecops-agent/ai-code-reviewer
pip install streamlit httpx pandas plotly
streamlit run dashboard/app.py
```

**→ Opens at http://localhost:8501**

Works **fully offline** with realistic demo data — no API keys, no Docker, no config.
Shows real data automatically when the FastAPI backend is running.

### Connect live data on Streamlit Cloud

In **Streamlit Cloud → Manage app → Secrets**, add:
```toml
API_BASE_URL = "https://your-deployed-api.railway.app"
```
The banner turns green and all pages show live audit data.

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                      GitHub Pull Request                            │
└────────────────────────────┬────────────────────────────────────────┘
                             │  POST /webhook/github
                             │  X-Hub-Signature-256: sha256=...
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│              FastAPI Webhook Gateway  (api/main.py)                 │
│   • HMAC-SHA256 signature verification                              │
│   • Pydantic v2 payload validation                                  │
│   • Enqueue → Redis / ARQ task queue                                │
└────────────────────────────┬────────────────────────────────────────┘
                             │
              ┌──────────────▼──────────────┐
              │   Redis + ARQ Worker         │
              │   (api/worker.py)            │
              └──────────────┬──────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────────┐
│                  Multi-Agent Orchestrator                           │
│                  (agents/orchestrator.py)                           │
│                                                                     │
│  Stage 1 ── Tree-sitter AST Diff Parser  ── −70% token cost        │
│  Stage 2 ── Fan-out: Agent A + Agent B  (PARALLEL)                 │
│                                                                     │
│   ┌─────────────────────┐     ┌──────────────────────────────┐      │
│   │  Agent A  🔧        │     │  Agent B  🛡️                 │      │
│   │  Code Quality       │     │  OWASP Security Audit         │      │
│   │                     │     │                              │      │
│   │  • ruff  (QA-003)   │     │  • MCP: Bandit  (SEC-002-006)│      │
│   │  • radon (QA-001)   │     │  • MCP: Semgrep (SEC-003,8,9)│      │
│   │  • AST   (QA-002,4) │     │  • MCP: Trivy  (SEC-007)     │      │
│   │                     │     │  • Regex       (SEC-001)     │      │
│   └──────────┬──────────┘     └───────────────┬──────────────┘      │
│              └───────────── Fan-in ────────────┘                    │
│                             │                                       │
│  Stage 3 ── Agent C  🔨  (SEQUENTIAL)                              │
│   ┌─────────────────────────────────────────────────────────┐      │
│   │  • LLM generates unified-diff patch  (gpt-4o / claude)  │      │
│   │  • Writes pytest test for the fix                        │      │
│   │  • Runs both in Docker sandbox (--network none)          │      │
│   │  • Attaches patch only if test_passed=True AND cov≥80%   │      │
│   └─────────────────────────────────────────────────────────┘      │
│                                                                     │
│  Stage 4 ── OWASP Compliance Report  (Markdown)                    │
│  Stage 5 ── Post to GitHub  (inline review + status check)         │
└─────────────────────────────────────────────────────────────────────┘
                             │
       ┌─────────────────────┼──────────────────────┐
       ▼                     ▼                      ▼
  GitHub PR            Streamlit             Prometheus
  Review +             Dashboard             + Jaeger
  Status Check         :8501                 :9090 / :16686
```

---

## 📊 Dashboard — 5 Pages

| Page | What you see |
|---|---|
| 📊 **Dashboard** | KPI cards, PR status pie chart, findings bar chart, audit table |
| 🔍 **Audit Details** | Per-PR findings with OWASP tags, raw tool output, verified patches |
| 🤖 **Agent Traces** | Per-agent MCP call log, duration, OTel span context |
| 💰 **Cost Dashboard** | Token trend, cost by model/agent, per-call latency scatter |
| ⚙️ **Settings & Setup** | API health, readiness status, spec reference, setup guide |

**Offline mode:** shows realistic demo data when the API is not running.
**Online mode:** banner turns green, all data is live from the FastAPI backend.

---

## 📁 Project Structure

```
autonomous-devsecops-agent/
└── ai-code-reviewer/             ← root of the Python project
    │
    ├── .kiro/steering/
    │   ├── security-rules.spec   ← master spec: 19 rules, PR policy, anti-hallucination
    │   └── development-norms.md  ← Kiro auto-steering norms
    │
    ├── api/                      ← FastAPI service
    │   ├── main.py               ← webhook gateway, Prometheus metrics, override endpoint
    │   ├── models.py             ← Pydantic v2 schemas (Finding, AuditResult, …)
    │   ├── config.py             ← all settings via environment variables
    │   ├── state.py              ← RedisAuditStore + InMemoryAuditStore fallback
    │   ├── worker.py             ← ARQ job definition
    │   └── telemetry.py          ← OTel setup, LangSmith, per-call cost ledger
    │
    ├── agents/                   ← multi-agent pipeline
    │   ├── orchestrator.py       ← 8-stage coordinator
    │   ├── agent_a.py            ← code quality  (ruff · radon · AST)
    │   ├── agent_b.py            ← security       (MCP Bandit · Semgrep · Trivy)
    │   ├── agent_c.py            ← patch engine   (LLM + Docker sandbox)
    │   ├── diff_parser.py        ← Tree-sitter + regex differential parser
    │   ├── github_client.py      ← GitHub REST (PR reviews · status checks)
    │   └── report_generator.py   ← OWASP Top 10 Markdown report
    │
    ├── mcp_tools/                ← Model Context Protocol tool wrappers
    │   ├── base.py               ← MCPTool abstract base (traced · retried · timed)
    │   ├── bandit_tool.py        ← Bandit as MCP tool
    │   ├── semgrep_tool.py       ← Semgrep as MCP tool
    │   └── trivy_tool.py         ← Trivy as MCP tool
    │
    ├── sandbox/
    │   └── executor.py           ← Docker sandbox (--network none · --read-only)
    │
    ├── dashboard/
    │   └── app.py                ← Streamlit command center (5 pages, offline mode)
    │
    ├── docker/
    │   ├── docker-compose.yml    ← API + Worker + Redis + Jaeger + Prometheus
    │   ├── Dockerfile.api        ← multi-stage production image
    │   ├── Dockerfile.sandbox    ← isolated test-runner image
    │   └── Dockerfile.dashboard
    │
    ├── .github/workflows/
    │   ├── ci.yml                ← lint → test → CVE scan → Docker build → deploy
    │   └── pr-audit-trigger.yml  ← forwards PR events to reviewer API
    │
    ├── .vscode/
    │   ├── launch.json           ← F5 run configs: FastAPI · Streamlit · Tests
    │   ├── settings.json         ← ruff formatter, Python path
    │   └── extensions.json       ← recommended extensions
    │
    ├── .streamlit/config.toml    ← dark theme + server settings
    ├── tests/                    ← pytest suite
    ├── scripts/                  ← run_local.ps1 / run_local.sh
    ├── requirements.txt
    ├── requirements-dev.txt
    ├── pyproject.toml            ← ruff · mypy · pytest · bandit config
    └── .env.example              ← all configurable variables with docs
```

---

## 🚀 Build & Run the Streamlit App

### Step 1 — Clone the repository

```powershell
git clone https://github.com/avirajtambhale/autonomous-devsecops-agent.git
cd autonomous-devsecops-agent/ai-code-reviewer
```

### Step 2 — Install dependencies

```powershell
# Minimum (dashboard only)
pip install streamlit httpx pandas plotly

# Full stack
pip install -r requirements.txt
```

### Step 3 — Run Streamlit

```powershell
streamlit run dashboard/app.py
```

**→ http://localhost:8501** opens automatically.

| What you see | Meaning |
|---|---|
| 🟡 Yellow banner | API offline — showing demo data. Everything still works. |
| 🟢 Green banner | API is live — showing real audit data. |

### Step 4 (optional) — Start the FastAPI backend for live data

Open a **second PowerShell window**:

```powershell
cd autonomous-devsecops-agent/ai-code-reviewer

# Copy env file (only needed once)
copy .env.example .env

# Start API (no keys needed for local testing)
uvicorn api.main:app --reload --port 8000
```

Swagger UI → **http://localhost:8000/docs**

Click **🔄 Refresh Now** in the Streamlit sidebar — banner turns green.

### Step 5 (optional) — Full production stack via Docker

```powershell
copy .env.example .env
# Edit .env: add GITHUB_TOKEN + OPENAI_API_KEY

docker compose -f docker/docker-compose.yml up -d --build
```

| Service | URL |
|---|---|
| Streamlit Dashboard | http://localhost:8501 |
| FastAPI + Swagger | http://localhost:8000/docs |
| Jaeger Trace UI | http://localhost:16686 |
| Prometheus | http://localhost:9090 |

---

## 🔑 Environment Variables

```env
# ── GitHub (required for live webhook processing) ─────────────
GITHUB_TOKEN=ghp_...
GITHUB_WEBHOOK_SECRET=any-random-string

# ── LLM (required for Agent C patch generation) ───────────────
OPENAI_API_KEY=sk-...
LLM_MODEL=gpt-4o
LLM_TEMPERATURE=0.0

# ── Redis (optional — falls back to memory if not set) ────────
REDIS_URL=redis://localhost:6379/0
USE_REDIS_STORE=true

# ── OpenTelemetry (optional) ──────────────────────────────────
OTEL_ENABLED=false
OTLP_ENDPOINT=http://localhost:4317

# ── LangSmith (optional) ──────────────────────────────────────
LANGSMITH_ENABLED=false
LANGSMITH_API_KEY=ls__...
LANGSMITH_PROJECT=ai-code-reviewer

# ── Tree-sitter ───────────────────────────────────────────────
TREESITTER_ENABLED=true
```

> All variables are optional for local development.
> The dashboard and API start with zero configuration.

---

## 🛡️ Security Rules Spec

All agent findings must cite a rule from `.kiro/steering/security-rules.spec`.
**Zero-hallucination policy:** findings without a matching rule ID are silently discarded.

### Agent A — Code Quality Rules

| ID | Description | Severity | Tool |
|---|---|---|---|
| QA-001 | Cyclomatic complexity > 10 | HIGH | radon |
| QA-002 | Function length > 60 lines | MEDIUM | AST |
| QA-003 | PEP8 / lint violations | MEDIUM | ruff |
| QA-004 | Missing type annotations | LOW | AST |
| QA-005 | Docstring coverage < 80% | LOW | pydocstyle |
| QA-006 | Dead / unreachable code | LOW | vulture |

### Agent B — OWASP Security Rules

| ID | OWASP 2021 | Description | Severity | Tool |
|---|---|---|---|---|
| SEC-001 | A02 – Crypto Failures | Hardcoded secrets / API keys | CRITICAL | Semgrep + regex |
| SEC-002 | A03 – Injection | SQL injection (f-string queries) | CRITICAL | Bandit B608 |
| SEC-003 | A03 – Injection | Cross-site scripting (XSS) | HIGH | Semgrep |
| SEC-004 | A08 – Data Integrity | Insecure deserialization (pickle) | CRITICAL | Bandit B301/506 |
| SEC-005 | A03 – Injection | Shell injection (subprocess) | HIGH | Bandit B602-B605 |
| SEC-006 | A02 – Crypto Failures | Weak algorithms (MD5/SHA1/DES) | HIGH | Bandit B303-B324 |
| SEC-007 | A06 – Outdated Components | Vulnerable dependencies (CVEs) | CRITICAL/HIGH | Trivy |
| SEC-008 | A01 – Access Control | Path traversal | HIGH | Semgrep |
| SEC-009 | A10 – SSRF | Server-side request forgery | HIGH | Semgrep |
| SEC-010 | A01 – Access Control | Unprotected API routes | CRITICAL | AST |

### Agent C — Patch Verification Rules

| ID | Description | Enforcement |
|---|---|---|
| PATCH-001 | Test coverage >= 80% on generated patch | ENFORCED |
| PATCH-002 | No regression in existing test suite | ENFORCED |
| PATCH-003 | Sandbox execution <= 120 seconds | ENFORCED |

### PR Auto-block Policy

| Condition | Action |
|---|---|
| Any CRITICAL finding | ❌ Auto-block merge |
| Any ENFORCED HIGH finding | ❌ Auto-block merge |
| Patch coverage < 80% | ❌ Auto-block merge |
| WARNING count > 5 | ⚠️ Require human review |
| All findings pass | ✅ Auto-approve |
| Human override | ✅ With mandatory reason (audit trail) |

---

## 📄 API Reference

Base URL: `http://localhost:8000`

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Liveness probe — returns `{status: ok}` |
| `GET` | `/readiness` | Readiness probe — checks orchestrator + agents |
| `POST` | `/webhook/github` | GitHub PR webhook receiver |
| `GET` | `/audits` | List audits (`?limit=50&offset=0&repo=owner/repo`) |
| `GET` | `/audits/{id}` | Full audit result with all findings |
| `POST` | `/audits/{id}/rerun` | Re-queue an existing audit |
| `POST` | `/audits/{id}/override` | Human override (`?reason=...` required) |
| `GET` | `/telemetry/cost` | Aggregated LLM cost summary |
| `GET` | `/telemetry/tokens` | Per-call token usage log |
| `GET` | `/metrics` | Prometheus metrics endpoint |

Interactive docs: **http://localhost:8000/docs**

---

## 💰 Cost Tracking

Built-in token accounting covers every Agent C LLM call:

| Model | Input / 1K tokens | Output / 1K tokens |
|---|---|---|
| gpt-4o | $0.005 | $0.015 |
| gpt-4o-mini | $0.00015 | $0.0006 |
| gpt-4-turbo | $0.010 | $0.030 |
| claude-3-5-sonnet | $0.003 | $0.015 |
| claude-3-haiku | $0.00025 | $0.00125 |

All costs visible in the **💰 Cost Dashboard** page in Streamlit.
LangSmith traces available at https://smith.langchain.com/projects/ai-code-reviewer

---

## 🔭 Observability

| Tool | Purpose | URL |
|---|---|---|
| **Streamlit Dashboard** | Audit metrics, findings, agent traces, cost | http://localhost:8501 |
| **Prometheus** | `pr_audits_total`, `audit_duration_seconds`, `findings_total` | http://localhost:9090 |
| **Jaeger** | Full OpenTelemetry trace spans | http://localhost:16686 |
| **LangSmith** | LLM call traces, token breakdown, latency | https://smith.langchain.com |
| **structlog** | Structured JSON logs (all services) | stdout |

---

## 🧪 Run Tests

```powershell
pip install -r requirements-dev.txt
pytest tests/ -v --cov=api --cov=agents --cov-report=term-missing
```

| Test File | Coverage |
|---|---|
| `tests/test_webhook.py` | HMAC-SHA256 verification, payload parsing, event filtering |
| `tests/test_diff_parser.py` | Tree-sitter + regex diff parsing, token reduction |
| `tests/test_agent_b_regex.py` | 7 secret detection pattern tests (deterministic) |

---

## 🔄 Update on GitHub — VS Code Commands

### Every time you make changes

Open the VS Code integrated terminal (`Ctrl+`` `):

```powershell
# 1 — Navigate to project
cd C:\Users\Sumedh\projects\autonomous-devsecops-agent\ai-code-reviewer

# 2 — Stage all changes
git add -A

# 3 — Commit with a descriptive message
git commit -m "feat: describe what you changed"

# 4 — Push to GitHub
git push
```

### First push on a new machine

```powershell
# Generate a PAT at: https://github.com/settings/tokens
# Scope needed: repo only

# Set remote with token (one time only)
git remote set-url origin https://avirajtambhale:YOUR_PAT@github.com/avirajtambhale/autonomous-devsecops-agent.git
git push -u origin main

# Remove token from URL after push (security)
git remote set-url origin https://github.com/avirajtambhale/autonomous-devsecops-agent.git
```

### VS Code Source Control (no terminal needed)

1. Press `Ctrl+Shift+G` → Source Control panel
2. Type commit message in the box at top
3. Click `✓ Commit` → `... → Push`

### Useful git commands

```powershell
git status              # see what changed
git log --oneline -5    # last 5 commits
git diff                # see exact changes
git pull                # get latest from GitHub
```

---

## 🔗 Important Links

| Resource | URL |
|---|---|
| **GitHub Repository** | https://github.com/avirajtambhale/autonomous-devsecops-agent |
| **Issues & Bug Reports** | https://github.com/avirajtambhale/autonomous-devsecops-agent/issues |
| **GitHub Actions CI** | https://github.com/avirajtambhale/autonomous-devsecops-agent/actions |
| **Streamlit Dashboard** | http://localhost:8501 *(local)* |
| **FastAPI Swagger UI** | http://localhost:8000/docs *(local)* |
| **Jaeger Trace UI** | http://localhost:16686 *(Docker Compose)* |
| **Prometheus** | http://localhost:9090 *(Docker Compose)* |
| **LangSmith Project** | https://smith.langchain.com/projects/ai-code-reviewer |
| **Generate GitHub PAT** | https://github.com/settings/tokens/new |
| **OWASP Top 10 (2021)** | https://owasp.org/www-project-top-ten/ |
| **Semgrep Rule Registry** | https://semgrep.dev/r |
| **ARQ Documentation** | https://arq-docs.helpmanual.io |
| **OpenTelemetry Python** | https://opentelemetry-python.readthedocs.io |
| **Tree-sitter Python** | https://github.com/tree-sitter/tree-sitter-python |
| **Bandit Security Linter** | https://bandit.readthedocs.io |
| **Trivy Vulnerability Scanner** | https://trivy.dev |

---

## 🤝 Contributing

```powershell
# Setup dev environment
pip install -r requirements-dev.txt

# Check code quality
ruff check .
mypy api/ agents/

# Run full test suite
pytest tests/ -v

# Run linter + type check + tests in one go
ruff check . ; mypy api/ agents/ --ignore-missing-imports ; pytest tests/ -v
```

---

## 📄 License

MIT — see [LICENSE](LICENSE)

---

<div align="center">

**Built with** FastAPI · Streamlit · Redis · ARQ · OpenTelemetry · LangSmith
· Tree-sitter · Bandit · Semgrep · Trivy · Docker · Pydantic v2

</div>
