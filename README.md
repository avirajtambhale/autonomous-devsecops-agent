# 🔐 Autonomous DevSecOps Agent

<div align="center">

### AI-Powered Code Reviewer & Security Auditing System

[![GitHub](https://img.shields.io/badge/GitHub-avirajtambhale%2Fautonomous--devsecops--agent-181717?style=for-the-badge&logo=github)](https://github.com/avirajtambhale/autonomous-devsecops-agent)
[![Streamlit App](https://img.shields.io/badge/Streamlit-Live_Dashboard-FF4B4B?style=for-the-badge&logo=streamlit)](https://avirajtambhale-autonomous-devsecops-agent.streamlit.app)
[![FastAPI](https://img.shields.io/badge/FastAPI-Webhook_Gateway-009688?style=for-the-badge&logo=fastapi)](http://localhost:8000/docs)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python)](https://python.org)
[![Redis](https://img.shields.io/badge/Redis-ARQ_Queue-DC382D?logo=redis)](https://redis.io)
[![OpenTelemetry](https://img.shields.io/badge/OTel-Tracing-425CC7?logo=opentelemetry)](https://opentelemetry.io)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

**Production-grade autonomous code review** · Multi-agent orchestration
· Tree-sitter AST parsing (−70% token cost) · Redis task queue
· OpenTelemetry tracing · Streamlit cost dashboard

</div>

---

## ⚡ Run in 30 Seconds

```bash
git clone https://github.com/avirajtambhale/autonomous-devsecops-agent.git
cd autonomous-devsecops-agent/ai-code-reviewer
pip install streamlit httpx pandas plotly
streamlit run dashboard/app.py
```

**→ Opens at http://localhost:8501**

Works **fully offline with demo data** — no API keys, no Docker, no config needed.
The banner turns **green** automatically when the FastAPI backend is running.

### 🌐 Connect Live Data on Streamlit Cloud

In **Streamlit Cloud → Manage app → Secrets**, add:
```toml
API_BASE_URL = "https://your-deployed-api.railway.app"
```
The app reloads and shows real audit findings from your GitHub PRs.

---

## 🏗️ System Architecture

```
GitHub Pull Request
        │  webhook POST /webhook/github
        │  X-Hub-Signature-256: sha256=<hmac>
        ▼
┌─────────────────────────────────────────────────────────────┐
│            FastAPI Webhook Gateway  :8000                   │
│   HMAC-SHA256 verification · Pydantic v2 validation        │
│   → enqueue job to Redis / ARQ task queue                  │
└──────────────────────────┬──────────────────────────────────┘
                           │
              ┌────────────▼────────────┐
              │   ARQ Worker Process    │
              │   (api/worker.py)       │
              └────────────┬────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                Multi-Agent Orchestrator                     │
│                                                             │
│  Stage 1 ── Tree-sitter AST Diff Parser  ─── −70% tokens  │
│  Stage 2 ── Fan-out  ───────────────────────────────────── │
│                                                             │
│  ┌──────────────────┐        ┌──────────────────────────┐   │
│  │   Agent A  🔧    │        │   Agent B  🛡️            │   │
│  │  Code Quality    │        │  OWASP Security Audit     │   │
│  │  ruff  QA-003    │        │  MCP: Bandit  SEC-002-006 │   │
│  │  radon QA-001    │ PARALLEL│  MCP: Semgrep SEC-003,8,9│   │
│  │  AST   QA-002,4  │        │  MCP: Trivy   SEC-007     │   │
│  └────────┬─────────┘        │  Regex        SEC-001     │   │
│           └──── Fan-in ───── ┘                            │   │
│                    │                                       │   │
│  Stage 3 ── Agent C  🔨  (sequential)                     │   │
│  ┌──────────────────────────────────────────────────────┐  │   │
│  │  LLM generates unified-diff patch (gpt-4o/claude)    │  │   │
│  │  Writes pytest test · runs in Docker sandbox         │  │   │
│  │  Attaches patch only if test_passed=True AND cov≥80% │  │   │
│  └──────────────────────────────────────────────────────┘  │   │
│                                                             │
│  Stage 4 ── OWASP Compliance Report (Markdown)            │
│  Stage 5 ── Post inline review + commit status to GitHub  │
└──────────────────────────────────────────────────────────────┘
          │                     │                  │
     GitHub PR             Streamlit          Prometheus
    Review + Status        Dashboard          + Jaeger
    Check                  :8501              Observability
```

---

## 📊 Dashboard Features (v2.1)

| Page | Features |
|---|---|
| 📊 **Dashboard** | 7 KPI cards · PR status pie · findings bar chart · audit table with patch count |
| 🔍 **Audit Details** | Severity filter · OWASP tags · raw tool output · auto-patched diffs in tabs |
| 🤖 **Agent Traces** | Per-agent DataFrame · MCP tool call log · OTel span context |
| 💰 **Cost Dashboard** | Token trend · cost scatter · breakdown by model + agent · LangSmith link |
| ⚙️ **Settings** | Tabbed Local / Cloud / Docker guides · API health · spec reference |

**Offline mode:** realistic demo data (OWASP reports, code snippets, auto-patches)
**Online mode:** live findings from your GitHub PRs via FastAPI backend

---

## 📁 Project Structure

```
autonomous-devsecops-agent/
└── ai-code-reviewer/
    ├── .kiro/steering/
    │   ├── security-rules.spec    ← 19 rules, PR policy, anti-hallucination
    │   └── development-norms.md   ← Kiro auto-steering
    ├── api/
    │   ├── main.py                ← FastAPI gateway + Prometheus metrics
    │   ├── models.py              ← Pydantic v2 schemas
    │   ├── config.py              ← pydantic-settings (all optional locally)
    │   ├── state.py               ← RedisAuditStore + InMemory fallback
    │   ├── worker.py              ← ARQ job worker
    │   └── telemetry.py           ← OTel + LangSmith + cost ledger
    ├── agents/
    │   ├── orchestrator.py        ← 8-stage pipeline
    │   ├── agent_a.py             ← Code quality (ruff · radon · AST)
    │   ├── agent_b.py             ← Security (MCP: Bandit · Semgrep · Trivy)
    │   ├── agent_c.py             ← Patch engine (LLM + Docker sandbox)
    │   ├── diff_parser.py         ← Tree-sitter + regex diff parser
    │   ├── github_client.py       ← GitHub REST API
    │   └── report_generator.py    ← OWASP compliance report
    ├── mcp_tools/
    │   ├── base.py                ← MCPTool (OTel-traced · retried · timed)
    │   ├── bandit_tool.py         ← Bandit as MCP tool
    │   ├── semgrep_tool.py        ← Semgrep as MCP tool
    │   └── trivy_tool.py          ← Trivy as MCP tool
    ├── sandbox/executor.py        ← Docker sandbox (--network none)
    ├── dashboard/
    │   └── app.py                 ← Streamlit dashboard v2.1
    ├── docker/docker-compose.yml  ← API+Worker+Redis+Jaeger+Prometheus
    ├── .streamlit/config.toml     ← Dark theme
    ├── .python-version            ← 3.12 (pins Streamlit Cloud version)
    ├── requirements.txt           ← Dashboard only: 6 pure-Python packages
    ├── requirements-backend.txt   ← Full backend (local/Docker only)
    └── .env.example
```

---

## 🚀 Run Options

### Option 1 — Dashboard only (works right now)

```powershell
pip install streamlit httpx pandas plotly
streamlit run dashboard/app.py
# → http://localhost:8501
```

### Option 2 — Full stack (live data in dashboard)

**Terminal 1** — Redis (optional, falls back to memory)
```powershell
docker run -d -p 6379:6379 redis:7-alpine
```

**Terminal 2** — FastAPI backend
```powershell
pip install -r requirements-backend.txt
copy .env.example .env        # add GITHUB_TOKEN + OPENAI_API_KEY
uvicorn api.main:app --reload --port 8000
# → http://localhost:8000/docs
```

**Terminal 3** — Dashboard (banner turns green)
```powershell
streamlit run dashboard/app.py
# → http://localhost:8501
```

### Option 3 — Full Docker Compose

```powershell
copy .env.example .env
docker compose -f docker/docker-compose.yml up -d --build
```

| Service | URL |
|---|---|
| Streamlit Dashboard | http://localhost:8501 |
| FastAPI + Swagger | http://localhost:8000/docs |
| Jaeger Trace UI | http://localhost:16686 |
| Prometheus | http://localhost:9090 |

---

## 🛡️ Security Rules (Zero-hallucination)

Every finding must cite a rule from `.kiro/steering/security-rules.spec` AND include raw tool evidence. Findings without a rule ID are silently discarded.

### Agent A — Code Quality

| Rule | Description | Severity | Tool |
|---|---|---|---|
| QA-001 | Cyclomatic complexity > 10 | HIGH | radon |
| QA-002 | Function > 60 lines | MEDIUM | AST |
| QA-003 | Lint violations | MEDIUM | ruff |
| QA-004 | Missing type annotations | LOW | AST |
| QA-005 | Docstring coverage < 80% | LOW | pydocstyle |
| QA-006 | Dead code | LOW | vulture |

### Agent B — OWASP Security

| Rule | OWASP 2021 | Severity | Tool |
|---|---|---|---|
| SEC-001 | A02 – Cryptographic Failures | CRITICAL | Semgrep + regex |
| SEC-002 | A03 – Injection (SQL) | CRITICAL | Bandit B608 |
| SEC-003 | A03 – Injection (XSS) | HIGH | Semgrep |
| SEC-004 | A08 – Deserialization | CRITICAL | Bandit B301/506 |
| SEC-005 | A03 – Shell injection | HIGH | Bandit B602-B605 |
| SEC-006 | A02 – Weak crypto | HIGH | Bandit B303-B324 |
| SEC-007 | A06 – Vulnerable deps | CRITICAL | Trivy CVE |
| SEC-008 | A01 – Path traversal | HIGH | Semgrep |
| SEC-009 | A10 – SSRF | HIGH | Semgrep |
| SEC-010 | A01 – Unprotected routes | CRITICAL | AST |

### PR Auto-block Policy

| Condition | Action |
|---|---|
| Any CRITICAL finding | ❌ Block merge |
| Any ENFORCED HIGH finding | ❌ Block merge |
| Patch test coverage < 80% | ❌ Block merge |
| All pass | ✅ Auto-approve |

---

## 📄 API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Liveness probe |
| `GET` | `/readiness` | Readiness probe |
| `POST` | `/webhook/github` | GitHub PR webhook |
| `GET` | `/audits` | List audits |
| `GET` | `/audits/{id}` | Audit details + findings |
| `POST` | `/audits/{id}/rerun` | Re-queue audit |
| `POST` | `/audits/{id}/override` | Human override |
| `GET` | `/telemetry/cost` | LLM cost summary |
| `GET` | `/telemetry/tokens` | Per-call token log |
| `GET` | `/metrics` | Prometheus metrics |

Swagger UI: **http://localhost:8000/docs**

---

## 💰 LLM Cost Tracking

| Model | Input/1K | Output/1K |
|---|---|---|
| gpt-4o | $0.005 | $0.015 |
| gpt-4o-mini | $0.00015 | $0.0006 |
| claude-3-5-sonnet | $0.003 | $0.015 |
| claude-3-haiku | $0.00025 | $0.00125 |

All costs visible in the **💰 Cost Dashboard** page.

---

## 🔑 Environment Variables

```env
# Required for live GitHub webhook processing
GITHUB_TOKEN=ghp_...
GITHUB_WEBHOOK_SECRET=any-random-string

# Required for Agent C patch generation
OPENAI_API_KEY=sk-...
LLM_MODEL=gpt-4o

# Optional — auto-fallback to in-memory if not set
REDIS_URL=redis://localhost:6379/0
USE_REDIS_STORE=true

# Optional tracing
OTEL_ENABLED=false
LANGSMITH_ENABLED=false
LANGSMITH_API_KEY=ls__...
```

> All variables are optional for local development.

---

## 🔄 Update on GitHub

```powershell
cd C:\Users\Sumedh\projects\autonomous-devsecops-agent\ai-code-reviewer
git add -A
git commit -m "describe your change"
git push
```

### First push on a new machine

```powershell
# Get PAT: https://github.com/settings/tokens/new (scope: repo)
$PAT = "YOUR_PAT"
git -c "credential.helper=" push "https://avirajtambhale:$PAT@github.com/avirajtambhale/autonomous-devsecops-agent.git" main
```

---

## 🔗 Important Links

| Resource | URL |
|---|---|
| **GitHub Repo** | https://github.com/avirajtambhale/autonomous-devsecops-agent |
| **GitHub Issues** | https://github.com/avirajtambhale/autonomous-devsecops-agent/issues |
| **GitHub Actions** | https://github.com/avirajtambhale/autonomous-devsecops-agent/actions |
| **Streamlit Cloud** | https://share.streamlit.io |
| **FastAPI Docs** | http://localhost:8000/docs |
| **Jaeger UI** | http://localhost:16686 |
| **LangSmith** | https://smith.langchain.com/projects/ai-code-reviewer |
| **Generate PAT** | https://github.com/settings/tokens/new |
| **OWASP Top 10** | https://owasp.org/www-project-top-ten/ |
| **Semgrep Rules** | https://semgrep.dev/r |
| **Trivy Docs** | https://trivy.dev |

---

## 🧪 Tests

```powershell
pip install -r requirements-dev.txt
pytest tests/ -v --cov=api --cov=agents --cov-report=term-missing
```

---

## 📄 License

MIT — see [LICENSE](LICENSE)

---

<div align="center">
Built with FastAPI · Streamlit · Redis · ARQ · OpenTelemetry · LangSmith · Tree-sitter · Bandit · Semgrep · Trivy
</div>
