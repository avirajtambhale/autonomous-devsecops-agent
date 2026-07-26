# 🔐 Autonomous DevSecOps Agent — AI Code Reviewer

> Production-grade autonomous code review with multi-agent orchestration,
> Tree-sitter AST parsing (−70% token cost), Redis task queue, OpenTelemetry
> tracing, and a live Streamlit Cost Dashboard.

[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green)](https://fastapi.tiangolo.com/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.35-red)](https://streamlit.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## ⚡ TL;DR — Run the Dashboard Right Now

The dashboard works **offline with demo data** — no API key, no Redis, no Docker required.

```powershell
# From the ai-code-reviewer folder
pip install streamlit httpx pandas plotly
streamlit run dashboard/app.py
```

Browser opens at **http://localhost:8501** and shows demo audit data.
A yellow banner tells you the API is offline. Everything is clickable.

---

## 🏗️ Architecture

```
GitHub PR Webhook
        │
        ▼
┌─────────────────────────────┐
│  FastAPI Gateway            │  HMAC-SHA256 · Pydantic v2
│  api/main.py  :8000         │  → enqueue to ARQ / Redis
└──────────────┬──────────────┘
               │  Redis Task Queue (ARQ)
               ▼
┌─────────────────────────────────────────────────┐
│              Multi-Agent Orchestrator            │
│                                                  │
│  Tree-sitter AST Diff  (−70% token cost)        │
│                                                  │
│  Agent A 🔧 (parallel)  Agent B 🛡️ (parallel)   │
│  ruff · radon · AST     MCP: Bandit · Semgrep   │
│  Code quality           MCP: Trivy · regex       │
│           └──────── fan-in ───────┘              │
│                         ▼                        │
│              Agent C 🔨 (sequential)             │
│           LLM patches · Docker sandbox           │
└──────────────────────┬──────────────────────────┘
                       │
          ┌────────────┼──────────────┐
          ▼            ▼              ▼
   GitHub PR      OWASP Report   Streamlit
  Review+Status   (Markdown)     Dashboard
```

---

## 📁 Project Structure

```
ai-code-reviewer/
├── .kiro/steering/
│   └── security-rules.spec   ← 19 rules: QA-001-006, SEC-001-010, PATCH-001-003
├── api/
│   ├── main.py               ← FastAPI webhook gateway
│   ├── models.py             ← Pydantic v2 schemas
│   ├── config.py             ← pydantic-settings (all optional for dev)
│   ├── state.py              ← Redis AuditStore + in-memory fallback
│   ├── worker.py             ← ARQ task queue worker
│   └── telemetry.py          ← OpenTelemetry + LangSmith + cost ledger
├── agents/
│   ├── orchestrator.py       ← Pipeline coordinator
│   ├── agent_a.py            ← Code quality  (ruff, radon, AST)
│   ├── agent_b.py            ← Security       (MCP: Bandit, Semgrep, Trivy)
│   ├── agent_c.py            ← Patch engine   (LLM + Docker sandbox)
│   ├── diff_parser.py        ← Tree-sitter + regex differential parser
│   ├── github_client.py      ← GitHub REST API client
│   └── report_generator.py   ← OWASP compliance report
├── mcp_tools/
│   ├── base.py               ← MCPTool abstract base (OTel-traced)
│   ├── bandit_tool.py        ← Bandit MCP wrapper
│   ├── semgrep_tool.py       ← Semgrep MCP wrapper
│   └── trivy_tool.py         ← Trivy MCP wrapper
├── sandbox/executor.py       ← Docker sandbox (--network none)
├── dashboard/app.py          ← Streamlit dashboard (works offline)
├── docker/docker-compose.yml ← API + Worker + Redis + Jaeger + Prometheus
├── scripts/
│   ├── run_local.ps1         ← Windows one-command startup
│   └── run_local.sh          ← Mac/Linux one-command startup
├── .streamlit/config.toml    ← Streamlit dark theme
├── requirements.txt
└── .env.example
```

---

## 🚀 Startup Options

### Option 1 — Streamlit dashboard only (no API needed)

```powershell
cd ai-code-reviewer
pip install -r requirements.txt
streamlit run dashboard/app.py
```

✅ Opens at **http://localhost:8501**
Shows demo audits, findings, cost charts, agent traces.

---

### Option 2 — Full stack with FastAPI (live data)

Open **three separate PowerShell terminals**, all from the `ai-code-reviewer` folder:

**Terminal 1 — Redis** (requires Docker Desktop)
```powershell
docker run -d --name redis -p 6379:6379 redis:7-alpine
```
> No Docker? Skip this. The API auto-falls back to in-memory storage.

**Terminal 2 — FastAPI**
```powershell
cd ai-code-reviewer
copy .env.example .env          # first time only
# Edit .env: set GITHUB_TOKEN (optional for local testing)
uvicorn api.main:app --reload --port 8000
```
Swagger UI at **http://localhost:8000/docs**

**Terminal 3 — Streamlit**
```powershell
cd ai-code-reviewer
streamlit run dashboard/app.py
```
Dashboard at **http://localhost:8501** — banner turns green when API is live.

---

### Option 3 — Full Docker Compose (production)

```powershell
cd ai-code-reviewer
copy .env.example .env
# Edit .env with real secrets
docker compose -f docker/docker-compose.yml up -d --build
```

| Service | URL |
|---|---|
| FastAPI + Swagger | http://localhost:8000/docs |
| Streamlit Dashboard | http://localhost:8501 |
| Jaeger Trace UI | http://localhost:16686 |
| Prometheus | http://localhost:9090 |

---

## 🔑 Environment Variables

Copy `.env.example` → `.env`. Minimum required for full functionality:

```env
# Required for live GitHub webhook processing
GITHUB_TOKEN=ghp_...
GITHUB_WEBHOOK_SECRET=any-random-string

# Required for Agent C patch generation
OPENAI_API_KEY=sk-...

# Optional — defaults to in-memory if not set
REDIS_URL=redis://localhost:6379/0
USE_REDIS_STORE=true

# Optional tracing
OTEL_ENABLED=false            # set true + OTLP_ENDPOINT for traces
LANGSMITH_ENABLED=false       # set true + LANGSMITH_API_KEY for LLM traces
```

> **All variables are optional for local development.**
> The API and dashboard start without any `.env` file.

---

## 🪝 GitHub Webhook Setup

1. Go to your repo → **Settings → Webhooks → Add webhook**
2. Set:
   ```
   Payload URL:   https://your-domain.com/webhook/github
   Content type:  application/json
   Secret:        <same as GITHUB_WEBHOOK_SECRET in .env>
   Events:        Pull requests
   ```
3. Add these as GitHub Actions Secrets for auto-forwarding:
   ```
   AI_REVIEWER_URL            = https://your-domain.com
   AI_REVIEWER_WEBHOOK_SECRET = <same secret>
   ```

---

## 🛡️ Security Rules Spec

Every agent finding **must** cite a rule from `.kiro/steering/security-rules.spec`.
Findings without a matching rule ID are silently discarded (zero-hallucination).

| Agent | Rules | Tools |
|---|---|---|
| Agent A | QA-001 → QA-006 | ruff, radon, Python AST |
| Agent B | SEC-001 → SEC-010 | Bandit (MCP), Semgrep (MCP), Trivy (MCP), regex |
| Agent C | PATCH-001 → PATCH-003 | LLM + pytest + Docker sandbox |

### PR Auto-block conditions
- Any `CRITICAL` finding present
- Any `ENFORCED HIGH` finding present
- Patch test coverage < 80%

---

## 💰 Cost Dashboard

Click **💰 Cost Dashboard** in Streamlit to see:
- Total tokens + USD cost (live or demo)
- Cost by model (gpt-4o, claude-3-5-sonnet, etc.)
- Cost by agent (A / B / C)
- Per-call latency scatter plot
- LangSmith project link for full LLM traces

---

## 🔄 Update on GitHub

After making any changes:

```powershell
cd ai-code-reviewer

# Stage and commit
git add -A
git commit -m "your change description"

# Push (first time: set your PAT in the URL)
# git remote set-url origin "https://avirajtambhale:YOUR_PAT@github.com/avirajtambhale/autonomous-devsecops-agent.git"
git push
```

**Get a PAT:** GitHub → Settings → Developer settings →
Personal access tokens → Tokens (classic) → Generate (scope: `repo`)

---

## 🧪 Run Tests

```powershell
pip install -r requirements-dev.txt
pytest tests/ -v --cov
```

---

## 🤝 Contributing

```powershell
pip install -r requirements-dev.txt
ruff check .
mypy api/ agents/
pytest tests/ -v
```

---

## 📄 License

MIT — see [LICENSE](LICENSE)
