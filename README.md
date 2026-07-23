# 🔐 Autonomous DevSecOps Agent — AI Code Reviewer

> Production-grade autonomous code review with multi-agent orchestration, Tree-sitter AST parsing, Redis task queue, OpenTelemetry tracing, and a live Streamlit Cost Dashboard.

[![CI](https://github.com/avirajtambhale/autonomous-devsecops-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/avirajtambhale/autonomous-devsecops-agent/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green)](https://fastapi.tiangolo.com/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.35-red)](https://streamlit.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 🏗️ Architecture

```
GitHub PR Webhook
        │
        ▼
┌─────────────────────────────────┐
│   FastAPI Gateway               │  HMAC-SHA256 verification
│   Pydantic v2 validation        │  → enqueue to ARQ/Redis
└────────────┬────────────────────┘
             │  Redis Task Queue (ARQ)
             ▼
┌─────────────────────────────────────────────────────┐
│              Multi-Agent Orchestrator                │
│                                                      │
│  Tree-sitter AST Diff  (−70% token cost)            │
│                                                      │
│  ┌─────────────┐   ┌─────────────┐   PARALLEL       │
│  │  Agent A 🔧  │   │  Agent B 🛡️  │                 │
│  │ Code Quality│   │OWASP Scan   │                  │
│  │ruff · radon │   │MCP: Bandit  │                  │
│  │AST checks   │   │MCP: Semgrep │                  │
│  └──────┬──────┘   │MCP: Trivy   │                  │
│         └──────────┴──────┬──────┘                  │
│                            ▼  Fan-in                 │
│               ┌────────────────────┐                 │
│               │    Agent C 🔨      │  SEQUENTIAL     │
│               │  LLM Patch Engine  │                 │
│               │  Docker Sandbox    │                 │
│               │  pytest coverage   │                 │
│               └────────┬───────────┘                 │
└────────────────────────┼────────────────────────────┘
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
   GitHub PR       OWASP Report   Streamlit
  Comments +       (Markdown)     Dashboard
  Status Check                   + Cost View
```

---

## ✨ Features

| Feature | Detail |
|---|---|
| **HMAC-SHA256 Webhook** | Constant-time signature verification on every GitHub event |
| **Redis + ARQ Queue** | Durable async task queue; survives API restarts |
| **Tree-sitter AST Parsing** | Extracts only changed AST nodes → ~70% fewer tokens sent to LLM |
| **MCP Tool Wrappers** | Bandit, Semgrep, Trivy exposed as Model Context Protocol tools |
| **Kiro Steering Spec** | 19 rules (QA-001→006, SEC-001→010, PATCH-001→003) govern all findings |
| **Zero-hallucination** | Every finding requires `rule_id` + raw tool evidence — no rule, no flag |
| **OpenTelemetry** | Full trace spans → OTLP → Jaeger/Tempo/Honeycomb |
| **LangSmith** | Agent C LLM calls traced with token counts and latency |
| **Cost Dashboard** | Streamlit page: cost/call, cost/model, token trend charts |
| **Docker Sandbox** | Agent C test execution: `--network none`, `--read-only`, 120s timeout |

---

## 📁 Project Structure

```
ai-code-reviewer/
├── .kiro/steering/
│   └── security-rules.spec     ← Governing spec (all rule IDs + pass/fail criteria)
├── api/
│   ├── main.py                 ← FastAPI gateway
│   ├── models.py               ← Pydantic v2 schemas
│   ├── config.py               ← Settings (pydantic-settings)
│   ├── state.py                ← Redis + in-memory AuditStore
│   ├── worker.py               ← ARQ task queue worker
│   └── telemetry.py            ← OpenTelemetry + LangSmith + cost ledger
├── agents/
│   ├── orchestrator.py         ← Pipeline coordinator
│   ├── agent_a.py              ← Code quality (ruff, radon, AST)
│   ├── agent_b.py              ← Security (MCP: Bandit, Semgrep, Trivy)
│   ├── agent_c.py              ← Patch engine (LLM + Docker sandbox)
│   ├── diff_parser.py          ← Tree-sitter + regex differential parser
│   ├── github_client.py        ← GitHub REST API
│   └── report_generator.py     ← OWASP compliance report
├── mcp_tools/
│   ├── base.py                 ← MCPTool abstract base (OTel-traced)
│   ├── bandit_tool.py          ← Bandit MCP wrapper
│   ├── semgrep_tool.py         ← Semgrep MCP wrapper
│   └── trivy_tool.py           ← Trivy MCP wrapper
├── sandbox/
│   └── executor.py             ← Docker sandbox executor
├── dashboard/
│   └── app.py                  ← Streamlit command center + cost dashboard
├── docker/
│   ├── docker-compose.yml      ← API + Worker + Redis + Jaeger + Prometheus
│   ├── Dockerfile.api
│   ├── Dockerfile.sandbox
│   └── Dockerfile.dashboard
├── scripts/
│   ├── run_local.ps1           ← Windows one-command startup
│   ├── run_local.sh            ← Mac/Linux one-command startup
│   ├── push_to_github.ps1      ← Push + set GitHub secrets (Windows)
│   └── push_to_github.sh       ← Push + set GitHub secrets (Mac/Linux)
├── tests/
├── .streamlit/config.toml      ← Streamlit theme + server config
├── requirements.txt
└── .env.example
```

---

## 🚀 Quick Start

### Option A — Local development (recommended for first run)

**Windows PowerShell:**
```powershell
# 1. Clone
git clone https://github.com/avirajtambhale/autonomous-devsecops-agent.git
cd autonomous-devsecops-agent/ai-code-reviewer

# 2. Copy and edit environment
copy .env.example .env
# Open .env and fill in GITHUB_TOKEN and OPENAI_API_KEY at minimum

# 3. Install dependencies
pip install -r requirements.txt

# 4. Start Redis (requires Docker Desktop)
docker run -d --name redis -p 6379:6379 redis:7-alpine

# 5. Start FastAPI
uvicorn api.main:app --reload --port 8000

# 6. (New terminal) Start ARQ worker
arq api.worker.WorkerSettings

# 7. (New terminal) Start Streamlit dashboard
streamlit run dashboard/app.py
```

**Mac / Linux:**
```bash
git clone https://github.com/avirajtambhale/autonomous-devsecops-agent.git
cd autonomous-devsecops-agent/ai-code-reviewer
cp .env.example .env      # edit GITHUB_TOKEN + OPENAI_API_KEY
pip install -r requirements.txt
chmod +x scripts/run_local.sh
./scripts/run_local.sh    # starts Redis, FastAPI, ARQ worker, Streamlit
```

### Option B — Docker Compose (full production stack)

```bash
git clone https://github.com/avirajtambhale/autonomous-devsecops-agent.git
cd autonomous-devsecops-agent/ai-code-reviewer

# Fill in your secrets
cp .env.example .env

# Build and start everything
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

Copy `.env.example` → `.env` and set these minimum values:

```env
GITHUB_TOKEN=ghp_...            # GitHub PAT (repo + pull_requests scopes)
GITHUB_WEBHOOK_SECRET=...       # Random string — must match GitHub webhook secret
OPENAI_API_KEY=sk-...           # For Agent C patch generation
REDIS_URL=redis://localhost:6379/0
OTEL_ENABLED=true
LANGSMITH_ENABLED=false         # Set true + add LANGSMITH_API_KEY to trace LLM calls
```

---

## 🪝 GitHub Webhook Setup

1. Go to your repo → **Settings → Webhooks → Add webhook**
2. Fill in:
   ```
   Payload URL:   https://your-domain.com/webhook/github
   Content type:  application/json
   Secret:        <same as GITHUB_WEBHOOK_SECRET>
   Events:        ✅ Pull requests
   ```
3. The `pr-audit-trigger.yml` workflow also auto-forwards events if you set:
   ```
   AI_REVIEWER_URL            = https://your-domain.com
   AI_REVIEWER_WEBHOOK_SECRET = <same secret>
   ```
   as GitHub Actions secrets.

---

## 🛡️ Security Rules Spec

All findings must cite a rule from `.kiro/steering/security-rules.spec`:

| Agent | Rules | Tools |
|---|---|---|
| Agent A | QA-001 to QA-006 | ruff, radon, Python AST |
| Agent B | SEC-001 to SEC-010 | Bandit, Semgrep, Trivy, regex |
| Agent C | PATCH-001 to PATCH-003 | pytest, Docker sandbox |

---

## 💰 Cost Dashboard

Visit the **💰 Cost Dashboard** tab in Streamlit to see:
- Total tokens consumed + USD cost
- Cost breakdown by model (gpt-4o, claude-3-5-sonnet, etc.)
- Cost breakdown by agent
- Per-call latency vs. token scatter plot
- Direct link to your LangSmith project

---

## 🤝 Contributing

```bash
pip install -r requirements-dev.txt
pytest tests/ -v --cov
ruff check .
mypy api/ agents/
```

---

## 📄 License

MIT — see [LICENSE](LICENSE)
