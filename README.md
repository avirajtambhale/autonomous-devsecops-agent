# 🔐 Autonomous DevSecOps Agent — AI Code Reviewer

<div align="center">

[![GitHub Repo](https://img.shields.io/badge/GitHub-autonomous--devsecops--agent-181717?logo=github)](https://github.com/avirajtambhale/autonomous-devsecops-agent)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?logo=fastapi)](https://fastapi.tiangolo.com/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.35-FF4B4B?logo=streamlit)](https://streamlit.io/)
[![Redis](https://img.shields.io/badge/Redis-ARQ_Queue-DC382D?logo=redis)](https://redis.io/)
[![OpenTelemetry](https://img.shields.io/badge/OpenTelemetry-Tracing-425CC7?logo=opentelemetry)](https://opentelemetry.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Production-grade autonomous code review with multi-agent orchestration,
Tree-sitter AST differential parsing (−70% token cost), Redis task queue,
OpenTelemetry tracing, and a live Streamlit cost dashboard.**

[🚀 Quick Start](#-quick-start) · [📊 Dashboard](#-dashboard) · [🏗️ Architecture](#%EF%B8%8F-architecture) · [🛡️ Security Rules](#%EF%B8%8F-security-rules-spec) · [💰 Cost Dashboard](#-cost-dashboard) · [📄 API Docs](#-api-reference)

</div>

---

## ⚡ Run the Dashboard Right Now

> No API key · No Redis · No Docker required — works fully offline with demo data.

```powershell
# Clone
git clone https://github.com/avirajtambhale/autonomous-devsecops-agent.git
cd autonomous-devsecops-agent/ai-code-reviewer

# Install
pip install streamlit httpx pandas plotly

# Launch
streamlit run dashboard/app.py
```

Opens at **http://localhost:8501** → shows live demo audits, findings, cost charts, agent traces.
A yellow banner indicates API is offline; click any page — everything works.

---

## 🏗️ Architecture

```
GitHub Pull Request
        │
        ▼  HMAC-SHA256 verified
┌────────────────────────────────┐
│   FastAPI Webhook Gateway      │  Pydantic v2 · HMAC-SHA256
│   api/main.py  →  :8000        │  Enqueues to Redis / ARQ
└───────────────┬────────────────┘
                │
         Redis Task Queue (ARQ)
                │
                ▼
┌──────────────────────────────────────────────────┐
│            Multi-Agent Orchestrator              │
│                                                  │
│  ① Tree-sitter AST Diff Parser  (−70% tokens)   │
│                                                  │
│  ┌──────────────┐   ┌──────────────┐  PARALLEL  │
│  │  Agent A 🔧  │   │  Agent B 🛡️  │            │
│  │ Code Quality │   │ OWASP Audit  │            │
│  │ ruff · radon │   │ MCP: Bandit  │            │
│  │ AST checks   │   │ MCP: Semgrep │            │
│  └──────┬───────┘   │ MCP: Trivy   │            │
│         └───────────┴──────┬───────┘            │
│                             ▼  Fan-in            │
│               ┌─────────────────────┐            │
│               │    Agent C 🔨       │ SEQUENTIAL │
│               │  LLM Patch Engine   │            │
│               │  Docker Sandbox     │            │
│               │  pytest + coverage  │            │
│               └──────────┬──────────┘            │
└──────────────────────────┼──────────────────────┘
                            │
           ┌────────────────┼───────────────┐
           ▼                ▼               ▼
    GitHub PR          OWASP Report    Streamlit
   Review + Status     (Markdown)      Dashboard
   Check               Attached        + Cost View
```

---

## ✨ Feature Matrix

| Feature | Detail | Status |
|---|---|---|
| **HMAC-SHA256 Webhook** | Constant-time sig verification on every GitHub event | ✅ |
| **Pydantic v2 Validation** | Strict schema on all PR payloads | ✅ |
| **Redis + ARQ Queue** | Durable async task queue; survives API restarts | ✅ |
| **Tree-sitter AST Parsing** | Only changed AST nodes extracted → ~70% fewer LLM tokens | ✅ |
| **MCP Tool Wrappers** | Bandit · Semgrep · Trivy as Model Context Protocol tools | ✅ |
| **Kiro Steering Spec** | 19 rules govern all agent findings | ✅ |
| **Zero-hallucination** | Every finding requires `rule_id` + raw tool evidence | ✅ |
| **OpenTelemetry** | Full spans → OTLP → Jaeger / Tempo / Honeycomb | ✅ |
| **LangSmith Tracing** | Agent C LLM calls traced with token counts + latency | ✅ |
| **Cost Dashboard** | Streamlit: cost/call · cost/model · token trend charts | ✅ |
| **Docker Sandbox** | `--network none` · `--read-only` · 120 s timeout | ✅ |
| **Offline Demo Mode** | Dashboard works without any running service | ✅ |

---

## 📁 Project Structure

```
autonomous-devsecops-agent/
└── ai-code-reviewer/
    ├── .kiro/
    │   └── steering/
    │       ├── security-rules.spec   ← 19 rules: QA/SEC/PATCH + PR policy
    │       └── development-norms.md  ← Kiro steering (auto-loaded)
    │
    ├── api/
    │   ├── main.py         ← FastAPI gateway, HMAC webhook, Prometheus metrics
    │   ├── models.py       ← Pydantic v2 schemas (Finding, AuditResult, etc.)
    │   ├── config.py       ← pydantic-settings (all env-var driven)
    │   ├── state.py        ← RedisAuditStore + InMemoryAuditStore fallback
    │   ├── worker.py       ← ARQ job: run_audit_job
    │   └── telemetry.py    ← OTel setup + LangSmith + per-call cost ledger
    │
    ├── agents/
    │   ├── orchestrator.py     ← 8-stage pipeline coordinator
    │   ├── agent_a.py          ← Code quality  (ruff · radon · AST)
    │   ├── agent_b.py          ← Security       (MCP: Bandit · Semgrep · Trivy)
    │   ├── agent_c.py          ← Patch engine   (LLM → Docker sandbox)
    │   ├── diff_parser.py      ← Tree-sitter + regex differential parser
    │   ├── github_client.py    ← GitHub REST API (PR reviews + status checks)
    │   └── report_generator.py ← OWASP Top 10 compliance report
    │
    ├── mcp_tools/
    │   ├── base.py         ← MCPTool abstract base (OTel-traced, retried)
    │   ├── bandit_tool.py  ← Bandit as MCP tool
    │   ├── semgrep_tool.py ← Semgrep as MCP tool
    │   └── trivy_tool.py   ← Trivy as MCP tool
    │
    ├── sandbox/
    │   └── executor.py     ← Docker sandbox executor
    │
    ├── dashboard/
    │   └── app.py          ← Streamlit dashboard (online + offline modes)
    │
    ├── docker/
    │   ├── docker-compose.yml  ← API + Worker + Redis + Jaeger + Prometheus
    │   ├── Dockerfile.api
    │   ├── Dockerfile.sandbox
    │   └── Dockerfile.dashboard
    │
    ├── scripts/
    │   ├── run_local.ps1   ← Windows one-command full startup
    │   └── run_local.sh    ← Mac/Linux one-command full startup
    │
    ├── tests/              ← pytest test suite
    ├── .streamlit/
    │   └── config.toml     ← Dark theme + server config
    ├── requirements.txt
    ├── requirements-dev.txt
    ├── pyproject.toml      ← ruff · mypy · pytest config
    └── .env.example        ← All configurable variables
```

---

## 🚀 Quick Start

### Option 1 — Dashboard only (no dependencies)

```powershell
cd ai-code-reviewer
pip install streamlit httpx pandas plotly
streamlit run dashboard/app.py
# → http://localhost:8501
```

### Option 2 — Full stack with FastAPI (live data)

Open **3 PowerShell terminals** in `ai-code-reviewer/`:

**Terminal 1 — Redis** *(optional — API falls back to memory without it)*
```powershell
docker run -d --name redis -p 6379:6379 redis:7-alpine
```

**Terminal 2 — FastAPI API server**
```powershell
pip install -r requirements.txt
copy .env.example .env    # first time — add GITHUB_TOKEN + OPENAI_API_KEY
uvicorn api.main:app --reload --port 8000
# Swagger UI → http://localhost:8000/docs
```

**Terminal 3 — Streamlit dashboard**
```powershell
streamlit run dashboard/app.py
# → http://localhost:8501  (banner turns green when API is live)
```

### Option 3 — Docker Compose (full production stack)

```powershell
cd ai-code-reviewer
copy .env.example .env    # fill in secrets
docker compose -f docker/docker-compose.yml up -d --build
```

| Service | URL | Description |
|---|---|---|
| FastAPI + Swagger | http://localhost:8000/docs | Webhook gateway + REST API |
| Streamlit Dashboard | http://localhost:8501 | Command center + cost view |
| Jaeger Trace UI | http://localhost:16686 | OpenTelemetry spans |
| Prometheus | http://localhost:9090 | Metrics scraping |
| Redis | localhost:6379 | Task queue + audit store |

---

## 🔑 Environment Variables

Copy `.env.example` → `.env`. Minimum for full functionality:

```env
# GitHub  (required for live webhook processing)
GITHUB_TOKEN=ghp_...
GITHUB_WEBHOOK_SECRET=any-random-string

# LLM  (required for Agent C patch generation)
OPENAI_API_KEY=sk-...
LLM_MODEL=gpt-4o

# Redis  (optional — falls back to in-memory if not set)
REDIS_URL=redis://localhost:6379/0
USE_REDIS_STORE=true

# Tracing  (all optional)
OTEL_ENABLED=false
OTLP_ENDPOINT=http://localhost:4317
LANGSMITH_ENABLED=false
LANGSMITH_API_KEY=ls__...
LANGSMITH_PROJECT=ai-code-reviewer

# Tree-sitter
TREESITTER_ENABLED=true
```

> All variables are **optional for local development** — the API and dashboard start without any `.env` file.

---

## 🪝 GitHub Webhook Setup

1. Your repo → **Settings → Webhooks → Add webhook**
2. Configure:
   ```
   Payload URL:   https://your-domain.com/webhook/github
   Content type:  application/json
   Secret:        <value of GITHUB_WEBHOOK_SECRET>
   Events:        Pull requests ✅
   ```
3. Add GitHub Actions secrets for auto-forwarding:
   ```
   AI_REVIEWER_URL            = https://your-domain.com
   AI_REVIEWER_WEBHOOK_SECRET = <same secret>
   ```

---

## 🛡️ Security Rules Spec

Every agent finding **must** cite a rule from `.kiro/steering/security-rules.spec`.
Findings without a matching rule ID are silently discarded → **zero-hallucination**.

### Agent A — Code Quality

| Rule | Description | Tool |
|---|---|---|
| QA-001 | Cyclomatic complexity > 10 | radon |
| QA-002 | Function length > 60 lines | AST |
| QA-003 | PEP8 / lint violations | ruff |
| QA-004 | Missing type annotations | AST |
| QA-005 | Docstring coverage < 80% | pydocstyle |
| QA-006 | Dead code | vulture |

### Agent B — OWASP Security

| Rule | OWASP Category | Tool |
|---|---|---|
| SEC-001 | A02 – Hardcoded secrets | Semgrep + regex |
| SEC-002 | A03 – SQL injection | Bandit B608 |
| SEC-003 | A03 – XSS | Semgrep |
| SEC-004 | A08 – Insecure deserialization | Bandit B301/B506 |
| SEC-005 | A03 – Shell injection | Bandit B602-B605 |
| SEC-006 | A02 – Weak crypto (MD5/SHA1) | Bandit B303-B324 |
| SEC-007 | A06 – Vulnerable dependencies | Trivy CVE scan |
| SEC-008 | A01 – Path traversal | Semgrep |
| SEC-009 | A10 – SSRF | Semgrep |
| SEC-010 | A01 – Missing auth on routes | AST |

### Agent C — Patch Verification

| Rule | Description |
|---|---|
| PATCH-001 | Test coverage ≥ 80% |
| PATCH-002 | No regression in existing tests |
| PATCH-003 | Sandbox execution ≤ 120 s |

### PR Auto-block Conditions
- Any `CRITICAL` finding
- Any `HIGH` finding (ENFORCED rules)
- Patch coverage < 80%

---

## 📄 API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Liveness probe |
| `GET` | `/readiness` | Readiness probe (checks orchestrator) |
| `POST` | `/webhook/github` | GitHub PR webhook receiver |
| `GET` | `/audits` | List recent audits |
| `GET` | `/audits/{id}` | Get audit details + findings |
| `POST` | `/audits/{id}/rerun` | Re-queue an audit |
| `POST` | `/audits/{id}/override` | Human override (requires reason) |
| `GET` | `/telemetry/cost` | LLM cost summary |
| `GET` | `/telemetry/tokens` | Per-call token usage log |
| `GET` | `/metrics` | Prometheus metrics |

Full interactive docs at **http://localhost:8000/docs** (Swagger UI)

---

## 📊 Dashboard

Five pages in the Streamlit dashboard:

| Page | What it shows |
|---|---|
| 📊 Dashboard | KPI metrics, PR status pie, findings bar chart, recent audits table |
| 🔍 Audit Details | Per-PR findings with OWASP tags, raw tool output, verified patches |
| 🤖 Agent Traces | Per-agent MCP tool call log, duration, OTel span context |
| 💰 Cost Dashboard | Token usage trend, cost by model/agent, per-call latency scatter |
| ⚙️ Settings & Setup | API health, readiness, spec reference, setup instructions |

**Works offline** — shows demo data with a yellow banner when the API is not running.

---

## 💰 Cost Dashboard

Built-in token tracking covers:
- Total tokens consumed + USD cost (live or demo)
- Cost breakdown by model: `gpt-4o`, `gpt-4o-mini`, `claude-3-5-sonnet`, etc.
- Cost breakdown by agent: A / B / C
- Per-call latency vs token scatter plot
- Direct link to LangSmith project

Token rates (July 2025):

| Model | Input / 1K tokens | Output / 1K tokens |
|---|---|---|
| gpt-4o | $0.005 | $0.015 |
| gpt-4o-mini | $0.00015 | $0.0006 |
| claude-3-5-sonnet | $0.003 | $0.015 |
| claude-3-haiku | $0.00025 | $0.00125 |

---

## 🔭 Observability Stack

| Tool | Purpose | URL |
|---|---|---|
| **Prometheus** | Metrics: audits total, duration, findings by severity | http://localhost:9090 |
| **Jaeger** | OpenTelemetry trace viewer | http://localhost:16686 |
| **LangSmith** | LLM call traces, token usage, latency | https://smith.langchain.com |
| **structlog** | Structured JSON logging (all services) | stdout / log collector |

Prometheus metrics exposed at `/metrics`:

| Metric | Type | Labels |
|---|---|---|
| `pr_audits_total` | Counter | `action`, `status` |
| `audit_duration_seconds` | Histogram | — |
| `findings_total` | Counter | `severity`, `agent` |
| `webhook_requests_total` | Counter | `event_type` |

---

## 🧪 Tests

```powershell
pip install -r requirements-dev.txt
pytest tests/ -v --cov=api --cov=agents --cov-report=term-missing
```

| Test file | What it covers |
|---|---|
| `tests/test_webhook.py` | HMAC verification, payload validation, event filtering |
| `tests/test_diff_parser.py` | Tree-sitter + regex diff parsing, token reduction |
| `tests/test_agent_b_regex.py` | Secret detection patterns (deterministic) |

---

## 🔄 Update on GitHub

```powershell
cd C:\Users\Sumedh\projects\autonomous-devsecops-agent\ai-code-reviewer

# Stage all changes
git add -A

# Commit
git commit -m "describe your change"

# Push
git push
```

> **First push on a new machine:** set a GitHub PAT in the remote URL:
> ```powershell
> git remote set-url origin https://avirajtambhale:YOUR_PAT@github.com/avirajtambhale/autonomous-devsecops-agent.git
> git push -u origin main
> # Then clean it: git remote set-url origin https://github.com/avirajtambhale/autonomous-devsecops-agent.git
> ```

---

## 🔗 Important Links

| Resource | URL |
|---|---|
| **GitHub Repository** | https://github.com/avirajtambhale/autonomous-devsecops-agent |
| **GitHub Issues** | https://github.com/avirajtambhale/autonomous-devsecops-agent/issues |
| **GitHub Actions CI** | https://github.com/avirajtambhale/autonomous-devsecops-agent/actions |
| **FastAPI Swagger UI** | http://localhost:8000/docs *(when running)* |
| **Streamlit Dashboard** | http://localhost:8501 *(when running)* |
| **Jaeger Trace UI** | http://localhost:16686 *(Docker Compose)* |
| **Prometheus** | http://localhost:9090 *(Docker Compose)* |
| **LangSmith Project** | https://smith.langchain.com/projects/ai-code-reviewer |
| **Semgrep Rules** | https://semgrep.dev/r |
| **OWASP Top 10** | https://owasp.org/www-project-top-ten/ |
| **ARQ Docs** | https://arq-docs.helpmanual.io |
| **OpenTelemetry Python** | https://opentelemetry-python.readthedocs.io |
| **Tree-sitter Python** | https://github.com/tree-sitter/tree-sitter-python |

---

## 🤝 Contributing

```powershell
# Install dev deps
pip install -r requirements-dev.txt

# Lint
ruff check .

# Type check
mypy api/ agents/

# Test
pytest tests/ -v
```

---

## 📄 License

MIT — see [LICENSE](LICENSE)

---

<div align="center">
Built with FastAPI · Streamlit · Redis · OpenTelemetry · Tree-sitter · Bandit · Semgrep · Trivy
</div>
