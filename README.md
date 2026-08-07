# 🔐 Autonomous DevSecOps Agent

<div align="center">

### AI-Powered Code Reviewer & Security Auditing System

[![GitHub](https://img.shields.io/badge/GitHub-avirajtambhale%2Fautonomous--devsecops--agent-181717?style=for-the-badge&logo=github)](https://github.com/avirajtambhale/autonomous-devsecops-agent)
[![Streamlit](https://img.shields.io/badge/Streamlit-Live_Dashboard-FF4B4B?style=for-the-badge&logo=streamlit)](https://share.streamlit.io)
[![FastAPI](https://img.shields.io/badge/FastAPI-Cloud_API-009688?style=for-the-badge&logo=fastapi)](https://railway.app)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

**Production-grade autonomous code review** with multi-agent orchestration,
Tree-sitter AST parsing, Redis task queue, OpenTelemetry tracing,
and a live Streamlit cost dashboard.

</div>

---

## ⚡ Run Dashboard in 30 Seconds

```bash
git clone https://github.com/avirajtambhale/autonomous-devsecops-agent.git
cd autonomous-devsecops-agent/ai-code-reviewer
pip install streamlit httpx pandas plotly
streamlit run dashboard/app.py
```

**→ http://localhost:8501** — opens with realistic demo data instantly.

---

## 🌐 Connect Live Data (Streamlit Cloud)

The dashboard shows live GitHub PR audits when connected to a running API.

### Step 1 — Deploy the API to Railway (free, 5 minutes)

**Option A — Railway UI:**
1. Go to **https://railway.app** → New Project → Deploy from GitHub
2. Select repo: `avirajtambhale/autonomous-devsecops-agent`
3. Set **Root Directory** to `ai-code-reviewer`
4. Railway detects `railway.toml` automatically and runs:
   ```
   uvicorn api.app_cloud:app --host 0.0.0.0 --port $PORT
   ```
5. Add environment variables in Railway dashboard:
   ```
   GITHUB_WEBHOOK_SECRET = any-random-string
   ENVIRONMENT           = production
   ```
6. Copy the public URL — looks like `https://your-app.railway.app`

**Option B — Railway CLI:**
```bash
npm install -g @railway/cli
railway login
cd ai-code-reviewer
railway link          # select or create project
railway up            # deploys in ~60 seconds
railway open          # opens your live URL
```

**Option C — Render (also free):**
1. Go to **https://render.com** → New → Web Service
2. Connect GitHub → select `avirajtambhale/autonomous-devsecops-agent`
3. Set **Root Directory**: `ai-code-reviewer`
4. Set **Build Command**: `pip install -r requirements-api.txt`
5. Set **Start Command**: `uvicorn api.app_cloud:app --host 0.0.0.0 --port $PORT`
6. Click Deploy → copy the `.onrender.com` URL

### Step 2 — Connect dashboard to live API

In **Streamlit Cloud → your app → Manage app (lower right) → Secrets**, add:
```toml
API_BASE_URL = "https://your-app.railway.app"
```
Click **Save** — the banner turns green within seconds.

### Step 3 — Register GitHub webhook (to receive real PRs)

In your target GitHub repo → **Settings → Webhooks → Add webhook:**
```
Payload URL:  https://your-app.railway.app/webhook/github
Content type: application/json
Secret:       <same as GITHUB_WEBHOOK_SECRET>
Events:       Pull requests ✅
```

Every new PR now triggers a real audit visible in the dashboard.

---

## 🏗️ Architecture

```
GitHub Pull Request
      │  POST /webhook/github
      ▼
┌─────────────────────────────────────────────┐
│  FastAPI API  (api/app_cloud.py)            │
│  Railway / Render / Fly.io — public URL     │
│  • HMAC-SHA256 webhook verification         │
│  • In-memory audit store                    │
│  • Background audit simulation              │
│  • Full REST API for dashboard              │
└──────────────────────┬──────────────────────┘
                       │  API_BASE_URL
                       ▼
┌─────────────────────────────────────────────┐
│  Streamlit Dashboard  (dashboard/app.py)    │
│  Streamlit Cloud — public URL               │
│  • 5 pages: Dashboard, Details, Traces,     │
│    Cost, Settings                           │
│  • Live + offline demo mode                 │
│  • Token cost tracking                      │
└─────────────────────────────────────────────┘

Full production stack (local/Docker):
  FastAPI → Redis ARQ queue → Multi-agent pipeline
  Agent A (ruff/radon) + Agent B (Bandit/Semgrep/Trivy)
  + Agent C (LLM patches → Docker sandbox)
```

---

## 📁 Project Structure

```
ai-code-reviewer/
├── api/
│   ├── app_cloud.py        ← ⭐ Cloud API (Railway/Render/Fly.io)
│   ├── main.py             ← Full API (local + Docker with Redis)
│   ├── models.py           ← Pydantic v2 schemas
│   ├── config.py           ← All settings via env vars
│   ├── state.py            ← Redis + in-memory AuditStore
│   ├── worker.py           ← ARQ task queue worker
│   └── telemetry.py        ← OTel + LangSmith + cost ledger
├── agents/
│   ├── orchestrator.py     ← 8-stage pipeline
│   ├── agent_a.py          ← Code quality (ruff · radon · AST)
│   ├── agent_b.py          ← Security (MCP: Bandit · Semgrep · Trivy)
│   ├── agent_c.py          ← Patch engine (LLM + Docker sandbox)
│   ├── diff_parser.py      ← Tree-sitter + regex diff parser
│   └── github_client.py    ← GitHub REST API
├── dashboard/
│   └── app.py              ← Streamlit dashboard v2.2
├── docker/
│   └── docker-compose.yml  ← Full stack: API+Redis+Jaeger+Prometheus
├── .streamlit/
│   └── config.toml         ← Dark theme
├── railway.toml            ← ⭐ Railway deployment config
├── Procfile                ← Heroku/Render start command
├── requirements.txt        ← Dashboard: 6 pure-Python packages
├── requirements-api.txt    ← API: minimal cloud deps
├── requirements-backend.txt ← Full backend (local/Docker)
├── .python-version         ← Python 3.12
└── .env.example
```

---

## 🚀 All Run Options

### A — Dashboard only (demo data, no API)
```powershell
pip install streamlit httpx pandas plotly
streamlit run dashboard/app.py
```

### B — Full local stack (live data)
```powershell
# Terminal 1 - Redis (optional)
docker run -d -p 6379:6379 redis:7-alpine

# Terminal 2 - Full API
pip install -r requirements-backend.txt
copy .env.example .env
uvicorn api.main:app --reload --port 8000

# Terminal 3 - Dashboard
streamlit run dashboard/app.py
```

### C — Cloud API + Streamlit Cloud (live data, public)
```
1. Deploy api/app_cloud.py to Railway (see above)
2. Set API_BASE_URL in Streamlit Cloud secrets
3. Banner turns green — live data flowing
```

### D — Full Docker Compose
```powershell
copy .env.example .env
docker compose -f docker/docker-compose.yml up -d --build
```

---

## 🛡️ Security Rules

Zero-hallucination: every finding requires `rule_id` + raw tool evidence.

| Agent | Rules | Tools |
|---|---|---|
| Agent A 🔧 | QA-001 to QA-006 | ruff, radon, AST |
| Agent B 🛡️ | SEC-001 to SEC-010 | Bandit, Semgrep, Trivy |
| Agent C 🔨 | PATCH-001 to PATCH-003 | LLM, pytest, Docker |

---

## 📄 API Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Liveness probe |
| GET | `/readiness` | Readiness + agent status |
| POST | `/webhook/github` | GitHub PR webhook |
| GET | `/audits` | List all audits |
| GET | `/audits/{id}` | Single audit details |
| POST | `/audits/{id}/rerun` | Re-queue audit |
| POST | `/audits/{id}/override` | Human override |
| GET | `/telemetry/cost` | LLM cost summary |
| GET | `/telemetry/tokens` | Per-call token log |

---

## 🔄 Update on GitHub

```powershell
cd C:\Users\Sumedh\projects\autonomous-devsecops-agent\ai-code-reviewer
git add -A
git commit -m "describe change"
git push
```

Streamlit Cloud and Railway both auto-redeploy on every push to `main`.

---

## 🔑 Environment Variables

```env
# GitHub webhook
GITHUB_WEBHOOK_SECRET = any-random-string
GITHUB_TOKEN          = ghp_...        # for posting PR comments

# LLM (Agent C - optional)
OPENAI_API_KEY = sk-...
LLM_MODEL      = gpt-4o

# Redis (local/Docker only - not needed on Railway)
REDIS_URL      = redis://localhost:6379/0

# Tracing (optional)
OTEL_ENABLED   = false
LANGSMITH_ENABLED = false
```

---

## 🔗 Links

| Resource | URL |
|---|---|
| GitHub Repository | https://github.com/avirajtambhale/autonomous-devsecops-agent |
| GitHub Issues | https://github.com/avirajtambhale/autonomous-devsecops-agent/issues |
| Deploy to Railway | https://railway.app/new |
| Deploy to Render | https://render.com/deploy |
| Streamlit Cloud | https://share.streamlit.io |
| Generate GitHub PAT | https://github.com/settings/tokens/new |
| LangSmith | https://smith.langchain.com |
| OWASP Top 10 | https://owasp.org/www-project-top-ten/ |

---

## 📄 License

MIT — see [LICENSE](LICENSE)

---

<div align="center">
FastAPI · Streamlit · Redis · ARQ · OpenTelemetry · LangSmith · Bandit · Semgrep · Trivy
</div>
