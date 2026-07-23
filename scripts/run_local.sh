#!/usr/bin/env bash
# =============================================================
# run_local.sh — Start the full stack locally for development
# =============================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "=== AI Code Reviewer — Local Dev Stack ==="

# 1. Check Python
python3 --version || { echo "Python 3.11+ required"; exit 1; }

# 2. Virtual env
if [ ! -d ".venv" ]; then
  echo "→ Creating virtual environment..."
  python3 -m venv .venv
fi
source .venv/bin/activate

# 3. Install dependencies
echo "→ Installing dependencies..."
pip install -q -r requirements.txt
pip install -q -r requirements-dev.txt

# 4. Install Tree-sitter language bindings (best-effort)
echo "→ Installing Tree-sitter language bindings..."
pip install -q tree-sitter tree-sitter-python tree-sitter-javascript 2>/dev/null || \
  echo "  ⚠ Tree-sitter bindings not available — regex parser will be used"

# 5. Validate .env
if [ ! -f ".env" ]; then
  echo "→ Copying .env.example → .env (edit it before starting!)"
  cp .env.example .env
fi

# 6. Start Redis (if Docker available)
if command -v docker &>/dev/null; then
  echo "→ Starting Redis..."
  docker run -d --name ai-reviewer-redis \
    -p 6379:6379 redis:7-alpine \
    2>/dev/null || docker start ai-reviewer-redis 2>/dev/null || true
fi

# 7. Start FastAPI
echo ""
echo "→ Starting FastAPI on http://localhost:8000"
echo "  Swagger UI: http://localhost:8000/docs"
uvicorn api.main:app --reload --port 8000 &
API_PID=$!
sleep 3

# 8. Start ARQ worker (background)
echo "→ Starting ARQ worker..."
arq api.worker.WorkerSettings &
WORKER_PID=$!
sleep 1

# 9. Start Streamlit
echo "→ Starting Streamlit dashboard on http://localhost:8501"
echo ""
echo "  Press Ctrl+C to stop all services"
echo "────────────────────────────────────────"
trap "kill $API_PID $WORKER_PID 2>/dev/null; echo 'Stopped.'" EXIT
streamlit run dashboard/app.py --server.port 8501
