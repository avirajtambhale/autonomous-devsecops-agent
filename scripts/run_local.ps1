# =============================================================
# run_local.ps1 — Windows PowerShell local dev startup
# =============================================================
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot)

Write-Host "=== AI Code Reviewer — Local Dev Stack ===" -ForegroundColor Cyan

# 1. Ensure .env exists
if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "Created .env from .env.example — edit it before running!" -ForegroundColor Yellow
}

# 2. Install dependencies
Write-Host "Installing Python dependencies..." -ForegroundColor Yellow
pip install -q -r requirements.txt
pip install -q -r requirements-dev.txt

# 3. Try Tree-sitter
try {
    pip install -q tree-sitter tree-sitter-python tree-sitter-javascript
    Write-Host "Tree-sitter installed." -ForegroundColor Green
} catch {
    Write-Host "Tree-sitter not available, using regex parser." -ForegroundColor Yellow
}

# 4. Start Redis via Docker (best-effort)
try {
    docker run -d --name ai-reviewer-redis -p 6379:6379 redis:7-alpine 2>$null
    Write-Host "Redis started." -ForegroundColor Green
} catch {
    Write-Host "Docker/Redis not available — using in-memory store." -ForegroundColor Yellow
}

# 5. FastAPI (in a new window)
Write-Host "Starting FastAPI on http://localhost:8000 ..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "uvicorn api.main:app --reload --port 8000"

Start-Sleep -Seconds 3

# 6. ARQ Worker (in a new window)
Write-Host "Starting ARQ worker..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "arq api.worker.WorkerSettings"

Start-Sleep -Seconds 1

# 7. Streamlit
Write-Host ""
Write-Host "Starting Streamlit on http://localhost:8501 ..." -ForegroundColor Cyan
streamlit run dashboard/app.py --server.port 8501
