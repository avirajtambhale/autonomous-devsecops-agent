# =============================================================
# push_to_github.ps1 — Windows PowerShell version
# Push project to GitHub and configure secrets
#
# Usage:
#   $env:GITHUB_USERNAME = "yourname"
#   $env:REPO_NAME = "ai-code-reviewer"
#   .\scripts\push_to_github.ps1
# =============================================================

$ErrorActionPreference = "Stop"

$GITHUB_USERNAME = $env:GITHUB_USERNAME
$REPO_NAME       = if ($env:REPO_NAME) { $env:REPO_NAME } else { "ai-code-reviewer" }
$REPO_FULL       = "$GITHUB_USERNAME/$REPO_NAME"
$BRANCH          = if ($env:BRANCH) { $env:BRANCH } else { "main" }

if (-not $GITHUB_USERNAME) {
    Write-Error "Set `$env:GITHUB_USERNAME before running this script."
    exit 1
}

Write-Host "─────────────────────────────────────────" -ForegroundColor Cyan
Write-Host "Pushing to github.com/$REPO_FULL" -ForegroundColor Cyan
Write-Host "─────────────────────────────────────────" -ForegroundColor Cyan

# Create repo if it doesn't exist
$repoExists = gh repo view $REPO_FULL 2>$null
if (-not $repoExists) {
    Write-Host "Creating repo $REPO_FULL..." -ForegroundColor Yellow
    gh repo create $REPO_FULL `
        --public `
        --description "Production-grade AI Code Reviewer & Security Auditing Agent" `
        --clone=false
} else {
    Write-Host "Repo $REPO_FULL already exists." -ForegroundColor Green
}

# Init git and set remote
if (-not (Test-Path ".git")) {
    git init
    git checkout -b $BRANCH
}

$remoteExists = git remote get-url origin 2>$null
if ($remoteExists) {
    git remote set-url origin "https://github.com/$REPO_FULL.git"
} else {
    git remote add origin "https://github.com/$REPO_FULL.git"
}

# Create .gitignore
if (-not (Test-Path ".gitignore")) {
    @"
.env
*.pyc
__pycache__/
.venv/
venv/
dist/
build/
.pytest_cache/
.mypy_cache/
coverage.xml
.coverage
"@ | Set-Content .gitignore
}

# Commit and push
git add -A
$status = git status --porcelain
if (-not $status) {
    Write-Host "Nothing to commit." -ForegroundColor Yellow
    exit 0
}

git commit -m "feat: AI Code Reviewer v2 - Redis queue, Tree-sitter, OTel, Cost Dashboard"
git push -u origin $BRANCH

Write-Host ""
Write-Host "Pushed to https://github.com/$REPO_FULL" -ForegroundColor Green
Write-Host ""

# Set GitHub Actions secrets
$secrets = @{
    GITHUB_TOKEN               = $env:GITHUB_TOKEN
    GITHUB_WEBHOOK_SECRET      = $env:GITHUB_WEBHOOK_SECRET
    OPENAI_API_KEY             = $env:OPENAI_API_KEY
    AI_REVIEWER_URL            = $env:AI_REVIEWER_URL
    AI_REVIEWER_WEBHOOK_SECRET = $env:AI_REVIEWER_WEBHOOK_SECRET
}

Write-Host "Setting GitHub Actions secrets..." -ForegroundColor Yellow
foreach ($kv in $secrets.GetEnumerator()) {
    if ($kv.Value) {
        Write-Host "  Setting $($kv.Key)..." -ForegroundColor DarkGray
        echo $kv.Value | gh secret set $kv.Key -R $REPO_FULL
    } else {
        Write-Host "  Skipping $($kv.Key) (not set in env)" -ForegroundColor DarkYellow
    }
}

Write-Host ""
Write-Host "─────────────────────────────────────────" -ForegroundColor Cyan
Write-Host "Done! Next steps:" -ForegroundColor Green
Write-Host "  1. Register GitHub webhook"
Write-Host "     URL: https://<your-domain>/webhook/github"
Write-Host "     Events: Pull requests"
Write-Host "  2. Deploy: cd docker && docker compose up -d"
Write-Host "  3. Dashboard: streamlit run dashboard/app.py"
Write-Host "─────────────────────────────────────────" -ForegroundColor Cyan
