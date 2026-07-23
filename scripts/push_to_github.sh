#!/usr/bin/env bash
# =============================================================
# push_to_github.sh — Push project to GitHub and set secrets
#
# Usage:
#   chmod +x scripts/push_to_github.sh
#   GITHUB_USERNAME=yourname REPO_NAME=ai-code-reviewer ./scripts/push_to_github.sh
#
# Prerequisites:
#   - git installed
#   - gh (GitHub CLI) installed and authenticated: gh auth login
#   - Set GITHUB_USERNAME and REPO_NAME env vars
# =============================================================

set -euo pipefail

GITHUB_USERNAME="${GITHUB_USERNAME:?Set GITHUB_USERNAME}"
REPO_NAME="${REPO_NAME:-ai-code-reviewer}"
REPO_FULL="${GITHUB_USERNAME}/${REPO_NAME}"
BRANCH="${BRANCH:-main}"

echo "────────────────────────────────────────────────"
echo "📦  Pushing to github.com/${REPO_FULL}"
echo "────────────────────────────────────────────────"

# 1. Create the GitHub repo (skip if it already exists)
if ! gh repo view "${REPO_FULL}" &>/dev/null; then
  echo "→ Creating repo ${REPO_FULL}..."
  gh repo create "${REPO_FULL}" \
    --public \
    --description "Production-grade AI Code Reviewer & Security Auditing Agent" \
    --clone=false
else
  echo "→ Repo ${REPO_FULL} already exists."
fi

# 2. Init git if needed and add remote
if [ ! -d ".git" ]; then
  git init
  git checkout -b "${BRANCH}"
fi

if ! git remote get-url origin &>/dev/null; then
  git remote add origin "https://github.com/${REPO_FULL}.git"
else
  git remote set-url origin "https://github.com/${REPO_FULL}.git"
fi

# 3. Create .gitignore if missing
if [ ! -f ".gitignore" ]; then
cat > .gitignore << 'EOF'
.env
*.pyc
__pycache__/
.venv/
venv/
dist/
build/
*.egg-info/
.pytest_cache/
.mypy_cache/
.ruff_cache/
coverage.xml
.coverage
htmlcov/
EOF
fi

# 4. Stage all files
git add -A
git diff --cached --quiet && echo "→ Nothing to commit." && exit 0

git commit -m "feat: AI Code Reviewer v2 — Redis queue, Tree-sitter, OTel, Cost Dashboard"

# 5. Push
git push -u origin "${BRANCH}"

echo ""
echo "✅  Pushed to https://github.com/${REPO_FULL}"
echo ""

# 6. Set GitHub Actions secrets (requires: GITHUB_TOKEN, OPENAI_API_KEY in local env)
echo "→ Setting GitHub Actions secrets..."
declare -A SECRETS=(
  ["GITHUB_TOKEN"]="${GITHUB_TOKEN:-}"
  ["GITHUB_WEBHOOK_SECRET"]="${GITHUB_WEBHOOK_SECRET:-}"
  ["OPENAI_API_KEY"]="${OPENAI_API_KEY:-}"
  ["AI_REVIEWER_URL"]="${AI_REVIEWER_URL:-}"
  ["AI_REVIEWER_WEBHOOK_SECRET"]="${AI_REVIEWER_WEBHOOK_SECRET:-}"
)

for secret_name in "${!SECRETS[@]}"; do
  value="${SECRETS[$secret_name]}"
  if [ -n "$value" ]; then
    echo "  → Setting ${secret_name}..."
    echo "${value}" | gh secret set "${secret_name}" -R "${REPO_FULL}"
  else
    echo "  ⚠  ${secret_name} not set — skipping (set it manually in GitHub Settings)"
  fi
done

echo ""
echo "────────────────────────────────────────────────"
echo "🎉  Done! Next steps:"
echo "   1. Add GitHub webhook:"
echo "      URL:    https://<your-domain>/webhook/github"
echo "      Secret: \$GITHUB_WEBHOOK_SECRET"
echo "      Events: Pull requests"
echo "   2. Deploy with Docker:"
echo "      cd docker && docker compose up -d"
echo "   3. Run Streamlit:"
echo "      streamlit run dashboard/app.py"
echo "────────────────────────────────────────────────"
