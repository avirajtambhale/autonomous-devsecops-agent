"""
GitHub API Client
Handles all GitHub REST API interactions:
  - Fetching PR diffs
  - Posting inline review comments
  - Creating commit status checks
  - Attaching compliance reports as PR comments
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import structlog

from api.config import Settings
from api.models import ComplianceReport, Finding, Severity

logger = structlog.get_logger(__name__)

GITHUB_API_VERSION = "2022-11-28"


class GitHubClient:
    """Async GitHub API client using httpx."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        token = settings.github_token.get_secret_value() if settings.github_token else ""
        self._base_url = settings.github_api_url
        self._token = token
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            headers={
                "Authorization": f"Bearer {token}" if token else "",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": GITHUB_API_VERSION,
                "User-Agent": "ai-code-reviewer/1.0.0",
            },
            timeout=30.0,
        )

    async def fetch_pr_diff(self, repo: str, pr_number: int) -> str:
        """Fetch the raw unified diff for a PR."""
        url = f"/repos/{repo}/pulls/{pr_number}"
        logger.info("fetching_diff", repo=repo, pr=pr_number)

        response = await self._client.get(
            url,
            headers={"Accept": "application/vnd.github.v3.diff"},
        )
        response.raise_for_status()
        return response.text

    async def post_pr_review(
        self,
        repo: str,
        pr_number: int,
        head_sha: str,
        findings: list[Finding],
        compliance_report: ComplianceReport,
    ) -> None:
        """
        Post a GitHub PR review with:
        - Inline comments for each finding
        - A summary comment with the full OWASP compliance report
        """
        if not findings and not compliance_report.markdown_report:
            return

        # Build inline review comments
        inline_comments = []
        for f in findings:
            if f.suppressed:
                continue
            body = self._format_finding_comment(f)
            inline_comments.append({
                "path": f.location.file,
                "line": f.location.line_start,
                "side": "RIGHT",
                "body": body,
            })

        # Determine review event based on findings
        critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL and not f.suppressed)
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH and not f.suppressed)

        if critical_count > 0:
            event = "REQUEST_CHANGES"
        elif high_count > 0:
            event = "REQUEST_CHANGES"
        elif findings:
            event = "COMMENT"
        else:
            event = "APPROVE"

        summary_body = self._format_review_summary(findings, compliance_report)

        review_payload: dict[str, Any] = {
            "commit_id": head_sha,
            "body": summary_body,
            "event": event,
            "comments": inline_comments[:50],  # GitHub limits to 50 inline comments per review
        }

        url = f"/repos/{repo}/pulls/{pr_number}/reviews"
        response = await self._client.post(url, json=review_payload)

        if response.status_code not in (200, 201):
            logger.error(
                "pr_review_post_failed",
                status=response.status_code,
                body=response.text[:200],
            )
        else:
            logger.info("pr_review_posted", repo=repo, pr=pr_number, event=event)

    async def post_commit_status(
        self,
        repo: str,
        sha: str,
        state: str,
        description: str,
    ) -> None:
        """Create a GitHub commit status check."""
        url = f"/repos/{repo}/statuses/{sha}"
        payload = {
            "state": state,  # error | failure | pending | success
            "description": description[:140],  # GitHub limit
            "context": "ai-code-reviewer/security-audit",
            "target_url": f"https://your-reviewer-dashboard/audits/{sha}",
        }
        response = await self._client.post(url, json=payload)
        if response.status_code not in (200, 201):
            logger.error(
                "commit_status_post_failed",
                status=response.status_code,
                body=response.text[:200],
            )
        else:
            logger.info("commit_status_posted", repo=repo, sha=sha[:8], state=state)

    async def close(self) -> None:
        await self._client.aclose()

    # ─── Formatting helpers ────────────────────────────────────

    def _format_finding_comment(self, finding: Finding) -> str:
        severity_emoji = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
            Severity.INFO: "⚪",
        }.get(finding.severity, "⚪")

        patch_section = ""
        if finding.patch and finding.patch.test_passed:
            patch_section = f"""

### ✅ Verified Patch Available
```diff
{finding.patch.patch_diff[:1000]}
```
*Coverage: {finding.patch.coverage_pct:.1f}% | Confidence: {finding.patch.confidence_score:.0%}*
"""

        return f"""{severity_emoji} **[{finding.severity}] {finding.rule_id}: {finding.title}**

{finding.description}

> **Evidence** (`{finding.evidence.tool_name}`): `{finding.location.code_snippet[:150]}`

| Field | Value |
|---|---|
| Rule | `{finding.rule_id}` |
| Agent | `{finding.agent_id}` |
| OWASP | {finding.owasp_category or "N/A"} |
| Tool | `{finding.evidence.tool_name}` |
{patch_section}
---
*AI Code Reviewer — zero-hallucination mode. All findings backed by tool evidence.*
"""

    def _format_review_summary(
        self,
        findings: list[Finding],
        compliance_report: ComplianceReport,
    ) -> str:
        active = [f for f in findings if not f.suppressed]
        critical = sum(1 for f in active if f.severity == Severity.CRITICAL)
        high = sum(1 for f in active if f.severity == Severity.HIGH)
        medium = sum(1 for f in active if f.severity == Severity.MEDIUM)
        low = sum(1 for f in active if f.severity == Severity.LOW)
        patched = sum(1 for f in active if f.patch and f.patch.test_passed)

        status_emoji = "❌ BLOCKED" if (critical + high) > 0 else "✅ PASSED"

        return f"""# 🤖 AI Code Security Review

## Status: {status_emoji}

### Finding Summary
| Severity | Count |
|---|---|
| 🔴 Critical | {critical} |
| 🟠 High | {high} |
| 🟡 Medium | {medium} |
| 🔵 Low | {low} |
| ✅ Auto-Patched | {patched} |

---
{compliance_report.markdown_report[:3000]}

---
*Powered by AI Code Reviewer v1.0.0 — Agents: Ruff + Bandit + Semgrep + Trivy*
"""
