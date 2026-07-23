"""
OWASP Compliance Report Generator
Generates structured OWASP Top 10 compliance summaries in Markdown format
to be attached directly to GitHub PR comments.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import structlog

from api.config import Settings
from api.models import ComplianceReport, Finding, FindingCategory, Severity

logger = structlog.get_logger(__name__)

# Complete OWASP Top 10 2021 categories
OWASP_TOP_10_2021 = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery",
}

SEVERITY_SCORE = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 7.0,
    Severity.MEDIUM: 4.0,
    Severity.LOW: 1.0,
    Severity.INFO: 0.0,
}


class ReportGenerator:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def generate_owasp_report(
        self,
        findings: list[Finding],
        pr_number: int,
        repo: str,
        head_sha: str,
    ) -> ComplianceReport:
        """Generate a complete OWASP Top 10 compliance report from audit findings."""
        now = datetime.now(timezone.utc)
        active = [f for f in findings if not f.suppressed]

        # Group findings by OWASP category
        owasp_findings: dict[str, list[str]] = {k: [] for k in OWASP_TOP_10_2021}

        for finding in active:
            if finding.owasp_category:
                # Extract category code from string like "A03:2021 – Injection"
                for code in OWASP_TOP_10_2021:
                    if code in (finding.owasp_category or ""):
                        owasp_findings[code].append(finding.finding_id)
                        break

        # Calculate risk score (max 10.0)
        max_score = max(
            (SEVERITY_SCORE.get(f.severity, 0.0) for f in active),
            default=0.0,
        )

        markdown = self._build_markdown(
            owasp_findings=owasp_findings,
            findings=active,
            pr_number=pr_number,
            repo=repo,
            head_sha=head_sha,
            generated_at=now,
            risk_score=max_score,
        )

        return ComplianceReport(
            generated_at=now,
            pr_number=pr_number,
            repo=repo,
            head_sha=head_sha,
            owasp_findings=owasp_findings,
            overall_risk_score=max_score,
            markdown_report=markdown,
        )

    def _build_markdown(
        self,
        owasp_findings: dict[str, list[str]],
        findings: list[Finding],
        pr_number: int,
        repo: str,
        head_sha: str,
        generated_at: datetime,
        risk_score: float,
    ) -> str:
        critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH)

        risk_badge = self._risk_badge(risk_score)

        # Build OWASP table rows
        owasp_rows = []
        for code, name in OWASP_TOP_10_2021.items():
            count = len(owasp_findings.get(code, []))
            status = "✅ Pass" if count == 0 else f"❌ {count} finding(s)"
            owasp_rows.append(f"| `{code}` | {name} | {status} |")

        owasp_table = "\n".join(owasp_rows)

        # Detailed findings section (critical + high only)
        priority_findings = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        details_section = ""
        if priority_findings:
            details_lines = []
            for f in priority_findings[:20]:  # Cap at 20 to avoid huge comments
                patch_status = (
                    "✅ Patch verified" if (f.patch and f.patch.test_passed)
                    else "⚠️ Manual fix required"
                )
                details_lines.append(
                    f"- **[{f.severity}]** `{f.rule_id}` — {f.title} "
                    f"(`{f.location.file}:{f.location.line_start}`) — {patch_status}"
                )
            details_section = "\n### Priority Findings\n" + "\n".join(details_lines)

        return f"""## 🛡️ OWASP Top 10 Compliance Report

**Repository:** `{repo}` | **PR:** #{pr_number} | **Commit:** `{head_sha[:8]}`
**Generated:** {generated_at.strftime('%Y-%m-%d %H:%M UTC')} | **Risk Score:** {risk_badge}

### Executive Summary
| Metric | Value |
|---|---|
| Total Findings | {len(findings)} |
| 🔴 Critical | {critical_count} |
| 🟠 High | {high_count} |
| Overall Risk Score | {risk_score:.1f}/10 |

### OWASP Top 10 2021 Coverage

| Category | Description | Status |
|---|---|---|
{owasp_table}
{details_section}

### Compliance Verdict
{'❌ **NON-COMPLIANT** — Critical/High findings must be resolved before merge.' if (critical_count + high_count) > 0 else '✅ **COMPLIANT** — No critical or high severity findings detected.'}

---
*Report generated by AI Code Reviewer using Bandit, Semgrep, and Trivy.*
*All findings are backed by tool evidence (zero-hallucination mode).*
"""

    @staticmethod
    def _risk_badge(score: float) -> str:
        if score >= 9.0:
            return f"🔴 **CRITICAL** ({score:.1f}/10)"
        elif score >= 7.0:
            return f"🟠 **HIGH** ({score:.1f}/10)"
        elif score >= 4.0:
            return f"🟡 **MEDIUM** ({score:.1f}/10)"
        elif score > 0:
            return f"🔵 **LOW** ({score:.1f}/10)"
        return f"✅ **NONE** ({score:.1f}/10)"
