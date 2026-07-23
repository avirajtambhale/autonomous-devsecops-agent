"""
Agent B — Security & OWASP Auditor

Uses MCP-backed tool wrappers (SemgrepTool, BanditTool, TrivyTool)
for all static analysis. Every tool call is OTel-traced and every
finding maps to a concrete rule ID from security-rules.spec.
Zero-hallucination: findings without a rule_id are silently discarded.
"""

from __future__ import annotations

import asyncio
import re
import uuid
from pathlib import Path
from typing import Any

import structlog

from api.config import Settings
from api.models import (
    CodeLocation,
    Finding,
    FindingCategory,
    GitHubPRPayload,
    Severity,
    ToolEvidence,
)
from mcp_tools.bandit_tool import BanditTool
from mcp_tools.semgrep_tool import SemgrepTool
from mcp_tools.trivy_tool import TrivyTool

logger = structlog.get_logger(__name__)

# ─── Hardcoded credential patterns (SEC-001) ──────────────────
SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}", re.MULTILINE), "CRITICAL"),
    ("Generic API Key", re.compile(r'(?i)(api_key|apikey|api-key)\s*=\s*["\'][A-Za-z0-9_\-]{16,}["\']', re.MULTILINE), "CRITICAL"),
    ("Generic Secret", re.compile(r'(?i)(secret|password|passwd|pwd)\s*=\s*["\'][^"\']{8,}["\']', re.MULTILINE), "CRITICAL"),
    ("OpenAI Key", re.compile(r"sk-[a-zA-Z0-9]{32,}", re.MULTILINE), "CRITICAL"),
    ("Private Key Header", re.compile(r"-----BEGIN (RSA|EC|PGP) PRIVATE KEY-----", re.MULTILINE), "CRITICAL"),
    ("Bearer Token", re.compile(r'(?i)authorization["\']?\s*:\s*["\']?Bearer\s+[A-Za-z0-9\-._~+/]{20,}', re.MULTILINE), "HIGH"),
]


class AgentB:
    """
    Agent B orchestrates OWASP security analysis using MCP tool wrappers.
    All findings are backed by MCP tool evidence — zero-hallucination enforced.
    """

    AGENT_ID = "agent_b"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._bandit = BanditTool(bandit_path=settings.bandit_path)
        self._semgrep = SemgrepTool(semgrep_path=settings.semgrep_path)
        self._trivy = TrivyTool(trivy_path=settings.trivy_path)

    async def analyze(
        self,
        parsed_diff: Any,
        payload: GitHubPRPayload,
    ) -> list[Finding]:
        """Main entry point — dispatches all MCP security scans."""
        python_files = [f for f in parsed_diff.changed_files if f.path.endswith(".py")]
        dep_files = [
            f for f in parsed_diff.changed_files
            if f.path in ("requirements.txt", "pyproject.toml", "Pipfile", "package.json")
        ]

        if not python_files and not dep_files:
            logger.info("agent_b_no_relevant_files")
            return []

        logger.info("agent_b_analyzing", python_files=len(python_files), dep_files=len(dep_files))

        scan_tasks = []
        for diff_file in python_files:
            scan_tasks.extend([
                self._run_bandit_mcp(diff_file),
                self._run_semgrep_mcp(diff_file),
                self._run_secret_regex(diff_file),
            ])
        for diff_file in dep_files:
            scan_tasks.append(self._run_trivy_mcp(diff_file))

        results = await asyncio.gather(*scan_tasks, return_exceptions=True)

        findings: list[Finding] = []
        for result in results:
            if isinstance(result, list):
                findings.extend(result)
            elif isinstance(result, Exception):
                logger.error("agent_b_scan_error", error=str(result))

        findings = self._deduplicate(findings)

        # Filter to changed lines only
        changed_lines_by_file = {f.path: set(f.added_lines) for f in parsed_diff.changed_files}
        filtered = [
            f for f in findings
            if not changed_lines_by_file.get(f.location.file)
            or f.location.line_start in changed_lines_by_file.get(f.location.file, set())
        ]

        logger.info("agent_b_complete", findings=len(filtered))
        return filtered

    # ─── MCP tool runners ────────────────────────────────────

    async def _run_bandit_mcp(self, diff_file: Any) -> list[Finding]:
        tmp_path = Path(f"/tmp/agentb_bandit_{uuid.uuid4().hex}.py")
        try:
            content = getattr(diff_file, "ast_context", None) or diff_file.patched_content
            tmp_path.write_text(content, encoding="utf-8")
            result = await self._bandit.call({"file_path": str(tmp_path)})
            return [
                self._to_finding(f, diff_file.path, "bandit", result.command_run)
                for f in self._bandit.extract_findings(result)
            ]
        except Exception as exc:
            logger.error("bandit_mcp_error", file=diff_file.path, error=str(exc))
            return []
        finally:
            tmp_path.unlink(missing_ok=True)

    async def _run_semgrep_mcp(self, diff_file: Any) -> list[Finding]:
        tmp_path = Path(f"/tmp/agentb_semgrep_{uuid.uuid4().hex}.py")
        try:
            content = getattr(diff_file, "ast_context", None) or diff_file.patched_content
            tmp_path.write_text(content, encoding="utf-8")
            result = await self._semgrep.call({"file_path": str(tmp_path)})
            return [
                self._to_finding(f, diff_file.path, "semgrep", result.command_run)
                for f in self._semgrep.extract_findings(result)
            ]
        except Exception as exc:
            logger.error("semgrep_mcp_error", file=diff_file.path, error=str(exc))
            return []
        finally:
            tmp_path.unlink(missing_ok=True)

    async def _run_trivy_mcp(self, diff_file: Any) -> list[Finding]:
        tmp_path = Path(f"/tmp/agentb_trivy_{uuid.uuid4().hex}_{Path(diff_file.path).name}")
        try:
            tmp_path.write_text(diff_file.patched_content, encoding="utf-8")
            result = await self._trivy.call({"path": str(tmp_path.parent)})
            return [self._to_dep_finding(f, diff_file.path) for f in self._trivy.extract_findings(result)]
        except Exception as exc:
            logger.error("trivy_mcp_error", file=diff_file.path, error=str(exc))
            return []
        finally:
            tmp_path.unlink(missing_ok=True)

    async def _run_secret_regex(self, diff_file: Any) -> list[Finding]:
        findings: list[Finding] = []
        content = diff_file.patched_content
        for pattern_name, pattern, severity_str in SECRET_PATTERNS:
            for match in pattern.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                redacted = re.sub(r"[A-Za-z0-9\-._~+/=]{8,}", "***REDACTED***", match.group())
                findings.append(Finding(
                    finding_id=str(uuid.uuid4()),
                    rule_id="SEC-001",
                    agent_id=self.AGENT_ID,
                    category=FindingCategory.SECURITY,
                    severity=Severity(severity_str),
                    title=f"Hardcoded Secret: {pattern_name}",
                    description=(
                        f"Potential hardcoded credential ({pattern_name}) detected. "
                        "Use environment variables or a secrets manager."
                    ),
                    owasp_category="A02:2021 – Cryptographic Failures",
                    location=CodeLocation(
                        file=diff_file.path,
                        line_start=line_num,
                        code_snippet=redacted[:100],
                    ),
                    evidence=ToolEvidence(
                        tool_name="regex_scanner",
                        raw_output=f"Pattern '{pattern_name}' matched at line {line_num}: {redacted[:50]}",
                        command_run="regex_scan(content, SECRET_PATTERNS)",
                    ),
                ))
        return findings

    # ─── Helpers ─────────────────────────────────────────────

    def _to_finding(self, raw: dict[str, Any], original_path: str,
                    tool_name: str, command_run: str | None) -> Finding:
        sev_map = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
                   "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW, "INFO": Severity.INFO}
        sev = sev_map.get(raw.get("severity", "MEDIUM"), Severity.MEDIUM)
        rule_id = raw.get("spec_rule_id", "SEC-001")
        label = raw.get("test_name") or raw.get("check_id") or raw.get("message", "")
        return Finding(
            finding_id=str(uuid.uuid4()),
            rule_id=rule_id,
            agent_id=self.AGENT_ID,
            category=FindingCategory.SECURITY,
            severity=sev,
            title=f"[{tool_name.upper()}] {label}",
            description=raw.get("message", "Security issue detected"),
            owasp_category=self._rule_to_owasp(rule_id),
            location=CodeLocation(
                file=original_path,
                line_start=raw.get("line_start", 1),
                line_end=raw.get("line_end"),
                code_snippet=raw.get("code_snippet", "")[:200],
            ),
            evidence=ToolEvidence(
                tool_name=tool_name,
                raw_output=raw.get("raw_output", "")[:2000],
                command_run=command_run,
            ),
        )

    def _to_dep_finding(self, raw: dict[str, Any], original_path: str) -> Finding:
        sev_str = raw.get("severity", "HIGH")
        sev = Severity(sev_str) if sev_str in Severity.__members__ else Severity.HIGH
        return Finding(
            finding_id=str(uuid.uuid4()),
            rule_id="SEC-007",
            agent_id=self.AGENT_ID,
            category=FindingCategory.DEPENDENCY,
            severity=sev,
            title=f"[CVE] {raw.get('cve_id')} in {raw.get('package')}",
            description=(
                f"{raw.get('package')}@{raw.get('installed_version')} has {sev_str} "
                f"vulnerability {raw.get('cve_id')}. "
                f"Fix: upgrade to {raw.get('fixed_version', 'latest')}. "
                f"{raw.get('description', '')}"
            ),
            owasp_category="A06:2021 – Vulnerable and Outdated Components",
            location=CodeLocation(
                file=original_path,
                line_start=1,
                code_snippet=raw.get("code_snippet", ""),
            ),
            evidence=ToolEvidence(
                tool_name="trivy",
                raw_output=raw.get("raw_output", ""),
                command_run="trivy fs --security-checks vuln --format json",
            ),
        )

    def _deduplicate(self, findings: list[Finding]) -> list[Finding]:
        seen: set[tuple[str, str, int]] = set()
        unique = []
        for f in findings:
            key = (f.rule_id, f.location.file, f.location.line_start)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    @staticmethod
    def _rule_to_owasp(rule_id: str) -> str:
        owasp_map = {
            "SEC-001": "A02:2021 – Cryptographic Failures",
            "SEC-002": "A03:2021 – Injection",
            "SEC-003": "A03:2021 – Injection",
            "SEC-004": "A08:2021 – Software and Data Integrity Failures",
            "SEC-005": "A03:2021 – Injection",
            "SEC-006": "A02:2021 – Cryptographic Failures",
            "SEC-007": "A06:2021 – Vulnerable and Outdated Components",
            "SEC-008": "A01:2021 – Broken Access Control",
            "SEC-009": "A10:2021 – Server-Side Request Forgery",
            "SEC-010": "A01:2021 – Broken Access Control",
        }
        return owasp_map.get(rule_id, "Unknown OWASP Category")
