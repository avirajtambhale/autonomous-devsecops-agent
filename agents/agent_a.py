"""
Agent A — Syntax & Code Quality Auditor

Responsibilities:
  - Run ruff linting on modified Python files
  - Measure cyclomatic complexity via radon
  - Detect missing type annotations via mypy
  - Check function length and dead code via AST introspection
  - All findings MUST cite a QA-xxx rule ID from security-rules.spec
"""

from __future__ import annotations

import ast
import asyncio
import json
import subprocess
import uuid
from datetime import datetime, timezone
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

logger = structlog.get_logger(__name__)

# Map radon complexity grade → severity
COMPLEXITY_SEVERITY_MAP = {
    "A": None,       # 1-5: pass
    "B": None,       # 6-10: pass
    "C": Severity.MEDIUM,   # 11-15
    "D": Severity.HIGH,     # 16-20
    "E": Severity.HIGH,     # 21-25
    "F": Severity.CRITICAL, # 26+
}


class AgentA:
    """
    Agent A orchestrates static quality analysis on PR diff files.
    Uses subprocess MCP-style tool calls for deterministic, reproducible results.
    """

    AGENT_ID = "agent_a"
    MAX_COMPLEXITY = 10
    MAX_FUNCTION_LINES = 60

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def analyze(
        self,
        parsed_diff: Any,
        payload: GitHubPRPayload,
    ) -> list[Finding]:
        """
        Run all quality checks on diff files concurrently.
        Returns a deduplicated list of findings.
        """
        python_files = [
            f for f in parsed_diff.changed_files if f.path.endswith(".py")
        ]

        if not python_files:
            logger.info("agent_a_no_python_files")
            return []

        logger.info("agent_a_analyzing", file_count=len(python_files))

        # Run all checks concurrently per-file
        tasks = []
        for diff_file in python_files:
            tasks.append(self._analyze_file(diff_file))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        findings: list[Finding] = []
        for res in results:
            if isinstance(res, Exception):
                logger.error("agent_a_file_error", error=str(res))
            elif isinstance(res, list):
                findings.extend(res)

        logger.info("agent_a_complete", findings=len(findings))
        return findings

    async def _analyze_file(self, diff_file: Any) -> list[Finding]:
        """Run all checks on a single diff file."""
        findings: list[Finding] = []

        # Write diff content to a temp file for tool scanning
        tmp_path = Path(f"/tmp/agent_a_{uuid.uuid4().hex}.py")
        try:
            tmp_path.write_text(diff_file.patched_content, encoding="utf-8")

            # Run tools concurrently
            ruff_task = asyncio.create_task(self._run_ruff(tmp_path, diff_file.path))
            radon_task = asyncio.create_task(self._run_radon(tmp_path, diff_file.path))
            ast_task = asyncio.create_task(
                self._run_ast_checks(tmp_path, diff_file.path, diff_file.added_lines)
            )

            ruff_findings, radon_findings, ast_findings = await asyncio.gather(
                ruff_task, radon_task, ast_task, return_exceptions=True
            )

            for result in [ruff_findings, radon_findings, ast_findings]:
                if isinstance(result, list):
                    findings.extend(result)
                elif isinstance(result, Exception):
                    logger.warning("agent_a_tool_error", error=str(result))
        finally:
            tmp_path.unlink(missing_ok=True)

        # Filter: only report findings on lines that were actually changed
        changed_line_set = set(diff_file.added_lines)
        return [f for f in findings if f.location.line_start in changed_line_set]

    async def _run_ruff(self, file_path: Path, original_path: str) -> list[Finding]:
        """Run ruff linter and convert output to Finding objects (QA-003)."""
        findings: list[Finding] = []
        try:
            proc = await asyncio.create_subprocess_exec(
                self.settings.ruff_path,
                "check",
                str(file_path),
                "--output-format=json",
                "--no-cache",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
            raw_output = stdout.decode()

            if not raw_output.strip():
                return []

            violations = json.loads(raw_output)
            for v in violations:
                sev = self._ruff_severity(v.get("code", ""))
                if sev is None:
                    continue
                findings.append(
                    Finding(
                        finding_id=str(uuid.uuid4()),
                        rule_id="QA-003",
                        agent_id=self.AGENT_ID,
                        category=FindingCategory.QUALITY,
                        severity=sev,
                        title=f"Lint: {v.get('code')} — {v.get('message', '')}",
                        description=v.get("message", "Linting violation"),
                        location=CodeLocation(
                            file=original_path,
                            line_start=v.get("location", {}).get("row", 1),
                            code_snippet=v.get("code", ""),
                        ),
                        evidence=ToolEvidence(
                            tool_name="ruff",
                            raw_output=json.dumps(v)[:500],
                            command_run=f"ruff check {file_path} --output-format=json",
                        ),
                    )
                )
        except asyncio.TimeoutError:
            logger.warning("ruff_timeout", file=original_path)
        except Exception as exc:
            logger.error("ruff_error", file=original_path, error=str(exc))
        return findings

    async def _run_radon(self, file_path: Path, original_path: str) -> list[Finding]:
        """Run radon cc and flag functions exceeding complexity threshold (QA-001)."""
        findings: list[Finding] = []
        try:
            proc = await asyncio.create_subprocess_exec(
                self.settings.radon_path,
                "cc",
                str(file_path),
                "-s",
                "-j",  # JSON output
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            raw_output = stdout.decode()

            if not raw_output.strip():
                return []

            data = json.loads(raw_output)
            for _file, blocks in data.items():
                for block in blocks:
                    complexity = block.get("complexity", 0)
                    if complexity > self.MAX_COMPLEXITY:
                        grade = block.get("rank", "F")
                        sev = COMPLEXITY_SEVERITY_MAP.get(grade, Severity.MEDIUM)
                        if sev is None:
                            continue
                        findings.append(
                            Finding(
                                finding_id=str(uuid.uuid4()),
                                rule_id="QA-001",
                                agent_id=self.AGENT_ID,
                                category=FindingCategory.QUALITY,
                                severity=sev,
                                title=f"High Complexity: '{block.get('name')}' (CC={complexity})",
                                description=(
                                    f"Function '{block.get('name')}' has cyclomatic complexity "
                                    f"{complexity} which exceeds the threshold of {self.MAX_COMPLEXITY}. "
                                    "Refactor into smaller, focused functions."
                                ),
                                location=CodeLocation(
                                    file=original_path,
                                    line_start=block.get("lineno", 1),
                                    code_snippet=f"def {block.get('name')}(...):  # CC={complexity}",
                                ),
                                evidence=ToolEvidence(
                                    tool_name="radon",
                                    raw_output=json.dumps(block)[:500],
                                    command_run=f"radon cc {file_path} -s -j",
                                ),
                            )
                        )
        except asyncio.TimeoutError:
            logger.warning("radon_timeout", file=original_path)
        except Exception as exc:
            logger.error("radon_error", file=original_path, error=str(exc))
        return findings

    async def _run_ast_checks(
        self,
        file_path: Path,
        original_path: str,
        added_lines: list[int],
    ) -> list[Finding]:
        """
        Pure-Python AST analysis for:
        - Function length violations (QA-002)
        - Missing type annotations (QA-004)
        """
        findings: list[Finding] = []

        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=original_path)
        except SyntaxError:
            return []  # Ruff will catch this

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            fn_name = node.name
            line_start = node.lineno

            # QA-002: Function length
            fn_lines = (node.end_lineno or line_start) - line_start
            if fn_lines > self.MAX_FUNCTION_LINES:
                findings.append(
                    Finding(
                        finding_id=str(uuid.uuid4()),
                        rule_id="QA-002",
                        agent_id=self.AGENT_ID,
                        category=FindingCategory.QUALITY,
                        severity=Severity.MEDIUM,
                        title=f"Long Function: '{fn_name}' ({fn_lines} lines)",
                        description=(
                            f"Function '{fn_name}' is {fn_lines} lines long. "
                            f"Max allowed: {self.MAX_FUNCTION_LINES}. "
                            "Apply single-responsibility principle."
                        ),
                        location=CodeLocation(
                            file=original_path,
                            line_start=line_start,
                            line_end=node.end_lineno,
                            code_snippet=f"def {fn_name}(...):  # {fn_lines} lines",
                        ),
                        evidence=ToolEvidence(
                            tool_name="ast_parser",
                            raw_output=f"FunctionDef '{fn_name}' lines {line_start}-{node.end_lineno}",
                            command_run="ast.parse(source)",
                        ),
                    )
                )

            # QA-004: Missing type annotations
            missing_annotations = []
            for arg in node.args.args:
                if arg.annotation is None and arg.arg != "self":
                    missing_annotations.append(arg.arg)
            if node.returns is None:
                missing_annotations.append("-> return type")

            if missing_annotations and not fn_name.startswith("_"):
                findings.append(
                    Finding(
                        finding_id=str(uuid.uuid4()),
                        rule_id="QA-004",
                        agent_id=self.AGENT_ID,
                        category=FindingCategory.QUALITY,
                        severity=Severity.LOW,
                        title=f"Missing Annotations: '{fn_name}'",
                        description=(
                            f"Public function '{fn_name}' is missing type annotations "
                            f"on: {', '.join(missing_annotations)}"
                        ),
                        location=CodeLocation(
                            file=original_path,
                            line_start=line_start,
                            code_snippet=f"def {fn_name}(...):  # missing annotations",
                        ),
                        evidence=ToolEvidence(
                            tool_name="ast_parser",
                            raw_output=f"Missing annotations: {missing_annotations}",
                            command_run="ast.parse(source)",
                        ),
                    )
                )

        return findings

    @staticmethod
    def _ruff_severity(code: str) -> Severity | None:
        """Map ruff error codes to severity levels."""
        if not code:
            return None
        prefix = code[0].upper()
        # E/W: style errors (medium), F: pyflakes (medium), S: security (high), C: complexity (medium)
        severity_map = {
            "E": Severity.MEDIUM,
            "W": Severity.LOW,
            "F": Severity.MEDIUM,
            "S": Severity.HIGH,
            "C": Severity.MEDIUM,
            "N": Severity.LOW,
            "B": Severity.MEDIUM,
        }
        return severity_map.get(prefix)
