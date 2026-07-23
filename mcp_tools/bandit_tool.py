"""
MCP-backed Bandit Tool

Wraps the Bandit CLI as a Model Context Protocol tool.

Tool schema (MCP-compatible):
  name: bandit_scan
  description: Run Bandit SAST scanner against a Python file
  inputSchema:
    type: object
    properties:
      file_path:   { type: string }
      test_ids:    { type: array, items: { type: string } }
      severity:    { type: string, enum: [LOW, MEDIUM, HIGH] }
      confidence:  { type: string, enum: [LOW, MEDIUM, HIGH] }
    required: [file_path]
"""

from __future__ import annotations

import json
from typing import Any

import structlog

from mcp_tools.base import MCPTool, MCPToolResult

logger = structlog.get_logger(__name__)

# All Bandit test IDs that map to spec rule IDs
BANDIT_SPEC_MAP: dict[str, tuple[str, str]] = {
    "B608": ("SEC-002", "CRITICAL"),
    "B301": ("SEC-004", "CRITICAL"),
    "B302": ("SEC-004", "CRITICAL"),
    "B506": ("SEC-004", "HIGH"),
    "B602": ("SEC-005", "HIGH"),
    "B603": ("SEC-005", "HIGH"),
    "B604": ("SEC-005", "HIGH"),
    "B605": ("SEC-005", "HIGH"),
    "B303": ("SEC-006", "HIGH"),
    "B304": ("SEC-006", "HIGH"),
    "B305": ("SEC-006", "HIGH"),
    "B324": ("SEC-006", "HIGH"),
    "B105": ("SEC-001", "CRITICAL"),
    "B106": ("SEC-001", "CRITICAL"),
    "B107": ("SEC-001", "CRITICAL"),
    "B101": ("QA-003", "LOW"),     # assert_used
    "B201": ("SEC-005", "HIGH"),   # flask_debug_true
    "B501": ("SEC-006", "MEDIUM"), # request_with_no_cert_validation
    "B502": ("SEC-006", "MEDIUM"), # ssl_with_no_version
    "B503": ("SEC-006", "MEDIUM"), # ssl_with_bad_version
}


class BanditTool(MCPTool):
    """MCP-backed Bandit scanner."""

    tool_name = "bandit_scan"
    tool_version = "1.7.8"
    default_timeout = 60

    def __init__(self, bandit_path: str = "bandit") -> None:
        self._bandit_path = bandit_path

    async def _invoke(self, params: dict[str, Any]) -> MCPToolResult:
        file_path = params["file_path"]
        test_ids = params.get("test_ids", list(BANDIT_SPEC_MAP.keys()))
        severity = params.get("severity", "LOW")
        confidence = params.get("confidence", "LOW")

        # Restrict to mapped tests only (zero-hallucination)
        tests_arg = ",".join(t for t in test_ids if t in BANDIT_SPEC_MAP)

        cmd = [
            self._bandit_path,
            "-r", file_path,
            "--format", "json",
            "--quiet",
            "-l",  # report only low severity+
        ]
        if tests_arg:
            cmd += ["-t", tests_arg]

        command_str = " ".join(cmd)
        stdout, stderr, rc = await self._run_subprocess(cmd, timeout=self.default_timeout)

        parsed: dict[str, Any] | None = None
        if stdout.strip():
            try:
                parsed = json.loads(stdout)
                # Annotate each result with spec rule IDs
                for issue in parsed.get("results", []):
                    test_id = issue.get("test_id", "")
                    mapping = BANDIT_SPEC_MAP.get(test_id)
                    issue["_spec_rule_id"] = mapping[0] if mapping else None
                    issue["_spec_severity"] = mapping[1] if mapping else "INFO"
            except json.JSONDecodeError:
                pass

        return MCPToolResult(
            tool_name=self.tool_name,
            tool_version=self.tool_version,
            call_id="",
            input_params=params,
            raw_output=stdout[:3000],
            parsed_output=parsed,
            exit_code=rc,
            duration_ms=0.0,
            command_run=command_str,
        )

    def extract_findings(self, result: MCPToolResult) -> list[dict[str, Any]]:
        """Convert MCPToolResult into a flat list of finding dicts."""
        if not result.parsed_output or not isinstance(result.parsed_output, dict):
            return []
        findings = []
        for issue in result.parsed_output.get("results", []):
            spec_id = issue.get("_spec_rule_id")
            if not spec_id:
                continue  # Zero-hallucination: skip unmapped rules
            findings.append({
                "spec_rule_id": spec_id,
                "test_id": issue.get("test_id", ""),
                "test_name": issue.get("test_name", ""),
                "severity": issue.get("_spec_severity", "MEDIUM"),
                "message": issue.get("issue_text", ""),
                "file": issue.get("filename", ""),
                "line_start": issue.get("line_number", 1),
                "line_end": (issue.get("line_range") or [None])[-1],
                "code_snippet": issue.get("code", "").strip()[:200],
                "raw_output": json.dumps(issue)[:500],
            })
        return findings
