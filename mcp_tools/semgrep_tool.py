"""
MCP-backed Semgrep Tool

Wraps the Semgrep CLI as a Model Context Protocol tool.
Supports rule sets from semgrep.dev registry and local YAML rules.

Tool schema (MCP-compatible):
  name: semgrep_scan
  description: Run Semgrep static analysis against a code snippet or file
  inputSchema:
    type: object
    properties:
      file_path:    { type: string }
      config:       { type: array, items: { type: string } }
      language:     { type: string }
      timeout:      { type: integer }
    required: [file_path]
"""

from __future__ import annotations

import json
from typing import Any

import structlog

from mcp_tools.base import MCPTool, MCPToolResult

logger = structlog.get_logger(__name__)

# Spec-aligned rule sets
DEFAULT_SEMGREP_CONFIGS = [
    "p/owasp-top-ten",
    "p/xss",
    "p/ssrf",
    "p/secrets",
]

# Map semgrep check_id patterns → spec rule IDs
SEMGREP_SPEC_MAP: dict[str, str] = {
    "xss": "SEC-003",
    "ssrf": "SEC-009",
    "path-traversal": "SEC-008",
    "path_traversal": "SEC-008",
    "sql": "SEC-002",
    "injection": "SEC-002",
    "secret": "SEC-001",
    "hardcoded": "SEC-001",
    "crypto": "SEC-006",
    "insecure-hash": "SEC-006",
    "pickle": "SEC-004",
    "deserialization": "SEC-004",
    "subprocess": "SEC-005",
}


class SemgrepTool(MCPTool):
    """MCP-backed Semgrep scanner."""

    tool_name = "semgrep_scan"
    tool_version = "1.60.0"
    default_timeout = 90

    def __init__(self, semgrep_path: str = "semgrep") -> None:
        self._semgrep_path = semgrep_path

    async def _invoke(self, params: dict[str, Any]) -> MCPToolResult:
        file_path = params["file_path"]
        configs = params.get("config", DEFAULT_SEMGREP_CONFIGS)
        timeout = params.get("timeout", self.default_timeout)

        # Build command
        cmd = [self._semgrep_path]
        for cfg in configs:
            cmd += [f"--config={cfg}"]
        cmd += [file_path, "--json", "--quiet", "--no-git-ignore"]

        command_str = " ".join(cmd)
        stdout, stderr, rc = await self._run_subprocess(cmd, timeout=timeout)

        parsed: dict[str, Any] | None = None
        if stdout.strip():
            try:
                parsed = json.loads(stdout)
                # Annotate each result with spec rule ID
                for result in parsed.get("results", []):
                    check_id = result.get("check_id", "").lower()
                    rule_id = None
                    for pattern, spec_id in SEMGREP_SPEC_MAP.items():
                        if pattern in check_id:
                            rule_id = spec_id
                            break
                    result["_spec_rule_id"] = rule_id  # injected field
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
        for r in result.parsed_output.get("results", []):
            spec_id = r.get("_spec_rule_id")
            if not spec_id:
                continue  # Zero-hallucination: skip unmapped rules
            findings.append({
                "spec_rule_id": spec_id,
                "check_id": r.get("check_id", ""),
                "message": r.get("extra", {}).get("message", ""),
                "severity": r.get("extra", {}).get("severity", "WARNING"),
                "file": r.get("path", ""),
                "line_start": r.get("start", {}).get("line", 1),
                "line_end": r.get("end", {}).get("line"),
                "code_snippet": r.get("extra", {}).get("lines", "")[:200],
                "raw_output": json.dumps(r)[:500],
            })
        return findings
