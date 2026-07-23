"""
MCP-backed Trivy Tool

Wraps the Trivy CLI for filesystem vulnerability scanning.

Tool schema (MCP-compatible):
  name: trivy_scan
  description: Scan dependency files for CVEs using Trivy
  inputSchema:
    type: object
    properties:
      path:       { type: string, description: "File or directory path to scan" }
      severity:   { type: array, items: { type: string } }
      format:     { type: string, default: "json" }
    required: [path]
"""

from __future__ import annotations

import json
from typing import Any

import structlog

from mcp_tools.base import MCPTool, MCPToolResult

logger = structlog.get_logger(__name__)


class TrivyTool(MCPTool):
    """MCP-backed Trivy dependency vulnerability scanner."""

    tool_name = "trivy_scan"
    tool_version = "0.51.1"
    default_timeout = 120

    def __init__(self, trivy_path: str = "trivy") -> None:
        self._trivy_path = trivy_path

    async def _invoke(self, params: dict[str, Any]) -> MCPToolResult:
        scan_path = params["path"]
        severity = params.get("severity", ["CRITICAL", "HIGH"])
        fmt = params.get("format", "json")

        cmd = [
            self._trivy_path,
            "fs",
            "--security-checks", "vuln",
            "--format", fmt,
            "--quiet",
            "--severity", ",".join(severity),
            scan_path,
        ]

        command_str = " ".join(cmd)
        stdout, stderr, rc = await self._run_subprocess(cmd, timeout=self.default_timeout)

        parsed: dict[str, Any] | None = None
        if stdout.strip():
            try:
                parsed = json.loads(stdout)
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
        if not result.parsed_output or not isinstance(result.parsed_output, dict):
            return []
        findings = []
        for scan_result in result.parsed_output.get("Results", []):
            for vuln in scan_result.get("Vulnerabilities", []):
                sev = vuln.get("Severity", "UNKNOWN")
                if sev not in ("CRITICAL", "HIGH"):
                    continue
                findings.append({
                    "spec_rule_id": "SEC-007",
                    "cve_id": vuln.get("VulnerabilityID", ""),
                    "package": vuln.get("PkgName", ""),
                    "installed_version": vuln.get("InstalledVersion", ""),
                    "fixed_version": vuln.get("FixedVersion", "latest"),
                    "severity": sev,
                    "description": vuln.get("Description", "")[:300],
                    "code_snippet": f"{vuln.get('PkgName')}=={vuln.get('InstalledVersion')}",
                    "raw_output": json.dumps(vuln)[:500],
                })
        return findings
