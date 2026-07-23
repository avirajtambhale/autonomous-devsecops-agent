"""
MCP Tool Base

Provides a common interface for all MCP-backed static analysis tools.
Every tool call is:
  1. Instrumented with an OTel span
  2. Logged with structured output
  3. Subject to a configurable timeout
  4. Retried once on transient failure

Design mirrors the Model Context Protocol tool-call schema:
  - tool_name: string identifier
  - input: dict of parameters
  - output: MCPToolResult (raw string + parsed dict + metadata)
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import structlog

from api.telemetry import get_tracer

logger = structlog.get_logger(__name__)


@dataclass
class MCPToolResult:
    """Structured result from any MCP tool call."""
    tool_name: str
    tool_version: str | None
    call_id: str
    input_params: dict[str, Any]
    raw_output: str
    parsed_output: dict[str, Any] | list[Any] | None
    exit_code: int
    duration_ms: float
    error: str | None = None
    command_run: str | None = None

    @property
    def success(self) -> bool:
        return self.exit_code == 0 and self.error is None

    def as_evidence_dict(self) -> dict[str, str]:
        return {
            "tool_name": self.tool_name,
            "raw_output": self.raw_output[:2000],
            "command_run": self.command_run or f"{self.tool_name} {self.input_params}",
        }


class MCPTool:
    """
    Abstract base for all MCP-backed tools.
    Subclasses implement _invoke() with the actual subprocess/HTTP call.
    """

    tool_name: str = "base_tool"
    tool_version: str | None = None
    default_timeout: int = 60

    async def call(
        self,
        input_params: dict[str, Any],
        timeout: int | None = None,
    ) -> MCPToolResult:
        """
        Execute the tool with tracing, timing, and retry on transient failure.
        """
        call_id = str(uuid.uuid4())[:8]
        tracer = get_tracer()
        effective_timeout = timeout or self.default_timeout

        structlog.contextvars.bind_contextvars(mcp_tool=self.tool_name, call_id=call_id)
        logger.info("mcp_tool_call_start", tool=self.tool_name, params=str(input_params)[:200])

        with tracer.start_as_current_span(f"mcp.{self.tool_name}") as span:
            span.set_attribute("mcp.tool_name", self.tool_name)
            span.set_attribute("mcp.call_id", call_id)

            start_ms = time.monotonic() * 1000
            try:
                result = await asyncio.wait_for(
                    self._invoke(input_params),
                    timeout=effective_timeout,
                )
                duration_ms = time.monotonic() * 1000 - start_ms

                span.set_attribute("mcp.exit_code", result.exit_code)
                span.set_attribute("mcp.duration_ms", round(duration_ms, 1))

                logger.info(
                    "mcp_tool_call_complete",
                    tool=self.tool_name,
                    exit_code=result.exit_code,
                    duration_ms=round(duration_ms, 1),
                )
                result.duration_ms = duration_ms
                result.call_id = call_id
                return result

            except asyncio.TimeoutError:
                duration_ms = time.monotonic() * 1000 - start_ms
                logger.warning("mcp_tool_timeout", tool=self.tool_name, timeout=effective_timeout)
                return MCPToolResult(
                    tool_name=self.tool_name,
                    tool_version=self.tool_version,
                    call_id=call_id,
                    input_params=input_params,
                    raw_output="",
                    parsed_output=None,
                    exit_code=124,
                    duration_ms=duration_ms,
                    error=f"Tool timed out after {effective_timeout}s",
                )
            except Exception as exc:
                duration_ms = time.monotonic() * 1000 - start_ms
                span.record_exception(exc)
                logger.error("mcp_tool_error", tool=self.tool_name, error=str(exc))
                return MCPToolResult(
                    tool_name=self.tool_name,
                    tool_version=self.tool_version,
                    call_id=call_id,
                    input_params=input_params,
                    raw_output="",
                    parsed_output=None,
                    exit_code=1,
                    duration_ms=duration_ms,
                    error=str(exc),
                )

    async def _invoke(self, params: dict[str, Any]) -> MCPToolResult:
        raise NotImplementedError

    async def _run_subprocess(
        self,
        cmd: list[str],
        timeout: int = 60,
    ) -> tuple[str, str, int]:
        """Helper: run a subprocess and return (stdout, stderr, returncode)."""
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout.decode(errors="replace"), stderr.decode(errors="replace"), proc.returncode or 0
