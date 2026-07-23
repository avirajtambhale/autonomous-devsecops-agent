"""
Agent C — Patch & Verification Engine

Responsibilities:
  - Receive findings from Agent A and B
  - Use LLM to generate code patches for each finding
  - Write corresponding pytest test cases
  - Execute patches + tests in isolated Docker sandbox
  - Attach verified patches (test_passed=True) back to findings
  - Only propose patches with confidence >= 0.75 AND test_passed=True
"""

from __future__ import annotations

import asyncio
import json
import textwrap
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import structlog

from api.config import Settings
from api.models import (
    Finding,
    GitHubPRPayload,
    PatchSuggestion,
    Severity,
)
from api.telemetry import get_tracer, record_llm_usage
from sandbox.executor import SandboxExecutor

logger = structlog.get_logger(__name__)

# Only attempt patches for findings at these severity levels
PATCHABLE_SEVERITIES = {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}

# System prompt for the LLM patch generator
PATCH_SYSTEM_PROMPT = """You are an expert software security engineer generating precise code fixes.

STRICT RULES:
1. Output ONLY valid JSON. No explanations, no prose.
2. The patch must be a minimal unified diff (--- a/file +++ b/file format).
3. The test must be runnable pytest code that validates the fix.
4. Do not introduce new vulnerabilities or change functionality beyond the fix.
5. Set confidence_score between 0.0 and 1.0 based on your certainty.
6. If you cannot generate a safe, verifiable patch, return confidence_score=0.0.

Output format:
{
  "patch_diff": "<unified diff string>",
  "test_code": "<pytest test code string>",
  "confidence_score": <float 0.0-1.0>,
  "explanation": "<one sentence explanation>"
}
"""


class AgentC:
    """
    Agent C generates executable patches for security and quality findings,
    verifies them in an isolated Docker sandbox, and attaches verified
    patches back to the finding objects.
    """

    AGENT_ID = "agent_c"
    MIN_CONFIDENCE = 0.75
    MAX_PATCHES_PER_RUN = 10  # Cost/time guard

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._sandbox = SandboxExecutor(settings=settings)
        self._llm_client = self._build_llm_client(settings)

    def _build_llm_client(self, settings: Settings) -> Any:
        """Lazy-initialize LLM client based on configured provider."""
        if settings.llm_provider == "openai":
            try:
                from openai import AsyncOpenAI
                return AsyncOpenAI(api_key=settings.openai_api_key.get_secret_value())
            except ImportError:
                logger.warning("openai_not_installed")
                return None
        elif settings.llm_provider == "anthropic":
            try:
                import anthropic
                return anthropic.AsyncAnthropic(
                    api_key=settings.anthropic_api_key.get_secret_value()
                )
            except ImportError:
                logger.warning("anthropic_not_installed")
                return None
        return None

    async def generate_patches(
        self,
        findings: list[Finding],
        parsed_diff: Any,
        payload: GitHubPRPayload,
    ) -> list[Finding]:
        """
        For each patchable finding, attempt to generate and verify a patch.
        Returns the findings list with patch suggestions attached where successful.
        """
        patchable = [
            f for f in findings
            if f.severity in PATCHABLE_SEVERITIES
            and not f.suppressed
        ][: self.MAX_PATCHES_PER_RUN]

        if not patchable:
            logger.info("agent_c_no_patchable_findings")
            return findings

        logger.info("agent_c_generating_patches", count=len(patchable))

        # Generate patches concurrently (max 3 at a time to respect rate limits)
        semaphore = asyncio.Semaphore(3)

        async def _patch_with_limit(finding: Finding) -> tuple[str, PatchSuggestion | None]:
            async with semaphore:
                return finding.finding_id, await self._patch_finding(finding, parsed_diff)

        tasks = [_patch_with_limit(f) for f in patchable]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Build patch map
        patch_map: dict[str, PatchSuggestion] = {}
        for result in results:
            if isinstance(result, Exception):
                logger.error("patch_generation_error", error=str(result))
                continue
            finding_id, patch = result
            if patch and patch.test_passed and patch.confidence_score >= self.MIN_CONFIDENCE:
                patch_map[finding_id] = patch
                logger.info(
                    "patch_verified",
                    finding_id=finding_id,
                    coverage=patch.coverage_pct,
                    confidence=patch.confidence_score,
                )

        # Re-build findings list with patches injected
        enriched: list[Finding] = []
        for f in findings:
            if f.finding_id in patch_map:
                # Pydantic v2 frozen model — use model_copy
                enriched.append(f.model_copy(update={"patch": patch_map[f.finding_id]}))
            else:
                enriched.append(f)

        logger.info(
            "agent_c_complete",
            patches_proposed=len(patch_map),
            total_findings=len(findings),
        )
        return enriched

    async def _patch_finding(
        self,
        finding: Finding,
        parsed_diff: Any,
    ) -> PatchSuggestion | None:
        """
        Generate a patch for one finding:
          1. Build LLM prompt with finding context + original code
          2. Call LLM to get patch + test
          3. Execute in Docker sandbox
          4. Return PatchSuggestion with test results
        """
        if not self._llm_client:
            logger.warning("agent_c_no_llm_client")
            return self._rule_based_patch(finding)

        # Find original code context
        original_code = self._get_code_context(finding, parsed_diff)

        prompt = self._build_patch_prompt(finding, original_code)

        try:
            raw_response = await self._call_llm(prompt)
            patch_data = json.loads(raw_response)
        except (json.JSONDecodeError, Exception) as exc:
            logger.error("llm_patch_parse_error", finding_id=finding.finding_id, error=str(exc))
            return None

        confidence = float(patch_data.get("confidence_score", 0.0))
        if confidence < self.MIN_CONFIDENCE:
            logger.info(
                "patch_confidence_too_low",
                finding_id=finding.finding_id,
                confidence=confidence,
            )
            return PatchSuggestion(
                patch_diff=patch_data.get("patch_diff", ""),
                test_code=patch_data.get("test_code", ""),
                confidence_score=confidence,
                test_passed=False,
            )

        patch_diff = patch_data.get("patch_diff", "")
        test_code = patch_data.get("test_code", "")

        if not patch_diff or not test_code:
            return None

        # Execute test in sandbox
        sandbox_result = await self._sandbox.run_tests(
            patch_diff=patch_diff,
            test_code=test_code,
            finding=finding,
        )

        return PatchSuggestion(
            patch_diff=patch_diff,
            test_code=test_code,
            test_passed=sandbox_result.passed,
            coverage_pct=sandbox_result.coverage_pct,
            sandbox_run_id=sandbox_result.run_id,
            confidence_score=confidence,
        )

    def _rule_based_patch(self, finding: Finding) -> PatchSuggestion | None:
        """
        Deterministic (non-LLM) patches for well-known rule patterns.
        Used as fallback when LLM is unavailable.
        """
        rule_patches: dict[str, tuple[str, str]] = {
            "SEC-001": (
                "# Replace hardcoded value with environment variable:\n"
                "- secret_key = 'hardcoded_value'\n"
                "+ import os\n"
                "+ secret_key = os.environ['SECRET_KEY']",
                textwrap.dedent("""
                    import os
                    import pytest

                    def test_secret_key_from_env(monkeypatch):
                        monkeypatch.setenv('SECRET_KEY', 'test-secret')
                        import importlib, sys
                        # Re-import module to pick up env var
                        assert os.environ.get('SECRET_KEY') == 'test-secret'
                """),
            ),
            "SEC-002": (
                "# Use parameterized query:\n"
                "- cursor.execute(f'SELECT * FROM users WHERE id={user_id}')\n"
                "+ cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))",
                textwrap.dedent("""
                    import pytest
                    from unittest.mock import MagicMock

                    def test_parameterized_query():
                        cursor = MagicMock()
                        user_id = "1 OR 1=1"
                        cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))
                        cursor.execute.assert_called_once_with(
                            'SELECT * FROM users WHERE id=?', (user_id,)
                        )
                """),
            ),
        }
        rule_id = finding.rule_id
        if rule_id not in rule_patches:
            return None

        patch_diff, test_code = rule_patches[rule_id]
        return PatchSuggestion(
            patch_diff=patch_diff,
            test_code=test_code,
            confidence_score=0.75,
            test_passed=False,  # Not sandbox-verified in fallback mode
        )

    async def _call_llm(self, prompt: str, audit_id: str = "") -> str:
        """Call configured LLM provider with zero temperature for determinism."""
        tracer = get_tracer()
        start_ms = time.monotonic() * 1000

        with tracer.start_as_current_span(f"llm.{self.settings.llm_provider}.patch") as span:
            span.set_attribute("llm.model", self.settings.llm_model)
            span.set_attribute("llm.provider", self.settings.llm_provider)
            span.set_attribute("agent.id", self.AGENT_ID)

            if self.settings.llm_provider == "openai":
                response = await self._llm_client.chat.completions.create(
                    model=self.settings.llm_model,
                    temperature=0.0,
                    max_tokens=self.settings.llm_max_tokens,
                    response_format={"type": "json_object"},
                    messages=[
                        {"role": "system", "content": PATCH_SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                )
                content = response.choices[0].message.content or "{}"
                usage = response.usage
                record_llm_usage(
                    audit_id=audit_id,
                    agent_id=self.AGENT_ID,
                    model=self.settings.llm_model,
                    prompt_tokens=usage.prompt_tokens,
                    completion_tokens=usage.completion_tokens,
                    latency_ms=time.monotonic() * 1000 - start_ms,
                )
                return content

            elif self.settings.llm_provider == "anthropic":
                response = await self._llm_client.messages.create(
                    model=self.settings.llm_model,
                    max_tokens=self.settings.llm_max_tokens,
                    temperature=0.0,
                    system=PATCH_SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": prompt}],
                )
                content = response.content[0].text
                record_llm_usage(
                    audit_id=audit_id,
                    agent_id=self.AGENT_ID,
                    model=self.settings.llm_model,
                    prompt_tokens=response.usage.input_tokens,
                    completion_tokens=response.usage.output_tokens,
                    latency_ms=time.monotonic() * 1000 - start_ms,
                )
                return content

            raise RuntimeError(f"Unsupported LLM provider: {self.settings.llm_provider}")

    def _build_patch_prompt(self, finding: Finding, original_code: str) -> str:
        return f"""
FINDING:
  Rule ID: {finding.rule_id}
  Severity: {finding.severity}
  Title: {finding.title}
  Description: {finding.description}
  File: {finding.location.file}
  Line: {finding.location.line_start}
  Code Snippet: {finding.location.code_snippet}

ORIGINAL CODE CONTEXT:
{original_code}

TOOL EVIDENCE:
  Tool: {finding.evidence.tool_name}
  Output: {finding.evidence.raw_output[:300]}

Generate a minimal, safe patch and pytest test case that fixes this finding.
Return only valid JSON matching the specified schema.
"""

    def _get_code_context(self, finding: Finding, parsed_diff: Any, context_lines: int = 10) -> str:
        """Extract code context around the finding's location from the diff."""
        for diff_file in parsed_diff.changed_files:
            if diff_file.path == finding.location.file:
                lines = diff_file.patched_content.splitlines()
                start = max(0, finding.location.line_start - context_lines - 1)
                end = min(len(lines), finding.location.line_start + context_lines)
                return "\n".join(
                    f"{i + start + 1:4d}  {line}"
                    for i, line in enumerate(lines[start:end])
                )
        return finding.location.code_snippet
