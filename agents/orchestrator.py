"""
Multi-Agent Orchestrator
Coordinates Agent A (Quality), Agent B (Security), and Agent C (Patch)
in a parallel → sequential fan-out/fan-in pipeline.

Pipeline stages:
  1. Fetch PR diff from GitHub API
  2. Parse differential AST — extract only modified lines
  3. Fan-out: Agent A and Agent B run in PARALLEL
  4. Fan-in: Collect findings from A and B
  5. Sequential: Agent C receives findings → generates patches & tests
  6. Post results to GitHub PR (inline comments + status check)
  7. Generate OWASP compliance report
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any

import structlog

from agents.agent_a import AgentA
from agents.agent_b import AgentB
from agents.agent_c import AgentC
from agents.diff_parser import DiffParser
from agents.github_client import GitHubClient
from agents.report_generator import ReportGenerator
from api.config import Settings
from api.models import (
    AgentMetrics,
    AuditResult,
    AuditStatus,
    ComplianceReport,
    Finding,
    GitHubPRPayload,
    Severity,
)

logger = structlog.get_logger(__name__)


class AgentOrchestrator:
    """
    Coordinates the three specialized agents and the full PR audit lifecycle.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._github_client = GitHubClient(settings=settings)
        self._diff_parser = DiffParser()
        self._report_generator = ReportGenerator(settings=settings)

        # Instantiate agents
        self._agent_a = AgentA(settings=settings)
        self._agent_b = AgentB(settings=settings)
        self._agent_c = AgentC(settings=settings)

        self._ready = True

    def is_ready(self) -> bool:
        return self._ready

    def agent_status(self) -> dict[str, str]:
        return {
            "agent_a": "ready",
            "agent_b": "ready",
            "agent_c": "ready" if self.settings.enable_patch_generation else "disabled",
        }

    async def run(
        self,
        audit_id: str,
        payload: GitHubPRPayload,
    ) -> AuditResult:
        """
        Execute the full audit pipeline for a PR and return the AuditResult.
        """
        log = logger.bind(audit_id=audit_id, pr=payload.pull_request.number)
        log.info("orchestrator_run_started")

        start_ts = datetime.now(timezone.utc)

        # ── Stage 1: Skip draft PRs ──────────────────────────
        if self.settings.skip_draft_prs and payload.pull_request.draft:
            log.info("skipping_draft_pr")
            return self._build_result(
                audit_id=audit_id,
                payload=payload,
                status=AuditStatus.PASSED,
                findings=[],
                agent_metrics=[],
                started_at=start_ts,
                note="Draft PR skipped per configuration.",
            )

        # ── Stage 2: Fetch PR diff ───────────────────────────
        log.info("fetching_pr_diff")
        try:
            raw_diff = await self._github_client.fetch_pr_diff(
                repo=payload.repository.full_name,
                pr_number=payload.pull_request.number,
            )
        except Exception as exc:
            log.error("diff_fetch_failed", error=str(exc))
            return self._build_result(
                audit_id=audit_id,
                payload=payload,
                status=AuditStatus.ERROR,
                findings=[],
                agent_metrics=[],
                started_at=start_ts,
                error=f"Failed to fetch PR diff: {exc}",
            )

        # ── Stage 3: Differential AST Parsing ───────────────
        log.info("parsing_diff")
        parsed_diff = await self._diff_parser.parse(raw_diff)
        log.info(
            "diff_parsed",
            files_changed=len(parsed_diff.changed_files),
            added_lines=parsed_diff.total_added_lines,
        )

        if not parsed_diff.changed_files:
            log.info("no_relevant_files_in_diff")
            return self._build_result(
                audit_id=audit_id,
                payload=payload,
                status=AuditStatus.PASSED,
                findings=[],
                agent_metrics=[],
                started_at=start_ts,
            )

        # ── Stage 4: Parallel Agent A + B ───────────────────
        log.info("launching_parallel_agents")
        agent_a_task = asyncio.create_task(
            self._run_agent_a(parsed_diff=parsed_diff, payload=payload),
            name=f"agent_a_{audit_id}",
        )
        agent_b_task = asyncio.create_task(
            self._run_agent_b(parsed_diff=parsed_diff, payload=payload),
            name=f"agent_b_{audit_id}",
        )

        (a_findings, a_metrics), (b_findings, b_metrics) = await asyncio.gather(
            agent_a_task,
            agent_b_task,
            return_exceptions=False,
        )

        combined_findings: list[Finding] = a_findings + b_findings
        log.info(
            "parallel_agents_complete",
            agent_a_findings=len(a_findings),
            agent_b_findings=len(b_findings),
        )

        # ── Stage 5: Agent C — Patch Generation ─────────────
        c_findings: list[Finding] = []
        c_metrics: AgentMetrics | None = None

        if self.settings.enable_patch_generation and combined_findings:
            log.info("launching_agent_c", findings_to_patch=len(combined_findings))
            c_findings, c_metrics = await self._run_agent_c(
                findings=combined_findings,
                parsed_diff=parsed_diff,
                payload=payload,
            )
            # Agent C enriches existing findings with patches; merge back
            combined_findings = self._merge_patches(combined_findings, c_findings)
            log.info("agent_c_complete", patches_generated=len(c_findings))

        all_metrics = [m for m in [a_metrics, b_metrics, c_metrics] if m is not None]

        # ── Stage 6: Determine overall PR status ────────────
        overall_status = self._determine_status(combined_findings)

        # ── Stage 7: OWASP Compliance Report ────────────────
        compliance_report = self._report_generator.generate_owasp_report(
            findings=combined_findings,
            pr_number=payload.pull_request.number,
            repo=payload.repository.full_name,
            head_sha=payload.pull_request.head.sha,
        )

        # ── Stage 8: Post to GitHub ──────────────────────────
        if self.settings.enable_pr_comments or self.settings.enable_pr_status_checks:
            await self._post_github_results(
                payload=payload,
                findings=combined_findings,
                compliance_report=compliance_report,
                overall_status=overall_status,
            )

        log.info(
            "orchestrator_run_complete",
            status=overall_status,
            total_findings=len(combined_findings),
        )

        return self._build_result(
            audit_id=audit_id,
            payload=payload,
            status=overall_status,
            findings=combined_findings,
            agent_metrics=all_metrics,
            compliance_report=compliance_report,
            started_at=start_ts,
        )

    # ─────────────────────────────────────────────────────────
    # Private: Agent runners with error isolation
    # ─────────────────────────────────────────────────────────

    async def _run_agent_a(
        self,
        parsed_diff: Any,
        payload: GitHubPRPayload,
    ) -> tuple[list[Finding], AgentMetrics]:
        start = datetime.now(timezone.utc)
        try:
            findings = await self._agent_a.analyze(parsed_diff=parsed_diff, payload=payload)
            return findings, AgentMetrics(
                agent_id="agent_a",
                started_at=start,
                completed_at=datetime.now(timezone.utc),
                duration_seconds=(datetime.now(timezone.utc) - start).total_seconds(),
                files_scanned=len(parsed_diff.changed_files),
            )
        except Exception as exc:
            logger.error("agent_a_failed", error=str(exc))
            return [], AgentMetrics(
                agent_id="agent_a",
                started_at=start,
                completed_at=datetime.now(timezone.utc),
                error=str(exc),
            )

    async def _run_agent_b(
        self,
        parsed_diff: Any,
        payload: GitHubPRPayload,
    ) -> tuple[list[Finding], AgentMetrics]:
        start = datetime.now(timezone.utc)
        try:
            findings = await self._agent_b.analyze(parsed_diff=parsed_diff, payload=payload)
            return findings, AgentMetrics(
                agent_id="agent_b",
                started_at=start,
                completed_at=datetime.now(timezone.utc),
                duration_seconds=(datetime.now(timezone.utc) - start).total_seconds(),
                files_scanned=len(parsed_diff.changed_files),
            )
        except Exception as exc:
            logger.error("agent_b_failed", error=str(exc))
            return [], AgentMetrics(
                agent_id="agent_b",
                started_at=start,
                completed_at=datetime.now(timezone.utc),
                error=str(exc),
            )

    async def _run_agent_c(
        self,
        findings: list[Finding],
        parsed_diff: Any,
        payload: GitHubPRPayload,
    ) -> tuple[list[Finding], AgentMetrics]:
        start = datetime.now(timezone.utc)
        try:
            enriched = await self._agent_c.generate_patches(
                findings=findings,
                parsed_diff=parsed_diff,
                payload=payload,
            )
            return enriched, AgentMetrics(
                agent_id="agent_c",
                started_at=start,
                completed_at=datetime.now(timezone.utc),
                duration_seconds=(datetime.now(timezone.utc) - start).total_seconds(),
            )
        except Exception as exc:
            logger.error("agent_c_failed", error=str(exc))
            return findings, AgentMetrics(
                agent_id="agent_c",
                started_at=start,
                completed_at=datetime.now(timezone.utc),
                error=str(exc),
            )

    # ─────────────────────────────────────────────────────────
    # Private helpers
    # ─────────────────────────────────────────────────────────

    def _determine_status(self, findings: list[Finding]) -> AuditStatus:
        """
        Apply PR policy from security-rules.spec to determine final PR status.
        Any CRITICAL finding → BLOCKED. Any ENFORCED HIGH → BLOCKED.
        """
        active = [f for f in findings if not f.suppressed]

        has_critical = any(f.severity == Severity.CRITICAL for f in active)
        has_enforced_high = any(f.severity == Severity.HIGH for f in active)

        if has_critical or has_enforced_high:
            return AuditStatus.BLOCKED
        return AuditStatus.PASSED

    def _merge_patches(
        self,
        original: list[Finding],
        patched: list[Finding],
    ) -> list[Finding]:
        """Merge Agent C patch suggestions back into the finding list."""
        patched_map = {f.finding_id: f for f in patched}
        return [patched_map.get(f.finding_id, f) for f in original]

    async def _post_github_results(
        self,
        payload: GitHubPRPayload,
        findings: list[Finding],
        compliance_report: ComplianceReport,
        overall_status: AuditStatus,
    ) -> None:
        """Post inline comments and status check to GitHub."""
        try:
            if self.settings.enable_pr_comments:
                await self._github_client.post_pr_review(
                    repo=payload.repository.full_name,
                    pr_number=payload.pull_request.number,
                    head_sha=payload.pull_request.head.sha,
                    findings=findings,
                    compliance_report=compliance_report,
                )

            if self.settings.enable_pr_status_checks:
                await self._github_client.post_commit_status(
                    repo=payload.repository.full_name,
                    sha=payload.pull_request.head.sha,
                    state="failure" if overall_status == AuditStatus.BLOCKED else "success",
                    description=f"AI Code Review: {overall_status.value} — {len(findings)} findings",
                )
        except Exception as exc:
            logger.error("github_posting_failed", error=str(exc))

    def _build_result(
        self,
        audit_id: str,
        payload: GitHubPRPayload,
        status: AuditStatus,
        findings: list[Finding],
        agent_metrics: list[AgentMetrics],
        started_at: datetime,
        compliance_report: ComplianceReport | None = None,
        note: str | None = None,
        error: str | None = None,
    ) -> AuditResult:
        return AuditResult(
            audit_id=audit_id,
            pr_number=payload.pull_request.number,
            repo_full_name=payload.repository.full_name,
            head_sha=payload.pull_request.head.sha,
            delivery_id=str(uuid.uuid4()),
            overall_status=status,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
            findings=findings,
            agent_metrics=agent_metrics,
            compliance_report=compliance_report,
            original_payload=payload,
            error_detail=error,
        )
