"""
ARQ (Async Redis Queue) worker.

This module defines the ARQ WorkerSettings and the audit job function.
The worker runs separately from the FastAPI server and pulls jobs from
the Redis queue, executing audit pipelines in isolated worker processes.

Usage:
    arq api.worker.WorkerSettings

Architecture:
    FastAPI (webhook) ──enqueue──► Redis Queue ──pull──► ARQ Worker
                                                           │
                                              AgentOrchestrator.run()
                                                           │
                                              RedisAuditStore.complete()
"""

from __future__ import annotations

import os
from typing import Any

import structlog

from api.config import get_settings
from api.models import AuditStatus, GitHubPRPayload
from api.state import get_audit_store
from api.telemetry import get_tracer

logger = structlog.get_logger(__name__)


# ─────────────────────────────────────────────────────────────
# Job: Run full audit pipeline
# ─────────────────────────────────────────────────────────────

async def run_audit_job(
    ctx: dict[str, Any],
    audit_id: str,
    payload_dict: dict[str, Any],
) -> dict[str, Any]:
    """
    ARQ job that executes a full multi-agent audit pipeline.

    Args:
        ctx: ARQ context (contains Redis connection and shared state)
        audit_id: Unique ID for this audit run
        payload_dict: Serialised GitHubPRPayload as a plain dict

    Returns:
        Summary dict with status and finding counts
    """
    settings = get_settings()
    audit_store = get_audit_store(settings)
    tracer = get_tracer()

    structlog.contextvars.bind_contextvars(audit_id=audit_id, worker_pid=os.getpid())
    logger.info("arq_job_started", audit_id=audit_id)

    with tracer.start_as_current_span("arq.run_audit_job") as span:
        span.set_attribute("audit.id", audit_id)

        try:
            # Deserialize payload
            payload = GitHubPRPayload.model_validate(payload_dict)
            span.set_attribute("github.pr_number", payload.pull_request.number)
            span.set_attribute("github.repo", payload.repository.full_name)

            # Import here to avoid circular imports at module load time
            from agents.orchestrator import AgentOrchestrator

            orchestrator = AgentOrchestrator(settings=settings)
            audit_store.update_status(audit_id, AuditStatus.RUNNING)

            result = await orchestrator.run(audit_id=audit_id, payload=payload)
            audit_store.complete(audit_id=audit_id, result=result)

            span.set_attribute("audit.status", result.overall_status.value)
            span.set_attribute("audit.findings_count", len(result.findings))

            logger.info(
                "arq_job_complete",
                audit_id=audit_id,
                status=result.overall_status.value,
                findings=len(result.findings),
            )
            return {
                "audit_id": audit_id,
                "status": result.overall_status.value,
                "findings": len(result.findings),
            }

        except Exception as exc:
            audit_store.update_status(audit_id, AuditStatus.ERROR, error=str(exc))
            span.record_exception(exc)
            logger.exception("arq_job_failed", audit_id=audit_id, error=str(exc))
            raise


# ─────────────────────────────────────────────────────────────
# ARQ WorkerSettings
# ─────────────────────────────────────────────────────────────

async def startup(ctx: dict[str, Any]) -> None:
    settings = get_settings()
    logger.info("arq_worker_startup", pid=os.getpid(), redis=settings.redis_url.split("@")[-1])


async def shutdown(ctx: dict[str, Any]) -> None:
    logger.info("arq_worker_shutdown", pid=os.getpid())


class WorkerSettings:
    """ARQ WorkerSettings class — run with: arq api.worker.WorkerSettings"""
    functions = [run_audit_job]
    on_startup = startup
    on_shutdown = shutdown

    # Pull Redis URL from env at class definition time
    redis_settings = None  # Overridden dynamically below

    max_jobs = 20
    job_timeout = 600         # 10 minutes
    keep_result = 3600        # Keep job results for 1 hour
    max_tries = 2             # Retry once on failure
    retry_delay = 10.0        # Wait 10s before retry


def _configure_worker_redis() -> None:
    """Set ARQ Redis settings from application config."""
    try:
        from arq.connections import RedisSettings as ArqRedisSettings
        from urllib.parse import urlparse
        settings = get_settings()
        parsed = urlparse(settings.redis_url)
        WorkerSettings.redis_settings = ArqRedisSettings(
            host=parsed.hostname or "localhost",
            port=parsed.port or 6379,
            database=int(parsed.path.lstrip("/") or 0),
            password=parsed.password,
        )
    except Exception as exc:
        logger.warning("worker_redis_config_failed", error=str(exc))


_configure_worker_redis()
