"""
FastAPI Webhook Gateway — AI Code Reviewer & Security Auditing Agent
Handles GitHub PR webhooks and dispatches multi-agent audit pipelines.

Upgrade: Redis-backed AuditStore + ARQ task queue + OTel tracing.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any

import structlog
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import Counter, Histogram, make_asgi_app

from api.config import Settings, get_settings
from api.models import (
    AuditResult,
    AuditStatus,
    GitHubPRPayload,
    PRAction,
    WebhookEvent,
)
from api.state import get_audit_store
from agents.orchestrator import AgentOrchestrator

# Telemetry is optional — import gracefully
try:
    from api.telemetry import get_cost_summary, get_token_ledger, setup_telemetry
    _TELEMETRY_AVAILABLE = True
except ImportError:
    _TELEMETRY_AVAILABLE = False
    def setup_telemetry(s: Any) -> None: pass  # type: ignore[misc]
    def get_cost_summary() -> dict: return {}   # type: ignore[misc]
    def get_token_ledger() -> list: return []   # type: ignore[misc]

# ─────────────────────────────────────────────────────────────
# Structured logging
# ─────────────────────────────────────────────────────────────
structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer() if __debug__ else structlog.processors.JSONRenderer(),
    ]
)
logger = structlog.get_logger(__name__)

# ─────────────────────────────────────────────────────────────
# Prometheus metrics
# ─────────────────────────────────────────────────────────────
PR_AUDITS_TOTAL = Counter("pr_audits_total", "Total PR audits triggered", ["action", "status"])
AUDIT_DURATION = Histogram("audit_duration_seconds", "Time spent on full audit pipeline")
FINDINGS_TOTAL = Counter("findings_total", "Total findings by severity", ["severity", "agent"])
WEBHOOK_REQUESTS = Counter("webhook_requests_total", "Webhook requests received", ["event_type"])


# ─────────────────────────────────────────────────────────────
# App Lifespan
# ─────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize and teardown shared resources."""
    settings = get_settings()

    # ── OpenTelemetry ────────────────────────────────────────
    setup_telemetry(settings)

    # ── Audit store (Redis or in-memory) ────────────────────
    app.state.audit_store = get_audit_store(settings)

    # ── ARQ Redis pool (for job enqueueing) ──────────────────
    app.state.arq_pool = None
    try:
        from arq import create_pool
        from arq.connections import RedisSettings as ArqRedisSettings
        from urllib.parse import urlparse
        parsed = urlparse(settings.redis_url)
        arq_settings = ArqRedisSettings(
            host=parsed.hostname or "localhost",
            port=parsed.port or 6379,
            database=int(parsed.path.lstrip("/") or 0),
            password=parsed.password,
        )
        app.state.arq_pool = await create_pool(arq_settings)
        logger.info("arq_pool_ready", redis=settings.redis_url.split("@")[-1])
    except Exception as exc:
        logger.warning("arq_pool_failed_fallback_to_background_tasks", error=str(exc))

    # ── Orchestrator ─────────────────────────────────────────
    app.state.orchestrator = AgentOrchestrator(settings=settings)
    logger.info("ai_code_reviewer_started", version="1.0.0", env=settings.environment)

    yield

    # ── Cleanup ──────────────────────────────────────────────
    if app.state.arq_pool:
        await app.state.arq_pool.aclose()
    logger.info("ai_code_reviewer_shutdown")


# ─────────────────────────────────────────────────────────────
# FastAPI Application
# ─────────────────────────────────────────────────────────────
def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="AI Code Reviewer & Security Auditing Agent",
        version="1.0.0",
        description="Production-grade autonomous code review with multi-agent orchestration.",
        docs_url="/docs" if settings.environment != "production" else None,
        redoc_url="/redoc" if settings.environment != "production" else None,
        lifespan=lifespan,
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    # Prometheus metrics endpoint
    metrics_app = make_asgi_app()
    app.mount("/metrics", metrics_app)

    return app


app = create_app()


# ─────────────────────────────────────────────────────────────
# Security: GitHub Webhook Signature Verification
# ─────────────────────────────────────────────────────────────
async def verify_github_signature(
    request: Request,
    x_hub_signature_256: str | None = Header(default=None),
    settings: Settings = Depends(get_settings),
) -> None:
    """
    Verifies the HMAC-SHA256 signature provided by GitHub on every webhook.
    Rejects requests with invalid or missing signatures with HTTP 401.
    """
    if not settings.github_webhook_secret:
        logger.warning("webhook_secret_not_configured")
        return  # Allow in dev mode without secret configured

    if not x_hub_signature_256:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-Hub-Signature-256 header.",
        )

    body = await request.body()
    expected_sig = (
        "sha256="
        + hmac.new(
            settings.github_webhook_secret.encode(),
            body,
            hashlib.sha256,
        ).hexdigest()
    )

    if not hmac.compare_digest(expected_sig, x_hub_signature_256):
        logger.warning("invalid_webhook_signature", received=x_hub_signature_256[:20])
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature.",
        )


# ─────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────
@app.get("/health", tags=["Infrastructure"])
async def health_check() -> dict[str, str]:
    """Liveness probe endpoint."""
    return {"status": "ok", "service": "ai-code-reviewer", "version": "1.0.0"}


@app.get("/readiness", tags=["Infrastructure"])
async def readiness_check(request: Request) -> dict[str, Any]:
    """Readiness probe — verifies orchestrator is initialized."""
    orchestrator: AgentOrchestrator = request.app.state.orchestrator
    ready = orchestrator.is_ready()
    if not ready:
        raise HTTPException(status_code=503, detail="Orchestrator not ready.")
    return {"status": "ready", "agents": orchestrator.agent_status()}


@app.post(
    "/webhook/github",
    tags=["Webhook"],
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(verify_github_signature)],
)
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_github_event: str | None = Header(default=None),
    x_github_delivery: str | None = Header(default=None),
    settings: Settings = Depends(get_settings),
) -> dict[str, str]:
    """
    Primary GitHub webhook endpoint.

    Accepts 'pull_request' events on relevant actions (opened, synchronize,
    reopened) and dispatches the multi-agent audit pipeline asynchronously.
    All other events are acknowledged and discarded.
    """
    event_type = x_github_event or "unknown"
    delivery_id = x_github_delivery or str(uuid.uuid4())

    WEBHOOK_REQUESTS.labels(event_type=event_type).inc()
    structlog.contextvars.bind_contextvars(delivery_id=delivery_id, event_type=event_type)

    logger.info("webhook_received", event_type=event_type, delivery_id=delivery_id)

    # Only process pull_request events
    if event_type != "pull_request":
        logger.info("webhook_ignored", reason="not_pull_request_event")
        return {"status": "ignored", "reason": f"Event '{event_type}' not handled."}

    # Parse and validate payload with Pydantic
    try:
        raw_body = await request.json()
        payload = GitHubPRPayload.model_validate(raw_body)
    except Exception as exc:
        logger.error("payload_validation_failed", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid GitHub PR payload: {exc}",
        )

    # Filter by actionable PR events
    actionable_actions = {PRAction.OPENED, PRAction.SYNCHRONIZE, PRAction.REOPENED}
    if payload.action not in actionable_actions:
        logger.info("webhook_ignored", reason="non_actionable_pr_action", action=payload.action)
        return {"status": "ignored", "reason": f"PR action '{payload.action}' not audited."}

    # Create an audit record
    audit_id = str(uuid.uuid4())
    audit_store: AuditStore = request.app.state.audit_store
    audit_store.create(
        audit_id=audit_id,
        pr_number=payload.pull_request.number,
        repo_full_name=payload.repository.full_name,
        head_sha=payload.pull_request.head.sha,
        delivery_id=delivery_id,
    )

    # Dispatch via ARQ queue if available, else FastAPI BackgroundTasks
    arq_pool = getattr(request.app.state, "arq_pool", None)
    if arq_pool:
        try:
            await arq_pool.enqueue_job(
                "run_audit_job",
                audit_id,
                payload.model_dump(mode="json"),
            )
            logger.info("audit_enqueued_arq", audit_id=audit_id)
        except Exception as exc:
            logger.warning("arq_enqueue_failed_fallback", error=str(exc))
            orchestrator: AgentOrchestrator = request.app.state.orchestrator
            background_tasks.add_task(
                _run_audit_pipeline,
                orchestrator=orchestrator,
                audit_store=audit_store,
                audit_id=audit_id,
                payload=payload,
                settings=settings,
            )
    else:
        orchestrator: AgentOrchestrator = request.app.state.orchestrator
        background_tasks.add_task(
            _run_audit_pipeline,
            orchestrator=orchestrator,
            audit_store=audit_store,
            audit_id=audit_id,
            payload=payload,
            settings=settings,
        )

    PR_AUDITS_TOTAL.labels(action=payload.action, status="dispatched").inc()
    logger.info(
        "audit_dispatched",
        audit_id=audit_id,
        pr_number=payload.pull_request.number,
        repo=payload.repository.full_name,
    )

    return {
        "status": "accepted",
        "audit_id": audit_id,
        "message": "Audit pipeline dispatched.",
    }


@app.get("/audits/{audit_id}", tags=["Audits"])
async def get_audit_status(audit_id: str, request: Request) -> AuditResult:
    """Retrieve the current status and findings of an audit by ID."""
    audit_store: AuditStore = request.app.state.audit_store
    result = audit_store.get(audit_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Audit '{audit_id}' not found.")
    return result


@app.get("/audits", tags=["Audits"])
async def list_audits(
    request: Request,
    limit: int = 50,
    offset: int = 0,
    repo: str | None = None,
) -> dict[str, Any]:
    """List recent audits with optional repo filter."""
    audit_store: AuditStore = request.app.state.audit_store
    results = audit_store.list_all(limit=limit, offset=offset, repo_filter=repo)
    return {
        "total": audit_store.count(),
        "limit": limit,
        "offset": offset,
        "results": results,
    }


@app.post("/audits/{audit_id}/rerun", tags=["Audits"])
async def rerun_audit(
    audit_id: str,
    request: Request,
    background_tasks: BackgroundTasks,
    settings: Settings = Depends(get_settings),
) -> dict[str, str]:
    """Manually trigger a re-audit of an existing audit record."""
    audit_store: AuditStore = request.app.state.audit_store
    existing = audit_store.get(audit_id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Audit '{audit_id}' not found.")

    orchestrator: AgentOrchestrator = request.app.state.orchestrator
    background_tasks.add_task(
        _run_audit_pipeline,
        orchestrator=orchestrator,
        audit_store=audit_store,
        audit_id=audit_id,
        payload=existing.original_payload,
        settings=settings,
    )
    audit_store.update_status(audit_id, AuditStatus.PENDING)
    logger.info("audit_rerun_triggered", audit_id=audit_id)
    return {"status": "rerun_dispatched", "audit_id": audit_id}


@app.get("/audits/{audit_id}/override", tags=["Audits"])
async def get_cost_telemetry(request: Request) -> dict[str, Any]:
    """Return aggregated LLM token usage and cost summary."""
    return get_cost_summary()


@app.get("/telemetry/tokens", tags=["Telemetry"])
async def get_token_usage(limit: int = 100) -> dict[str, Any]:
    """Return raw per-call token usage records (newest first)."""
    ledger = list(reversed(get_token_ledger()))[:limit]
    return {
        "total_records": len(get_token_ledger()),
        "records": [
            {
                "timestamp": r.timestamp,
                "audit_id": r.audit_id,
                "agent_id": r.agent_id,
                "model": r.model,
                "prompt_tokens": r.prompt_tokens,
                "completion_tokens": r.completion_tokens,
                "total_tokens": r.total_tokens,
                "cost_usd": r.cost_usd,
                "latency_ms": r.latency_ms,
            }
            for r in ledger
        ],
    }


@app.get("/telemetry/cost", tags=["Telemetry"])
async def get_cost_dashboard_data(request: Request) -> dict[str, Any]:
    """Cost dashboard endpoint — returns summary + breakdown for Streamlit."""
    return get_cost_summary()
async def override_audit_block(
    audit_id: str,
    request: Request,
    reason: str,
    settings: Settings = Depends(get_settings),
) -> dict[str, str]:
    """
    Human override: un-block a PR that was blocked by the agent.
    Requires a mandatory reason string for audit trail.
    """
    if not reason or len(reason.strip()) < 10:
        raise HTTPException(
            status_code=400,
            detail="Override reason must be at least 10 characters.",
        )
    audit_store: AuditStore = request.app.state.audit_store
    existing = audit_store.get(audit_id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Audit '{audit_id}' not found.")

    audit_store.apply_override(audit_id=audit_id, reason=reason.strip())
    logger.warning("audit_override_applied", audit_id=audit_id, reason=reason)
    return {"status": "override_applied", "audit_id": audit_id}


# ─────────────────────────────────────────────────────────────
# Internal: Audit Pipeline Runner
# ─────────────────────────────────────────────────────────────
async def _run_audit_pipeline(
    orchestrator: AgentOrchestrator,
    audit_store: AuditStore,
    audit_id: str,
    payload: GitHubPRPayload,
    settings: Settings,
) -> None:
    """
    Background task that runs the full multi-agent audit pipeline.
    Updates the audit record progressively and handles all failures.
    """
    start_time = time.monotonic()
    structlog.contextvars.bind_contextvars(audit_id=audit_id)

    try:
        audit_store.update_status(audit_id, AuditStatus.RUNNING)
        logger.info("audit_pipeline_started", pr_number=payload.pull_request.number)

        result: AuditResult = await orchestrator.run(
            audit_id=audit_id,
            payload=payload,
        )

        audit_store.complete(audit_id=audit_id, result=result)

        elapsed = time.monotonic() - start_time
        AUDIT_DURATION.observe(elapsed)
        PR_AUDITS_TOTAL.labels(action=payload.action, status=result.overall_status.value).inc()

        for finding in result.findings:
            FINDINGS_TOTAL.labels(severity=finding.severity, agent=finding.agent_id).inc()

        logger.info(
            "audit_pipeline_completed",
            audit_id=audit_id,
            status=result.overall_status,
            findings=len(result.findings),
            duration_seconds=round(elapsed, 2),
        )

    except Exception as exc:
        elapsed = time.monotonic() - start_time
        audit_store.update_status(audit_id, AuditStatus.ERROR, error=str(exc))
        PR_AUDITS_TOTAL.labels(action=payload.action, status="error").inc()
        logger.exception(
            "audit_pipeline_failed",
            audit_id=audit_id,
            error=str(exc),
            duration_seconds=round(elapsed, 2),
        )


# ─────────────────────────────────────────────────────────────
# Global Exception Handler
# ─────────────────────────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("unhandled_exception", path=request.url.path, error=str(exc))
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "detail": "Check server logs for details."},
    )
