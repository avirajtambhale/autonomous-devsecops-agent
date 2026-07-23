"""
OpenTelemetry + LangSmith Instrumentation

Initialises a TracerProvider backed by an OTLP exporter (gRPC or HTTP).
Also configures LangSmith run tracing for Agent C LLM calls.

Call setup_telemetry() once at application startup (in lifespan).
Call get_tracer() anywhere to get a named Tracer instance.
Call trace_llm_call() to record Agent C LLM token usage + cost.
"""

from __future__ import annotations

import os
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Generator

import structlog

logger = structlog.get_logger(__name__)

# ─── Cost constants (USD per 1K tokens, July 2025 pricing) ───
LLM_COST_PER_1K: dict[str, dict[str, float]] = {
    "gpt-4o":           {"input": 0.005,  "output": 0.015},
    "gpt-4o-mini":      {"input": 0.00015, "output": 0.0006},
    "gpt-4-turbo":      {"input": 0.01,   "output": 0.03},
    "claude-3-5-sonnet": {"input": 0.003,  "output": 0.015},
    "claude-3-opus":    {"input": 0.015,  "output": 0.075},
    "claude-3-haiku":   {"input": 0.00025, "output": 0.00125},
}

# ─── Module-level tracer (lazy-initialised) ────────────────────
_tracer = None
_langsmith_client = None
_token_ledger: list["TokenUsageRecord"] = []


@dataclass
class TokenUsageRecord:
    """Single LLM call token usage record for cost tracking."""
    timestamp: str
    audit_id: str
    agent_id: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    cost_usd: float
    latency_ms: float
    tool_name: str = "llm_patch"
    run_id: str = ""

    @property
    def input_cost(self) -> float:
        rates = LLM_COST_PER_1K.get(self.model, {"input": 0.0, "output": 0.0})
        return (self.prompt_tokens / 1000) * rates["input"]

    @property
    def output_cost(self) -> float:
        rates = LLM_COST_PER_1K.get(self.model, {"input": 0.0, "output": 0.0})
        return (self.completion_tokens / 1000) * rates["output"]


# ─────────────────────────────────────────────────────────────
# Setup
# ─────────────────────────────────────────────────────────────

def setup_telemetry(settings: Any) -> None:
    """
    Initialise OpenTelemetry TracerProvider and LangSmith client.
    Safe to call multiple times (idempotent).
    """
    global _tracer, _langsmith_client

    if not settings.otel_enabled:
        logger.info("otel_disabled")
        _tracer = _NoopTracer()
        return

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.resources import Resource, SERVICE_NAME, SERVICE_VERSION
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

        resource = Resource.create({
            SERVICE_NAME: settings.otel_service_name,
            SERVICE_VERSION: settings.otel_service_version,
            "deployment.environment": settings.environment,
        })

        # Parse headers from "key=val,key2=val2" format
        headers: dict[str, str] = {}
        if settings.otlp_headers:
            for pair in settings.otlp_headers.split(","):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    headers[k.strip()] = v.strip()

        exporter = OTLPSpanExporter(
            endpoint=settings.otlp_endpoint,
            headers=headers,
        )

        provider = TracerProvider(resource=resource)
        provider.add_span_processor(BatchSpanProcessor(exporter))

        # Install FastAPI auto-instrumentation
        try:
            from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
            FastAPIInstrumentor().instrument()
        except Exception:
            pass

        # Install httpx auto-instrumentation
        try:
            from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
            HTTPXClientInstrumentor().instrument()
        except Exception:
            pass

        trace.set_tracer_provider(provider)
        _tracer = trace.get_tracer(settings.otel_service_name, settings.otel_service_version)
        logger.info("otel_configured", endpoint=settings.otlp_endpoint)

    except ImportError:
        logger.warning("otel_packages_not_installed_using_noop")
        _tracer = _NoopTracer()
    except Exception as exc:
        logger.error("otel_setup_failed", error=str(exc))
        _tracer = _NoopTracer()

    # LangSmith
    if settings.langsmith_enabled and settings.langsmith_api_key:
        try:
            os.environ["LANGCHAIN_TRACING_V2"] = "true"
            os.environ["LANGCHAIN_ENDPOINT"] = settings.langsmith_endpoint
            os.environ["LANGCHAIN_API_KEY"] = settings.langsmith_api_key.get_secret_value()
            os.environ["LANGCHAIN_PROJECT"] = settings.langsmith_project

            from langsmith import Client
            _langsmith_client = Client(
                api_url=settings.langsmith_endpoint,
                api_key=settings.langsmith_api_key.get_secret_value(),
            )
            logger.info("langsmith_configured", project=settings.langsmith_project)
        except Exception as exc:
            logger.warning("langsmith_setup_failed", error=str(exc))


def get_tracer() -> Any:
    """Return the configured tracer. Initialises a no-op tracer if setup not called."""
    global _tracer
    if _tracer is None:
        _tracer = _NoopTracer()
    return _tracer


# ─────────────────────────────────────────────────────────────
# Token / Cost recording
# ─────────────────────────────────────────────────────────────

def record_llm_usage(
    audit_id: str,
    agent_id: str,
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
    latency_ms: float,
    tool_name: str = "llm_patch",
    run_id: str = "",
) -> TokenUsageRecord:
    """
    Record a single LLM call's token usage and cost.
    Appends to the in-process ledger (also exported via OTel spans).
    """
    total = prompt_tokens + completion_tokens
    rates = LLM_COST_PER_1K.get(model, {"input": 0.005, "output": 0.015})
    cost = (prompt_tokens / 1000 * rates["input"]) + (completion_tokens / 1000 * rates["output"])

    record = TokenUsageRecord(
        timestamp=datetime.now(timezone.utc).isoformat(),
        audit_id=audit_id,
        agent_id=agent_id,
        model=model,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=total,
        cost_usd=cost,
        latency_ms=latency_ms,
        tool_name=tool_name,
        run_id=run_id,
    )
    _token_ledger.append(record)

    # Emit OTel span attributes for this LLM call
    tracer = get_tracer()
    with tracer.start_as_current_span("llm.call") as span:
        span.set_attribute("llm.model", model)
        span.set_attribute("llm.prompt_tokens", prompt_tokens)
        span.set_attribute("llm.completion_tokens", completion_tokens)
        span.set_attribute("llm.total_tokens", total)
        span.set_attribute("llm.cost_usd", round(cost, 6))
        span.set_attribute("llm.latency_ms", round(latency_ms, 1))
        span.set_attribute("audit.id", audit_id)
        span.set_attribute("agent.id", agent_id)

    logger.info(
        "llm_usage_recorded",
        model=model,
        tokens=total,
        cost_usd=round(cost, 6),
        latency_ms=round(latency_ms, 1),
    )
    return record


def get_token_ledger() -> list[TokenUsageRecord]:
    """Return all recorded token usage records (for dashboard)."""
    return list(_token_ledger)


def get_cost_summary() -> dict[str, Any]:
    """Aggregate cost summary across all recorded LLM calls."""
    if not _token_ledger:
        return {
            "total_calls": 0, "total_tokens": 0,
            "total_cost_usd": 0.0, "by_model": {}, "by_agent": {},
        }

    by_model: dict[str, dict[str, Any]] = {}
    by_agent: dict[str, dict[str, Any]] = {}

    for r in _token_ledger:
        # By model
        if r.model not in by_model:
            by_model[r.model] = {"calls": 0, "tokens": 0, "cost_usd": 0.0}
        by_model[r.model]["calls"] += 1
        by_model[r.model]["tokens"] += r.total_tokens
        by_model[r.model]["cost_usd"] = round(by_model[r.model]["cost_usd"] + r.cost_usd, 6)

        # By agent
        if r.agent_id not in by_agent:
            by_agent[r.agent_id] = {"calls": 0, "tokens": 0, "cost_usd": 0.0}
        by_agent[r.agent_id]["calls"] += 1
        by_agent[r.agent_id]["tokens"] += r.total_tokens
        by_agent[r.agent_id]["cost_usd"] = round(by_agent[r.agent_id]["cost_usd"] + r.cost_usd, 6)

    return {
        "total_calls": len(_token_ledger),
        "total_tokens": sum(r.total_tokens for r in _token_ledger),
        "total_cost_usd": round(sum(r.cost_usd for r in _token_ledger), 6),
        "by_model": by_model,
        "by_agent": by_agent,
    }


# ─────────────────────────────────────────────────────────────
# Noop tracer (when OTel is disabled / not installed)
# ─────────────────────────────────────────────────────────────

class _NoopSpan:
    def set_attribute(self, *a: Any, **kw: Any) -> None: pass
    def record_exception(self, *a: Any, **kw: Any) -> None: pass
    def __enter__(self) -> "_NoopSpan": return self
    def __exit__(self, *a: Any) -> None: pass


class _NoopTracer:
    def start_as_current_span(self, name: str, **kw: Any) -> "_NoopSpan":
        return _NoopSpan()
