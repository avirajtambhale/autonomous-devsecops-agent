"""
Audit Store — Redis-backed with in-memory fallback.

The RedisAuditStore serialises AuditResult objects as JSON into Redis
with configurable TTL.  The InMemoryAuditStore is used when Redis is
unavailable or in unit tests.

get_audit_store() returns the correct implementation based on Settings.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

import structlog

from api.models import AuditResult, AuditStatus, GitHubPRPayload

logger = structlog.get_logger(__name__)

# ─────────────────────────────────────────────────────────────
# Base class / protocol
# ─────────────────────────────────────────────────────────────

class AuditStore:
    """Synchronous-safe audit store interface."""

    def create(self, audit_id: str, pr_number: int, repo_full_name: str,
               head_sha: str, delivery_id: str) -> None:
        raise NotImplementedError

    def get(self, audit_id: str) -> AuditResult | None:
        raise NotImplementedError

    def list_all(self, limit: int = 50, offset: int = 0,
                 repo_filter: str | None = None) -> list[dict[str, Any]]:
        raise NotImplementedError

    def count(self) -> int:
        raise NotImplementedError

    def update_status(self, audit_id: str, status: AuditStatus,
                      error: str | None = None) -> None:
        raise NotImplementedError

    def complete(self, audit_id: str, result: AuditResult) -> None:
        raise NotImplementedError

    def apply_override(self, audit_id: str, reason: str) -> None:
        raise NotImplementedError


# ─────────────────────────────────────────────────────────────
# In-Memory implementation (test / no-Redis fallback)
# ─────────────────────────────────────────────────────────────

class InMemoryAuditStore(AuditStore):
    """Thread-safe in-memory store. Use in tests or when Redis is unavailable."""

    def __init__(self) -> None:
        self._store: dict[str, dict[str, Any]] = {}

    def create(self, audit_id: str, pr_number: int, repo_full_name: str,
               head_sha: str, delivery_id: str) -> None:
        self._store[audit_id] = {
            "audit_id": audit_id,
            "pr_number": pr_number,
            "repo_full_name": repo_full_name,
            "head_sha": head_sha,
            "delivery_id": delivery_id,
            "overall_status": AuditStatus.PENDING,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "completed_at": None,
            "findings": [],
            "agent_metrics": [],
            "compliance_report": None,
            "original_payload": None,
            "override_reason": None,
            "error_detail": None,
        }

    def get(self, audit_id: str) -> AuditResult | None:
        record = self._store.get(audit_id)
        if not record:
            return None
        try:
            return AuditResult.model_validate(record)
        except Exception:
            return None

    def list_all(self, limit: int = 50, offset: int = 0,
                 repo_filter: str | None = None) -> list[dict[str, Any]]:
        records = list(self._store.values())
        if repo_filter:
            records = [r for r in records if r.get("repo_full_name") == repo_filter]
        records.sort(key=lambda r: r.get("started_at") or "", reverse=True)
        return records[offset: offset + limit]

    def count(self) -> int:
        return len(self._store)

    def update_status(self, audit_id: str, status: AuditStatus,
                      error: str | None = None) -> None:
        if audit_id in self._store:
            self._store[audit_id]["overall_status"] = status.value if hasattr(status, "value") else status
            if error:
                self._store[audit_id]["error_detail"] = error

    def complete(self, audit_id: str, result: AuditResult) -> None:
        if audit_id in self._store:
            data = json.loads(result.model_dump_json())
            self._store[audit_id].update(data)
            self._store[audit_id]["completed_at"] = datetime.now(timezone.utc).isoformat()

    def apply_override(self, audit_id: str, reason: str) -> None:
        if audit_id in self._store:
            self._store[audit_id]["overall_status"] = AuditStatus.OVERRIDDEN.value
            self._store[audit_id]["override_reason"] = reason


# ─────────────────────────────────────────────────────────────
# Redis-backed implementation
# ─────────────────────────────────────────────────────────────

class RedisAuditStore(AuditStore):
    """
    Durable audit store backed by Redis.

    Data layout:
      audit:{audit_id}          → JSON blob of the full record
      audit_index               → Redis Sorted Set of (score=timestamp, member=audit_id)
      audit_repo:{repo}         → Redis Set of audit_ids for that repo

    All writes use MULTI/EXEC pipelines for atomicity.
    TTL is applied on every write via EXPIRE.
    """

    AUDIT_KEY_PREFIX = "audit:"
    INDEX_KEY = "audit_index"
    REPO_PREFIX = "audit_repo:"

    def __init__(self, redis_url: str, ttl_seconds: int = 604800) -> None:
        import redis as _redis
        self._client = _redis.from_url(
            redis_url,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
            retry_on_timeout=True,
            health_check_interval=30,
        )
        self._ttl = ttl_seconds
        logger.info("redis_store_connected", url=redis_url.split("@")[-1])

    def _key(self, audit_id: str) -> str:
        return f"{self.AUDIT_KEY_PREFIX}{audit_id}"

    def _score(self) -> float:
        return datetime.now(timezone.utc).timestamp()

    def create(self, audit_id: str, pr_number: int, repo_full_name: str,
               head_sha: str, delivery_id: str) -> None:
        record: dict[str, Any] = {
            "audit_id": audit_id,
            "pr_number": pr_number,
            "repo_full_name": repo_full_name,
            "head_sha": head_sha,
            "delivery_id": delivery_id,
            "overall_status": "PENDING",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "completed_at": None,
            "findings": [],
            "agent_metrics": [],
            "compliance_report": None,
            "original_payload": None,
            "override_reason": None,
            "error_detail": None,
        }
        pipe = self._client.pipeline()
        pipe.set(self._key(audit_id), json.dumps(record, default=str), ex=self._ttl)
        pipe.zadd(self.INDEX_KEY, {audit_id: self._score()})
        pipe.expire(self.INDEX_KEY, self._ttl)
        pipe.sadd(f"{self.REPO_PREFIX}{repo_full_name}", audit_id)
        pipe.expire(f"{self.REPO_PREFIX}{repo_full_name}", self._ttl)
        pipe.execute()

    def get(self, audit_id: str) -> AuditResult | None:
        raw = self._client.get(self._key(audit_id))
        if not raw:
            return None
        try:
            data = json.loads(raw)
            return AuditResult.model_validate(data)
        except Exception as exc:
            logger.error("redis_get_parse_error", audit_id=audit_id, error=str(exc))
            return None

    def list_all(self, limit: int = 50, offset: int = 0,
                 repo_filter: str | None = None) -> list[dict[str, Any]]:
        if repo_filter:
            audit_ids = list(self._client.smembers(f"{self.REPO_PREFIX}{repo_filter}"))
        else:
            # Get IDs sorted by insertion time (newest first)
            audit_ids = self._client.zrevrange(self.INDEX_KEY, offset, offset + limit - 1)

        if not audit_ids:
            return []

        # Batch fetch
        pipe = self._client.pipeline()
        for aid in audit_ids:
            pipe.get(self._key(aid))
        results = pipe.execute()

        records = []
        for raw in results:
            if raw:
                try:
                    records.append(json.loads(raw))
                except Exception:
                    pass

        records.sort(key=lambda r: r.get("started_at") or "", reverse=True)
        return records[: limit]

    def count(self) -> int:
        return self._client.zcard(self.INDEX_KEY)

    def update_status(self, audit_id: str, status: AuditStatus,
                      error: str | None = None) -> None:
        raw = self._client.get(self._key(audit_id))
        if not raw:
            return
        data = json.loads(raw)
        data["overall_status"] = status.value if hasattr(status, "value") else str(status)
        if error:
            data["error_detail"] = error
        self._client.set(self._key(audit_id), json.dumps(data, default=str), ex=self._ttl)

    def complete(self, audit_id: str, result: AuditResult) -> None:
        data = json.loads(result.model_dump_json())
        data["completed_at"] = datetime.now(timezone.utc).isoformat()
        self._client.set(self._key(audit_id), json.dumps(data, default=str), ex=self._ttl)

    def apply_override(self, audit_id: str, reason: str) -> None:
        raw = self._client.get(self._key(audit_id))
        if not raw:
            return
        data = json.loads(raw)
        data["overall_status"] = "OVERRIDDEN"
        data["override_reason"] = reason
        self._client.set(self._key(audit_id), json.dumps(data, default=str), ex=self._ttl)

    def ping(self) -> bool:
        try:
            return self._client.ping()
        except Exception:
            return False


# ─────────────────────────────────────────────────────────────
# Factory
# ─────────────────────────────────────────────────────────────

def get_audit_store(settings: Any) -> AuditStore:
    """
    Return the appropriate AuditStore based on configuration.
    Falls back to InMemory if Redis connection fails.
    """
    if not settings.use_redis_store or not settings.redis_url:
        logger.info("using_in_memory_audit_store")
        return InMemoryAuditStore()

    try:
        store = RedisAuditStore(
            redis_url=settings.redis_url,
            ttl_seconds=settings.audit_ttl_seconds,
        )
        if store.ping():
            logger.info("using_redis_audit_store")
            return store
        else:
            logger.warning("redis_ping_failed_fallback_to_memory")
            return InMemoryAuditStore()
    except Exception as exc:
        logger.warning("redis_connection_failed_fallback_to_memory", error=str(exc))
        return InMemoryAuditStore()
