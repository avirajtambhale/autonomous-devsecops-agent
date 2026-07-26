"""
Application configuration via Pydantic Settings.
All values come from environment variables or a .env file.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    environment: Literal["development", "staging", "production"] = "development"
    log_level: str = "INFO"
    allowed_origins: list[str] = Field(default=["http://localhost:8501"])

    # GitHub Integration
    github_webhook_secret: str | None = Field(default=None, description="HMAC secret for webhook validation")
    github_token: SecretStr | None = Field(default=None, description="GitHub PAT or App token for API calls")
    github_api_url: str = "https://api.github.com"

    # Agent / LLM Configuration
    openai_api_key: SecretStr | None = None
    anthropic_api_key: SecretStr | None = None
    llm_provider: Literal["openai", "anthropic", "local"] = "openai"
    llm_model: str = "gpt-4o"
    llm_temperature: float = Field(default=0.0, ge=0.0, le=1.0)
    llm_max_tokens: int = Field(default=4096, ge=256)

    # MCP Tool Paths (resolved inside Docker)
    bandit_path: str = "bandit"
    semgrep_path: str = "semgrep"
    trivy_path: str = "trivy"
    ruff_path: str = "ruff"
    radon_path: str = "radon"
    mypy_path: str = "mypy"

    # Sandbox Docker
    sandbox_image: str = "ai-reviewer-sandbox:latest"
    sandbox_network: str = "none"
    sandbox_timeout_seconds: int = 120
    sandbox_memory_limit: str = "512m"
    sandbox_cpu_quota: int = 50000

    # ─── Redis + ARQ Task Queue ──────────────────────────────
    redis_url: str = "redis://localhost:6379/0"
    redis_pool_size: int = 10
    audit_ttl_seconds: int = 86400 * 7   # 7 days
    arq_max_jobs: int = 20               # Max concurrent ARQ workers
    arq_job_timeout: int = 600           # 10-minute job timeout

    # ─── OpenTelemetry ───────────────────────────────────────
    otel_enabled: bool = True
    otel_service_name: str = "ai-code-reviewer"
    otel_service_version: str = "1.0.0"
    # OTLP endpoint — set to your collector (Jaeger/Tempo/etc.)
    otlp_endpoint: str = "http://localhost:4317"
    otlp_headers: str = ""              # "key=val,key2=val2" format
    otel_sample_rate: float = Field(default=1.0, ge=0.0, le=1.0)

    # ─── LangSmith Tracing ───────────────────────────────────
    langsmith_enabled: bool = False
    langsmith_api_key: SecretStr | None = None
    langsmith_project: str = "ai-code-reviewer"
    langsmith_endpoint: str = "https://api.smith.langchain.com"

    # ─── Tree-sitter ─────────────────────────────────────────
    # Controls whether tree-sitter is used for enhanced AST parsing.
    # Falls back to regex diff parser if tree-sitter not installed.
    treesitter_enabled: bool = True

    # Spec file path
    spec_file_path: str = ".kiro/steering/security-rules.spec"

    # Feature flags
    enable_patch_generation: bool = True
    enable_pr_comments: bool = True
    enable_pr_status_checks: bool = True
    skip_draft_prs: bool = True
    use_redis_store: bool = True    # Use Redis-backed AuditStore vs. in-memory

    @field_validator("llm_temperature")
    @classmethod
    def temperature_precision(cls, v: float) -> float:
        return round(v, 2)

    @field_validator("otlp_headers")
    @classmethod
    def parse_otlp_headers(cls, v: str) -> str:
        # Just validate format; actual parsing done at trace init time
        return v.strip()


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
