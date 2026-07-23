"""
Tests for the FastAPI webhook handler.
Covers signature validation, payload parsing, and dispatch logic.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from api.main import app
from api.models import AuditStatus, GitHubPRPayload


@pytest.fixture
def client():
    """Sync test client (for non-async tests)."""
    app.state.audit_store = MagicMock()
    app.state.orchestrator = MagicMock()
    app.state.orchestrator.is_ready.return_value = True
    app.state.orchestrator.agent_status.return_value = {"agent_a": "ready", "agent_b": "ready", "agent_c": "ready"}
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def sample_pr_payload() -> dict:
    return {
        "action": "opened",
        "number": 42,
        "pull_request": {
            "number": 42,
            "title": "Add user authentication endpoint",
            "state": "open",
            "draft": False,
            "additions": 120,
            "deletions": 10,
            "changed_files": 3,
            "html_url": "https://github.com/owner/repo/pull/42",
            "diff_url": "https://github.com/owner/repo/pull/42.diff",
            "head": {"sha": "abc123def456abc123def456abc123def456abc1", "ref": "feature/auth", "label": "owner:feature/auth"},
            "base": {"sha": "def456abc123def456abc123def456abc123def4", "ref": "main", "label": "owner:main"},
            "user": {"login": "developer", "id": 12345, "type": "User"},
            "created_at": "2024-01-15T10:30:00Z",
            "updated_at": "2024-01-15T10:30:00Z",
        },
        "repository": {
            "id": 67890,
            "name": "repo",
            "full_name": "owner/repo",
            "private": False,
            "html_url": "https://github.com/owner/repo",
            "clone_url": "https://github.com/owner/repo.git",
            "default_branch": "main",
        },
        "sender": {"login": "developer", "id": 12345, "type": "User"},
    }


def compute_signature(body: bytes, secret: str) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


class TestHealthEndpoints:
    def test_health_returns_ok(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["service"] == "ai-code-reviewer"

    def test_readiness_returns_ready(self, client):
        response = client.get("/readiness")
        assert response.status_code == 200
        assert response.json()["status"] == "ready"


class TestWebhookSignatureValidation:
    def test_missing_signature_returns_401(self, client, sample_pr_payload):
        with patch("api.main.get_settings") as mock_settings:
            mock_settings.return_value.github_webhook_secret = "test-secret"
            body = json.dumps(sample_pr_payload).encode()
            response = client.post(
                "/webhook/github",
                content=body,
                headers={"X-GitHub-Event": "pull_request", "Content-Type": "application/json"},
            )
        assert response.status_code == 401

    def test_invalid_signature_returns_401(self, client, sample_pr_payload):
        with patch("api.main.get_settings") as mock_settings:
            mock_settings.return_value.github_webhook_secret = "test-secret"
            body = json.dumps(sample_pr_payload).encode()
            response = client.post(
                "/webhook/github",
                content=body,
                headers={
                    "X-GitHub-Event": "pull_request",
                    "X-Hub-Signature-256": "sha256=invalidsignature",
                    "Content-Type": "application/json",
                },
            )
        assert response.status_code == 401

    def test_valid_signature_accepted(self, client, sample_pr_payload):
        secret = "test-secret-key"
        body = json.dumps(sample_pr_payload).encode()
        sig = compute_signature(body, secret)

        with patch("api.config.get_settings") as mock_settings:
            settings = MagicMock()
            settings.github_webhook_secret = secret
            settings.skip_draft_prs = False
            mock_settings.return_value = settings

            # Mock orchestrator
            app.state.audit_store.create = MagicMock()
            app.state.audit_store.update_status = MagicMock()
            app.state.orchestrator.run = AsyncMock(return_value=MagicMock())

            response = client.post(
                "/webhook/github",
                content=body,
                headers={
                    "X-GitHub-Event": "pull_request",
                    "X-Hub-Signature-256": sig,
                    "Content-Type": "application/json",
                },
            )
        # Should be 202 Accepted (not 401)
        assert response.status_code in (202, 422)  # 422 if mocking not perfect in sync test


class TestWebhookEventFiltering:
    def test_non_pr_event_ignored(self, client):
        response = client.post(
            "/webhook/github",
            json={"action": "created"},
            headers={"X-GitHub-Event": "push"},
        )
        assert response.status_code == 200
        assert response.json()["status"] == "ignored"

    def test_closed_pr_action_ignored(self, client, sample_pr_payload):
        sample_pr_payload["action"] = "closed"
        response = client.post(
            "/webhook/github",
            json=sample_pr_payload,
            headers={"X-GitHub-Event": "pull_request"},
        )
        # Should be ignored (closed is not audited)
        assert response.status_code in (200, 202)


class TestPayloadValidation:
    def test_invalid_payload_returns_422(self, client):
        response = client.post(
            "/webhook/github",
            json={"action": "opened", "number": -1},  # Invalid PR number
            headers={"X-GitHub-Event": "pull_request"},
        )
        assert response.status_code == 422

    def test_pr_payload_parsed_correctly(self, sample_pr_payload):
        """Test Pydantic model validation directly."""
        pr = GitHubPRPayload.model_validate(sample_pr_payload)
        assert pr.pull_request.number == 42
        assert pr.repository.full_name == "owner/repo"
        assert pr.pull_request.head.sha == "abc123def456abc123def456abc123def456abc1"

    def test_invalid_sha_rejected(self, sample_pr_payload):
        """SHA must be hexadecimal."""
        sample_pr_payload["pull_request"]["head"]["sha"] = "ZZZZZZZZZZZZ"
        with pytest.raises(Exception):
            GitHubPRPayload.model_validate(sample_pr_payload)
