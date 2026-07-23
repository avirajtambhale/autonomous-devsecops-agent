"""
Tests for Agent B secret detection patterns.
These are deterministic regex tests — no external tool calls needed.
"""

from __future__ import annotations

import pytest

from agents.agent_b import SECRET_PATTERNS


def scan_for_secrets(content: str) -> list[tuple[str, int]]:
    """Helper: return list of (pattern_name, line_num) for all matches."""
    matches = []
    for pattern_name, pattern, _severity in SECRET_PATTERNS:
        for match in pattern.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            matches.append((pattern_name, line_num))
    return matches


class TestSecretDetection:
    def test_aws_access_key_detected(self):
        code = "aws_key = 'AKIAIOSFODNN7EXAMPLE'\n"
        hits = scan_for_secrets(code)
        assert any("AWS" in name for name, _ in hits)

    def test_openai_key_detected(self):
        code = "client = OpenAI(api_key='sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcd')\n"
        hits = scan_for_secrets(code)
        assert any("OpenAI" in name for name, _ in hits)

    def test_generic_password_detected(self):
        code = "DB_PASSWORD = 'super_secret_password_123'\n"
        hits = scan_for_secrets(code)
        assert len(hits) > 0

    def test_private_key_header_detected(self):
        code = "key = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n'"
        hits = scan_for_secrets(code)
        assert any("Private Key" in name for name, _ in hits)

    def test_env_variable_not_flagged(self):
        """Variables loaded from environment should NOT trigger."""
        code = "api_key = os.environ['API_KEY']\n"
        hits = scan_for_secrets(code)
        # The above should NOT match since no literal string value is present
        # (patterns look for literal string assignment)
        assert len(hits) == 0

    def test_short_value_not_flagged(self):
        """Values under 8 chars should not be flagged."""
        code = "password = 'short'\n"
        hits = scan_for_secrets(code)
        assert len(hits) == 0

    def test_correct_line_number_reported(self):
        code = "import os\n\nDB_PASSWORD = 'super_secret_password_123'\n"
        hits = scan_for_secrets(code)
        assert any(line == 3 for _, line in hits)
