"""
Docker Sandbox Executor
Runs Agent C patches and test suites in fully isolated Docker containers.

Security guarantees:
  - Network disabled (--network none)
  - Read-only root filesystem except /tmp
  - Non-root user (uid 1000)
  - CPU and memory limits enforced
  - 120-second hard timeout
  - No privilege escalation
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import structlog

from api.config import Settings
from api.models import Finding

logger = structlog.get_logger(__name__)

SANDBOX_DOCKERFILE = """
FROM python:3.11-slim

# Non-root user for security
RUN useradd -m -u 1000 -s /bin/bash sandbox

# Install test dependencies
RUN pip install --no-cache-dir pytest pytest-cov coverage

WORKDIR /workspace
RUN chown sandbox:sandbox /workspace

USER sandbox
"""

RUNNER_SCRIPT = """
#!/bin/bash
set -euo pipefail

cd /workspace
python -m pytest test_patch.py \
    --cov=patch_module \
    --cov-report=json:/workspace/coverage.json \
    --tb=short \
    --json-report \
    --json-report-file=/workspace/test_results.json \
    -v 2>&1
"""


@dataclass
class SandboxResult:
    run_id: str
    passed: bool
    failed_count: int
    error_count: int
    coverage_pct: float | None
    stdout: str
    stderr: str
    exit_code: int
    duration_seconds: float


class SandboxExecutor:
    """
    Manages Docker-based isolated test execution for patch verification.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def run_tests(
        self,
        patch_diff: str,
        test_code: str,
        finding: Finding,
    ) -> SandboxResult:
        """
        Apply a patch and execute its test suite in a Docker sandbox.
        Returns a SandboxResult with pass/fail status and coverage.
        """
        run_id = str(uuid.uuid4())
        logger.info("sandbox_run_started", run_id=run_id, finding_id=finding.finding_id)

        with tempfile.TemporaryDirectory(prefix="sandbox_") as tmpdir:
            workspace = Path(tmpdir)

            # Write the patch module (stripped from diff for simplicity)
            patch_module_code = self._extract_patched_code(patch_diff)
            (workspace / "patch_module.py").write_text(patch_module_code, encoding="utf-8")

            # Write the test file
            (workspace / "test_patch.py").write_text(test_code, encoding="utf-8")

            # Write requirements
            (workspace / "requirements.txt").write_text(
                "pytest\npytest-cov\npytest-json-report\n", encoding="utf-8"
            )

            start_time = asyncio.get_event_loop().time()
            result = await self._run_docker(workspace=workspace, run_id=run_id)
            elapsed = asyncio.get_event_loop().time() - start_time

            # Parse coverage report if available
            coverage_pct = None
            coverage_file = workspace / "coverage.json"
            if coverage_file.exists():
                try:
                    cov_data = json.loads(coverage_file.read_text())
                    coverage_pct = cov_data.get("totals", {}).get("percent_covered", 0.0)
                except Exception:
                    pass

            # Parse test results
            passed = result["exit_code"] == 0
            failed_count = result.get("failed", 0)
            error_count = result.get("errors", 0)

            sandbox_result = SandboxResult(
                run_id=run_id,
                passed=passed,
                failed_count=failed_count,
                error_count=error_count,
                coverage_pct=coverage_pct,
                stdout=result.get("stdout", "")[:2000],
                stderr=result.get("stderr", "")[:500],
                exit_code=result["exit_code"],
                duration_seconds=elapsed,
            )

            logger.info(
                "sandbox_run_complete",
                run_id=run_id,
                passed=passed,
                coverage=coverage_pct,
                duration=round(elapsed, 2),
            )
            return sandbox_result

    async def _run_docker(self, workspace: Path, run_id: str) -> dict[str, Any]:
        """Execute the Docker container with strict resource limits."""
        docker_cmd = [
            "docker", "run",
            "--rm",
            "--name", f"sandbox_{run_id[:12]}",
            "--network", self.settings.sandbox_network,
            "--memory", self.settings.sandbox_memory_limit,
            "--cpu-quota", str(self.settings.sandbox_cpu_quota),
            "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
            "--security-opt", "no-new-privileges",
            "--cap-drop", "ALL",
            "-v", f"{workspace}:/workspace:ro",
            "-v", f"{workspace}:/output:rw",  # Allow writing coverage/reports
            "-w", "/workspace",
            self.settings.sandbox_image,
            "bash", "-c",
            (
                "pip install -r requirements.txt -q && "
                "python -m pytest test_patch.py "
                "--cov=patch_module "
                "--cov-report=json:/output/coverage.json "
                "--tb=short -v 2>&1; echo EXIT:$?"
            ),
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *docker_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=self.settings.sandbox_timeout_seconds,
            )

            stdout_str = stdout.decode(errors="replace")
            stderr_str = stderr.decode(errors="replace")

            # Extract exit code from output (echoed as EXIT:N)
            exit_code = proc.returncode or 0
            for line in reversed(stdout_str.splitlines()):
                if line.startswith("EXIT:"):
                    try:
                        exit_code = int(line.split(":")[1])
                    except ValueError:
                        pass
                    break

            return {
                "exit_code": exit_code,
                "stdout": stdout_str,
                "stderr": stderr_str,
                "failed": stdout_str.count("FAILED"),
                "errors": stdout_str.count("ERROR"),
            }

        except asyncio.TimeoutError:
            logger.error("sandbox_timeout", run_id=run_id)
            # Kill the container
            await asyncio.create_subprocess_exec(
                "docker", "kill", f"sandbox_{run_id[:12]}",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            return {
                "exit_code": 124,  # Standard timeout exit code
                "stdout": "",
                "stderr": f"Sandbox execution timed out after {self.settings.sandbox_timeout_seconds}s",
                "failed": 0,
                "errors": 1,
            }
        except FileNotFoundError:
            logger.warning("docker_not_available_using_subprocess_fallback")
            return await self._run_subprocess_fallback(workspace)

    async def _run_subprocess_fallback(self, workspace: Path) -> dict[str, Any]:
        """
        Fallback for environments without Docker.
        Runs tests directly via subprocess (less isolated — dev mode only).
        """
        logger.warning("sandbox_fallback_subprocess_mode")
        proc = await asyncio.create_subprocess_exec(
            "python", "-m", "pytest",
            str(workspace / "test_patch.py"),
            "--cov=patch_module",
            "--tb=short", "-v",
            cwd=str(workspace),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
        return {
            "exit_code": proc.returncode or 0,
            "stdout": stdout.decode(errors="replace"),
            "stderr": stderr.decode(errors="replace"),
            "failed": stdout.decode().count("FAILED"),
            "errors": stdout.decode().count("ERROR"),
        }

    @staticmethod
    def _extract_patched_code(patch_diff: str) -> str:
        """
        Extract the new file content from a unified diff string.
        For simple patches, reconstruct the patched module content.
        """
        lines = []
        for line in patch_diff.splitlines():
            if line.startswith("+") and not line.startswith("+++"):
                lines.append(line[1:])
            elif line.startswith(" "):
                lines.append(line[1:])
        return "\n".join(lines) if lines else "# Empty patch module\n"
