---
inclusion: auto
---

# AI Code Reviewer — Development Steering Norms

## Project Identity
This is a production-grade, zero-hallucination AI Code Reviewer.
Every code change must uphold the security and quality contracts in `security-rules.spec`.

## Non-Negotiable Rules for All Code Changes

1. **Zero-hallucination**: Agents only report findings backed by raw tool output.
   Every `Finding` object MUST have `rule_id`, `evidence.tool_name`, and `evidence.raw_output`.

2. **Pydantic v2**: Use `model_validate()` not `.parse_obj()`. Use `model_copy(update={...})`
   not direct mutation. All models are frozen unless explicitly mutable.

3. **Async-first**: All I/O operations (HTTP, subprocess, file) must use `asyncio`.
   No blocking calls in async functions. Use `asyncio.create_subprocess_exec` not `subprocess.run`.

4. **Structured logging**: Use `structlog.get_logger(__name__)`. Every log call must
   include context fields: `logger.info("event_name", key=value)`. No `print()` statements.

5. **Error isolation**: Each agent runs in its own try/except. One agent failure
   must not abort the entire pipeline. Return `[]` findings + error in `AgentMetrics`.

6. **Sandbox security**: All Agent C test execution goes through `SandboxExecutor`.
   Never execute generated code outside Docker. `--network none` is mandatory.

7. **Type annotations**: All public functions must have full type annotations.
   Run `mypy` before committing — zero mypy errors in `api/` and `agents/`.

## Architecture Constraints

- The `orchestrator.py` coordinates agents — do NOT add business logic there.
- Agents (A, B, C) are stateless — they receive input and return `list[Finding]`.
- `api/models.py` is the single source of truth for all data shapes.
- `security-rules.spec` is the single source of truth for all rule IDs.

## Adding a New Security Rule

1. Add the rule to `.kiro/steering/security-rules.spec` with a new ID (e.g., `SEC-011`)
2. Add the rule ID mapping in `agents/agent_b.py` (`BANDIT_TEST_RULE_MAP` or `_semgrep_rule_to_spec_id`)
3. Add a test in `tests/test_agent_b_regex.py`
4. Update the OWASP map in `agents/report_generator.py`

## Tool Call Pattern for MCP Integration

When adding new static analysis tools, follow this pattern:

```python
proc = await asyncio.create_subprocess_exec(
    tool_path, *args,
    stdout=asyncio.subprocess.PIPE,
    stderr=asyncio.subprocess.PIPE,
)
stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
```

Always set a timeout. Always parse JSON output. Always map to a spec rule ID.
