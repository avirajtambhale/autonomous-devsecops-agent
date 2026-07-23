# ============================================================
# Kiro Steering Specification: Security & Quality Rules
# AI Code Reviewer & Security Auditing Agent
# Version: 1.0.0
# ============================================================
#
# PURPOSE:
#   This specification defines deterministic pass/fail criteria for
#   all PR audits. Agents MUST cite a rule ID from this spec when
#   flagging any issue. If no rule ID can be cited, the agent MUST
#   NOT flag the issue (zero-hallucination enforcement).
#
# RULE STATUS: ENFORCED | WARNING | INFO
# ============================================================

spec:
  name: "Enterprise Security & Code Quality Specification"
  version: "1.0.0"
  enforcement: strict          # strict | permissive
  halt_on_critical: true       # Block PR merge on CRITICAL findings
  max_cyclomatic_complexity: 10
  min_test_coverage_pct: 80
  max_function_length_lines: 60
  max_file_length_lines: 500

# ─────────────────────────────────────────
# AGENT A — Syntax & Code Quality Rules
# ─────────────────────────────────────────
quality_rules:

  - id: "QA-001"
    name: "Cyclomatic Complexity Threshold"
    status: ENFORCED
    severity: HIGH
    description: >
      No function may exceed a cyclomatic complexity of 10.
      Measured via radon. Each branch (if/elif/for/while/except/with)
      increments the counter by 1 starting from 1.
    tool: radon
    command: "radon cc -s -n C {file}"
    pass_condition: "complexity <= 10"
    fail_message: "Function '{fn}' has complexity {value} > 10. Refactor into smaller units."

  - id: "QA-002"
    name: "Function Length Limit"
    status: ENFORCED
    severity: MEDIUM
    description: >
      Functions longer than 60 lines violate single-responsibility.
    tool: ast_parser
    pass_condition: "function_lines <= 60"
    fail_message: "Function '{fn}' is {value} lines. Max allowed: 60."

  - id: "QA-003"
    name: "PEP8 / Ruff Lint Compliance"
    status: ENFORCED
    severity: MEDIUM
    description: >
      All Python files must pass ruff linting with zero errors.
    tool: ruff
    command: "ruff check {file} --output-format=json"
    pass_condition: "error_count == 0"
    fail_message: "Lint errors found: {errors}"

  - id: "QA-004"
    name: "Missing Type Annotations"
    status: WARNING
    severity: LOW
    description: >
      All public functions and methods must carry type annotations
      on parameters and return types.
    tool: mypy
    command: "mypy {file} --ignore-missing-imports --json-report -"
    pass_condition: "missing_annotations == 0"
    fail_message: "Function '{fn}' is missing type annotations."

  - id: "QA-005"
    name: "Docstring Coverage"
    status: WARNING
    severity: LOW
    description: >
      Public modules, classes, and functions must have docstrings.
    tool: pydocstyle
    pass_condition: "docstring_coverage >= 0.80"
    fail_message: "Docstring coverage {value}% below 80% threshold."

  - id: "QA-006"
    name: "Dead Code Detection"
    status: INFO
    severity: LOW
    description: >
      Unused imports and unreachable code branches should be removed.
    tool: vulture
    command: "vulture {file} --min-confidence 80"
    pass_condition: "dead_code_count == 0"
    fail_message: "Dead code detected: {items}"

# ─────────────────────────────────────────
# AGENT B — Security & OWASP Audit Rules
# ─────────────────────────────────────────
security_rules:

  - id: "SEC-001"
    name: "Hardcoded Secrets Detection"
    status: ENFORCED
    severity: CRITICAL
    owasp: "A02:2021 – Cryptographic Failures"
    description: >
      No secrets, API keys, passwords, tokens, or private keys may
      appear in source code. Detected via Semgrep patterns and
      custom regex scanning.
    tool: semgrep
    command: "semgrep --config=p/secrets {file} --json"
    patterns:
      - "(?i)(password|passwd|pwd|secret|api_key|apikey|token|auth)\\s*=\\s*['\\\"][^'\\\"]{8,}"
      - "(?i)AKIA[0-9A-Z]{16}"          # AWS Access Key
      - "(?i)sk-[a-zA-Z0-9]{32,}"       # OpenAI / Stripe SK
      - "(?i)-----BEGIN (RSA|EC|PGP) PRIVATE KEY-----"
    pass_condition: "secrets_found == 0"
    fail_message: "CRITICAL: Hardcoded secret detected at line {line}. Rotate credentials immediately and use environment variables."

  - id: "SEC-002"
    name: "SQL Injection Prevention"
    status: ENFORCED
    severity: CRITICAL
    owasp: "A03:2021 – Injection"
    description: >
      Raw string SQL query construction using f-strings, format(),
      or % interpolation with user-controlled variables is forbidden.
      Must use parameterized queries or ORM abstractions.
    tool: bandit
    command: "bandit -r {file} -t B608 --format json"
    pass_condition: "sql_injection_count == 0"
    fail_message: "SQL injection risk at line {line}: use parameterized queries."

  - id: "SEC-003"
    name: "Cross-Site Scripting (XSS) Prevention"
    status: ENFORCED
    severity: HIGH
    owasp: "A03:2021 – Injection"
    description: >
      User-supplied data must not be rendered in HTML responses
      without sanitization. Jinja2 autoescaping must remain enabled.
      Direct use of Markup() on user inputs is forbidden.
    tool: semgrep
    command: "semgrep --config=p/xss {file} --json"
    pass_condition: "xss_count == 0"
    fail_message: "XSS risk at line {line}: sanitize user inputs before rendering."

  - id: "SEC-004"
    name: "Insecure Deserialization"
    status: ENFORCED
    severity: CRITICAL
    owasp: "A08:2021 – Software and Data Integrity Failures"
    description: >
      Use of pickle.loads(), yaml.load() without SafeLoader,
      marshal.loads() on untrusted data is forbidden.
    tool: bandit
    command: "bandit -r {file} -t B301,B302,B506 --format json"
    pass_condition: "deserialization_issues == 0"
    fail_message: "Insecure deserialization at line {line}. Use safe alternatives."

  - id: "SEC-005"
    name: "Subprocess Shell Injection"
    status: ENFORCED
    severity: HIGH
    owasp: "A03:2021 – Injection"
    description: >
      subprocess.call/run/Popen with shell=True and user-controlled
      input is forbidden without explicit sanitization.
    tool: bandit
    command: "bandit -r {file} -t B602,B603,B604,B605 --format json"
    pass_condition: "shell_injection_count == 0"
    fail_message: "Shell injection risk at line {line}: avoid shell=True with user input."

  - id: "SEC-006"
    name: "Cryptographic Weakness"
    status: ENFORCED
    severity: HIGH
    owasp: "A02:2021 – Cryptographic Failures"
    description: >
      Algorithms MD5, SHA1, DES, RC4 must not be used for
      security-sensitive operations. Use SHA-256+ or bcrypt/argon2.
    tool: bandit
    command: "bandit -r {file} -t B303,B304,B305,B324 --format json"
    pass_condition: "weak_crypto_count == 0"
    fail_message: "Weak cryptography at line {line}: use SHA-256 or stronger."

  - id: "SEC-007"
    name: "Dependency Vulnerability Scan"
    status: ENFORCED
    severity: CRITICAL
    owasp: "A06:2021 – Vulnerable and Outdated Components"
    description: >
      All dependencies declared in requirements.txt, pyproject.toml,
      or package.json must be free of HIGH/CRITICAL CVEs.
    tool: trivy
    command: "trivy fs --security-checks vuln --format json {path}"
    pass_condition: "critical_cves == 0 AND high_cves == 0"
    fail_message: "Dependency {pkg}@{version} has CVE {cve_id} ({severity}). Upgrade to {fixed_version}."

  - id: "SEC-008"
    name: "Path Traversal Prevention"
    status: ENFORCED
    severity: HIGH
    owasp: "A01:2021 – Broken Access Control"
    description: >
      File path construction using user-controlled input without
      normalization and prefix-check is forbidden.
    tool: semgrep
    command: "semgrep --config=p/python.lang.security.audit.path-traversal {file} --json"
    pass_condition: "path_traversal_count == 0"
    fail_message: "Path traversal risk at line {line}: validate and normalize file paths."

  - id: "SEC-009"
    name: "SSRF Prevention"
    status: ENFORCED
    severity: HIGH
    owasp: "A10:2021 – Server-Side Request Forgery"
    description: >
      HTTP requests built from user-supplied URLs must validate
      against an allowlist of permitted domains/schemes.
    tool: semgrep
    command: "semgrep --config=p/python.lang.security.audit.ssrf {file} --json"
    pass_condition: "ssrf_count == 0"
    fail_message: "SSRF risk at line {line}: validate URL against allowlist before requesting."

  - id: "SEC-010"
    name: "Authentication & Authorization Checks"
    status: ENFORCED
    severity: CRITICAL
    owasp: "A01:2021 – Broken Access Control"
    description: >
      All API routes handling sensitive data must include
      authentication decorators or dependency injection guards.
      Routes without auth checks on protected resources will be flagged.
    tool: ast_parser
    pass_condition: "unprotected_routes == 0"
    fail_message: "Route '{route}' at line {line} appears to lack authentication guard."

# ─────────────────────────────────────────
# AGENT C — Patch & Verification Rules
# ─────────────────────────────────────────
patch_rules:

  - id: "PATCH-001"
    name: "Test Coverage Gate"
    status: ENFORCED
    severity: HIGH
    description: >
      Any patch proposed by Agent C MUST achieve >= 80% line coverage
      when the associated test suite is run in the sandbox.
    tool: pytest_cov
    command: "pytest --cov={module} --cov-report=json --cov-fail-under=80"
    pass_condition: "coverage_pct >= 80"
    fail_message: "Patch coverage {value}% below minimum 80%. Add more test cases."

  - id: "PATCH-002"
    name: "No Patch Regression"
    status: ENFORCED
    severity: CRITICAL
    description: >
      Agent C patches must not break any existing passing tests.
      Full test suite must remain green after patch application.
    tool: pytest
    pass_condition: "failed_tests == 0 AND errors == 0"
    fail_message: "Patch introduces regression: {failed_count} tests now failing."

  - id: "PATCH-003"
    name: "Sandbox Isolation"
    status: ENFORCED
    severity: CRITICAL
    description: >
      All test execution MUST occur inside Docker sandbox containers
      with no network access (--network none) and read-only filesystem
      mounts. Execution timeout: 120 seconds.
    tool: docker
    pass_condition: "sandbox_exit_code == 0 AND execution_time <= 120"
    fail_message: "Sandbox execution failed or timed out."

# ─────────────────────────────────────────
# PR APPROVAL POLICY
# ─────────────────────────────────────────
pr_policy:
  auto_approve_conditions:
    - "all CRITICAL findings == 0"
    - "all ENFORCED HIGH findings == 0"
    - "test_coverage >= 80"
    - "patch_regressions == 0"
  auto_block_conditions:
    - "any CRITICAL finding present"
    - "SEC-001 triggered (hardcoded secret)"
    - "SEC-007 triggered (critical/high CVE in deps)"
    - "PATCH-002 triggered (regression detected)"
  require_human_review:
    - "WARNING severity count > 5"
    - "INFO severity count > 10"
    - "patch_confidence_score < 0.75"

# ─────────────────────────────────────────
# ZERO-HALLUCINATION ENFORCEMENT
# ─────────────────────────────────────────
anti_hallucination:
  policy: >
    Agents MUST NOT report any finding that cannot be directly
    attributed to a rule ID in this spec AND backed by raw tool
    output. All findings must include:
      - rule_id: (string, required)
      - tool_output_ref: (string, required — excerpt from raw tool output)
      - file: (string, required)
      - line: (int, required)
      - evidence: (string, required — exact code snippet)
    Findings missing any of these fields MUST be discarded silently.
  confidence_threshold: 0.95
  require_tool_evidence: true
  allow_llm_only_findings: false
