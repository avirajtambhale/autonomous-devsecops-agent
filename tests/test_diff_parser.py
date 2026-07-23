"""
Tests for the DiffParser — differential AST parsing logic.
"""

from __future__ import annotations

import asyncio

import pytest

from agents.diff_parser import DiffParser

SAMPLE_DIFF = """\
diff --git a/api/auth.py b/api/auth.py
index abc123..def456 100644
--- a/api/auth.py
+++ b/api/auth.py
@@ -10,7 +10,12 @@ def login(username, password):
     # Existing code
     conn = get_db_connection()
-    query = f"SELECT * FROM users WHERE username='{username}'"
+    # FIX: Use parameterized query to prevent SQL injection
+    query = "SELECT * FROM users WHERE username=?"
+    result = conn.execute(query, (username,))
+    if not result:
+        return None
+    return result.fetchone()
     cursor = conn.execute(query)

diff --git a/requirements.txt b/requirements.txt
index 111aaa..222bbb 100644
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,3 +1,4 @@
 fastapi==0.111.0
+requests==2.32.0
 pydantic==2.7.2
"""

BINARY_DIFF = """\
diff --git a/static/logo.png b/static/logo.png
index abc..def 100644
Binary files a/static/logo.png and b/static/logo.png differ
"""


@pytest.mark.asyncio
async def test_basic_diff_parsed():
    parser = DiffParser()
    result = await parser.parse(SAMPLE_DIFF)

    assert result.total_added_lines > 0
    assert len(result.changed_files) == 2


@pytest.mark.asyncio
async def test_python_files_identified():
    parser = DiffParser()
    result = await parser.parse(SAMPLE_DIFF)

    py_files = [f for f in result.changed_files if f.path.endswith(".py")]
    assert len(py_files) == 1
    assert py_files[0].path == "api/auth.py"


@pytest.mark.asyncio
async def test_added_lines_captured():
    parser = DiffParser()
    result = await parser.parse(SAMPLE_DIFF)

    auth_file = next(f for f in result.changed_files if f.path == "api/auth.py")
    assert len(auth_file.added_lines) > 0
    # Should have added lines from the hunk


@pytest.mark.asyncio
async def test_removed_lines_captured():
    parser = DiffParser()
    result = await parser.parse(SAMPLE_DIFF)

    auth_file = next(f for f in result.changed_files if f.path == "api/auth.py")
    # The old SQL injection line was removed
    assert len(auth_file.removed_lines) > 0


@pytest.mark.asyncio
async def test_empty_diff_returns_empty():
    parser = DiffParser()
    result = await parser.parse("")
    assert result.changed_files == []
    assert result.total_added_lines == 0


@pytest.mark.asyncio
async def test_patched_content_reconstructed():
    parser = DiffParser()
    result = await parser.parse(SAMPLE_DIFF)

    auth_file = next(f for f in result.changed_files if f.path == "api/auth.py")
    # Patched content should contain the new safe query
    assert "parameterized" in auth_file.patched_content or "?" in auth_file.patched_content


@pytest.mark.asyncio
async def test_non_python_files_still_parsed():
    parser = DiffParser()
    result = await parser.parse(SAMPLE_DIFF)

    txt_files = [f for f in result.changed_files if f.path == "requirements.txt"]
    assert len(txt_files) == 1


@pytest.mark.asyncio
async def test_node_modules_skipped():
    diff_with_vendor = """\
diff --git a/node_modules/lodash/lodash.js b/node_modules/lodash/lodash.js
index abc..def 100644
--- a/node_modules/lodash/lodash.js
+++ b/node_modules/lodash/lodash.js
@@ -1 +1 @@
-old
+new
"""
    parser = DiffParser()
    result = await parser.parse(diff_with_vendor)
    # node_modules should be skipped
    assert all("node_modules" not in f.path for f in result.changed_files)
