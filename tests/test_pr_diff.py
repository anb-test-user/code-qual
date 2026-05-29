"""Unified-diff parsing used by the PR scanner."""
from codequal.scanners import parse_unified_diff

DIFF = """diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -0,0 +1,2 @@
+import os
+secret = "abc123def"
@@ -10,1 +12,1 @@ def handler():
+    changed = True
diff --git a/old.py b/old.py
deleted file mode 100644
index 3333333..0000000
--- a/old.py
+++ /dev/null
@@ -1,2 +0,0 @@
-gone
-also_gone
"""


def test_parses_added_lines_with_new_file_numbering():
    changed = parse_unified_diff(DIFF)
    assert changed["app.py"] == {1, 2, 12}


def test_deleted_file_has_no_added_lines():
    changed = parse_unified_diff(DIFF)
    assert "old.py" not in changed


def test_empty_diff_is_empty_mapping():
    assert parse_unified_diff("") == {}
