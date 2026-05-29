"""Offline heuristic engine tests (no API key required)."""
from codequal import Engine, EngineConfig
from codequal.scanners import scan_content

SAMPLE = '''import hashlib

API_KEY = "abcdef123456789"


def handler(x, store=[]):
    if x == None:
        return eval(x)
    try:
        return hashlib.md5(x).hexdigest()
    except:
        pass
'''


def heuristic_engine():
    return Engine(EngineConfig(no_ai=True))


def titles(result):
    return [f.title for f in result.findings]


def test_engine_runs_in_heuristic_mode():
    engine = heuristic_engine()
    assert engine.mode == "heuristic"


def test_detects_core_issue_classes():
    result = scan_content("f.py", SAMPLE, engine=heuristic_engine())
    joined = " | ".join(titles(result)).lower()
    assert "possible hardcoded secret" in joined
    assert "mutable default argument" in joined
    assert "comparison to none" in joined
    assert "dynamic code execution" in joined
    assert "weak hash" in joined
    assert any("except" in t.lower() for t in titles(result))


def test_clean_code_yields_no_findings():
    result = scan_content("clean.py", "def add(a, b):\n    return a + b\n", engine=heuristic_engine())
    assert result.total == 0


def test_focus_lines_restrict_to_changed_region():
    # Line 7 is `if x == None:`; restricting focus should drop all other findings.
    result = scan_content("f.py", SAMPLE, engine=heuristic_engine(), focus_lines={7})
    assert result.total >= 1
    assert all(f.line == 7 for f in result.findings)


def test_placeholder_secret_is_ignored():
    code = 'API_KEY = "your-api-key-here"\n'
    result = scan_content("c.py", code, engine=heuristic_engine())
    assert not any("secret" in t.lower() for t in titles(result))
