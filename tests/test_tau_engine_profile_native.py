"""Pinned engine profile vs the REAL engine (no mocks).

Property under test: loading the native module in a real process reports
the pinned tau-lang ref as VERIFIED (the CI image carries the
``/app/tau-lang/.git/HEAD`` the check reads), and the load scrub removes
planted steering variables while keeping the repo-owned ones.

Harness shape follows tests/test_rule_scoping_native.py: the real engine
runs in a child process, results come back on one SENTINEL line, and the
whole file skips when no native module is importable.
"""
import json
import os
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PINNED_REF = "6ea436e8d3113a7d90635b9d06113e5bc506176c"


def _native_python():
    return os.environ.get("TAU_NATIVE_PYTHON") or sys.executable


def _child_env(extra=None):
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")
    env["REPO_ROOT"] = REPO_ROOT
    if extra:
        env.update(extra)
    return env


def _native_available():
    try:
        proc = subprocess.run(
            [_native_python(), "-c",
             "import tau_native; assert tau_native.load_tau_module() is not None"],
            capture_output=True, text=True, env=_child_env(), timeout=120,
        )
        return proc.returncode == 0
    except Exception:
        return False


_NATIVE = _native_available()
requires_native = pytest.mark.skipif(not _NATIVE, reason="native tau module not importable")

_PREAMBLE = r'''
import json, os, sys
os.environ["TAU_ENV"] = "test"
os.environ["TAU_FORCE_TEST"] = "0"
# Planted steering variables: the load must scrub them (unknown TAU_* +
# credentials) while keeping the repo-owned TAU_FORCE_TEST.
os.environ["TAU_SOME_ENGINE_OPTION"] = "1"
os.environ["OPENAI_API_KEY"] = "sk-planted"
import tau_native

SENTINEL = "SPIKE_RESULT "


def emit(obj):
    print(SENTINEL + json.dumps(obj))
    sys.stdout.flush()
    # The native engine segfaults on interpreter teardown (known pre-existing
    # flaky crash). The result above is already computed; hard-exit before any
    # native destructor runs so the child reports a clean exit code.
    os._exit(0)
'''


def _run_child(tmp_path, name, body, extra_env=None):
    script = tmp_path / (name + ".py")
    script.write_text(_PREAMBLE + "\n" + body)
    proc = subprocess.run(
        [_native_python(), str(script)],
        capture_output=True, text=True,
        env=_child_env(extra_env),
        timeout=300,
    )
    line = next((l for l in proc.stdout.splitlines()
                 if l.startswith("SPIKE_RESULT ")), None)
    parsed = json.loads(line[len("SPIKE_RESULT "):]) if line else None
    return proc, parsed


def _assert_ok(proc, parsed):
    assert proc.returncode == 0, (
        f"child exited {proc.returncode}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    )
    assert parsed is not None, (
        f"child produced no result line\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    )


@requires_native
def test_load_reports_the_pinned_ref_verified(tmp_path):
    proc, parsed = _run_child(tmp_path, "profile_load", r'''
res = {}
tau_mod = tau_native.load_tau_module()
res["loaded"] = tau_mod is not None
from consensus.engine_profile import engine_profile
res["profile"] = engine_profile()
# The load scrub must have removed the planted variables...
res["planted_tau_gone"] = "TAU_SOME_ENGINE_OPTION" not in os.environ
res["planted_key_gone"] = "OPENAI_API_KEY" not in os.environ
# ...while keeping the repo-owned ones the node itself needs.
res["force_test_kept"] = os.environ.get("TAU_FORCE_TEST")
emit(res)
''')
    _assert_ok(proc, parsed)
    assert parsed["loaded"] is True
    profile = parsed["profile"]
    assert profile["tau_lang_ref"] == PINNED_REF
    assert profile["tau_lang_ref_short"] == "6ea436e8"
    # In the CI image the tau-lang checkout carries .git/HEAD, so the ref
    # must be VERIFIED, not merely claimed. If this fails, the image no
    # longer carries a verifiable checkout -- read profile["ref_detail"].
    assert profile["ref_verified"] is True, profile
    assert parsed["planted_tau_gone"] is True
    assert parsed["planted_key_gone"] is True
    assert parsed["force_test_kept"] == "0"
