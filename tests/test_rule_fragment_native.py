"""Fragment screen vs the REAL engine (no mocks).

Property under test: every rule the syntax allow-list ADMITS must also be
accepted by the pinned engine's isolated compile gate -- the screen must
never refuse a rule the engine itself would run. (The converse is false
on purpose: the screen is stricter than the engine; a rule the screen
refuses never reaches the engine at all.)

Harness shape follows tests/test_rule_scoping_native.py: the real engine
runs in a child process (it segfaults on teardown), results come back on
one SENTINEL line, and the whole file skips when no native module is
importable.
"""
import json
import os
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


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

A = "aa" * 48

_PREAMBLE = r'''
import json, os, sys, tempfile
os.environ["TAU_ENV"] = "test"
os.environ["TAU_FORCE_TEST"] = "0"
# Deliberately no config/db import: these cases exercise TauInterface at the
# raw layer. That keeps the child runnable under a bare interpreter that only
# has the built nanobind module on PYTHONPATH.
import tau_native

SENTINEL = "SPIKE_RESULT "
ROUTER = "((!(i0[t] = 0)) ? ( u[t] = i0[t] && o0[t] = 0 ) : o0[t] = 1)"
BASE = "o1[t]:bv[24] = i1[t]:bv[24]"


def emit(obj):
    print(SENTINEL + json.dumps(obj))
    sys.stdout.flush()
    # The native engine segfaults on interpreter teardown (known pre-existing
    # flaky crash). The result above is already computed; hard-exit before any
    # native destructor runs so the child reports a clean exit code.
    os._exit(0)
'''


def _run_child(tmp_path, name, body):
    script = tmp_path / (name + ".py")
    script.write_text(_PREAMBLE + "\n" + body)
    proc = subprocess.run(
        [_native_python(), str(script)],
        capture_output=True, text=True,
        env=_child_env({"SPIKE_DB": str(tmp_path / (name + ".db"))}),
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


# Rules the allow-list admits (shapes from tests/test_rule_fragment.py).
# NOTE (2026-11-27): each fragment must be consistent with the ACCUM typing
# below -- BASE types i1 as bv[24], so `effect_1_typed` annotates i1 bv[24],
# not bv[64] (a bv[64] annotation conflicts with the accumulated spec and
# the pinned engine rejects it; the screen judges shape in isolation and
# does not re-enforce width policy, so the fragment carries the width the
# harness context assigns). See G1-FIX-2026-11-27.md §1.
ADMITTED = {
    "rule_b": "always (o26[t]:bv[24] = { 7 }:bv[24]).",
    "rule_o8": "always (o8[t]:bv[64] = { 100 }:bv[64]).",
    "effect_1_typed": (
        "always ( ((i12[t]:bv[384] = { #xaa }:bv[384] || "
        "i1[t]:bv[24] > { 0 }:bv[24]) "
        "? (o8[t]:bv[64] = { 100 }:bv[64]) : "
        "(o8[t]:bv[64] = { 0 }:bv[64])) )."
    ),
    "o5_ternary": (
        "always ( (i1[t]:bv[24] > { 0 }:bv[24]) ? "
        "(o5[t]:bv[24] = { #x000001 }:bv[24]) : "
        "(o5[t]:bv[24] = { #x000000 }:bv[24]) )."
    ),
    "payout_clause": (
        "always ((o30[t]:bv[64] = { 1 }:bv[64]) && "
        "(o31[t]:bv[64] = { 0 }:bv[64]) && "
        "(o32[t]:bv[64] = { 100 }:bv[64]))"
    ),
    "guarded": (
        "always ( (i12[t]:bv[384] = { #x" + A + " }:bv[384]) -> "
        "(o26[t]:bv[24] = { #x000001 }:bv[24]) )."
    ),
}


@requires_native
def test_admitted_fragments_are_accepted_by_the_real_engine(tmp_path):
    """The allow-list must not refuse anything the pinned engine runs."""
    body = "res = {}\nACCUM = (\"always ( \" + ROUTER + \" ).\\n\"\n         \"always ( \" + BASE + \" ).\")\n"
    body += "RULES = " + json.dumps(ADMITTED) + "\n"
    body += r'''
for name, rule in RULES.items():
    try:
        r = tau_native.TauInterface.compile_revisions_isolated(ACCUM, [rule])
    except Exception as e:
        r = "EXC: %s: %s" % (type(e).__name__, e)
    res[name] = tau_native.strip_ansi(r) if r else None
emit(res)
'''
    proc, parsed = _run_child(tmp_path, "frag_engine", body)
    _assert_ok(proc, parsed)
    for name, err in parsed.items():
        assert err is None, (
            f"allow-list admits {name}, but the real engine refuses it: {err}"
        )


@requires_native
def test_genesis_consensus_rule_builds_on_the_real_engine(tmp_path):
    """The genesis consensus rule (mixed = and &&, no parens) must build:
    it is the reason the allow-list uses a precedence table instead of a
    paren mandate."""
    proc, parsed = _run_child(tmp_path, "frag_genesis", r'''
res = {}
tau_mod = tau_native.load_tau_module()
GENESIS = open(os.path.join(os.environ["REPO_ROOT"], "genesis.tau")).read().strip()
itp = tau_mod.get_interpreter(tau_native.TauInterface.preprocess_spec_text(
    "always ( " + GENESIS + " )."))
res["built"] = bool(itp)
emit(res)
''')
    _assert_ok(proc, parsed)
    assert parsed["built"] is True


@requires_native
def test_u_writing_rule_refused_by_screen_not_engine(tmp_path):
    """The refusal of a `u`-writing rule lives in the screens, not the engine.

    `u` is the engine's spec-update stream (writing it revises the running
    spec itself): the legacy special-stream screen refuses it with
    TX_REJECTED (consensus/admission.py: screen_stream_names) and the
    fragment screen refuses it with RULE_FRAGMENT_CODE (`u` is not an
    i<N>/o<N> stream). The raw engine compile gate, however, accepts
    `always u[t] = 0.` silently -- it is an engine-special stream, so the
    compile gate has no reason to refuse it. The old test assumed the
    engine refused it too; that assumption was wrong (run 45930209937).
    The belt-and-braces property that actually holds is: the screens
    refuse, so the engine is never reached.
    """
    # Screen side (no native needed): both screens refuse `u`.
    from consensus.admission import screen_user_rule_text
    from consensus.rule_fragment import FragmentError, parse_rule_fragment

    with pytest.raises(FragmentError) as excinfo:
        parse_rule_fragment("always u[t] = 0.")
    assert excinfo.value.code == "RULE_FRAGMENT"
    rejection = screen_user_rule_text("always u[t] = 0.", "", False)
    assert rejection is not None and rejection.code == "TX_REJECTED"
    # Engine side (native): the compile gate accepts it silently -- document
    # the behaviour instead of assuming a rejection.
    proc, parsed = _run_child(tmp_path, "frag_u", r'''
res = {}
ACCUM = ("always ( " + ROUTER + " ).\n"
         "always ( " + BASE + " ).")
try:
    r = tau_native.TauInterface.compile_revisions_isolated(ACCUM, ["always u[t] = 0."])
except Exception as e:
    r = "EXC: %s: %s" % (type(e).__name__, e)
res["u_rule"] = tau_native.strip_ansi(r) if r else None
emit(res)
''')
    _assert_ok(proc, parsed)
    assert parsed["u_rule"] is None, (
        "engine now rejects a `u`-writing rule; the screen-side refusal "
        "above is still the gate, but update this note: "
        f"{parsed['u_rule']}"
    )
