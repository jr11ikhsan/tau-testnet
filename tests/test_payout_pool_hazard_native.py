"""Bounty 01 (POOLCHECK): payout-pool determinism hazard reproduction.

jimb000o (PR #141 commit 28849f2, accepted by Messi after he re-ran the 4
options tests himself) found that on the pinned engine (tau-lang c3ea334) a
Tau rule stepped after another rule was built and probed in the SAME policy
worker sometimes refuses the step: 21 of 400 fresh workers for
`o30 = i27 / 5` after a second rule was validated, and never on tau-lang
0.8.5. A node whose worker refuses settles a payout differently from one
whose worker answers, so two nodes could disagree about a block.

Our G4 branch has NO payout pool: payout execution steps the owner's clause
through the shared "apply" pool (admission: "admission") with the default
options (cache 256, pin 0.1s) — exactly the settings his patch abandoned.
Our G4 CI is green but does not prove immunity: the native G4 tests step one
rule once per scenario, never several rules in turn in one worker.

These tests reproduce jimb's trigger pattern against OUR pools, in three
shapes, and count every refusal and every wrong answer:

- A: jimb's shape, in turn in ONE worker: step `o30 = i27 / 5` after
  validating `i27 / 6` .. `i27 / 65` one at a time (his committed native
  test, against the default pool options his fix replaces).
- B: six rules in turn in ONE worker against a model (his second committed
  native test), 400 iterations with validations mixed in.
- C: fresh-worker sweep: 100 fresh evaluators; in each, validate a second
  rule, then step `o30 = i27 / 5` (his 21/400 shape, at 100 trials).
- D: the G4 path itself: the real grant clause from
  tests/test_payout_tau_rule_native.py stepped through
  sender_policy.clause_outputs(pool="apply") after another rule was
  validated in the same pool, with the admission pool exercised the same
  way once per round.

Each test asserts ZERO refusals and ZERO wrong answers. A failure here IS
the reproduction: it proves the hazard reaches our payout path. The fix
(one interpreter at a time, never pinned, for payout-clause stepping only)
must make these pass without touching the o5 clause pools.

Kept in its own file so the real-Tau CI job can register exactly this
file: the proof needs the native bindings the mock job does not have. The
skip is environment-driven, exactly as the other Bounty 01 native suites.
Locally (no native engine) every test skips.
"""
import os
import random
import sys
import time

import pytest

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    import tau_native
    tau_native.load_tau_module()
    _NATIVE_TAU = True
except Exception:
    _NATIVE_TAU = False

import tau_policy
from tau_policy import PolicyStepError, PolicyBuildError
from consensus import sender_policy

FRESH_WORKERS = 100
WEEK = 604_800


def _divide(by):
    return "o30[t]:bv[24] = i27[t]:bv[24] / { %d }:bv[24]" % by


def _fresh_evaluator():
    """A PolicyEvaluator built exactly the way the node builds the "apply"
    pool: default options (cache 256, pin 0.1s)."""
    return tau_policy.PolicyEvaluator(pool="apply")


@pytest.mark.skipif(not _NATIVE_TAU, reason="native tau module not available")
def test_a_rule_answers_after_every_other_rule_built_in_one_worker():
    """A (jimb's shape, in turn): `i27/5` stepped after each of `i27/6` ..
    `i27/65` is validated in the same worker. Any refusal or wrong answer
    fails — that IS the hazard reaching our pool."""
    ev = _fresh_evaluator()
    try:
        fifth = _divide(5)
        assert ev.outputs(fifth, {"i27": "100"})["o30"] == "20"
        refusals = []
        wrong = []
        for by in range(6, 66):
            assert ev.validate(_divide(by)).ok
            for value, want in (("100", "20"), ("101", "20")):
                try:
                    got = ev.outputs(fifth, {"i27": value})["o30"]
                except (PolicyStepError, PolicyBuildError) as exc:
                    refusals.append((by, value, str(exc)[:120]))
                    continue
                if got != want:
                    wrong.append((by, value, got, want))
        assert not refusals, f"step refusals stepping i27/5 after validations: {refusals}"
        assert not wrong, f"wrong answers stepping i27/5 after validations: {wrong}"
    finally:
        ev.close()


@pytest.mark.skipif(not _NATIVE_TAU, reason="native tau module not available")
def test_rules_in_turn_in_one_pool_all_answer_like_their_model():
    """B (jimb's shape, rotation vs model): six rules in turn in one worker,
    400 iterations, validations mixed in. Any refusal or model mismatch
    fails."""
    def c(n):
        return "{ %d }:bv[24]" % n

    rules = [
        (_divide(5), lambda v: v // 5),
        (_divide(2), lambda v: v // 2),
        (f"(i27[t]:bv[24] > {c(50)}) ? (o30[t]:bv[24] = {c(7)}) : (o30[t]:bv[24] = {c(0)})",
         lambda v: 7 if v > 50 else 0),
        (f"o30[t]:bv[24] = i27[t]:bv[24] + {c(3)}", lambda v: v + 3),
        (f"(i27[t]:bv[24] < {c(10)}) ? (o30[t]:bv[24] = {c(0)}) : "
         f"(o30[t]:bv[24] = i27[t]:bv[24] / {c(10)})", lambda v: 0 if v < 10 else v // 10),
        (f"(o30[t]:bv[24] = i27[t]:bv[24] / {c(4)}) && (o31[t]:bv[24] = i27[t]:bv[24] / {c(8)})",
         lambda v: v // 4),
    ]
    ev = _fresh_evaluator()
    try:
        rng = random.Random(63)
        refusals = []
        wrong = []
        for n in range(400):
            if rng.random() < 0.3:
                assert ev.validate(rng.choice(rules)[0]).ok
            body, model = rng.choice(rules)
            value = rng.choice([0, 1, 4, 9, 10, 25, 50, 51, 100, 101, 999, 65_535, 1_000_000])
            try:
                got = ev.outputs(body, {"i27": str(value)})["o30"]
            except (PolicyStepError, PolicyBuildError) as exc:
                refusals.append((n, body[:40], value, str(exc)[:120]))
                continue
            if got != str(model(value)):
                wrong.append((n, body[:40], value, got, model(value)))
        assert not refusals, f"step refusals in rotation: {refusals[:10]} (total {len(refusals)})"
        assert not wrong, f"model mismatches in rotation: {wrong[:10]} (total {len(wrong)})"
    finally:
        ev.close()


@pytest.mark.skipif(not _NATIVE_TAU, reason="native tau module not available")
def test_fresh_workers_step_after_a_second_rule_was_validated():
    """C (jimb's 21/400 shape, at 100 trials): in each FRESH evaluator,
    validate a second rule, then step `i27/5`. Any refusal fails."""
    refusals = []
    wrong = []
    for trial in range(FRESH_WORKERS):
        ev = _fresh_evaluator()
        try:
            assert ev.validate(_divide(6 + (trial % 60))).ok
            try:
                got = ev.outputs(_divide(5), {"i27": "100"})["o30"]
            except (PolicyStepError, PolicyBuildError) as exc:
                refusals.append((trial, str(exc)[:120]))
                continue
            if got != "20":
                wrong.append((trial, got))
        finally:
            ev.close()
    assert not refusals, (
        f"step refusals in fresh workers: {len(refusals)}/{FRESH_WORKERS}: {refusals[:10]}")
    assert not wrong, f"wrong answers in fresh workers: {wrong[:10]}"


@pytest.mark.skipif(not _NATIVE_TAU, reason="native tau module not available")
def test_g4_payout_clause_answers_after_other_rules_in_the_apply_pool():
    """D (the G4 path): the real grant clause, stepped through
    sender_policy.clause_outputs(pool="apply") after another rule was
    validated in the same pool — the exact admission/apply path G4 uses.
    Inputs put the clause in its third-week draw branch: i1=500, i5 in week
    3, i26=1000 paid of 1500 released, so the expected legs are exactly
    one leg to candidate 0 for 500. Any None (step refusal) or wrong legs
    fails. The admission pool is exercised the same way once per round."""
    from tests.test_payout_tau_rule_native import _grant_clause

    now = int(time.time())
    anchor = now - 3 * WEEK + 60
    clause = _grant_clause(anchor, 0, 1)
    inputs = {"i1": "500", "i2": "5000", "i3": "0", "i4": "0",
              "i5": str(now), "i26": "1000"}
    want = {"o30": "1", "o31": "0", "o32": "500"}
    ev = tau_policy.get_policy_evaluator("apply")
    ev_admission = tau_policy.get_policy_evaluator("admission")
    refusals = []
    wrong = []
    for k in range(60):
        # The trigger must be built in EACH pool's worker: validate another
        # rule in the apply pool AND in the admission pool before stepping.
        assert ev.validate(_divide(6 + k)).ok
        assert ev_admission.validate(_divide(6 + k)).ok
        for pool in ("apply", "admission"):
            outputs, detail = sender_policy.clause_outputs(clause, inputs, pool=pool)
            if outputs is None:
                refusals.append((k, pool, detail[:120]))
                continue
            got = {name: outputs.get(name) for name in ("o30", "o31", "o32")}
            if got != want:
                wrong.append((k, pool, got))
    assert not refusals, f"G4 clause step refusals via clause_outputs: {refusals[:10]} (total {len(refusals)})"
    assert not wrong, f"G4 clause wrong legs via clause_outputs: {wrong[:10]} (total {len(wrong)})"
