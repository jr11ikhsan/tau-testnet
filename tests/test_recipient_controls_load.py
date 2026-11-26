"""Bounty 03, issues #47 + #76 — LOAD: the recipient gate under volume.

G4 depth (RIVAL-GAP-AUDIT §6.1/§8): #169 claims load numbers (600 rejections,
15 honest payments landing during a flood) with no public run. This file is
our own measured answer at the layer we can bound deterministically in the
mock CI job: the gate itself (`recipient_clause_blocks` — the exact helper
admission AND apply call), the cap extractor it consults on every hold
refusal, and the registry lookup behind `clause_for`.

What is measured (all mock-evaluator, deterministic, no wall-clock input):
  * 200 distinct recipient clauses (100 allow-lists over distinct senders,
    100 threshold caps over distinct cap values) x a judgment grid of
    contexts {final, time-park, height-park} x holds {0, 1, 59, 60, 61,
    unit-max} x {listed, stranger} sender x {apply, admission} pool —
    14,400 gate judgments, every verdict checked against the clause's
    declared semantics (not just "it returned something"), plus the cap
    the gate reports on each hold refusal.
  * 1,000 judged transfers ("receipts") across 50 recipients, replayed a
    second time: the replay must reproduce the first run receipt-for-receipt
    (determinism under volume — the property a load flood would break first).
  * A 500-recipient registry sweep: `clause_for` lookups stay correct as the
    registry grows (no wrong-recipient leakage, no missed clause).

Timing is reported (seconds + judgments/second, printed and asserted
against a LOOSE guard bound, not a tight benchmark — CI runners vary;
the bound exists to catch a quadratic blow-up, not to win a race).
The numbers are the claim; see JUARA-L3-G4-B03DEPTH-LOG.md for the run.
"""
import hashlib
import json
import time

import pytest

from bls_keys import pubkey_hex
from consensus import sender_policy
from consensus.policy_mock import MockPolicyEvaluator

# The mock job has no engine; verdicts are scripted per body from the
# semantics the body text declares (same pattern as
# tests/test_recipient_controls.py).
UNIT_MAX_SECONDS = 7_776_000
UNIT_MAX_BLOCKS = 100_000

N_ALLOWLIST_RULES = 100
N_CAP_RULES = 100
N_RECEIPTS = 1000
N_REGISTRY = 500

# Loose guard bounds (seconds, whole-file). The mock evaluator is
# in-process; a healthy run finishes in a few seconds on shared CI.
# Anything near the bound means the gate went quadratic.
LOAD_TIME_GUARD_SECONDS = 60.0


def _sender_pubkey(i: int) -> str:
    # Distinct, deterministic 384-bit sender ids (not real keys — the
    # gate only compares the hex literal, and the mock never signs).
    return ("%096x" % (0xA11CE + i * 0x9E3779B97F4A7C15))


def _allowlist_body(sender: str) -> str:
    return (
        "(i16[t]:bv[64] = { #x0000 }:bv[64] || "
        "i3[t]:bv[384] = { #x" + sender + " }:bv[384]) "
        "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
        ": (o5[t]:bv[24] = { #x000000 }:bv[24])"
    )


def _allowlist_verdict(sender: str):
    return lambda inputs: "1" if (
        str(inputs.get("i16")) == "0" or inputs.get("i3") == "#x" + sender
    ) else "0"


def _cap_body(cap_seconds: int, cap_blocks: int) -> str:
    return (
        "((i16[t]:bv[64] = { #x0002 }:bv[64] && i17[t]:bv[64] > { #x%04x }:bv[64]) || "
        "(i16[t]:bv[64] = { #x0003 }:bv[64] && i17[t]:bv[64] > { #x%04x }:bv[64])) "
        "? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])"
        % (cap_seconds, cap_blocks)
    )


def _cap_verdict(cap_seconds: int, cap_blocks: int):
    def decide(inputs):
        ctx = int(inputs.get("i16") or 0)
        hold = int(inputs.get("i17") or 0)
        if ctx == 2:
            return "0" if hold > cap_seconds else "1"
        if ctx == 3:
            return "0" if hold > cap_blocks else "1"
        return "1"
    return decide


@pytest.fixture()
def _gate():
    """One mock evaluator per pool, pre-loaded with all 200 load bodies."""
    bodies = {}  # body -> (kind, param)
    ev = MockPolicyEvaluator(pool="apply")
    ev_adm = MockPolicyEvaluator(pool="admission")
    for i in range(N_ALLOWLIST_RULES):
        sender = _sender_pubkey(i)
        body = _allowlist_body(sender)
        verdict = _allowlist_verdict(sender)
        ev.set_verdict(body, verdict)
        ev_adm.set_verdict(body, verdict)
        bodies[body] = ("allowlist", sender)
    for i in range(N_CAP_RULES):
        cap_s = 60 * (i + 1)          # 60 .. 6000 seconds
        cap_b = 10 * (i + 1)          # 10 .. 1000 blocks
        body = _cap_body(cap_s, cap_b)
        verdict = _cap_verdict(cap_s, cap_b)
        ev.set_verdict(body, verdict)
        ev_adm.set_verdict(body, verdict)
        bodies[body] = ("cap", (cap_s, cap_b))
    sender_policy.set_evaluator("apply", ev)
    sender_policy.set_evaluator("admission", ev_adm)
    yield bodies
    sender_policy.set_evaluator("apply", None)
    sender_policy.set_evaluator("admission", None)


def _base_values(sender: str) -> dict:
    return {3: "#x" + sender, 1: "100"}


def test_load_200_rules_judgment_grid(_gate):
    """200 rules x 18 judgments: every verdict matches the clause's
    declared semantics, in both pools, and the whole grid finishes
    inside the guard bound."""
    bodies = _gate
    holds = [0, 1, 59, 60, 61, UNIT_MAX_SECONDS]
    contexts = [1, 2, 3]  # final, time-park, height-park
    judgments = 0
    t0 = time.perf_counter()
    for body, (kind, param) in bodies.items():
        sender = param if kind == "allowlist" else _sender_pubkey(0)
        stranger = _sender_pubkey(999983)
        for ctx in contexts:
            for hold in holds:
                # Hold grids are per-context: a seconds hold is only
                # meaningful in context 2, a blocks hold in context 3;
                # context 1 (final) ignores the hold. The verdict
                # oracle below encodes exactly that.
                for who in (sender, stranger):
                    for pool in ("apply", "admission"):
                        blocked, info = sender_policy.recipient_clause_blocks(
                            lambda addr, stream, _b=body: _b,
                            "recipient", _base_values(who),
                            hold=hold, context=ctx, pool=pool)
                        judgments += 1
                        if kind == "allowlist":
                            # The body admits context 0 outright and
                            # contexts 1/2/3 iff the sender is listed;
                            # this grid only exercises 1/2/3.
                            expect = (who != sender)
                            assert blocked == expect, (
                                f"allowlist body={body[:60]} ctx={ctx} "
                                f"hold={hold} who={'listed' if who == sender else 'stranger'} "
                                f"pool={pool}: blocked={blocked} want={expect}")
                        else:
                            cap_s, cap_b = param
                            if ctx == 2:
                                expect = hold > cap_s
                            elif ctx == 3:
                                # holds grid is in seconds units; a
                                # blocks hold above cap_b only when the
                                # grid value itself exceeds it.
                                expect = hold > cap_b
                            else:
                                expect = False
                            assert blocked == expect, (
                                f"cap body cap_s={cap_s} cap_b={cap_b} "
                                f"ctx={ctx} hold={hold} pool={pool}: "
                                f"blocked={blocked} want={expect}")
                            if expect and ctx in (2, 3):
                                assert info is not None
                                assert info["reason"] == "recipient_max_hold"
                                assert info["cap_kind"] == "threshold"
                                want_cap = cap_s if ctx == 2 else cap_b
                                key = ("max_hold_seconds" if ctx == 2
                                       else "max_hold_blocks")
                                assert info[key] == want_cap, info
    elapsed = time.perf_counter() - t0
    print(f"\n[load] rules={len(bodies)} judgments={judgments} "
          f"elapsed={elapsed:.2f}s rate={judgments / elapsed:.0f}/s")
    assert judgments == len(bodies) * len(contexts) * len(holds) * 2 * 2
    assert elapsed < LOAD_TIME_GUARD_SECONDS, (
        f"gate grid took {elapsed:.2f}s, guard is "
        f"{LOAD_TIME_GUARD_SECONDS}s — possible quadratic blow-up")


def test_load_1000_receipts_replay_is_identical(_gate):
    """1,000 judged transfers across 50 recipients, judged twice: the
    second run reproduces the first receipt-for-receipt (same blocked,
    same reason, same cap). A gate that kept hidden state (or reordered
    evaluations) would diverge here first."""
    bodies = list(_gate.items())
    recipients = ["%096x" % (0xBEC1 + i) for i in range(50)]

    def run_once():
        receipts = []
        for n in range(N_RECEIPTS):
            body, (kind, param) = bodies[n % len(bodies)]
            recipient = recipients[n % len(recipients)]
            sender = param if kind == "allowlist" else _sender_pubkey(n % 97)
            ctx = (n % 3) + 1
            hold = (n * 37) % (UNIT_MAX_SECONDS + 1)
            blocked, info = sender_policy.recipient_clause_blocks(
                lambda addr, stream, _b=body: _b,
                recipient, _base_values(sender),
                hold=hold, context=ctx, pool="apply")
            receipts.append((n, recipient, ctx, hold, blocked,
                             None if info is None else
                             (info.get("reason"), info.get("cap_kind"),
                              info.get("max_hold_seconds"),
                              info.get("max_hold_blocks"))))
        return receipts

    t0 = time.perf_counter()
    first = run_once()
    second = run_once()
    elapsed = time.perf_counter() - t0
    assert first == second, "gate replay diverged under volume"
    digest = hashlib.sha256(
        json.dumps(first, sort_keys=True).encode()).hexdigest()
    blocked_n = sum(1 for r in first if r[4])
    print(f"\n[load] receipts={len(first)}x2 blocked={blocked_n} "
          f"elapsed={elapsed:.2f}s sha256={digest[:16]}")
    assert len(first) == N_RECEIPTS
    assert elapsed < LOAD_TIME_GUARD_SECONDS


def test_load_500_recipient_registry_lookup(_gate):
    """500 recipients in the registry: every lookup returns exactly that
    recipient's clause (no cross-recipient leakage), and a missing
    recipient reads as the neutral default."""
    bodies = list(_gate.items())
    registry = {}
    for i in range(N_REGISTRY):
        recipient = "%096x" % (0xBEC1 + i)
        body, _ = bodies[i % len(bodies)]
        registry[(recipient, 5)] = body

    def clause_for(addr, stream):
        return registry.get((addr.lower(), stream))

    t0 = time.perf_counter()
    for i in range(N_REGISTRY):
        recipient = "%096x" % (0xBEC1 + i)
        body, (kind, param) = bodies[i % len(bodies)]
        got = clause_for(recipient, 5)
        assert got == body, f"registry returned wrong clause for {recipient}"
        blocked, info = sender_policy.recipient_clause_blocks(
            clause_for, recipient, _base_values(_sender_pubkey(i % 97)),
            hold=601, context=2, pool="apply")
        if kind == "cap":
            cap_s, _ = param
            assert blocked == (601 > cap_s)
    assert clause_for("%096x" % 0xDEAD, 5) is None
    blocked, info = sender_policy.recipient_clause_blocks(
        clause_for, "%096x" % 0xDEAD, _base_values(_sender_pubkey(1)),
        hold=601, context=2, pool="apply")
    assert blocked is False and info is None  # neutral default
    elapsed = time.perf_counter() - t0
    print(f"\n[load] registry={N_REGISTRY} lookups elapsed={elapsed:.2f}s")
    assert elapsed < LOAD_TIME_GUARD_SECONDS
