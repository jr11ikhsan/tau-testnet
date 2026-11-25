"""Recipient controls, Bounty 03 parts 3-4 (issues #47 + #76): the
recipient's clause judging a payment by its condition facts — the
allowance normalised to a 30-day rate (i28), the encoded refund delay
(i29) and the expiry (i32) — beside the hold gate of parts 1-2.

The facts are node-fed from the park's signed condition terms and
FORCED into the judged input map by the gate, exactly like i17/i16:
a sender-supplied value on a fact stream never reaches the clause.
Stream allocation is PROVISIONAL (tau_defs): i28/i29/i32 follow the
canonical layout proposed on issue #47.

Mock evaluator throughout, like tests/test_recipient_controls.py:
clause verdicts are scripted by input, keyed on the fact streams, and
the body texts beside them declare the same semantics in the canonical
annotated form the deploy screens and the cap extractor read.
"""
import pytest

import tau_defs
from consensus import sender_policy
from consensus.approvals import screen_recipient_stream_widths
from consensus.policy_mock import MockPolicyEvaluator
from consensus.retractable import (
    ConditionTerms,
    RetractableShapeError,
    normalize_allowance_30d,
    parse_condition_terms,
    parse_retractable_transfer,
)

import test_approval_apply as ap

POOLS = ("apply", "admission")

ALLOWANCE = tau_defs.ALLOWANCE_STREAM_INDEX
REFUND = tau_defs.REFUND_DELAY_STREAM_INDEX
EXPIRY = tau_defs.EXPIRY_STREAM_INDEX


@pytest.fixture(autouse=True)
def _reset_overrides():
    for pool in POOLS:
        sender_policy.set_evaluator(pool, None)
    yield
    for pool in POOLS:
        sender_policy.set_evaluator(pool, None)


def _ev(body, fn, pool="apply"):
    ev = MockPolicyEvaluator(pool=pool)
    ev.set_verdict(body, fn)
    return ev


def _clause_for(mapping):
    return lambda addr, stream: mapping.get((addr, stream))


def _values():
    return {1: "5", 3: "{ #x" + ap.ALICE + " }:bv[384]"}


# --- clause bodies and their scripted semantics ------------------------------

# Caps the payment's 30-day allowance rate at 2000. Reads i28 only: the
# fact streams are an opt-in of their own, no i16/i17 needed.
ALLOWANCE_CAP_BODY = (
    "(i28[t]:bv[64] > { #x07d0 }:bv[64]) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000001 }:bv[24])"
)


def allowance_cap_verdict(inputs):
    return "0" if int(inputs.get("i28") or 0) > 2000 else "1"


# Requires the money to be refundable within an hour: never-refundable
# (0) and a delay past 3600 s (encoded > 3601) both refuse.
REFUND_BODY = (
    "((i29[t]:bv[64] = { #x0000 }:bv[64]) || "
    "(i29[t]:bv[64] > { #xe11 }:bv[64])) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000001 }:bv[24])"
)


def refund_verdict(inputs):
    enc = int(inputs.get("i29") or 0)
    return "0" if enc == 0 or enc > 3601 else "1"


# Refuses money that expires too soon: an expiry inside (0, 86400)
# refuses; never-expiring (0) and a day or more both pass.
EXPIRY_BODY = (
    "((i32[t]:bv[64] > { #x0000 }:bv[64]) && "
    "(i32[t]:bv[64] < { #x15180 }:bv[64])) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000001 }:bv[24])"
)


def expiry_verdict(inputs):
    exp = int(inputs.get("i32") or 0)
    return "0" if 0 < exp < 86400 else "1"


# Upper bounds only: allowance rate at most 2000, refund delay encoded
# at most 3601. Every "no condition" value (0) passes both.
UPPER_BOUNDS_BODY = (
    "((i28[t]:bv[64] > { #x07d0 }:bv[64]) || "
    "(i29[t]:bv[64] > { #xe11 }:bv[64])) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000001 }:bv[24])"
)


def upper_bounds_verdict(inputs):
    if int(inputs.get("i28") or 0) > 2000:
        return "0"
    if int(inputs.get("i29") or 0) > 3601:
        return "0"
    return "1"


# --- (ii) the 30-day normalisation is exact ----------------------------------

def test_normalize_allowance_30d_exact():
    # The documented example: a weekly 500 is 2_142 per 30 days (floor).
    assert normalize_allowance_30d(500, 604_800) == 2_142
    assert normalize_allowance_30d(100, 86_400) == 3_000
    assert normalize_allowance_30d(7, 2_592_000) == 7
    assert normalize_allowance_30d(2_000, 2_592_000) == 2_000
    # Floor, stated plainly: below one unit per 30 days reads as 0.
    assert normalize_allowance_30d(1, 7_776_000) == 0
    assert normalize_allowance_30d(0, 604_800) == 0


# --- condition terms: parsing, facts, malformed (v) --------------------------

_PARK = {
    "sender_pubkey": "aa" * 48,
    "recipient_pubkey": "bb" * 48,
    "amount": 100,
    "sequence_number": 0,
    "release_at_time": 2_000_000_000,
}


def test_parse_condition_terms_absent_and_present():
    assert parse_condition_terms(dict(_PARK)) == ConditionTerms()
    terms = parse_condition_terms({
        **_PARK,
        "allowance_amount": 500,
        "allowance_period_seconds": 604_800,
        "refund_delay": 1801,
        "expiry_seconds": 90_000,
    })
    assert terms == ConditionTerms(500, 604_800, 1801, 90_000)
    entry = parse_retractable_transfer({
        **_PARK, "allowance_amount": 500,
        "allowance_period_seconds": 604_800,
    })
    assert entry.terms.allowance_amount == 500
    # Terms are judged at creation only: the id does not commit to them.
    plain = parse_retractable_transfer(dict(_PARK))
    assert entry.retractable_id == plain.retractable_id


@pytest.mark.parametrize("bad", [
    {"allowance_amount": 500},                              # half the pair
    {"allowance_period_seconds": 604_800},                   # half the pair
    {"allowance_amount": 500, "allowance_period_seconds": 0},
    {"allowance_amount": -1, "allowance_period_seconds": 7},
    {"allowance_amount": True, "allowance_period_seconds": 7},
    {"allowance_amount": 2 ** 64, "allowance_period_seconds": 7},
    {"allowance_amount": 2 ** 64 - 1, "allowance_period_seconds": 1},
    {"refund_delay": -1},
    {"refund_delay": "1801"},
    {"refund_delay": 2 ** 64 - 1},  # encoded fact (delay + 1) would overflow bv[64]
    {"expiry_seconds": 2 ** 64},
])
def test_parse_condition_terms_malformed_fails_closed(bad):
    with pytest.raises(RetractableShapeError):
        parse_condition_terms({**_PARK, **bad})
    with pytest.raises(RetractableShapeError):
        parse_retractable_transfer({**_PARK, **bad})


def test_condition_facts_mapping():
    assert sender_policy.condition_facts(None) == {
        ALLOWANCE: 0, REFUND: 0, EXPIRY: 0}
    facts = sender_policy.condition_facts(
        ConditionTerms(500, 604_800, 1801, 90_000))
    # The refund delay is fed ENCODED: 1801 seconds -> fact 1802
    # (0 = never, 1 = at once, 1+N = after N seconds).
    assert facts == {ALLOWANCE: 2_142, REFUND: 1802, EXPIRY: 90_000}
    assert sender_policy.condition_facts(ConditionTerms()) == {
        ALLOWANCE: 0, REFUND: 0, EXPIRY: 0}
    # A zero-second delay encodes to 1 (refundable at once), never to 0.
    assert sender_policy.condition_facts(
        ConditionTerms(None, None, 0, None))[REFUND] == 1


# --- the overlay forces the facts, in every key shape ------------------------

def test_fact_streams_are_forced_not_merged():
    forged = {1: "5", 28: "999999", "28": "999999", "i28": "999999",
              29: "1", "i32": "1"}
    out = sender_policy.recipient_hold_inputs(
        forged, hold=0, context=1, facts={ALLOWANCE: 2_142})
    seen = sender_policy.clause_inputs(out)
    assert seen["i28"] == "2142" and seen["i29"] == "0"
    assert seen["i32"] == "0"
    assert forged["i28"] == "999999"  # the caller's map is untouched


def test_clause_reading_only_a_fact_stream_is_inbound_capable():
    assert sender_policy.clause_is_inbound_capable(ALLOWANCE_CAP_BODY)
    assert sender_policy.clause_is_inbound_capable(REFUND_BODY)
    assert sender_policy.clause_is_inbound_capable(EXPIRY_BODY)
    # A clause reading none of the gate's streams keeps the neutral default.
    sender_policy.set_evaluator(
        "apply", _ev("(o5[t]:bv[24] = { #x000000 }:bv[24])", "0"))
    blocked, info = sender_policy.recipient_clause_blocks(
        _clause_for({(ap.BOB, 5): "(o5[t]:bv[24] = { #x000000 }:bv[24])"}),
        ap.BOB, _values(), hold=0, context=1, pool="apply",
        facts={ALLOWANCE: 10 ** 9})
    assert blocked is False and info is None


# --- (i) the allowance gate ---------------------------------------------------

def test_allowance_over_cap_refused_with_verified_cap():
    sender_policy.set_evaluator(
        "apply", _ev(ALLOWANCE_CAP_BODY, allowance_cap_verdict))
    blocked, info = sender_policy.recipient_clause_blocks(
        _clause_for({(ap.BOB, 5): ALLOWANCE_CAP_BODY}), ap.BOB, _values(),
        hold=100, context=2, pool="apply", facts={ALLOWANCE: 2_142})
    assert blocked is True
    assert info["reason"] == "recipient_allowance_limit"
    assert info["code"] == "RECIPIENT_ALLOWANCE_LIMIT"
    assert info["allowance_30d"] == 2_142
    assert info["cap_kind"] == "threshold"
    assert info["max_allowance_30d"] == 2_000


def test_allowance_at_and_under_cap_admitted():
    sender_policy.set_evaluator(
        "apply", _ev(ALLOWANCE_CAP_BODY, allowance_cap_verdict))
    for rate in (0, 1_500, 2_000):
        blocked, info = sender_policy.recipient_clause_blocks(
            _clause_for({(ap.BOB, 5): ALLOWANCE_CAP_BODY}), ap.BOB,
            _values(), hold=0, context=1, pool="apply",
            facts={ALLOWANCE: rate})
        assert blocked is False, rate


def test_allowance_end_to_end_from_terms():
    """Terms on the park -> facts -> gate: a weekly 500 (2_142 per 30
    days) is refused by the 2_000 cap; a weekly 300 (1_285) is admitted."""
    sender_policy.set_evaluator(
        "apply", _ev(ALLOWANCE_CAP_BODY, allowance_cap_verdict))
    over = sender_policy.condition_facts(ConditionTerms(500, 604_800))
    blocked, info = sender_policy.recipient_clause_blocks(
        _clause_for({(ap.BOB, 5): ALLOWANCE_CAP_BODY}), ap.BOB, _values(),
        hold=100, context=2, pool="apply", facts=over)
    assert blocked is True and info["allowance_30d"] == 2_142
    under = sender_policy.condition_facts(ConditionTerms(300, 604_800))
    blocked, _ = sender_policy.recipient_clause_blocks(
        _clause_for({(ap.BOB, 5): ALLOWANCE_CAP_BODY}), ap.BOB, _values(),
        hold=100, context=2, pool="apply", facts=under)
    assert blocked is False


def test_sender_supplied_fact_streams_never_reach_the_clause():
    sender_policy.set_evaluator(
        "apply", _ev(ALLOWANCE_CAP_BODY, allowance_cap_verdict))
    forged = {**_values(), 28: "1", "i28": "1"}
    # Judged with the payment's real (over-cap) facts: refused.
    blocked, _ = sender_policy.recipient_clause_blocks(
        _clause_for({(ap.BOB, 5): ALLOWANCE_CAP_BODY}), ap.BOB, forged,
        hold=0, context=1, pool="apply", facts={ALLOWANCE: 2_142})
    assert blocked is True
    # Judged with no terms: the forged 1 (and any forged value) is
    # overwritten by the gate's 0, never merged.
    forged[28] = "999999"
    blocked, _ = sender_policy.recipient_clause_blocks(
        _clause_for({(ap.BOB, 5): ALLOWANCE_CAP_BODY}), ap.BOB, forged,
        hold=0, context=1, pool="apply")
    assert blocked is False


# --- (iii) the refund delay ---------------------------------------------------

def test_refund_delay_too_long_refused_with_measured_fact():
    sender_policy.set_evaluator("apply", _ev(REFUND_BODY, refund_verdict))
    blocked, info = sender_policy.recipient_clause_blocks(
        _clause_for({(ap.BOB, 5): REFUND_BODY}), ap.BOB, _values(),
        hold=100, context=2, pool="apply", facts={REFUND: 7_201})
    assert blocked is True
    assert info["reason"] == "recipient_refund_delay"
    assert info["code"] == "RECIPIENT_REFUND_DELAY"
    assert info["refund_delay"] == 7_201
    assert info["refund_delay_seconds"] == 7_200
    assert info["refund_timing"] == "after_delay"
    assert info["cap_kind"] == "rule"


def test_refund_delay_within_terms_admitted():
    sender_policy.set_evaluator("apply", _ev(REFUND_BODY, refund_verdict))
    for enc in (1, 1801, 3601):
        blocked, _ = sender_policy.recipient_clause_blocks(
            _clause_for({(ap.BOB, 5): REFUND_BODY}), ap.BOB, _values(),
            hold=0, context=1, pool="apply", facts={REFUND: enc})
        assert blocked is False, enc


def test_refund_never_refused_only_when_the_clause_requires_refundability():
    sender_policy.set_evaluator("apply", _ev(REFUND_BODY, refund_verdict))
    blocked, info = sender_policy.recipient_clause_blocks(
        _clause_for({(ap.BOB, 5): REFUND_BODY}), ap.BOB, _values(),
        hold=0, context=1, pool="apply", facts={REFUND: 0})
    assert blocked is True and info["refund_timing"] == "never"
    assert info["refund_delay_seconds"] is None


# --- expiry -------------------------------------------------------------------

def test_expiry_too_soon_refused_never_and_late_admitted():
    sender_policy.set_evaluator("apply", _ev(EXPIRY_BODY, expiry_verdict))
    blocked, info = sender_policy.recipient_clause_blocks(
        _clause_for({(ap.BOB, 5): EXPIRY_BODY}), ap.BOB, _values(),
        hold=100, context=2, pool="apply", facts={EXPIRY: 3_600})
    assert blocked is True
    assert info["reason"] == "recipient_expiry"
    assert info["code"] == "RECIPIENT_EXPIRY"
    assert info["expiry_seconds"] == 3_600
    for exp in (0, 86_400, 90_000):
        blocked, _ = sender_policy.recipient_clause_blocks(
            _clause_for({(ap.BOB, 5): EXPIRY_BODY}), ap.BOB, _values(),
            hold=0, context=1, pool="apply", facts={EXPIRY: exp})
        assert blocked is False, exp


# --- (iv) no terms: every "no condition" value passes upper bounds ------------

def test_no_terms_payment_admitted_under_upper_bound_clause():
    sender_policy.set_evaluator(
        "apply", _ev(UPPER_BOUNDS_BODY, upper_bounds_verdict))
    for facts in (None, {}, sender_policy.condition_facts(None),
                  sender_policy.condition_facts(ConditionTerms())):
        blocked, _ = sender_policy.recipient_clause_blocks(
            _clause_for({(ap.BOB, 5): UPPER_BOUNDS_BODY}), ap.BOB,
            _values(), hold=0, context=1, pool="apply", facts=facts)
        assert blocked is False, facts


def test_combined_fact_block_reports_all_measured_facts():
    """Both facts over their bounds: zeroing either one alone still
    blocks, so the refusal is the combined one, with both facts."""
    sender_policy.set_evaluator(
        "apply", _ev(UPPER_BOUNDS_BODY, upper_bounds_verdict))
    blocked, info = sender_policy.recipient_clause_blocks(
        _clause_for({(ap.BOB, 5): UPPER_BOUNDS_BODY}), ap.BOB, _values(),
        hold=0, context=1, pool="apply",
        facts={ALLOWANCE: 3_000, REFUND: 7_201})
    assert blocked is True
    assert info["reason"] == "recipient_condition_block"
    assert info["allowance_30d"] == 3_000
    assert info["refund_delay"] == 7_201
    assert info["expiry_seconds"] == 0


# --- (v) deploy-side screens --------------------------------------------------

def test_fact_stream_width_screen():
    assert screen_recipient_stream_widths(ALLOWANCE_CAP_BODY) is None
    bad = screen_recipient_stream_widths(
        "(i28[t]:bv[24] > { #x07d0 }:bv[24]) "
        "? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
        ": (o5[t]:bv[24] = { #x000001 }:bv[24])")
    assert bad is not None and "i28" in bad
    untyped = screen_recipient_stream_widths(
        "(i29[t] > { #xe11 }:bv[64]) "
        "? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
        ": (o5[t]:bv[24] = { #x000001 }:bv[24])")
    assert untyped is not None and "i29" in untyped


def test_fact_streams_reserved_exactly_when_active():
    off = tau_defs.reserved_operation_keys(recipient_policy_active=False)
    on = tau_defs.reserved_operation_keys(recipient_policy_active=True)
    for idx in (ALLOWANCE, REFUND, EXPIRY):
        assert idx not in off and idx in on
    # Readable from a registered o5 clause while active; forbidden in
    # ordinary rule text.
    clause_forbidden = tau_defs.rule_text_forbidden_input_streams(
        context=tau_defs.RULE_TEXT_CONTEXT_O5_CLAUSE,
        recipient_policy_active=True)
    assert "i28" not in clause_forbidden
    user_forbidden = tau_defs.rule_text_forbidden_input_streams(
        context=tau_defs.RULE_TEXT_CONTEXT_USER,
        recipient_policy_active=True)
    assert "i28" in user_forbidden and "i29" in user_forbidden
    assert "i32" in user_forbidden
