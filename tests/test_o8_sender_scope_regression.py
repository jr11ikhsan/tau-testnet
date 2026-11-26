"""Regression tests for the structural o8 sender-scope screen (G2, B01).

The screen proves, over the rule's AST, that every CHARGED write to the shared
fee stream o8 is conjoined with a literal identity guard (``i12``/``i3`` =
literal) on the same path. A textual mention of ``i12`` is not a guard.

Design (clean-room, from the repo's own semantics — see
``JUARA-L2-G2-O8SCREEN-LOG.md`` §3):
- a write of a literal ZERO to o8 charges nobody, so it needs no guard
  (this is what lets the honest ternary ``G ? (o8 = i1) : (o8 = 0)`` pass);
- a guard only covers the branch it actually gates: the else-branch of a
  ternary holds exactly when the guard is FALSE, so a charged write there is
  unguarded even when the then-branch is guarded;
- anything the parser cannot account for fails closed (screen returns False).
"""
import pytest

from consensus.admission import (
    screen_o8_sender_scope,
    validate_user_tx_reserved_domains,
)
from consensus.facade import TipAdmissionView

PUBKEY = "{ #x" + "ab" * 48 + " }:bv[384]"
ZERO24 = "{ #x000000 }:bv[24]"
SCOPE = f"i12[t]:bv[384] = {PUBKEY}"


def _admit(rule):
    return validate_user_tx_reserved_domains(
        {"sender_pubkey": "ab" * 48, "operations": {"0": rule}},
        TipAdmissionView(),
    )


def test_positive_control_real_i12_guard_is_admitted():
    """A real literal-identity guard on the same path admits the rule."""
    guarded = (
        f"always (({SCOPE}) -> o8[t]:bv[24] = {{ #x000003 }}:bv[24])."
    )
    assert screen_o8_sender_scope(guarded) is True
    assert _admit(guarded).is_valid

    # i3 (from address) is the documented alternative to i12.
    guarded_i3 = (
        "always ((i3[t]:bv[384] = " + PUBKEY + ") -> "
        "o8[t]:bv[24] = { #x000003 }:bv[24])."
    )
    assert screen_o8_sender_scope(guarded_i3) is True
    assert _admit(guarded_i3).is_valid

    # Guard as a conjunction, not only as an implication antecedent.
    conj = (
        f"always (({SCOPE}) && (o8[t]:bv[24] = {{ #x000003 }}:bv[24]))."
    )
    assert screen_o8_sender_scope(conj) is True
    assert _admit(conj).is_valid

    # Tiered (ladder) fee under one guard: both branches inherit the guard.
    ladder = (
        f"always (({SCOPE}) -> "
        "(i1[t]:bv[24] > { #x0003e8 }:bv[24] && o8[t]:bv[24] = { #x000005 }:bv[24]) "
        "|| (i1[t]:bv[24] <= { #x0003e8 }:bv[24] && o8[t]:bv[24] = { #x000001 }:bv[24]))."
    )
    assert screen_o8_sender_scope(ladder) is True
    assert _admit(ladder).is_valid

    # Honest ternary: the charged side is guarded, the free side writes zero.
    ternary = (
        f"always (({SCOPE}) ? (o8[t]:bv[24] = i1[t]:bv[24]) : "
        f"(o8[t]:bv[24] = {ZERO24}))."
    )
    assert screen_o8_sender_scope(ternary) is True
    assert _admit(ternary).is_valid

    # The screen is a SCOPE screen, not a cap: a scoped rule charging a huge
    # fee still passes it. Bounding the amount is FIX 8's job, not this one's.
    huge = (
        f"always (({SCOPE}) -> o8[t]:bv[24] = {{ #xffffff }}:bv[24])."
    )
    assert screen_o8_sender_scope(huge) is True
    assert _admit(huge).is_valid

    # A flat write of literal zero charges nobody, so it needs no guard.
    free = f"always (o8[t]:bv[24] = {ZERO24})."
    assert screen_o8_sender_scope(free) is True
    assert _admit(free).is_valid


def test_positive_control_fixed_native_helper_rules_are_admitted():
    """The native-test helpers, with their else-branch fixed to zero.

    ``_history_policy`` (test_admission_isolation_native) and ``_scoped_rule``
    (test_authority_cutover_native) used to write ``o8 = 1`` in the else branch
    — a 1-unit fee on every sender except the author. With the else branch at
    literal zero they are genuinely scoped. These strings are asserted here so
    the helper fix is pinned by a mock test (native tests cannot run locally).
    """
    history_policy = (
        "always ( (i12[t]:bv[384] = { #x" + "ab" * 48 + " }:bv[384]) ? "
        "((i1[t-1]:bv[24] = { #x000007 }:bv[24]) ? (o8[t]:bv[24] = { #x001388 }:bv[24]) "
        ": (o8[t]:bv[24] = { #x000000 }:bv[24])) "
        ": (o8[t]:bv[24] = { #x000000 }:bv[24]) )."
    )
    # Scope-only: the temporal screen (not this screen) owns the i1[t-1] read.
    assert screen_o8_sender_scope(history_policy) is True

    scoped_rule = (
        "always ( (i12[t]:bv[384] = { #x" + "ab" * 48 + " }:bv[384]) ? "
        "(o8[t]:bv[24] = { #x000001 }:bv[24]) : "
        "(o8[t]:bv[24] = { #x000000 }:bv[24]) )."
    )
    assert screen_o8_sender_scope(scoped_rule) is True
    assert _admit(scoped_rule).is_valid


def test_tautology_guard_that_mentions_i12_is_rejected():
    """Mentioning i12 in a tautology/contradiction gates nothing."""
    # The known-gap shape: the write is unconditional; i12 only appears in a
    # branch that is always false.
    tautology = (
        "always (o8[t]:bv[24] = { #x000003 }:bv[24] || "
        "i12[t]:bv[384] != i12[t]:bv[384])."
    )
    assert screen_o8_sender_scope(tautology) is False
    result = _admit(tautology)
    assert not result.is_valid
    assert result.code == "UNSCOPED_USER_RULE"

    # i12 = i12 is always true, so it guards nothing either.
    self_equal = (
        "always ((i12[t]:bv[384] = i12[t]:bv[384]) -> "
        "o8[t]:bv[24] = { #x000003 }:bv[24])."
    )
    assert screen_o8_sender_scope(self_equal) is False

    # i12 = i3 pins no literal identity: it holds for every sender whose
    # from-address equals their pubkey.
    no_literal = (
        "always ((i12[t]:bv[384] = i3[t]:bv[384]) -> "
        "o8[t]:bv[24] = { #x000003 }:bv[24])."
    )
    assert screen_o8_sender_scope(no_literal) is False


def test_i12_in_a_dead_branch_that_gates_only_the_free_side_is_rejected():
    """A guard that only gates the zero-fee side leaves the charged side open.

    In ``G ? A : B`` the else branch B holds exactly when G is FALSE, so a
    charged o8 write in B is unguarded even though the then branch A is
    guarded. The old textual screen passed this shape because i12 appears.
    """
    free_side_only = (
        f"always ((({SCOPE}) ? (o8[t]:bv[24] = {ZERO24}) : "
        "(o8[t]:bv[24] = { #x000003 }:bv[24]))."
    )
    assert screen_o8_sender_scope(free_side_only) is False
    result = _admit(free_side_only)
    assert not result.is_valid
    assert result.code == "UNSCOPED_USER_RULE"

    # Same shape with a charged then-branch: the else write is still unguarded.
    charged_both = (
        f"always ((({SCOPE}) ? (o8[t]:bv[24] = i1[t]:bv[24]) : "
        "(o8[t]:bv[24] = { #x000003 }:bv[24]))."
    )
    assert screen_o8_sender_scope(charged_both) is False


def test_unscoped_flat_fee_is_rejected_positive_control():
    """The accidental global rule: an unconditional fee on every sender."""
    flat = "always (o8[t]:bv[24] = { #x000003 }:bv[24])."
    assert screen_o8_sender_scope(flat) is False
    result = _admit(flat)
    assert not result.is_valid
    assert result.code == "UNSCOPED_USER_RULE"
    assert result.details["stream"] == "o8"

    # Unparsable / out-of-fragment text fails closed, never defaults to admit.
    assert screen_o8_sender_scope("always (o8[t]:bv[24] = foo[t]:bv[24]).") is False
    assert screen_o8_sender_scope("") is False
    assert screen_o8_sender_scope("always (o8[t]:bv[24] = { #x000003 }:bv[24]).") is False
