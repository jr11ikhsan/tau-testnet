"""Syntax allow-list screen for rule fragments (G1).

The numbers pinned here are THIS parser's definition (each AST node = 1,
the ``always`` wrapper = 1). A rival implementation counts differently
(e.g. 14 nodes for the typed effect-1 rule where this parser counts 15 --
the difference is exactly the ``always`` wrapper node); the byte length
(146) agrees. Do not "fix" these numbers to match another implementation.
"""
import pytest

from consensus.rule_fragment import (
    RULE_FRAGMENT_CODE,
    TEMPORAL_REFERENCE_CODE,
    FragmentError,
    is_always_unit,
    parse_bare_body,
    parse_rule_fragment,
    parse_rule_fragment_or_body,
    screen_rule_fragment,
)

# --- Corpus: rule texts the repo itself admits (must parse) -----------------

# The repo's own B02-style rules (shapes from the team's admitted corpus).
RULE_B = "always (o26[t]:bv[24] = { 7 }:bv[24])."
RULE_A = "always ( o5[t]:bv[24] = { #x000001 }:bv[24] )."
RULE_GUARDED = (
    "always ( (i12[t]:bv[384] = { #xaa }:bv[384]) -> "
    "(o26[t]:bv[24] = { #x000001 }:bv[24]) )."
)
RULE_UNROUTABLE = (
    "always (o26[t]:bv[24] = { 7 }:bv[24] && o26[t]:bv[24] = { 8 }:bv[24])."
)
RULE_O5_TERNARY = (
    "always ( (i1[t]:bv[24] > { 0 }:bv[24]) ? "
    "(o5[t]:bv[24] = { #x000001 }:bv[24]) : "
    "(o5[t]:bv[24] = { #x000000 }:bv[24]) )."
)
# Genesis consensus rule (from networks/tau-testnet-v2/genesis.json).
GENESIS_CONSENSUS = (
    "always (\n"
    "    o6[t]:bv[16] = i10[t]:bv[16] &&\n"
    "    o7[t]:bv[16] = { 1 }:bv[16]\n &&\n"
    "    o9[t]:bv[24] = { #x00000a }:bv[24]\n)\n"
)
# Typed effect-1 rule from issue #183 (cross-account fee rule).
# NOTE (2026-11-27): `i1` is annotated bv[24] here -- NOT bv[64] -- because
# the native harness compiles this fragment against an accumulated spec
# whose BASE rule types i1 as bv[24] (`o1[t]:bv[24] = i1[t]:bv[24]`); a
# bv[64] annotation on i1 conflicts with the accumulated spec and the
# pinned engine rejects it (type inference, fail-closed). The screen
# judges shape in isolation and does not re-enforce width policy, so the
# fragment itself must carry the width the harness context assigns to i1.
# The substitution is byte-length preserving (bv[64] -> bv[24]), so the
# pinned byte_len 146 below is unchanged.
EFFECT_1_TYPED = (
    "always ( ((i12[t]:bv[384] = { #xaa }:bv[384] || "
    "i1[t]:bv[24] > { 0 }:bv[24]) "
    "? (o8[t]:bv[64] = { 100 }:bv[64]) : "
    "(o8[t]:bv[64] = { 0 }:bv[64])) )."
)
# FIX 8/9 payout clause body, wrapped as a unit.
PAYOUT_CLAUSE = (
    "always ((o30[t]:bv[64] = { 1 }:bv[64]) && "
    "(o31[t]:bv[64] = { 0 }:bv[64]) && "
    "(o32[t]:bv[64] = { 100 }:bv[64]))"
)


@pytest.mark.parametrize(
    "text,nodes,depth,max_width,reads,writes",
    [
        (RULE_B, 4, 3, 24, (), (26,)),
        (RULE_A, 4, 3, 24, (), (5,)),
        (RULE_GUARDED, 8, 4, 384, (12,), (26,)),
        (RULE_UNROUTABLE, 8, 4, 24, (), (26,)),
        (RULE_O5_TERNARY, 11, 4, 24, (1,), (5,)),
        (GENESIS_CONSENSUS, 12, 5, 24, (10,), (6, 7, 9)),
        (EFFECT_1_TYPED, 15, 5, 384, (1, 12), (8,)),
        (PAYOUT_CLAUSE, 12, 5, 64, (), (30, 31, 32)),
    ],
)
def test_admitted_corpus_parses_with_pinned_shape(
    text, nodes, depth, max_width, reads, writes
):
    info = parse_rule_fragment(text)
    assert info.nodes == nodes
    assert info.depth == depth
    assert info.max_width == max_width
    assert info.streams_read == reads
    assert info.streams_written == writes
    assert screen_rule_fragment(text) is None


def test_effect_1_typed_byte_length_matches_audit():
    # The position check measured 146 bytes for this exact text with an
    # independent implementation; the byte length must agree even though
    # the node count differs by the wrapper node (see module docstring).
    assert parse_rule_fragment(EFFECT_1_TYPED).byte_len == 146


def test_bare_zero_and_one_are_allowed():
    assert screen_rule_fragment("always (o0[t]=1).") is None
    assert screen_rule_fragment("always ( o0[t] = 1 ).") is None
    assert screen_rule_fragment("always (o1[t] = i1[t]).") is None


def test_comments_are_stripped_but_literals_survive():
    text = (
        "# a comment naming o99 must not confuse the screen\n"
        "always ( o5[t]:bv[24] = { #x000001 }:bv[24] ). # trailing"
    )
    info = parse_rule_fragment(text)
    assert info.streams_written == (5,)
    assert info.max_width == 24


def test_trailing_period_is_optional():
    assert screen_rule_fragment("always (o26[t]:bv[24] = { 7 }:bv[24])") is None
    assert screen_rule_fragment("always (o26[t]:bv[24] = { 7 }:bv[24]).") is None


def test_operators_and_grouping():
    # Negation, arithmetic with a constant operand, implication, disjunction.
    assert screen_rule_fragment(
        "always ( !(i1[t]:bv[24] = { 0 }:bv[24]) -> "
        "(o13[t]:bv[24] = i1[t]:bv[24] + { 1 }:bv[24]) )."
    ) is None
    assert screen_rule_fragment(
        "always ( (o13[t]:bv[24] = i1[t]:bv[24] * { 2 }:bv[24]) || "
        "(o13[t]:bv[24] = { 0 }:bv[24]) )."
    ) is None


# --- Rejections ---------------------------------------------------------------

@pytest.mark.parametrize(
    "text,code",
    [
        # Engine-special streams are not user streams.
        ("always u[t] = 0.", RULE_FRAGMENT_CODE),
        ("always ( o13[t]:bv[24] = this[t] ).", RULE_FRAGMENT_CODE),
        ("always ( foo[t] = 0 ).", RULE_FRAGMENT_CODE),
        # Steps other than [t] carry the temporal code.
        ("always ( o13[t]:bv[24] = i1[t-1]:bv[24] ).", TEMPORAL_REFERENCE_CODE),
        ("always ( o13[t]:bv[24] = i1[t+1]:bv[24] ).", TEMPORAL_REFERENCE_CODE),
        ("always ( o8[t]:bv[24] = i1[t-3]:bv[24] ).", TEMPORAL_REFERENCE_CODE),
        # Braced literals must be typed.
        ("always ( o8[t]:bv[24] = { 100 } ).", RULE_FRAGMENT_CODE),
        ("always ( o8[t] = { #x64 } ).", RULE_FRAGMENT_CODE),
        # Bare integers other than 0/1 must be typed.
        ("always ( o13[t]:bv[24] = 7 ).", RULE_FRAGMENT_CODE),
        ("always ( o13[t]:bv[24] = i1[t]:bv[24] * 2 ).", RULE_FRAGMENT_CODE),
        # Width over the cap.
        ("always ( o13[t]:bv[385] = { 1 }:bv[385] ).", RULE_FRAGMENT_CODE),
        # A product/quotient of two streams is not allowed.
        (
            "always ( o13[t]:bv[24] = i1[t]:bv[24] * i2[t]:bv[24] ).",
            RULE_FRAGMENT_CODE,
        ),
        (
            "always ( o13[t]:bv[24] = i1[t]:bv[24] / i2[t]:bv[24] ).",
            RULE_FRAGMENT_CODE,
        ),
        # Not exactly one always-unit.
        ("o26[t]:bv[24] = { 7 }:bv[24].", RULE_FRAGMENT_CODE),
        (
            "always ( o5[t] = 1 ). always ( o5[t] = 0 ).",
            RULE_FRAGMENT_CODE,
        ),
        ("always ( o5[t]:bv[24] = { #x000001 }:bv[24] ). garbage",
            RULE_FRAGMENT_CODE),
        ("always ( o5[t]:bv[24] = { #x000001 }:bv[24] .", RULE_FRAGMENT_CODE),
        ("always ( o5[t]:bv[24] = { #x000001 }:bv[24] ).).", RULE_FRAGMENT_CODE),
        ("", RULE_FRAGMENT_CODE),
        ("   ", RULE_FRAGMENT_CODE),
        # Quantifiers are engine-spec syntax, not user-rule syntax.
        (
            "always ( all b1 b1 != i10[t]:bv[16] ).",
            RULE_FRAGMENT_CODE,
        ),
        # Unknown token.
        ("always ( o5[t]:bv[24] = { #x000001 }:bv[24] ; ).", RULE_FRAGMENT_CODE),
        # Literal that does not fit its width.
        ("always ( o5[t]:bv[8] = { 256 }:bv[8] ).", RULE_FRAGMENT_CODE),
    ],
)
def test_rejected_fragments_carry_the_right_code(text, code):
    with pytest.raises(FragmentError) as excinfo:
        parse_rule_fragment(text)
    assert excinfo.value.code == code
    assert screen_rule_fragment(text) is not None


def test_screen_returns_text_not_exception():
    err = screen_rule_fragment("always ( foo[t] = 0 ).")
    assert isinstance(err, str) and "unknown stream" in err


# --- Screen scope (regression, 2026-11-27) ----------------------------------
# The admission screen judges ONLY the canonical `always ( ... )` form.
# Op-0 is not always an always-unit: bare bodies, opaque data,
# placeholders and garbage must pass the screen untouched so the compile
# gate -- the final judge -- answers them with its pinned codes
# (TX_REJECTED, ADMISSION_TIMEOUT, ...). Screening them relabelled all
# of those as RULE_FRAGMENT and rejected live bare-body rules at apply
# (17 failures in the 2026-11-27 full mock run).


def test_is_always_unit_shapes():
    assert is_always_unit("always (o26[t]:bv[24] = { 7 }:bv[24]).")
    assert is_always_unit("always(o26[t]:bv[24] = { 7 }:bv[24]).")
    assert is_always_unit("  always ( o5[t] = 1 ).")
    assert is_always_unit("# note\nalways (o5[t] = 1).")
    assert not is_always_unit("o12[t]:bv[24] = i1[t]:bv[24].")
    assert not is_always_unit("invalid rule here")
    assert not is_always_unit("some_other_op_data")
    assert not is_always_unit("rule X")
    assert not is_always_unit("alwaysx (o5[t] = 1).")
    assert not is_always_unit("always o12[t] := i9[t].")  # no parens: not a unit
    assert not is_always_unit("")


def test_bare_body_parses_for_measurement_only():
    info = parse_bare_body("o12[t]:bv[24] = i1[t]:bv[24].")
    assert (info.nodes, info.depth, info.max_width) == (3, 2, 24)
    assert info.streams_written == (12,)
    assert info.streams_read == (1,)
    with pytest.raises(FragmentError):
        parse_bare_body("invalid rule here")
    with pytest.raises(FragmentError):
        parse_bare_body("o12[t]:bv[24] = i1[t]:bv[24]. extra")


def test_parse_or_body_accepts_both_forms():
    assert parse_rule_fragment_or_body(RULE_B).nodes == 4  # + wrapper
    assert parse_rule_fragment_or_body(
        "o12[t]:bv[24] = i1[t]:bv[24]."
    ).nodes == 3  # no wrapper
    with pytest.raises(FragmentError):
        parse_rule_fragment_or_body("invalid rule here")


def test_screen_passes_non_always_texts_to_the_compile_gate():
    """The admission screen must not pre-empt the compile gate."""
    from consensus.admission import screen_user_rule_text

    for text in (
        "invalid rule here",  # -> compile gate -> TX_REJECTED
        "expensive_rule.",  # -> compile gate (may time out)
        "some_other_op_data",  # opaque op-0 data, queues fine
        "rule X",  # placeholder under mocks
        "o12[t]:bv[24] = i1[t]:bv[24].",  # bare body the engine accepts
    ):
        assert screen_user_rule_text(text, "", False) is None, text
    # ...while a malformed ALWAYS-unit is still refused here. (Note:
    # "always ( foo[t] = 0 )." is refused EARLIER by the legacy
    # special-stream screen with TX_REJECTED -- the fragment screen only
    # sees texts the legacy screens pass, e.g. a non-constant product.)
    rejection = screen_user_rule_text(
        "always ( o13[t]:bv[24] = i1[t]:bv[24] * i2[t]:bv[24] ).", "", False
    )
    assert rejection is not None
    assert rejection.code == RULE_FRAGMENT_CODE
    assert screen_user_rule_text(RULE_B, "", False) is None
