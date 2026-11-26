"""Cumulative shared-rule budget (G1).

Covers, per sub-part: limits validation, charge/would_exceed, what counts,
recount-from-text (incl. dedup + grandfathering), governance patching,
state-hash binding, db persistence, admission integration, and the block
header check (same harness shape as tests/test_block_rule_budget.py).
"""
import json

import pytest
from unittest.mock import MagicMock, patch

from consensus.rule_fragment import parse_rule_fragment
from consensus.shared_rule_budget import (
    PROPOSED_SHARED_RULE_LIMITS,
    SharedRuleBudget,
    SharedRuleLimits,
    check_shared_rule_budget,
    counts_toward_shared_budget,
    normalize_shared_rule_limits,
    recount_shared_budget,
    split_accumulated_units,
    validate_shared_rule_limits,
)
from consensus.governance import (
    ConsensusLifecycleManager,
    build_mechanism_metadata,
)
from consensus.admission import (
    TipAdmissionView,
    validate_user_tx_reserved_domains,
)

RULE_4 = "always (o26[t]:bv[24] = { 7 }:bv[24])."  # 4 nodes, depth 3
RULE_O5 = "always ( o5[t]:bv[24] = { #x000001 }:bv[24] )."
RULE_O8 = "always (o8[t]:bv[64] = { 100 }:bv[64])."
SEED = "((!(i0[t] = 0)) ? ( u[t] = i0[t] && o0[t] = 0 ) : o0[t] = 1)"
A = "aa" * 48


def _info(text):
    return parse_rule_fragment(text)


# --- limits validation -------------------------------------------------------

def test_proposed_defaults_are_the_documented_proposal():
    assert PROPOSED_SHARED_RULE_LIMITS == {
        "occurrences": 10,
        "total_nodes": 80,
        "rule_nodes": 32,
        "rule_depth": 8,
        "rule_bytes": 1024,
        "width": 384,
    }
    assert SharedRuleLimits().is_proposed_default() is True
    assert SharedRuleLimits(occurrences=11).is_proposed_default() is False


@pytest.mark.parametrize(
    "value",
    [
        PROPOSED_SHARED_RULE_LIMITS,
        {"occurrences": 1, "total_nodes": 1, "rule_nodes": 1,
         "rule_depth": 1, "rule_bytes": 1, "width": 1},
        {"occurrences": 10000, "total_nodes": 1000000, "rule_nodes": 10000,
         "rule_depth": 256, "rule_bytes": 1048576, "width": 384},
    ],
)
def test_valid_limits_pass(value):
    assert validate_shared_rule_limits(value) is None
    assert normalize_shared_rule_limits(value).as_dict() == value


@pytest.mark.parametrize(
    "value",
    [
        {"occurrences": 10},  # partial object: ambiguous across nodes
        {**PROPOSED_SHARED_RULE_LIMITS, "extra": 1},
        {**PROPOSED_SHARED_RULE_LIMITS, "occurrences": 0},
        {**PROPOSED_SHARED_RULE_LIMITS, "occurrences": -1},
        {**PROPOSED_SHARED_RULE_LIMITS, "occurrences": 10001},
        {**PROPOSED_SHARED_RULE_LIMITS, "width": 385},
        {**PROPOSED_SHARED_RULE_LIMITS, "rule_depth": 257},
        {**PROPOSED_SHARED_RULE_LIMITS, "occurrences": "10"},
        {**PROPOSED_SHARED_RULE_LIMITS, "occurrences": True},
        {**PROPOSED_SHARED_RULE_LIMITS, "occurrences": 10.0},
        "10 rules",
        None,
        True,
    ],
)
def test_invalid_limits_fail(value):
    assert validate_shared_rule_limits(value) is not None


# --- charge / would_exceed ---------------------------------------------------

def test_charge_counts_one_rule_and_its_nodes():
    budget = SharedRuleBudget()
    assert budget.would_exceed(_info(RULE_4)) is None
    budget.charge(_info(RULE_4))
    assert (budget.count, budget.nodes) == (1, 4)


def test_per_rule_limits():
    budget = SharedRuleBudget()
    big = "always (" + " && ".join(
        f"(o26[t]:bv[24] = {{ {i} }}:bv[24])" for i in range(12)
    ) + ")."
    info = _info(big)
    assert info.nodes > 32
    assert "32" in (budget.would_exceed(info) or "")
    with pytest.raises(ValueError, match="overrun"):
        budget.charge(info)
    deep = "always (" + "!" * 9 + "(o26[t]:bv[24] = { 1 }:bv[24])" + ")."
    assert _info(deep).depth == 12  # always + 9x! + = + leaf
    assert "depth" in (budget.would_exceed(_info(deep)) or "")
    wide = "always ( o13[t]:bv[384] = { 1 }:bv[384] )."
    assert budget.would_exceed(_info(wide)) is None  # exactly at the cap


def test_occurrences_cap_binds_before_total_nodes():
    budget = SharedRuleBudget(limits=SharedRuleLimits(occurrences=2))
    budget.charge(_info(RULE_4))
    budget.charge(_info(RULE_O8))
    assert "exhausted" in (budget.would_exceed(_info(RULE_4)) or "")
    assert "2 rules" in (budget.would_exceed(_info(RULE_4)) or "")


def test_total_nodes_cap():
    budget = SharedRuleBudget(limits=SharedRuleLimits(total_nodes=8))
    budget.charge(_info(RULE_4))
    assert budget.would_exceed(_info(RULE_4)) is None  # 4 + 4 = 8, exactly at cap
    budget.charge(_info(RULE_4))
    assert "total limit of 8" in (budget.would_exceed(_info(RULE_O8)) or "")


# --- what counts ---------------------------------------------------------------

def test_o5_does_not_count_o8_does():
    assert counts_toward_shared_budget(RULE_O5) is False
    assert counts_toward_shared_budget(RULE_O8) is True
    assert counts_toward_shared_budget(RULE_4) is True
    assert counts_toward_shared_budget("") is False
    assert counts_toward_shared_budget("   ") is False


def test_recount_sums_distinct_parseable_units():
    text = "\n".join([RULE_4, RULE_O8])
    assert recount_shared_budget(text) == (2, 4 + 4)


def test_recount_dedups_repeated_text():
    # The accumulation itself dedups exact units, so a repeated text costs
    # once -- deliberately NOT "same text 3x = 3x".
    text = "\n".join([RULE_4, RULE_4, RULE_4])
    assert recount_shared_budget(text) == (1, 4)
    assert split_accumulated_units(text) == [RULE_4.strip()]


def test_recount_skips_genesis_seed_and_unparseable_units():
    assert recount_shared_budget(SEED) == (0, 0)
    assert recount_shared_budget(SEED + "\n" + RULE_4) == (1, 4)
    assert recount_shared_budget("always u[t] = 0.\n" + RULE_4) == (1, 4)
    assert recount_shared_budget("") == (0, 0)


def test_recount_skips_o5_units():
    assert recount_shared_budget(RULE_O5 + "\n" + RULE_4) == (1, 4)


def test_check_shared_rule_budget():
    budget = SharedRuleBudget(limits=SharedRuleLimits(occurrences=1))
    assert check_shared_rule_budget(RULE_4, budget) is None
    assert check_shared_rule_budget(RULE_O5, budget) is None  # never counts
    budget.charge(_info(RULE_4))
    assert "exhausted" in (check_shared_rule_budget(RULE_O8, budget) or "")
    # A fragment-invalid text is a fragment matter, reported as such.
    assert "unknown stream" in (
        check_shared_rule_budget("always ( foo[t] = 0 ).", budget) or ""
    )


# --- governance ---------------------------------------------------------------

def test_governance_patch_changes_limits_not_counters():
    lm = ConsensusLifecycleManager(active_validators=[A])
    lm.shared_rule_budget.charge(_info(RULE_4))
    assert (lm.shared_rule_budget.count, lm.shared_rule_budget.nodes) == (1, 4)
    lm.apply_host_contract_patch({
        "shared_rule_limits": {**PROPOSED_SHARED_RULE_LIMITS, "occurrences": 3}
    })
    assert lm.shared_rule_budget.limits.occurrences == 3
    assert (lm.shared_rule_budget.count, lm.shared_rule_budget.nodes) == (1, 4)


def test_governance_patch_rejects_bad_limits():
    lm = ConsensusLifecycleManager(active_validators=[A])
    for bad in (
        {"occurrences": 10},  # partial
        {**PROPOSED_SHARED_RULE_LIMITS, "occurrences": 0},
        {**PROPOSED_SHARED_RULE_LIMITS, "width": 385},
        "ten",
    ):
        with pytest.raises(ValueError, match="shared_rule_limits"):
            lm.apply_host_contract_patch({"shared_rule_limits": bad})
    assert lm.shared_rule_budget.limits.is_proposed_default()


def test_lowering_limits_below_usage_only_blocks_future_rules():
    lm = ConsensusLifecycleManager(active_validators=[A])
    lm.shared_rule_budget.charge(_info(RULE_4))
    lm.shared_rule_budget.charge(_info(RULE_O8))
    # Lower occurrences to 1 while 2 rules are already accumulated: nothing
    # is evicted; only the NEXT rule is refused.
    lm.apply_host_contract_patch({
        "shared_rule_limits": {**PROPOSED_SHARED_RULE_LIMITS, "occurrences": 1}
    })
    assert lm.shared_rule_budget.count == 2
    assert lm.shared_rule_budget.would_exceed(_info(RULE_4)) is not None


def test_fork_adopt_carries_the_budget():
    lm = ConsensusLifecycleManager(active_validators=[A])
    fork = lm.fork()
    fork.shared_rule_budget.charge(_info(RULE_4))
    assert lm.shared_rule_budget.count == 0  # fork is private until adopted
    lm.adopt(fork)
    assert (lm.shared_rule_budget.count, lm.shared_rule_budget.nodes) == (1, 4)


# --- state-hash binding ---------------------------------------------------------

def test_genesis_defaults_emit_nothing_into_mechanism_metadata():
    # Hash-compat: a genesis (0 rules, proposed-default limits) must hash
    # exactly as before this package -- this is the no-regenesis property.
    mech = build_mechanism_metadata("supermajority")
    assert "shared_rule_limits" not in mech
    assert "shared_rule_count" not in mech
    assert "shared_rule_nodes" not in mech


def test_meta_hash_unchanged_at_genesis_changed_once_a_rule_lands():
    lm = ConsensusLifecycleManager(active_validators=[A])
    baseline = lm.consensus_meta_hash()
    # Default limits + zero counters: nothing emitted, hash unchanged.
    assert lm.consensus_meta_hash() == baseline
    lm.shared_rule_budget.charge(_info(RULE_4))
    assert lm.consensus_meta_hash() != baseline
    # Non-default limits are also bound.
    lm2 = ConsensusLifecycleManager(active_validators=[A])
    lm2.apply_host_contract_patch({
        "shared_rule_limits": {**PROPOSED_SHARED_RULE_LIMITS, "occurrences": 20}
    })
    assert lm2.consensus_meta_hash() != baseline


def test_mechanism_metadata_emission_rules():
    mech = build_mechanism_metadata(
        "supermajority",
        shared_rule_limits={**PROPOSED_SHARED_RULE_LIMITS, "occurrences": 20},
        shared_rule_count=0,
        shared_rule_nodes=0,
    )
    # Limits travel as a canonical JSON string (the meta-hash encoder
    # accepts no dict values); parse it back to compare.
    assert json.loads(mech["shared_rule_limits"])["occurrences"] == 20
    assert "shared_rule_count" not in mech
    mech = build_mechanism_metadata(
        "supermajority",
        shared_rule_limits=dict(PROPOSED_SHARED_RULE_LIMITS),
        shared_rule_count=2,
        shared_rule_nodes=8,
    )
    assert "shared_rule_limits" not in mech  # default limits are not emitted
    assert mech["shared_rule_count"] == 2
    assert mech["shared_rule_nodes"] == 8


# --- db persistence -------------------------------------------------------------

def test_canonical_rows_persist_budget_and_reload_recovers_it(temp_database):
    import db
    import chain_state

    prev_globals = (
        chain_state._balances,
        chain_state._sequence_numbers,
        chain_state._application_rules_state,
        chain_state._lifecycle_manager,
    )
    try:
        db.save_canonical_state_atomically(
            "ab" * 32, 1, {}, {}, RULE_4, "", "", [], [], [], [],
            shared_rule_limits=dict(PROPOSED_SHARED_RULE_LIMITS),
            shared_rule_count=1,
            shared_rule_nodes=4,
        )
        assert db.get_chain_state_value("shared_rule_count") == "1"
        assert db.get_chain_state_value("shared_rule_nodes") == "4"
        assert json.loads(db.get_chain_state_value("shared_rule_limits")) == (
            PROPOSED_SHARED_RULE_LIMITS
        )
        # Reload re-derives the counters from the stored application-rules
        # text (and restores the limits from the durable row).
        assert chain_state.load_state_from_db() is True
        budget = chain_state._lifecycle_manager.shared_rule_budget
        assert (budget.count, budget.nodes) == (1, 4)
        assert budget.limits.is_proposed_default()
    finally:
        (
            chain_state._balances,
            chain_state._sequence_numbers,
            chain_state._application_rules_state,
            chain_state._lifecycle_manager,
        ) = prev_globals


# --- admission integration ------------------------------------------------------

def _tip_view_with_budget(budget):
    view = MagicMock(spec=TipAdmissionView)
    view.active_validators = {A}
    view.next_block_height = 50
    view.eligibility_mode = ""
    view.approval_slots_active = False
    view.shared_rule_budget = budget
    return view


def _user_tx(rule):
    return {
        "tx_type": "user_tx",
        "sender_pubkey": A,
        "operations": {"0": rule},
    }


def test_admission_refuses_over_budget_rule_with_rule_budget_code():
    budget = SharedRuleBudget(limits=SharedRuleLimits(occurrences=1))
    budget.charge(_info(RULE_4))
    view = _tip_view_with_budget(budget)
    # A second, distinct, in-scope rule (o27, not o8 -- an unscoped o8 rule
    # is refused earlier by the sender-scope screen, not by the budget).
    second = "always (o27[t]:bv[24] = { 8 }:bv[24])."
    result = validate_user_tx_reserved_domains(_user_tx(second), view)
    assert result.is_valid is False
    assert result.code == "RULE_BUDGET"
    assert result.details["shared_rule_count"] == 1
    assert result.details["shared_rule_limit_occurrences"] == 1


def test_admission_accepts_within_budget_rule():
    budget = SharedRuleBudget()
    view = _tip_view_with_budget(budget)
    assert validate_user_tx_reserved_domains(_user_tx(RULE_4), view).is_valid is True


def test_admission_skips_budget_check_without_chain_state():
    # A tip view with no budget (unit tests, no chain) does not fail closed.
    view = MagicMock(spec=TipAdmissionView)
    view.active_validators = {A}
    view.next_block_height = 50
    view.eligibility_mode = ""
    view.approval_slots_active = False
    view.shared_rule_budget = None
    assert validate_user_tx_reserved_domains(_user_tx(RULE_4), view).is_valid is True


def test_admission_fragment_rejection_keeps_old_codes_first():
    # A text the old screens already refuse keeps its OLD code: the
    # fragment screen is additive and runs after them.
    view = _tip_view_with_budget(SharedRuleBudget())
    temporal = validate_user_tx_reserved_domains(
        _user_tx("always ( o13[t]:bv[24] = i1[t-1]:bv[24] )."), view
    )
    assert temporal.code == "TEMPORAL_REFERENCE"
    special = validate_user_tx_reserved_domains(
        _user_tx("always u[t] = 0."), view
    )
    assert special.code == "TX_REJECTED"
    # A text that PASSES the old screens but violates the allow-list gets
    # RULE_FRAGMENT.
    fragment = validate_user_tx_reserved_domains(
        _user_tx("always ( o13[t]:bv[24] = i1[t]:bv[24] * i2[t]:bv[24] )."),
        view,
    )
    assert fragment.is_valid is False
    assert fragment.code == "RULE_FRAGMENT"


# --- block header check (harness shape: tests/test_block_rule_budget.py) ------

def _header_view(count=0, nodes=0, limits=None, omit=False):
    from consensus.engine import ActiveConsensusView

    meta = {"poa": True, "eligibility_mode": "validator_set"}
    if not omit:
        meta["shared_rule_count"] = count
        meta["shared_rule_nodes"] = nodes
        meta["shared_rule_limits"] = (
            dict(PROPOSED_SHARED_RULE_LIMITS)
            if limits is None else dict(limits)
        )
    return ActiveConsensusView(
        target_height=10,
        consensus_rules="always ( o6[t]:bv[16] = i10[t]:bv[16] ).",
        active_validators=[bytes.fromhex(A)],
        mechanism_specific_metadata=meta,
    )


def _block(txs):
    from block import Block

    blk = Block.create(
        block_number=10,
        previous_hash="00" * 32,
        transactions=txs,
        proposer_pubkey=A,
        timestamp=1234567890,
    )
    blk.consensus_proof = {"scheme": "bls_header_sig", "signature": "ab" * 48}
    return blk


def _rule_tx(i, rule):
    return {
        "tx_id": f"rule-{i}",
        "tx_type": "user_tx",
        "sender_pubkey": A,
        "operations": {"0": rule},
    }


def _verify_header(block, view):
    from consensus.engine import TauConsensusEngine

    engine = TauConsensusEngine()
    with patch("tau_manager.tau_ready") as ready, \
         patch("tau_manager.communicate_with_tau_multi", return_value={6: "1", 7: "1"}), \
         patch("tau_manager.communicate_with_tau", return_value="1"), \
         patch.object(TauConsensusEngine, "_view_eligibility_mode", staticmethod(lambda v: "validator_set")), \
         patch("consensus.engine.normalize_validator_set", return_value={A}):
        ready.is_set.return_value = True
        return engine.verify_block_header(view, block, {"proof_ok": True})


def test_header_within_cumulative_budget_verifies():
    txs = [_rule_tx(0, RULE_4)]
    assert _verify_header(_block(txs), _header_view(count=9, nodes=76)) is True


def test_header_over_cumulative_budget_is_invalid():
    txs = [_rule_tx(0, RULE_4)]
    assert _verify_header(_block(txs), _header_view(count=10, nodes=76)) is False
    assert _verify_header(_block(txs), _header_view(count=9, nodes=77)) is False


def test_header_dedups_identical_texts_in_one_block():
    txs = [_rule_tx(0, RULE_4), _rule_tx(1, RULE_4), _rule_tx(2, RULE_4)]
    assert _verify_header(_block(txs), _header_view(count=9, nodes=76)) is True
    assert _verify_header(_block(txs), _header_view(count=10, nodes=76)) is False


def test_header_ignores_o5_and_fragment_invalid_txs():
    txs = [
        _rule_tx(0, RULE_O5),  # registers a clause; never accumulates
        _rule_tx(1, "always u[t] = 0."),  # refused by the screen; never lands
    ]
    assert _verify_header(_block(txs), _header_view(count=10, nodes=80)) is True


def test_header_skips_check_when_the_view_predates_the_budget():
    txs = [_rule_tx(i, RULE_4) for i in range(50)]
    assert _verify_header(_block(txs), _header_view(omit=True)) is True


def test_header_counts_governance_voted_limits():
    limits = {**PROPOSED_SHARED_RULE_LIMITS, "occurrences": 1}
    txs = [_rule_tx(0, RULE_4)]
    assert _verify_header(_block(txs), _header_view(count=1, nodes=4, limits=limits)) is False
    assert _verify_header(_block(txs), _header_view(count=0, nodes=0, limits=limits)) is True


def test_budget_travels_on_the_derived_view():
    from consensus.engine import TauConsensusEngine
    from consensus.state import TauStateSnapshot

    lm = ConsensusLifecycleManager(active_validators=[A])
    lm.shared_rule_budget.charge(_info(RULE_4))
    parent = TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=RULE_4.encode(),
        metadata={
            "balances": {}, "sequence_numbers": {}, "lifecycle_manager": lm,
            "consensus_rules_state": "always ( o6[t]:bv[16] = i10[t]:bv[16] ).",
            "active_consensus_id": "",
        },
    )
    view = TauConsensusEngine().derive_active_consensus(parent, 11)
    meta = view.mechanism_specific_metadata
    assert meta["shared_rule_count"] == 1
    assert meta["shared_rule_nodes"] == 4
    assert meta["shared_rule_limits"] == PROPOSED_SHARED_RULE_LIMITS
