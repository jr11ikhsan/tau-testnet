"""Cumulative shared-rule budget across reorg (G1).

The counters are a DERIVATION of the canonical application-rules text, so
a reorg must restore them exactly: abandoning the branch that carried a
rule un-counts it, and the surviving branch keeps its own count. These
tests drive that property at the level where it is decided -- the
lifecycle-manager snapshot + the canonical-text recount -- without
needing a live engine: the engine adopts the forked manager only for an
accepted transaction and the swap re-derives the counters from the
adopted text, so a manager-level test plus a recount test covers the
mechanism. A full two-node reorg run is a native-suite matter.
"""
import pytest

from consensus.governance import ConsensusLifecycleManager
from consensus.rule_fragment import parse_rule_fragment
from consensus.shared_rule_budget import (
    SharedRuleBudget,
    recount_shared_budget,
)

A = "aa" * 48
RULE_1 = "always (o26[t]:bv[24] = { 7 }:bv[24])."   # 4 nodes
RULE_2 = "always (o27[t]:bv[24] = { 8 }:bv[24])."   # 4 nodes
RULE_3 = "always (o28[t]:bv[24] = { 9 }:bv[24])."   # 4 nodes


def _info(text):
    return parse_rule_fragment(text)


def _manager_with_rules(*rules):
    lm = ConsensusLifecycleManager(active_validators=[A])
    for rule in rules:
        lm.shared_rule_budget.charge(_info(rule))
    return lm


def test_branch_fork_does_not_move_parent_counters_until_adopt():
    parent = _manager_with_rules(RULE_1)
    branch = parent.fork()
    branch.shared_rule_budget.charge(_info(RULE_2))
    assert (parent.shared_rule_budget.count, parent.shared_rule_budget.nodes) == (1, 4)
    assert (branch.shared_rule_budget.count, branch.shared_rule_budget.nodes) == (2, 8)
    # Abandoning the branch (no adopt) leaves the parent untouched.
    assert (parent.shared_rule_budget.count, parent.shared_rule_budget.nodes) == (1, 4)


def test_adopting_a_branch_moves_its_counters():
    parent = _manager_with_rules(RULE_1)
    branch = parent.fork()
    branch.shared_rule_budget.charge(_info(RULE_2))
    parent.adopt(branch)
    assert (parent.shared_rule_budget.count, parent.shared_rule_budget.nodes) == (2, 8)


def test_reorg_to_the_other_branch_restores_that_branch_count():
    # Two competing branches from the same parent text: branch X carries
    # RULE_2, branch Y carries RULE_3. Whichever head wins, the counters
    # must equal the recount of the WINNING text -- never the loser's.
    parent_text = RULE_1
    text_x = parent_text + "\n" + RULE_2
    text_y = parent_text + "\n" + RULE_3
    assert recount_shared_budget(text_x) == (2, 8)
    assert recount_shared_budget(text_y) == (2, 8)

    # The manager of each branch, built by charging its own rules...
    lm_x = _manager_with_rules(RULE_1, RULE_2)
    lm_y = _manager_with_rules(RULE_1, RULE_3)
    # ...must agree with the recount of its own branch text.
    assert (lm_x.shared_rule_budget.count, lm_x.shared_rule_budget.nodes) == (
        recount_shared_budget(text_x)
    )
    assert (lm_y.shared_rule_budget.count, lm_y.shared_rule_budget.nodes) == (
        recount_shared_budget(text_y)
    )


def test_reorg_that_drops_a_rule_un_counts_it():
    # Head A: rules 1+2 counted. Reorg to head B (same parent, rule 2 never
    # landed): the recount of B's text is 1 rule, and a manager synced to
    # B must report 1 -- the dropped rule's nodes do not linger.
    text_a = RULE_1 + "\n" + RULE_2
    text_b = RULE_1
    assert recount_shared_budget(text_a) == (2, 8)
    assert recount_shared_budget(text_b) == (1, 4)
    lm = _manager_with_rules(RULE_1, RULE_2)
    # Simulate the swap re-derivation onto B's text.
    from chain_state import _recount_shared_rule_budget

    _recount_shared_rule_budget(lm, text_b)
    assert (lm.shared_rule_budget.count, lm.shared_rule_budget.nodes) == (1, 4)


def test_recount_is_idempotent_across_reorg_cycles():
    text = RULE_1 + "\n" + RULE_2
    lm = _manager_with_rules(RULE_1, RULE_2)
    from chain_state import _recount_shared_rule_budget

    for _ in range(3):
        _recount_shared_rule_budget(lm, text)
        assert (lm.shared_rule_budget.count, lm.shared_rule_budget.nodes) == (2, 8)


def test_limits_survive_a_fork_but_counters_do_not_leak():
    lm = ConsensusLifecycleManager(active_validators=[A])
    lm.apply_host_contract_patch({
        "shared_rule_limits": {
            "occurrences": 3, "total_nodes": 30, "rule_nodes": 32,
            "rule_depth": 8, "rule_bytes": 1024, "width": 384,
        }
    })
    branch = lm.fork()
    assert branch.shared_rule_budget.limits.occurrences == 3
    branch.shared_rule_budget.charge(_info(RULE_1))
    assert lm.shared_rule_budget.count == 0
    assert branch.shared_rule_budget.count == 1
