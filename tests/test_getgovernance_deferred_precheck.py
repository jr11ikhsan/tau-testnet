"""Regression: getgovernance answers while a flag patch is scheduled.

Background (B03 #140, commands/getgovernance.py): the advisory precheck
for a scheduled update audits the tip's effective spec texts, and the
chain_state getters it reads take _rules_lock — a plain (non-re-entrant)
threading.Lock. getgovernance itself holds that lock while it assembles
the response, so running the precheck inside the locked block deadlocked
the read (and, with it, the balance/sequence locks block apply needs).
The fix defers the precheck until after the lock block; the entries it
fills are the same dicts the payload already references, so the verdicts
still land in the response.

This test pins the fix from the outside, the way the deadlock would
actually bite: a scheduled update carrying the recipient-policy
activation flag, over a tip whose consensus rules already read i17.
Proven here:
  1. getgovernance RETURNS (no deadlock) — the call runs in a worker
     thread against the REAL chain_state._rules_lock, and the test fails
     if the thread is still alive after the join timeout. A second
     acquire of that lock from the same thread never returns, so this is
     a real deadlock detector, not a timing guess.
  2. the precheck REALLY RAN — the entry's verdict is compared against
     a direct precheck_scheduled_update() call made on the main thread:
     "fail", naming the i17 collision in the live consensus rules. A
     test that only asserted "it answered" would pass even if the audit
     were silently skipped.
  3. the rest of the answer is intact (head, flag still off).

L0 note: #166 (AduAkorful, commit ec93a7a) added the same class of test
for its line; the mechanism was read there, but this test is written
from #140's own surfaces — our flag key is `recipient_policy_active`,
our audit is `audit_recipient_stream_collisions`, and the expected
verdict is computed from our own precheck, not copied.
"""
import json
import threading

import pytest

import chain_state
from commands.getgovernance import execute
from consensus.admission import precheck_scheduled_update
from consensus.governance import ConsensusLifecycleManager, ConsensusRuleUpdate

VALIDATOR = "d" * 96

# A live consensus rule already reading the hold stream: activating the
# recipient gate over this tip must fail the collision audit loudly.
COLLIDING_CONSENSUS_RULES = "i17[t]:bv[64] = 0"


class _DB:
    def get_canonical_head_block(self):
        return {"block_hash": "abc", "header": {"block_number": 1}}

    def get_mempool_txs(self):
        return []


def _scheduled_flag_patch(lm):
    update = ConsensusRuleUpdate(
        rule_revisions=["always ( o6[t]:bv[16] = i10[t]:bv[16] )."],
        activate_at_height=50,
        host_contract_patch={"recipient_policy_active": True},
        proposer_pubkey=VALIDATOR,
    )
    lm.update_payloads[update.update_id] = update
    lm.scheduled_updates.append((50, update.update_id))
    return update


def test_getgovernance_answers_while_recipient_flag_patch_scheduled():
    lm = ConsensusLifecycleManager(active_validators=[VALIDATOR])
    update = _scheduled_flag_patch(lm)

    # The verdict the audit must produce for this tip, computed directly
    # (lock free on this thread): the guardrail the response is checked
    # against, so a skipped audit cannot pass this test.
    saved = chain_state._consensus_rules_state
    chain_state._consensus_rules_state = COLLIDING_CONSENSUS_RULES
    try:
        expected = precheck_scheduled_update(update, [VALIDATOR])
        assert expected["status"] == "fail", expected
        assert "consensus_rules" in (expected["error"] or ""), expected
        assert "i17" in (expected["error"] or ""), expected

        class _Chain:
            # The REAL rules lock: a second acquire from the worker
            # thread while getgovernance holds it never returns.
            _balance_lock = threading.Lock()
            _sequence_lock = threading.Lock()
            _rules_lock = chain_state._rules_lock
            _active_consensus_id = None
            _consensus_rules_state = ""
            _application_rules_state = ""
            _lifecycle_manager = lm

        class _Container:
            chain_state = _Chain()
            db = _DB()

        outcome = {}

        def run():
            try:
                outcome["raw"] = execute("getgovernance", _Container())
            except Exception as exc:  # noqa: BLE001 - reported by the asserts
                outcome["error"] = exc

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        worker.join(10)
        assert not worker.is_alive(), (
            "getgovernance held _rules_lock across the precheck audit "
            "(deadlock: the audit reads chain_state getters that take "
            "the same non-re-entrant lock)")
        assert "error" not in outcome, outcome.get("error")
        data = json.loads(outcome["raw"])["data"]
        assert data["head_number"] == 1
        assert data["recipient_policy_active"] is False
        entry = data["scheduled_updates"][0]
        assert entry["activation_height"] == 50
        assert entry["precheck"] == expected["status"]
        assert entry.get("precheck_error") == expected["error"]
    finally:
        chain_state._consensus_rules_state = saved
