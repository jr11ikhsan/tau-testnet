"""Bounty 01, L7: a standing due retry re-checks the payer's CURRENT o5.

The hole (JUARA-L7, TERBUKTI CELAH): `_retry_due_standing_payments`
settled an owed retry by direct balance write and never re-checked
the payer's currently active transfer policy (o5). A payer who froze
their wallet AFTER the shortfall was recorded still lost one period
per retry — while the SAME payment attempted by explicit
TX_TYPE_EXECUTE_STANDING_PAYMENT was rejected by o5 through the
transfer seam. Issue #34 acceptance case 7 requires the re-check:
"Execution must re-check the payer's currently active transfer
policy (o5)... so a later freeze or stricter guard can stop it."

The fix (candidate, DROP semantics): pass 2 of the sweep evaluates
the payer's current o5 on the real recipient and amount of every leg
— the same two gates the transfer seam applies (the Tau o5 stream,
then the payer's own o5 clause via `clause_blocks`) — before the
book may settle. A retry the policy now blocks is DROPPED, like any
other non-shortfall refusal: the period stays unsettled, so it may
still be paid later by explicit execution once the freeze lifts.

Covered, with the policy pools scripted (the sender-policy mock) and
the Tau session faked at `communicate_with_tau_multi` (the mock
harness's own convention: key 5 of the multi result IS the o5
stream):

* a freeze installed as the payer's o5 clause blocks the retry —
  balances do not move, the retry is dropped, the period stays
  unsettled, and an explicit execution pays it once the freeze lifts;
* a freeze visible only on the Tau o5 stream (no clause installed)
  blocks the retry the same way — the session gate, exercised;
* without any freeze the retry settles exactly as before (control);
* a stand-in manager carrying no rule book at all fails closed —
  the L7 lab's detector, reconstructed: the sweep touches o5 and
  blocks instead of paying.
"""
import hashlib
import itertools
import types
from unittest.mock import patch

import pytest
import tau_manager
import tau_session
from py_ecc.bls import G2Basic

import tau_defs
from block import Block
from consensus import sender_policy
from consensus.engine import (
    ActiveConsensusView,
    TauConsensusEngine,
    _retry_due_standing_payments,
)
from consensus.governance import ConsensusLifecycleManager
from consensus.policy_mock import MockPolicyEvaluator
from consensus.standing_payments import (
    FORM_TAU_CLAUSE,
    StandingPaymentBook,
    parse_create_standing_payment,
)
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

HEIGHT = 20
TS = 1_800_000_000
FEE = 7
AMOUNT = 250
DAY = 86_400
RETRY_WEEK = 7 * DAY

PAY_FULL_CLAUSE = (
    "((o30[t]:bv[64] = { 1 }:bv[64]) "
    "&& (o31[t]:bv[64] = { 0 }:bv[64]) "
    "&& (o32[t]:bv[64] = { 250 }:bv[64]))"
)
PAY_1000_CLAUSE = (
    "((o30[t]:bv[64] = { 1 }:bv[64]) "
    "&& (o31[t]:bv[64] = { 0 }:bv[64]) "
    "&& (o32[t]:bv[64] = { 1000 }:bv[64]))"
)
# A payer freeze, as an o5 clause: o5 is BLOCK (0) for every transfer
# of theirs. The mock evaluator keys on the body text (no Tau parsing
# in mock); in production this body is installed via the offer/accept
# flow and read back through `rule_offers.clause_for`.
FREEZE_CLAUSE = "((o5[t]:bv[64] = { 0 }:bv[64]))"


def _key(seed):
    return seed, G2Basic.SkToPk(seed).hex()


SK_ALICE, ALICE = _key(11111)        # proposer / sole validator
SK_PAYER, PAYER = _key(22222)        # standing payer (short: 100 < 250)
SK_RECIPIENT, RECIPIENT = _key(33333)
SK_EXECUTOR, EXECUTOR = _key(55555)  # funder / any third party

_TX_SEQ = itertools.count()


def _sign(tx, sk):
    tx["signature"] = G2Basic.Sign(
        sk, hashlib.sha256(signing_message_bytes(tx)).digest()
    ).hex()
    return tx


def _lm():
    lm = ConsensusLifecycleManager(active_validators=[ALICE])
    lm.activate_approval_slots()
    return lm


class _Chain:
    """Threads apply_block results into the next block's parent snapshot
    (the standing engine suite's harness, verbatim, plus a `session`
    and a `fake_multi` hook so one block can drive the Tau o5 stream
    deterministically)."""

    def __init__(self, balances, lm=None, ts=TS):
        self.balances = dict(balances)
        self.sequences = {}
        self.lm = lm if lm is not None else _lm()
        self.ts = ts
        self.height = HEIGHT

    def apply(self, txs, fee=FEE, allow=True, session=None, fake_multi=None):
        parent = TauStateSnapshot(
            state_hash="0" * 64,
            tau_bytes=b"always (o0[t]=1).",
            metadata={
                "balances": dict(self.balances),
                "sequence_numbers": dict(self.sequences),
                "last_transfer_ts": {},
                "lifecycle_manager": self.lm,
                "consensus_rules_state": "always (o6[t]:bv[16] = i10[t]:bv[16]).",
                "active_consensus_id": "",
            },
        )
        view = ActiveConsensusView(
            target_height=self.height,
            consensus_rules=parent.metadata["consensus_rules_state"],
            active_validators=[bytes.fromhex(ALICE)],
            mechanism_specific_metadata={"poa": True, "approval_slots_active": True},
        )
        block = Block.create(
            block_number=self.height, previous_hash="00" * 32,
            transactions=txs, proposer_pubkey=ALICE, timestamp=self.ts,
        )

        def _fake_multi(**kwargs):
            vals = kwargs.get("input_stream_values") or {}
            amount = int(str(vals.get(1, "0")) or 0)
            return {1: str(amount), 8: "0", 9: str(fee), 5: "1" if allow else "0"}

        multi = fake_multi if fake_multi is not None else _fake_multi
        engine = TauConsensusEngine()
        with patch("tau_manager.communicate_with_tau", return_value="T"), \
             patch("tau_manager.communicate_with_tau_multi", side_effect=multi), \
             patch("chain_state.get_application_rules_state", return_value=""), \
             patch("tau_manager.tau_ready") as ready:
            ready.is_set.return_value = True
            result = engine.apply_block(view, block, parent, session=session)
        md = result.next_snapshot.metadata
        self.balances = md["balances"]
        self.sequences = md["sequence_numbers"]
        self.lm = md["lifecycle_manager"]
        self.height += 1
        return result


@pytest.fixture(autouse=True)
def _reset_pool_overrides():
    for pool in ("apply", "admission"):
        sender_policy.set_evaluator(pool, None)
    yield
    for pool in ("apply", "admission"):
        sender_policy.set_evaluator(pool, None)


def _script_pay_and_freeze():
    """One evaluator per pool: the pay clause computes its legs, the
    freeze clause verdicts BLOCK. Both hooks must live on the SAME
    evaluator — scripting them separately would replace one with
    the other."""
    for pool in ("apply", "admission"):
        ev = MockPolicyEvaluator(pool=pool)
        ev.set_outputs(PAY_FULL_CLAUSE, lambda inputs: {
            "o30": "1", "o31": "0", "o32": "250"})
        ev.set_verdict(FREEZE_CLAUSE, "0")
        sender_policy.set_evaluator(pool, ev)


def _o5_freeze_fake(payer_pubkey, fee=FEE):
    """`communicate_with_tau_multi` that emits o5=BLOCK only for a
    transfer map sent BY the frozen payer (i12 carries the sender,
    the transfer map's own convention) — every other sender allows.
    The standing clause map carries no i12, so it never trips."""
    def _fake(**kwargs):
        vals = kwargs.get("input_stream_values") or {}
        amount = int(str(vals.get(1, "0")) or 0)
        sender = str(vals.get(12, "") or "")
        o5 = "0" if ("#x" + payer_pubkey.lower()) in sender.lower() else "1"
        return {1: str(amount), 8: "0", 9: str(fee), 5: o5}
    return _fake


def _install_freeze(chain):
    chain.lm.rule_offers.accepted_clauses[
        (PAYER.lower(), tau_defs.USER_POLICY_STREAM_INDEX)
    ] = FREEZE_CLAUSE


def _lift_freeze(chain):
    del chain.lm.rule_offers.accepted_clauses[
        (PAYER.lower(), tau_defs.USER_POLICY_STREAM_INDEX)
    ]


def _create_clause_tx(payer, sk, recipient, seq, **kw):
    return _sign({
        "tx_id": f"retry-o5-create-{next(_TX_SEQ)}",
        "tx_type": "create_standing_payment",
        "sender_pubkey": payer,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": "100",
        "standing_recipient_pubkey": recipient,
        "standing_amount": kw.get("amount", AMOUNT),
        "standing_schedule": "daily",
        "standing_signed_day": 0,
        "standing_anchor_ts": kw.get("anchor_ts", TS - 100),
        "standing_window_seconds": 3600,
        "standing_final_ts": 0,
        "standing_max_occurrences": 0,
        "standing_max_total": kw.get("max_total", 100_000),
        "standing_fee_limit": 0,
        "standing_policy_version_ref": 0,
        "standing_allow_catch_up": 0,
        "standing_version": 1,
        "standing_form": FORM_TAU_CLAUSE,
        "standing_clause": kw.get("clause", PAY_FULL_CLAUSE),
        "standing_due_retry_seconds": kw.get("due_retry_seconds", RETRY_WEEK),
    }, sk)


def _execute_tx(sender, sk, auth_id, seq):
    return _sign({
        "tx_id": f"retry-o5-exec-{next(_TX_SEQ)}",
        "tx_type": "execute_standing_payment",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": "100",
        "standing_auth_id": auth_id.hex(),
    }, sk)


def _transfer(sender, sk, to, amount, seq):
    return _sign({
        "tx_id": f"tr-o5-{next(_TX_SEQ)}",
        "tx_type": "user_tx",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": "100",
        "operations": {"1": [[sender, to, str(amount)]]},
    }, sk)


def _funded_chain(**balances):
    base = {ALICE: 0, PAYER: 100, RECIPIENT: 1000, EXECUTOR: 1000}
    base.update(balances)
    return _Chain(base)


def _created_chain(**kw):
    """A chain with one live clause-form authorization whose payer is
    short (100, minus the 7 create fee, against a 250 period): the
    create block's own sweep discovers the short due point and owes
    its retry. The freeze verdict is scripted from the start but
    inert until the freeze clause is installed in rule_offers."""
    _script_pay_and_freeze()
    chain = _funded_chain()
    create = _create_clause_tx(PAYER, SK_PAYER, RECIPIENT, seq=0, **kw)
    result = chain.apply([create])
    assert create["tx_id"] in result.accepted_tx_ids
    owed = chain.lm.standing_payments.owed_retries()
    assert len(owed) == 1 and owed[0].period_index == 0
    return chain, parse_create_standing_payment(create).auth_id


def _book(chain):
    return chain.lm.standing_payments


def _events(result):
    return result.next_snapshot.metadata.get("standing_payment_events", [])


def _ended_events(result):
    return [e for e in _events(result) if e.get("action") == "due_retry_ended"]


# --- the o5 gates --------------------------------------------------------------


def test_o5_clause_freeze_drops_the_retry_and_pays_nothing():
    chain, auth_id = _created_chain()
    _install_freeze(chain)
    # Fund the payer in the next block: the retry is now affordable,
    # and the freeze is live — the sweep must not pay it.
    fund = _transfer(EXECUTOR, SK_EXECUTOR, PAYER, 500, seq=0)
    result = chain.apply([fund])
    assert fund["tx_id"] in result.accepted_tx_ids
    # The funding itself landed (the freeze is the PAYER's policy,
    # not the executor's): only the retry payment is blocked.
    assert chain.balances[PAYER] == 100 - FEE + 500
    assert chain.balances[RECIPIENT] == 1000
    assert chain.balances[EXECUTOR] == 1000 - FEE - 500
    assert _book(chain).owed_retries() == []
    assert _book(chain).total_executed(auth_id) == (0, 0)
    ended = _ended_events(result)
    assert len(ended) == 1
    assert ended[0]["auth_id"] == auth_id.hex()
    assert ended[0]["period_index"] == 0
    assert ended[0]["reason"] == "user_policy_block"


def test_dropped_retry_period_still_payable_by_explicit_execution():
    """DROP is not burn: the period stays unsettled, so once the
    freeze lifts the same period pays through the ordinary seam."""
    chain, auth_id = _created_chain()
    _install_freeze(chain)
    fund = _transfer(EXECUTOR, SK_EXECUTOR, PAYER, 500, seq=0)
    chain.apply([fund])
    assert _book(chain).owed_retries() == []
    assert _book(chain).total_executed(auth_id) == (0, 0)
    _lift_freeze(chain)
    execute = _execute_tx(EXECUTOR, SK_EXECUTOR, auth_id, seq=1)
    result = chain.apply([execute])
    assert execute["tx_id"] in result.accepted_tx_ids
    assert chain.balances[PAYER] == 100 - FEE + 500 - AMOUNT
    assert chain.balances[RECIPIENT] == 1000 + AMOUNT
    assert _book(chain).total_executed(auth_id) == (1, AMOUNT)
    assert _events(result) == [] or all(
        e.get("action") != "retry_executed" for e in _events(result))


def test_tau_stream_freeze_drops_the_retry_with_no_clause_installed():
    """The session gate, exercised alone: no o5 clause is installed
    (clause_for returns None, so the clause gate allows), but the
    live Tau rules emit o5=BLOCK for a transfer sent by the payer."""
    chain, auth_id = _created_chain()
    session = tau_session.InProcessSession(manager=tau_manager)
    fund = _transfer(EXECUTOR, SK_EXECUTOR, PAYER, 500, seq=0)
    result = chain.apply(
        [fund], session=session, fake_multi=_o5_freeze_fake(PAYER))
    assert fund["tx_id"] in result.accepted_tx_ids
    assert chain.balances[PAYER] == 100 - FEE + 500
    assert chain.balances[RECIPIENT] == 1000
    assert _book(chain).owed_retries() == []
    assert _book(chain).total_executed(auth_id) == (0, 0)
    ended = _ended_events(result)
    assert len(ended) == 1
    assert ended[0]["reason"] == "user_policy_block"
    # The period is still payable explicitly once the stream allows.
    execute = _execute_tx(EXECUTOR, SK_EXECUTOR, auth_id, seq=1)
    result = chain.apply([execute])
    assert execute["tx_id"] in result.accepted_tx_ids
    assert chain.balances[PAYER] == 100 - FEE + 500 - AMOUNT
    assert chain.balances[RECIPIENT] == 1000 + AMOUNT


def test_retry_settles_when_no_freeze_is_installed():
    """Control: the same timeline with no freeze anywhere settles
    exactly as before the fix — the gate allows, it does not invent
    refusals."""
    chain, auth_id = _created_chain()
    fund = _transfer(EXECUTOR, SK_EXECUTOR, PAYER, 500, seq=0)
    result = chain.apply([fund])
    assert fund["tx_id"] in result.accepted_tx_ids
    assert chain.balances[PAYER] == 100 - FEE + 500 - AMOUNT
    assert chain.balances[RECIPIENT] == 1000 + AMOUNT
    assert chain.balances[EXECUTOR] == 1000 - FEE - 500
    assert _book(chain).owed_retries() == []
    assert _book(chain).total_executed(auth_id) == (1, AMOUNT)
    events = [e for e in _events(result) if e.get("action") == "retry_executed"]
    assert len(events) == 1
    assert events[0]["auth_id"] == auth_id.hex()
    assert events[0]["amount"] == AMOUNT and events[0]["retry"] is True


def test_sweep_without_a_policy_book_fails_closed():
    """The L7 lab's detector, reconstructed: a stand-in manager that
    carries a real book but no rule_offers at all. Before the fix the
    sweep paid the retry (payer 5000 -> 4000) without touching o5;
    now the unreadable policy is a fail-closed block, not a silent
    allow — and the sweep does not crash on the missing book."""
    for pool in ("apply", "admission"):
        ev = MockPolicyEvaluator(pool=pool)
        ev.set_outputs(PAY_1000_CLAUSE, lambda inputs: {
            "o30": "1", "o31": "0", "o32": "1000"})
        sender_policy.set_evaluator(pool, ev)
    create = _create_clause_tx(
        PAYER, SK_PAYER, RECIPIENT, seq=0, amount=1000,
        clause=PAY_1000_CLAUSE, due_retry_seconds=RETRY_WEEK)
    entry = parse_create_standing_payment(create)
    book = StandingPaymentBook()
    auth_id = book.create(entry, TS)
    legs = ((RECIPIENT, 1000),)
    decision = book.discovery_decision(auth_id, 0, TS, 0, legs)
    assert not decision.executed
    assert decision.reason.startswith("insufficient funds")
    assert book.note_retry_owed(auth_id, 0, TS, HEIGHT) is True
    assert len(book.owed_retries()) == 1
    lm = types.SimpleNamespace(standing_payments=book, faucet_amount=0)
    balances = {PAYER: 5000, RECIPIENT: 0}
    events = _retry_due_standing_payments(
        lm, balances, {}, HEIGHT + 1, TS + 3600)
    assert balances[PAYER] == 5000
    assert balances[RECIPIENT] == 0
    assert book.owed_retries() == []
    assert book.total_executed(auth_id) == (0, 0)
    ended = [e for e in events if e.get("action") == "due_retry_ended"]
    assert len(ended) == 1
    assert ended[0]["reason"] == "user_policy_block"
    assert not [e for e in events if e.get("action") == "retry_executed"]
