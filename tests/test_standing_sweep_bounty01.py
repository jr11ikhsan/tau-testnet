"""Bounty 01, issue #34: the standing-payment due sweep (mock Tau).

Fix-3 (differential audit vs jimb000o #158/#160, axis 3): a due period
no longer waits for an executor willing to front a fee. At the end of
every block the node itself settles due standing periods through the
book's own execute() evaluation — the same live window, end conditions,
per-period caps and paid-for-period facts a transaction execution
faces — at most 16 settlements per block, earliest due first, with no
transaction and no fee.

Covered here, at engine level with full calendar control:
(1) a monthly payment signed for the 31st is paid on the last day of a
    short month by empty blocks alone — no transaction after create —
    and returns to the 31st the month after (clamp-and-return);
(2) a block late in the window still pays that period exactly once;
(3) an authorization whose payer cannot pay settles nothing, owes
    nothing and advances no marker; later blocks retry it while the
    window is live (a funding transfer in the due block itself counts,
    because the sweep runs after the transaction loop), and the next
    period pays once the payer is funded;
(4) two independent chains applying the same block stream agree
    exactly, including after one chain restores its book from stored
    rows (a restart) mid-scenario;
(5) the race pin: a transaction execution and the sweep in the same
    block settle a period exactly once, and a later execution attempt
    is refused — the sweep never double-pays;
(6) the inactive pins: before the first due date and after a window
    lapses the sweep changes nothing and a transaction execution is
    refused exactly as before this fix; a lapsed period is skipped
    forever (no unsigned catch-up) while the next period pays;
(7) the per-block cap: 17 due authorizations settle 16 in the first
    block — earliest due first — and the last one in the next block.
(8) the o5 gate (coordinator decision (i)): while the payer's own policy
    blocks, the sweep settles nothing and advances no marker; once the
    policy allows, the same period settles exactly once, fee-free.
"""
import copy
import hashlib
import itertools
from datetime import datetime, timezone
from unittest.mock import patch

from py_ecc.bls import G2Basic

from block import Block
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.standing_payments import (
    MAX_DUE_SWEEP_SETTLEMENTS_PER_BLOCK,
    StandingPaymentBook,
    parse_create_standing_payment,
)
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

HEIGHT = 20
FEE = 7
AMOUNT = 250


def _ts(year, month, day, hour=0, minute=0, second=0):
    return int(datetime(year, month, day, hour, minute, second,
                        tzinfo=timezone.utc).timestamp())


JAN31 = _ts(2027, 1, 31)
FEB28 = _ts(2027, 2, 28)
MAR31 = _ts(2027, 3, 31)
BASE = _ts(2027, 5, 10, 12, 0, 0)


def _key(seed):
    return seed, G2Basic.SkToPk(seed).hex()


SK_ALICE, ALICE = _key(11111)        # proposer / sole validator
SK_PAYER, PAYER = _key(22222)
SK_RECIPIENT, RECIPIENT = _key(33333)
SK_EXECUTOR, EXECUTOR = _key(55555)

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
    """Threads apply_block results into the next block's parent snapshot.

    The standing engine suite's harness: the scripted evaluator's o5
    allows and its fee step is FEE, so any balance movement beyond the
    signed amount in an empty block would be visible as a fee.
    """

    def __init__(self, balances, lm=None, ts=BASE):
        self.balances = dict(balances)
        self.sequences = {}
        self.lm = lm if lm is not None else _lm()
        self.ts = ts
        self.height = HEIGHT

    def apply(self, txs, fee=FEE, allow=True):
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

        engine = TauConsensusEngine()
        with patch("tau_manager.communicate_with_tau", return_value="T"), \
             patch("tau_manager.communicate_with_tau_multi", side_effect=_fake_multi), \
             patch("chain_state.get_application_rules_state", return_value=""), \
             patch("tau_manager.tau_ready") as ready:
            ready.is_set.return_value = True
            result = engine.apply_block(view, block, parent)
        md = result.next_snapshot.metadata
        self.balances = md["balances"]
        self.sequences = md["sequence_numbers"]
        self.lm = md["lifecycle_manager"]
        self.height += 1
        return result


def _create_tx(payer, sk, recipient, amount, seq, fee_limit="100", **kw):
    return _sign({
        "tx_id": f"standing-{next(_TX_SEQ)}",
        "tx_type": "create_standing_payment",
        "sender_pubkey": payer,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": fee_limit,
        "standing_recipient_pubkey": recipient,
        "standing_amount": amount,
        "standing_schedule": kw.get("schedule", "daily"),
        "standing_signed_day": kw.get("signed_day", 0),
        "standing_anchor_ts": kw.get("anchor_ts", BASE - 100),
        "standing_window_seconds": kw.get("window_seconds", 3600),
        "standing_final_ts": kw.get("final_ts", 0),
        "standing_max_occurrences": kw.get("max_occurrences", 0),
        "standing_max_total": kw.get("max_total", 0),
        "standing_fee_limit": kw.get("standing_fee_limit", 0),
        "standing_policy_version_ref": kw.get("policy_version_ref", 0),
        "standing_allow_catch_up": kw.get("allow_catch_up", 0),
        "standing_version": kw.get("version", 1),
    }, sk)


def _execute_tx(sender, sk, auth_id, seq, fee_limit="100"):
    return _sign({
        "tx_id": f"standing-exec-{next(_TX_SEQ)}",
        "tx_type": "execute_standing_payment",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": fee_limit,
        "standing_auth_id": auth_id.hex(),
    }, sk)


def _transfer(sender, sk, to, amount, seq, fee_limit="100"):
    return _sign({
        "tx_id": f"tr-{next(_TX_SEQ)}",
        "tx_type": "user_tx",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": fee_limit,
        "operations": {"1": [[sender, to, str(amount)]]},
    }, sk)


def _auth_id(create_tx):
    return parse_create_standing_payment(create_tx).auth_id


def _book(chain):
    return chain.lm.standing_payments


def _swept_events(result):
    events = result.next_snapshot.metadata.get("standing_payment_events") or []
    return [e for e in events if e.get("swept")]


def _created_chain(ts, balances=None, **kw):
    """A chain with one live authorization created at `ts` (block applied)."""
    if not any(k in kw for k in ("final_ts", "max_occurrences", "max_total")):
        kw["max_total"] = 100000
    chain = _Chain(
        balances if balances is not None
        else {ALICE: 0, PAYER: 100000, RECIPIENT: 1000, EXECUTOR: 1000},
        ts=ts,
    )
    create = _create_tx(PAYER, SK_PAYER, RECIPIENT, AMOUNT, seq=0, **kw)
    result = chain.apply([create])
    assert create["tx_id"] in result.accepted_tx_ids
    return chain, _auth_id(create)


# --- (1) monthly on the 31st, paid by empty blocks alone -----------------------

def test_monthly_on_31st_swept_on_last_day_of_month_with_no_transactions():
    chain, auth_id = _created_chain(
        JAN31 - 86400,
        schedule="monthly", signed_day=31, anchor_ts=JAN31,
        window_seconds=27 * 86400,
    )
    book = _book(chain)
    assert book.total_executed(auth_id) == (0, 0)

    for due_ts, period in ((JAN31, 0), (FEB28, 1), (MAR31, 2)):
        payer_before = chain.balances[PAYER]
        recipient_before = chain.balances[RECIPIENT]
        executor_before = chain.balances[EXECUTOR]
        chain.ts = due_ts + 120
        result = chain.apply([])  # an empty block: no transaction at all
        # Exactly the signed amount moved, and nobody paid any fee.
        assert chain.balances[RECIPIENT] - recipient_before == AMOUNT
        assert chain.balances[PAYER] - payer_before == -AMOUNT
        assert chain.balances[EXECUTOR] == executor_before
        (event,) = _swept_events(result)
        assert event["auth_id"] == auth_id.hex()
        assert event["period_index"] == period
        assert event["amount"] == AMOUNT
        assert event["executor_pubkey"] is None

    book = _book(chain)
    assert book.total_executed(auth_id) == (3, 3 * AMOUNT)
    assert [f.period_index for f in book.facts_for(auth_id)] == [0, 1, 2]
    # The February fact covers the clamped period [Feb 28, Mar 31).
    feb = book.paid_for_period(auth_id, 1)
    assert (feb.period_start_ts, feb.period_end_ts) == (FEB28, MAR31)


# --- (2) a late block still pays that period exactly once ----------------------

def test_late_block_in_window_pays_once_and_next_block_does_not_repay():
    chain, auth_id = _created_chain(BASE - 1000, anchor_ts=BASE,
                                    window_seconds=3600)
    chain.ts = BASE + 3599  # the last second of the signed window
    chain.apply([])
    assert _book(chain).total_executed(auth_id) == (1, AMOUNT)
    assert chain.balances[RECIPIENT] == 1000 + AMOUNT

    chain.ts = BASE + 3600 + 600  # window lapsed; period 1 not yet due
    result = chain.apply([])
    assert _swept_events(result) == []
    assert _book(chain).total_executed(auth_id) == (1, AMOUNT)
    assert chain.balances[RECIPIENT] == 1000 + AMOUNT


# --- (3) insufficient balance: nothing settles, no debt, retry works -----------

def test_empty_payer_settles_nothing_then_pays_when_funded():
    chain, auth_id = _created_chain(
        BASE - 1000,
        balances={ALICE: 0, PAYER: 100, RECIPIENT: 1000, EXECUTOR: 1000},
        anchor_ts=BASE, window_seconds=3600,
    )
    # The create fee left the payer below one payment.
    assert chain.balances[PAYER] < AMOUNT

    chain.ts = BASE + 10
    result = chain.apply([])
    assert _swept_events(result) == []
    assert _book(chain).total_executed(auth_id) == (0, 0)
    assert _book(chain).facts_for(auth_id) == []
    assert chain.balances[RECIPIENT] == 1000

    # A funding transfer inside the next due block lands first (the sweep
    # runs after the transaction loop), so the retry settles in that block.
    chain.ts = BASE + 100
    fund = _transfer(RECIPIENT, SK_RECIPIENT, PAYER, 500, seq=0)
    result = chain.apply([fund])
    assert fund["tx_id"] in result.accepted_tx_ids
    (event,) = _swept_events(result)
    assert event["period_index"] == 0
    assert _book(chain).total_executed(auth_id) == (1, AMOUNT)

    # The next period pays from what is left, again with no transaction.
    chain.ts = BASE + 86400 + 10
    chain.apply([])
    assert _book(chain).total_executed(auth_id) == (2, 2 * AMOUNT)


# --- (4) two chains agree, including a mid-scenario restart --------------------

def test_two_chains_agree_after_restart_mid_scenario():
    balances = {ALICE: 0, PAYER: 100000, RECIPIENT: 1000, EXECUTOR: 1000}
    create = _create_tx(
        PAYER, SK_PAYER, RECIPIENT, AMOUNT, seq=0, schedule="monthly",
        signed_day=31, anchor_ts=JAN31, window_seconds=27 * 86400,
        max_total=100000,
    )
    auth_id = _auth_id(create)
    chains = []
    for _ in range(2):
        chain = _Chain(dict(balances), ts=JAN31 - 86400)
        result = chain.apply([copy.deepcopy(create)])
        assert create["tx_id"] in result.accepted_tx_ids
        chains.append(chain)

    for due_ts in (JAN31, FEB28):
        for chain in chains:
            chain.ts = due_ts + 120
            chain.apply([])

    # Restart the second chain: rebuild its book from the stored rows,
    # exactly what a node reloading its state does.
    book_b = chains[1].lm.standing_payments
    chains[1].lm.standing_payments = StandingPaymentBook.restore(
        book_b.rows(), book_b.fact_rows()
    )

    last_events = []
    for chain in chains:
        chain.ts = MAR31 + 120
        last_events.append(_swept_events(chain.apply([])))

    assert chains[0].balances == chains[1].balances
    book_a, book_b = (_book(c) for c in chains)
    assert book_a.root() == book_b.root()
    assert book_a.fact_rows() == book_b.fact_rows()
    assert book_a.total_executed(auth_id) == book_b.total_executed(auth_id) == (3, 3 * AMOUNT)
    assert last_events[0] == last_events[1]


# --- (5) the race pin: transaction + sweep never pay twice ----------------------

def test_transaction_execution_and_sweep_in_one_block_pay_exactly_once():
    chain, auth_id = _created_chain(BASE - 1000, anchor_ts=BASE,
                                    window_seconds=3600)
    chain.ts = BASE + 100
    execute = _execute_tx(EXECUTOR, SK_EXECUTOR, auth_id, seq=0)
    result = chain.apply([execute])
    assert execute["tx_id"] in result.accepted_tx_ids
    # The transaction settled the period; the sweep in the same block had
    # nothing left to pay.
    assert _swept_events(result) == []
    assert chain.balances[RECIPIENT] == 1000 + AMOUNT
    assert _book(chain).total_executed(auth_id) == (1, AMOUNT)

    # A later execution attempt is refused and settles nothing, exactly
    # as a second transaction execution has always been refused.
    chain.ts = BASE + 200
    again = _execute_tx(EXECUTOR, SK_EXECUTOR, auth_id, seq=1)
    result = chain.apply([again])
    assert again["tx_id"] not in result.accepted_tx_ids
    assert chain.balances[RECIPIENT] == 1000 + AMOUNT
    assert _book(chain).total_executed(auth_id) == (1, AMOUNT)


# --- (6) inactive pins: not due / window lapsed behave exactly as before -------

def test_sweep_is_inert_before_due_and_a_lapsed_period_is_skipped():
    # Not yet due: the sweep changes nothing and an execution is refused
    # with the legacy verdict.
    chain, auth_id = _created_chain(BASE, anchor_ts=BASE + 100000,
                                    window_seconds=3600)
    before = dict(chain.balances)
    chain.ts = BASE + 50000
    result = chain.apply([])
    assert _swept_events(result) == []
    assert chain.balances == before
    early = _execute_tx(EXECUTOR, SK_EXECUTOR, auth_id, seq=0)
    result = chain.apply([early])
    assert early["tx_id"] not in result.accepted_tx_ids
    assert _book(chain).total_executed(auth_id) == (0, 0)

    # Window lapsed: period 0 is skipped forever (no unsigned catch-up);
    # period 1 pays normally when its own window is live.
    chain, auth_id = _created_chain(BASE - 1000, anchor_ts=BASE,
                                    window_seconds=60)
    chain.ts = BASE + 3600
    result = chain.apply([])
    assert _swept_events(result) == []
    late = _execute_tx(EXECUTOR, SK_EXECUTOR, auth_id, seq=0)
    result = chain.apply([late])
    assert late["tx_id"] not in result.accepted_tx_ids
    assert _book(chain).total_executed(auth_id) == (0, 0)

    chain.ts = BASE + 86400 + 30
    chain.apply([])
    book = _book(chain)
    assert book.total_executed(auth_id) == (1, AMOUNT)
    assert [f.period_index for f in book.facts_for(auth_id)] == [1]
    assert book.paid_for_period(auth_id, 0) is None


# --- (7) the per-block cap, earliest due first ----------------------------------

def test_sweep_settles_at_most_sixteen_per_block_earliest_due_first():
    payers = [_key(2000 + i) for i in range(17)]
    balances = {ALICE: 0, RECIPIENT: 0}
    balances.update({pk: 10000 for _, pk in payers})
    chain = _Chain(balances, ts=BASE - 10000)
    creates = [
        _create_tx(pk, sk, RECIPIENT, AMOUNT, seq=0, anchor_ts=BASE + i * 60,
                   window_seconds=3600, max_total=100000)
        for i, (sk, pk) in enumerate(payers)
    ]
    result = chain.apply(creates)
    for create in creates:
        assert create["tx_id"] in result.accepted_tx_ids
    auth_ids = [_auth_id(c) for c in creates]

    chain.ts = BASE + 16 * 60 + 30  # every authorization is due and live
    result = chain.apply([])
    swept = _swept_events(result)
    assert len(swept) == MAX_DUE_SWEEP_SETTLEMENTS_PER_BLOCK == 16
    assert chain.balances[RECIPIENT] == 16 * AMOUNT
    book = _book(chain)
    for auth_id in auth_ids[:16]:
        assert book.total_executed(auth_id) == (1, AMOUNT)
    # The latest due is the one left for the next block.
    assert book.total_executed(auth_ids[16]) == (0, 0)

    chain.ts = BASE + 16 * 60 + 90
    result = chain.apply([])
    (event,) = _swept_events(result)
    assert event["auth_id"] == auth_ids[16].hex()
    assert _book(chain).total_executed(auth_ids[16]) == (1, AMOUNT)
    assert chain.balances[RECIPIENT] == 17 * AMOUNT


# --- (8) the o5 gate: a blocked sweep settles nothing, then settles once ------

def test_o5_blocked_sweep_settles_nothing_then_settles_once():
    """Decision (i): the payer's own policy gates the sweep itself.

    The mirror of the transaction pin (#34-7): while the policy blocks,
    an empty block settles nothing and advances no marker; once the policy
    allows, the same period settles exactly once, fee-free, through the
    sweep alone.
    """
    chain, auth_id = _created_chain(BASE - 1000, anchor_ts=BASE,
                                    window_seconds=3600)
    payer_after_create = chain.balances[PAYER]

    chain.ts = BASE + 100
    result = chain.apply([], allow=False)
    assert _swept_events(result) == []
    assert chain.balances[PAYER] == payer_after_create
    assert chain.balances[RECIPIENT] == 1000
    assert _book(chain).total_executed(auth_id) == (0, 0)
    assert _book(chain).facts_for(auth_id) == []

    chain.ts = BASE + 200
    result = chain.apply([])
    (event,) = _swept_events(result)
    assert event["auth_id"] == auth_id.hex()
    assert event["amount"] == AMOUNT
    assert event["period_index"] == 0
    assert _book(chain).total_executed(auth_id) == (1, AMOUNT)
    assert chain.balances[RECIPIENT] == 1000 + AMOUNT
    assert chain.balances[PAYER] == payer_after_create - AMOUNT
