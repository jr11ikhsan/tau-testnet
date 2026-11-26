"""Bounty 02 (issue #42): the fee_rules view -- o8 attribution (G5).

`fee_rules` lists every accepted unit that writes the fee stream o8,
whoever sent it, in the order the units joined -- because o8 is worked
out from the whole specification for every transaction, a unit that
never names an account can still change what that account pays (#183).
Each row carries the unit's o8 fragments, their sha256, whether they
name the queried account, who sent the installing transaction
(`sent_by`, null when this node has no block for it), the block +
transaction that first brought it in, and the fee fragments' own
survival (`status` + `displaced_by`): a displaced fee rule stays
listed, and the row says it no longer applies.

Two seams, matching the two ledger tests that already exist:

* end-to-end (the `tests/test_active_rules_view.py` harness): real
  apply_block with the Tau seam stubbed, real blocks, real senders --
  guarded o8 rules from ALICE and BOB, a non-o8 rule, and the three
  commands + the CLI formatter over them;
* seeded (the `tests/test_active_rules_revision_ledger.py` seam):
  hand-recorded snapshots + rule outcomes, with blocks stored
  directly, for the cases the engine cannot produce in the mock --
  a displaced o8 unit (a plain o8 write is refused at admission
  without a sender scope, so no mock apply can displace one) and a
  unit whose transaction this node has no block for (`sent_by` null).

`fee_rules` is a read-only view: no test here writes consensus state,
and no test asserts a state hash.
"""
import hashlib
import json
import types

import db
from block import Block
from bls_keys import SK_ALICE, SK_BOB, pubkey_hex, sign_tx
from commands import getaccountrules, getactiverules, getrulesinforce
from consensus import active_rules
from tau_testnet_cli.cli import _format_fee_rules
from tests.test_active_rules_view import _Node, _rule_tx

ALICE = pubkey_hex(SK_ALICE)
BOB = pubkey_hex(SK_BOB)
GENESIS_TS = 1_700_000_000

# A fee rule scoped to its sender by an i12 guard: the only form
# admission accepts for an o8 write (an unscoped o8 write is refused
# as UNSCOPED_USER_RULE -- see test_plain_o8_write_is_refused).
FEE_ALICE = (
    "always ((i12[t]:bv[384] = { #x" + ALICE + " }:bv[384])"
    " -> (o8[t]:bv[24] = { #x000003 }:bv[24]))."
)
FEE_BOB = (
    "always ((i12[t]:bv[384] = { #x" + BOB + " }:bv[384])"
    " -> (o8[t]:bv[24] = { #x000005 }:bv[24]))."
)
# A rule that writes no fee stream: it must never appear in fee_rules.
RULE_O26 = "always (o26[t]:bv[64] = { 7 }:bv[64])."


def _rule_tx_from(tx_id, rule, sender, sk, seq=0):
    return sign_tx({
        "tx_id": tx_id,
        "tx_type": "user_tx",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "fee_limit": "100",
        "operations": {"0": rule},
    }, sk)


def _view(*args):
    resp = json.loads(
        getactiverules.execute(
            "getactiverules" + "".join(f" {a}" for a in args),
            types.SimpleNamespace(db=db),
        )
    )
    assert resp["status"] == "ok", resp
    return resp["data"]


def _account_view(account):
    resp = json.loads(
        getaccountrules.execute(
            f"getaccountrules {account}", types.SimpleNamespace(db=db)
        )
    )
    assert resp["status"] == "ok", resp
    assert resp["command"] == "getaccountrules", resp
    return resp["data"]


def _in_force_view(*args):
    resp = json.loads(
        getrulesinforce.execute(
            "getrulesinforce" + "".join(f" {a}" for a in args),
            types.SimpleNamespace(db=db),
        )
    )
    assert resp["status"] == "ok", resp
    assert resp["command"] == "getrulesinforce", resp
    return resp["data"]


def _apply_fee_chain(tmp_path):
    """ALICE fee rule, BOB fee rule, ALICE non-fee rule; returns the node
    and the three installing transactions' hashes."""
    node = _Node(tmp_path / "node.sqlite")
    _, b1 = node.apply_and_commit(
        [_rule_tx_from("fee-a1", FEE_ALICE, ALICE, SK_ALICE, 0)])
    _, b2 = node.apply_and_commit(
        [_rule_tx_from("fee-b1", FEE_BOB, BOB, SK_BOB, 0)])
    _, b3 = node.apply_and_commit([_rule_tx("o26-1", RULE_O26, seq=1)])
    assert b1.tx_ids and b2.tx_ids and b3.tx_ids
    return node, b1.tx_ids[0], b2.tx_ids[0], b3.tx_ids[0]


# --- end-to-end: join order, senders, naming, exclusion -------------------

def test_fee_rules_lists_o8_units_in_join_order(temp_database, tmp_path):
    """Two guarded fee rules, one per sender, plus a non-fee rule: the
    view lists exactly the two fee units, in the order they joined,
    each with its sender, its since block + tx, and its sha256 over
    the o8 fragment it installed."""
    _apply_fee_chain(tmp_path)

    rows = active_rules.fee_rules_for(ALICE)
    assert len(rows) == 2
    first, second = rows

    assert first["sent_by"] == ALICE
    assert first["names_this_account"] is True
    assert first["since"] == {"block_number": 1, "tx_hash": first["tx_hash"]}
    assert first["status"] == "in_force"
    assert first["displaced_by"] == []
    assert first["sent_by_status"] == "recorded"
    assert "o8[t]:bv[24]" in first["unit"]
    assert first["sha256"] == hashlib.sha256(
        first["unit"].encode("utf-8")).hexdigest()
    assert first["fragments"] == [first["unit"]]

    assert second["sent_by"] == BOB
    assert second["names_this_account"] is False
    assert second["since"]["block_number"] == 2
    assert second["status"] == "in_force"

    # The same rows name BOB when the query names BOB.
    rows_bob = active_rules.fee_rules_for(BOB)
    assert [r["names_this_account"] for r in rows_bob] == [False, True]
    assert [r["sent_by"] for r in rows_bob] == [ALICE, BOB]


def test_non_fee_units_never_appear(temp_database, tmp_path):
    """The o26 unit is accepted and in force -- and absent from
    fee_rules, which is the o8 projection of the ledger, not the
    ledger itself."""
    _apply_fee_chain(tmp_path)
    ledger = active_rules.survival_ledger()
    assert len(ledger) == 3
    assert len(active_rules.fee_rules_for(ALICE)) == 2
    assert all("o8" in row["unit"] for row in active_rules.fee_rules_for())


def test_getactiverules_serves_fee_rules(temp_database, tmp_path):
    """The field rides the rules-in-force view, next to `units`, and
    agrees with the ledger: same senders, same order, same hashes."""
    _, tx_a, tx_b, _ = _apply_fee_chain(tmp_path)
    data = _view(ALICE)
    assert data["available"] is True
    rows = data["fee_rules"]
    assert [r["tx_hash"] for r in rows] == [tx_a, tx_b]
    assert [r["sent_by"] for r in rows] == [ALICE, BOB]
    assert len(data["units"]) == 3
    assert [u["introduced_by_tx"] for u in data["units"]][:2] == [tx_a, tx_b]


def test_getaccountrules_serves_account_rules_and_fee_rules(
        temp_database, tmp_path):
    """The per-account entry point: the account's own rules plus the
    fee rules that can change what it pays -- including the other
    account's fee rule, which names BOB, not ALICE."""
    _apply_fee_chain(tmp_path)
    data = _account_view(ALICE)
    assert data["available"] is True
    assert data["account"] == ALICE
    assert len(data["rules"]) == 1
    assert "o8[t]:bv[24]" in data["rules"][0]
    assert len(data["fee_rules"]) == 2
    assert data["fee_rules"][1]["sent_by"] == BOB
    assert data["fee_rules"][1]["names_this_account"] is False


def test_getaccountrules_rejects_a_bad_account(temp_database, tmp_path):
    resp = json.loads(
        getaccountrules.execute(
            "getaccountrules not-an-account", types.SimpleNamespace(db=db)
        )
    )
    assert resp["status"] == "error", resp


def test_getrulesinforce_is_as_of_the_requested_height(
        temp_database, tmp_path):
    """At height 1 only ALICE's fee rule is known; at height 2 both
    are; the label says as-of, not current-tip -- the ledger at a past
    height is the history known then."""
    _apply_fee_chain(tmp_path)

    at_1 = _in_force_view(1)
    assert at_1["fee_rules_as_of"] == "as of height 1"
    assert [r["sent_by"] for r in at_1["fee_rules"]] == [ALICE]

    at_2 = _in_force_view(2)
    assert at_2["fee_rules_as_of"] == "as of height 2"
    assert [r["sent_by"] for r in at_2["fee_rules"]] == [ALICE, BOB]

    at_tip = _in_force_view()
    assert at_tip["fee_rules_as_of"] == "this block"
    assert [r["sent_by"] for r in at_tip["fee_rules"]] == [ALICE, BOB]


# --- seeded: displacement + unrecorded sender -------------------------------

def _receipt(before, after, outcome="ACCEPTED_CHANGED"):
    return {
        "outcome": outcome,
        "accepted": outcome.startswith("ACCEPTED"),
        "changed": outcome == "ACCEPTED_CHANGED",
        "delivered": True,
        "outputs": {"o0": "F"},
        "spec_revision_before": before,
        "spec_revision_after": after,
    }


def _seed_block(number, tx, previous_hash="00" * 32):
    block = Block.create(
        block_number=number, previous_hash=previous_hash,
        transactions=[tx], proposer_pubkey=ALICE,
        timestamp=GENESIS_TS + number * 10,
    )
    db.add_block(block)
    return block


def _seed_fee_displacement():
    """rev 1: plain o8 fragment A (ALICE's tx). rev 2: the same stream
    rewritten as fragment B (BOB's tx) -- A is displaced by B. rev 3:
    rewritten again as fragment C (a tx this node has no block for) --
    B is displaced by C, and C's sender is unrecorded, never guessed."""
    text_a = "always ( o8[t]:bv[24] = { #x000003 }:bv[24] )."
    text_b = "always ( o8[t]:bv[24] = { #x000005 }:bv[24] )."
    text_c = "always ( o8[t]:bv[24] = { #x000007 }:bv[24] )."
    tx_a = _rule_tx_from("seed-a", RULE_O26, ALICE, SK_ALICE, 0)
    tx_b = _rule_tx_from("seed-b", RULE_O26, BOB, SK_BOB, 0)
    block_a = _seed_block(1, tx_a)
    block_b = _seed_block(2, tx_b, block_a.block_hash)
    hash_a, hash_b = block_a.tx_ids[0], block_b.tx_ids[0]
    hash_c = "c3" * 32  # no block stored for this transaction
    db.record_spec_snapshot(
        1, 1, text_a, active_rules.spec_hash_of(text_a))
    db.record_spec_snapshot(
        2, 2, text_b, active_rules.spec_hash_of(text_b))
    db.record_spec_snapshot(
        3, 3, text_c, active_rules.spec_hash_of(text_c))
    db.record_rule_outcomes(f"{1:064x}", 1, [(hash_a, _receipt(0, 1))])
    db.record_rule_outcomes(f"{2:064x}", 2, [(hash_b, _receipt(1, 2))])
    db.record_rule_outcomes(f"{3:064x}", 3, [(hash_c, _receipt(2, 3))])
    return hash_a, hash_b, hash_c


def test_displaced_fee_rule_stays_listed_with_its_displacer(
        temp_database):
    """The displaced unit is still listed -- with status `displaced`
    and the displacing transaction named -- because a reader who
    cannot tell a live fee rule from a displaced one cannot tell what
    it pays. Its sender is still resolved: displacement does not
    erase attribution."""
    hash_a, hash_b, hash_c = _seed_fee_displacement()
    rows = active_rules.fee_rules_for(ALICE)
    assert len(rows) == 3
    first, second, third = rows
    assert first["tx_hash"] == hash_a
    assert first["status"] == "displaced"
    assert first["displaced_by"] == [hash_b]
    assert first["sent_by"] == ALICE
    assert first["since"] == {"block_number": 1, "tx_hash": hash_a}
    assert second["tx_hash"] == hash_b
    assert second["status"] == "displaced"
    assert second["displaced_by"] == [hash_c]
    assert second["sent_by"] == BOB
    assert third["tx_hash"] == hash_c
    assert third["status"] == "in_force"
    assert third["displaced_by"] == []


def test_unrecorded_sender_reads_null_never_a_guess(temp_database):
    """The third unit's transaction has no stored block on this node:
    `sent_by` is null and `sent_by_status` says so. The row is still
    served -- absence of attribution is not absence of the rule."""
    _, _, hash_c = _seed_fee_displacement()
    rows = active_rules.fee_rules_for(ALICE)
    third = [r for r in rows if r["tx_hash"] == hash_c][0]
    assert third["sent_by"] is None
    assert third["sent_by_status"] == "not_recorded"
    assert third["since"] == {"block_number": 3, "tx_hash": hash_c}


def test_empty_ledger_gives_empty_fee_rules(temp_database):
    """No recorded outcomes at all: fee_rules is an empty list, not
    an error -- the same empty-ledger discipline as survival_ledger."""
    assert active_rules.fee_rules_for(ALICE) == []


# --- CLI formatting ----------------------------------------------------------

def test_cli_fee_rules_format_names_senders_and_status():
    data = {
        "available": True,
        "fee_rules_as_of": "this block",
        "fee_rules": [
            {
                "sha256": "aa" * 32,
                "sent_by": ALICE,
                "names_this_account": True,
                "status": "in_force",
                "since": {"block_number": 1, "tx_hash": "11" * 32},
                "displaced_by": [],
            },
            {
                "sha256": "bb" * 32,
                "sent_by": None,
                "names_this_account": False,
                "status": "displaced",
                "since": {"block_number": 2, "tx_hash": "22" * 32},
                "displaced_by": ["33" * 32],
            },
        ],
    }
    text = _format_fee_rules(data)
    assert "fee rules (o8) of every account" in text
    assert "as of: this block" in text
    assert "aa" * 32 in text
    assert ALICE[:10] in text
    assert "names this account" in text
    assert "[in_force]" in text
    assert "sender not recorded" in text
    assert "[displaced]" in text
    assert ("33" * 32)[:10] in text


def test_cli_fee_rules_format_unavailable():
    text = _format_fee_rules(
        {"available": False, "message": "no spec snapshot recorded yet"})
    assert "not available" in text
    assert "no spec snapshot recorded yet" in text
