#!/usr/bin/env python3
"""Bounty 01: the wide two-node end-to-end proof, run as a CI step.

FIX 4 (AUDIT-JIMB158-160, SPESIFIKASI PERBAIKAN 4): our Bounty 01
two-node evidence was narrow — one exact-numbers grant case (named
case 5) inside the SA-5 fork-CI run. This script widens it to the
breadth the consolidated rival scripts claim, but keeps every number
inside a public CI run whose log anyone can open: it is executed as
its own step of the fork CI workflow, and its output (the check tally
and both nodes' final state roots) lands in that run's log.

One timeline, two real node processes (proposer + follower, each on
its OWN sqlite database, booted from the same genesis artifact and
miner identity exactly as the native suites boot), three phases:

  Phase 1 (fresh boots): every state change goes through a REAL
  transaction inside a block — no direct book installs:
    1. create_standing_payment (daily 250, max 2 occurrences)
    2. install_receive_route: recipient routes 20% to a destination
    3. install_receive_route: the destination routes 50% onward
    4. an ordinary 101 transfer to the recipient — the seam splits it
       81 / 20, and the routed 20 must NOT be re-routed (scenario b)
    5. execute_standing_payment #1, by a third party (scenario a, 1/2)
    6. create_grant 4,000 releasing 1,000/week
    7. draw_grant 1,000 by a third party
  RESTART: both processes exit. Phase 2 boots are NEW processes on
  the same databases, through the node's own restart path (the
  server.py startup restore: load the persisted state, restore the
  persisted Tau spec, then rebuild_state_from_blockchain(0) — a full
  replay from block 0, which is also how the Bounty 01 books are
  recovered: they have no tables of their own, their state is carried
  by the blocks). The post-restart checkpoint must equal the
  pre-restart one exactly, on both nodes (scenarios a and d).
  Phase 2 (after the restart):
    8. an empty block advancing the chain clock one day
    9. execute_standing_payment #2 — the standing authorization has
       now been paid twice, the second time after a node restart,
       and ends at its occurrence cap (scenario a, 2/2)
   10. an empty block at the grant deadline: the sweep refunds
       exactly 3,000 to the funder, fee-free, and both nodes agree
       the state root at that checkpoint (scenario c)
  Phase 3: both nodes restart once more (load + restore + replay
  from block 0) and their checkpoints must still equal the final
  phase-2 checkpoint — replay from block 0 plus a restart lands on
  the identical root (scenario d).

The scenario funding (100,000 / 1,000) is folded into the genesis
account mirrors every boot, fresh or restart, so a replay from
block 0 starts from the identical funded genesis on every node —
the replay-determinism harness's own device. Blocks are hand-built
after the timeline leaves the wall clock, with the miner's own
header computation (a dry-run of engine.apply_block, the resulting
state hash embedded, the proof signed with the miner key), because
createblock stamps wall time. Blocks cross between the processes as
serialized dicts (Block.to_dict()/from_dict(), the codebase's wire
format); the follower ingests through chain_state.process_new_block.
No live sockets are opened. The calendar is compressed into block
timestamps — the only clock the books ever read — and the ingestion
future-drift bound is widened in the children through the codebase's
own env knob (TAU_MAX_BLOCK_FUTURE_DRIFT), exactly as the existing
two-node native suite discloses for its scenario.
"""
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time

_REPO = pathlib.Path(__file__).resolve().parent.parent

# --- Child harness ------------------------------------------------------------
# One script, two roles (TWONODE_ROLE=proposer|follower), three phases
# (TWONODE_PHASE=1|2|3). Each child boots a complete node on its own
# database (fresh in phase 1; the restart path in phases 2-3), then
# either produces the op stream (proposer) or replays it (follower).
# Both record checkpoints, apply verdicts, admissions and ingestion
# results as JSON; the parent compares the records and counts checks.
# The child os._exit()s after writing its record — the native engine
# segfaults on interpreter teardown (the replay-determinism harness's
# documented reason).
_CHILD_SRC = r'''
import hashlib
import json
import os
import sys
import time
import traceback
from unittest.mock import patch

os.environ["TAU_ENV"] = "test"
os.environ["TAU_FORCE_TEST"] = "0"
# The scenario's blocks run up to four weeks ahead of the wall clock;
# widen the ingestion future-drift bound through config's own env knob
# BEFORE config is imported anywhere in this process.
os.environ["TAU_MAX_BLOCK_FUTURE_DRIFT"] = "6048000"

ROLE = os.environ["TWONODE_ROLE"]
PHASE = int(os.environ["TWONODE_PHASE"])
REPO = os.environ["TWONODE_REPO"]
WORKDIR = os.environ["TWONODE_WORKDIR"]
T0 = int(os.environ["TWONODE_T0"])
DB_PATH = os.path.join(WORKDIR, ROLE + ".sqlite")
OUT_PATH = os.path.join(
    WORKDIR, "record_" + ROLE + "_p" + str(PHASE) + ".json")

PAYER = %(PAYER)r
RECIPIENT = %(RECIPIENT)r
EXECUTOR = %(EXECUTOR)r
SECOND_HOP = %(SECOND_HOP)r

DAY = 86400
WEEK = 604800
DEADLINE = T0 + 4 * WEEK
TX_EXPIRY = T0 + 60 * DAY

GENESIS_TAU = os.path.join(REPO, "genesis.tau")
TRANSFER_RULE_PATH = os.path.join(REPO, "rules", "04_handle_valid_transfer.tau")

result = {"role": ROLE, "phase": PHASE, "checkpoints": {}, "verdicts": {},
          "admissions": {}, "ingest": {}, "notes": []}


def note(msg):
    result["notes"].append(str(msg))
    print("NOTE " + str(msg))
    sys.stdout.flush()


def finish(code=0):
    with open(OUT_PATH, "w") as fh:
        json.dump(result, fh, indent=1, sort_keys=True, default=str)
    sys.stdout.flush()
    os._exit(code)


def main():
    import config
    import chain_state
    import db
    import tau_manager
    import tau_native
    from bls_keys import SK_ALICE, SK_BOB, SK_CAROL, sign_payload
    from block import Block
    import block as block_mod
    from commands import createblock, sendtx
    from consensus.grants import GrantEntry
    from consensus.standing_payments import (
        SCHEDULE_DAILY, SCHEDULE_WEEKLY, StandingPaymentEntry)

    GRANT_ID = GrantEntry(
        funder_pubkey=PAYER, beneficiary_pubkey=RECIPIENT,
        total_amount=4000, release_per_period=1000,
        schedule_kind=SCHEDULE_WEEKLY, signed_day=0,
        start_ts=T0, deadline_ts=DEADLINE,
        locked_until_ts=0, window_start_ts=0, window_end_ts=0,
        inactivity_seconds=0, version=1,
    ).grant_id

    AUTH_ID = StandingPaymentEntry(
        payer_pubkey=PAYER, recipient_pubkey=RECIPIENT, amount=250,
        schedule_kind=SCHEDULE_DAILY, signed_day=0, anchor_ts=T0,
        window_seconds=43200, final_ts=0, max_occurrences=2,
        max_total=0, fee_limit=0, policy_version_ref=0,
        allow_catch_up=False, version=1,
    ).auth_id

    # --- Process-wide patches (the native suites' set): the subject is
    # state agreement, not consensus-proof verification.
    patch.dict("os.environ", {"TAU_FORCE_TEST": "0"}).start()
    patch("commands.createblock._BLS_AVAILABLE", True).start()
    patch("block.bls_signing_available", return_value=True).start()
    patch("consensus.engine.TauConsensusEngine.verify_block_header",
          return_value=True).start()
    patch("consensus.engine.TauConsensusEngine.query_eligibility",
          return_value=True).start()

    def load_miner_identity():
        if config.MINER_PRIVKEY:
            return True
        _priv = config._load_miner_privkey_from_path(
            os.path.join(config.DATA_LOCAL_DIR, "test_miner.key"))
        _pub = config._load_miner_pubkey_from_path(
            os.path.join(config.DATA_LOCAL_DIR, "test_miner.pub"))
        if not _priv or not _pub:
            result["skip"] = (
                "data_local/test_miner.key absent; local miner identity "
                "required for real PoA mining (see config.DATA_LOCAL_DIR)")
            return False
        config.MINER_PRIVKEY = _priv
        config.MINER_PUBKEY = _pub
        return True

    def seed_rules(iface):
        def seed_rule(rule_text, label):
            out = tau_manager.communicate_with_tau(
                rule_text=rule_text, target_output_stream_index=0,
                apply_rules_update=False, source="seed-" + label)
            if "error" in str(out).lower():
                raise RuntimeError("seeding " + label + " failed: " + str(out))
        seed_rule(open(TRANSFER_RULE_PATH).read(), "transfer-rule")
        seed_rule(
            chain_state._preprocess_tau_spec_text(
                json.load(open("data/genesis.json"))["consensus_rules"]),
            "genesis-consensus")

    def boot_fresh():
        iface = tau_native.TauInterface(GENESIS_TAU)
        config.set_database_path(DB_PATH)
        if not load_miner_identity():
            finish(0)
        if db._db_conn:
            db._db_conn.close()
        db._db_conn = None
        chain_state._balances.clear()
        chain_state._sequence_numbers.clear()
        db.init_db()
        chain_state.load_genesis("data/genesis.json")
        db.clear_mempool()
        # Scenario funding, folded into the genesis account mirrors as
        # well, so a replay from block 0 on any later boot starts from
        # the identical funded genesis.
        chain_state._balances[PAYER] = 100000
        chain_state._balances[EXECUTOR] = 1000
        chain_state._genesis_accounts_state[PAYER] = 100000
        chain_state._genesis_accounts_state[EXECUTOR] = 1000
        chain_state._lifecycle_manager.active_validators = set(
            chain_state._genesis_active_validators)
        chain_state._lifecycle_manager.recompute_approval_threshold()
        tau_manager.tau_direct_interface = iface
        tau_manager.tau_ready.set()
        seed_rules(iface)

    def boot_restart():
        # The node's own restart path (server.py's startup restore):
        # load the persisted state, restore the persisted Tau spec
        # into a fresh interpreter, then rebuild from block 0 — the
        # replay that also recovers the Bounty 01 books, whose state
        # is carried by the blocks themselves.
        iface = tau_native.TauInterface(GENESIS_TAU)
        config.set_database_path(DB_PATH)
        if not load_miner_identity():
            finish(0)
        if db._db_conn:
            db._db_conn.close()
        db._db_conn = None
        db.init_db()
        chain_state.load_genesis("data/genesis.json")
        chain_state._genesis_accounts_state[PAYER] = 100000
        chain_state._genesis_accounts_state[EXECUTOR] = 1000
        tau_manager.tau_direct_interface = iface
        tau_manager.tau_ready.set()
        persisted = chain_state.get_persisted_full_tau_spec()
        if persisted:
            tau_manager.restore_full_tau_spec(persisted)
        else:
            seed_rules(iface)
        res = chain_state.rebuild_state_from_blockchain(0)
        result["rebuild"] = {
            "ok": bool(res.ok),
            "stopped_at": str(getattr(res, "stopped_at_block", None)),
            "reason": str(getattr(res, "reason", "")),
        }
        if not res.ok:
            raise RuntimeError("restart rebuild failed: " + str(res))
        db.clear_mempool()

    # --- Shared helpers.
    def head_dict():
        return db.get_canonical_head_block()

    def standing_view():
        book = chain_state._lifecycle_manager.standing_payments
        try:
            count, total = book.total_executed(AUTH_ID)
            facts = [{"period": f.period_index, "amount": f.amount}
                     for f in book.facts_for(AUTH_ID)]
            head = head_dict()
            status = book.status(AUTH_ID, int(head["header"]["timestamp"]))
        except Exception:
            return None
        return {"total_executed": [count, total], "facts": facts,
                "status": status}

    def routes_view():
        book = chain_state._lifecycle_manager.receive_routes

        def one(owner):
            e = book.get(owner)
            if e is None:
                return None
            return {"destination": e.destination_pubkey, "bps": e.bps}
        return {"recipient": one(RECIPIENT), "destination": one(EXECUTOR)}

    def grant_view():
        book = chain_state._lifecycle_manager.grants
        if book.grant_count() == 0:
            return None
        head = head_dict()
        return {
            "accounting": book.accounting(GRANT_ID),
            "status": book.status(GRANT_ID, int(head["header"]["timestamp"])),
            "held_total": book.held_total(),
        }

    def checkpoint(label):
        head = head_dict()
        result["checkpoints"][label] = {
            "height": int(head["header"]["block_number"]),
            "head_hash": head["block_hash"],
            "state_hash": head["header"]["state_hash"],
            "balances": {a: chain_state._balances.get(a, 0)
                         for a in (PAYER, RECIPIENT, EXECUTOR, SECOND_HOP)},
            "sequences": {a: chain_state.get_sequence_number(a)
                          for a in (PAYER, EXECUTOR)},
            "standing": standing_view(),
            "routes": routes_view(),
            "grant": grant_view(),
        }

    def dry_run(candidate):
        """engine.apply_block on a candidate, with the interpreter
        save/restore createblock itself performs around its simulation."""
        from consensus.engine import TauConsensusEngine
        from consensus.state import TauStateSnapshot, compute_consensus_state_hash
        engine = TauConsensusEngine()
        app_rules = (chain_state._application_rules_state or "").encode("utf-8")
        cons_rules = (chain_state._consensus_rules_state or "").encode("utf-8")
        acc_hash = chain_state.compute_accounts_hash(
            chain_state._balances, chain_state._sequence_numbers)
        meta_hash = chain_state._lifecycle_manager.consensus_meta_hash()
        parent_snapshot = TauStateSnapshot(
            state_hash=compute_consensus_state_hash(
                cons_rules, app_rules, acc_hash, meta_hash),
            tau_bytes=app_rules,
            metadata={
                "source": "chain_state",
                "balances": chain_state._balances,
                "sequence_numbers": chain_state._sequence_numbers,
                "last_transfer_ts": chain_state._last_transfer_ts,
                "lifecycle_manager": chain_state._lifecycle_manager,
                "active_consensus_id": chain_state._active_consensus_id,
                "consensus_rules_state": chain_state._consensus_rules_state,
            })
        active_view = engine.derive_active_consensus(
            parent_snapshot, candidate.header.block_number)
        saved_app_rules = chain_state.get_application_rules_state()
        try:
            saved_db_full_spec = db.get_chain_state_value("full_tau_spec", "")
        except Exception:
            saved_db_full_spec = None
        saved_full_spec = None
        try:
            _iface = tau_manager.tau_direct_interface
            if _iface is not None and hasattr(_iface, "get_current_spec"):
                saved_full_spec = _iface.get_current_spec()
        except Exception:
            saved_full_spec = None
        if saved_full_spec is None:
            saved_full_spec = tau_manager.last_known_tau_spec
        try:
            saved_shrunk = tau_manager.get_runtime_shrunk_streams()
        except Exception:
            saved_shrunk = None
        try:
            return engine.apply_block(active_view, candidate, parent_snapshot)
        finally:
            if saved_full_spec is not None:
                try:
                    tau_manager.restore_full_tau_spec(
                        saved_full_spec, runtime_shrunk_streams=saved_shrunk)
                except Exception:
                    pass
            chain_state.save_application_rules_state(saved_app_rules)
            if saved_db_full_spec is not None:
                try:
                    db.set_chain_state_value("full_tau_spec", saved_db_full_spec)
                except Exception:
                    pass

    def record_verdict(label, res):
        md = res.next_snapshot.metadata or {}
        grant_events = [{
            "action": e.get("action"), "amount": e.get("amount"),
            "funder": e.get("funder_pubkey"),
            "grant_id": e.get("grant_id")}
            for e in (md.get("grant_events") or [])]
        result["verdicts"][label] = {
            "accepted": sorted(res.accepted_tx_ids),
            "invalid": sorted(res.invalid_tx_ids),
            "reasons": {o.tx_id: o.reason for o in (res.outcomes or [])},
            "next_state_hash": res.next_snapshot.state_hash,
            "routing_events": len(md.get("routing_events") or []),
            "standing_events": len(md.get("standing_payment_events") or []),
            "grant_events": grant_events,
        }

    def build_block(txs, ts, label):
        """Dry-run the candidate on this node's state, embed the
        resulting state hash (the real miner's header computation), sign
        the proof with the miner key as createblock does."""
        head = head_dict()
        height = int(head["header"]["block_number"]) + 1
        candidate = Block.create(
            block_number=height, previous_hash=head["block_hash"],
            transactions=txs, proposer_pubkey=config.MINER_PUBKEY,
            timestamp=ts)
        res = dry_run(candidate)
        record_verdict(label, res)
        candidate.header.state_hash = res.next_snapshot.state_hash
        candidate.header.state_locator = (
            config.STATE_LOCATOR_NAMESPACE + ":" + res.next_snapshot.state_hash)
        candidate.block_hash = block_mod.sha256_hex(
            candidate.header.canonical_bytes())
        from py_ecc.bls import G2Basic
        msg_hash = hashlib.sha256(candidate.header.canonical_bytes()).digest()
        sig = G2Basic.Sign(int(config.MINER_PRIVKEY, 16), msg_hash)
        candidate.consensus_proof = sig.hex()
        return candidate

    def ingest(block_dict, label):
        """Follower path: dry-run the imported candidate on THIS node's
        state, then ingest the identical bytes through the standard
        ingestion path."""
        candidate = Block.from_dict(block_dict)
        res = dry_run(candidate)
        record_verdict(label, res)
        result["ingest"][label] = bool(chain_state.process_new_block(candidate))

    # --- Proposer-only production helpers.
    def queue_and_fetch(payload, label):
        res = sendtx.queue_transaction(json.dumps(payload), propagate=False)
        result["admissions"][label] = {
            "ok": bool(res.get("ok")), "text": str(res)[:400]}
        if not res.get("ok"):
            raise RuntimeError(label + ": refused at admission: " + str(res))
        tx_id = payload["tx_id"]
        for raw in db.get_mempool_txs():
            tx = json.loads(raw)
            if tx.get("tx_id") == tx_id:
                return tx
        raise RuntimeError(label + ": admitted tx not found in mempool")

    def produce(label, txs, ts):
        candidate = build_block(txs, ts, label)
        result["ingest"][label] = bool(chain_state.process_new_block(candidate))
        db.clear_mempool()
        return candidate

    def base_tx(tx_id, tx_type, sender):
        tx = {
            "tx_id": tx_id,
            "sender_pubkey": sender,
            "sequence_number": chain_state.get_sequence_number(sender),
            "expiration_time": TX_EXPIRY,
            "expire_at_height": 5000,
            "fee_limit": "1000",
        }
        if tx_type is not None:
            tx["tx_type"] = tx_type
        return tx

    def sp_create_tx():
        tx = base_tx("fix4-sp-create", "create_standing_payment", PAYER)
        tx.update({
            "standing_recipient_pubkey": RECIPIENT,
            "standing_amount": 250,
            "standing_schedule": "daily",
            "standing_signed_day": 0,
            "standing_anchor_ts": T0,
            "standing_window_seconds": 43200,
            "standing_final_ts": 0,
            "standing_max_occurrences": 2,
            "standing_max_total": 0,
            "standing_fee_limit": 0,
            "standing_policy_version_ref": 0,
            "standing_allow_catch_up": 0,
            "standing_version": 1,
        })
        return sign_payload(tx, SK_ALICE)

    def route_tx(tx_id, owner, destination, bps, sk):
        tx = base_tx(tx_id, "install_receive_route", owner)
        tx.update({
            "route_destination_pubkey": destination,
            "route_bps": bps,
            "route_min_amount": 0,
            "route_activation_ts": 0,
            "route_expiry_ts": 0,
            "route_locked_until_ts": 0,
            "route_version": 1,
        })
        return sign_payload(tx, sk)

    def transfer_tx():
        tx = base_tx("fix4-route-pay", None, PAYER)
        tx["operations"] = {"1": [[PAYER, RECIPIENT, "101"]]}
        tx["fee_limit"] = "50"
        return sign_payload(tx, SK_ALICE)

    def sp_exec_tx(n):
        tx = base_tx("fix4-sp-exec-" + str(n), "execute_standing_payment",
                     EXECUTOR)
        tx["standing_auth_id"] = AUTH_ID.hex()
        tx["fee_limit"] = "50"
        return sign_payload(tx, SK_CAROL)

    def grant_create_tx():
        tx = base_tx("fix4-grant-create", "create_grant", PAYER)
        tx.update({
            "grant_beneficiary_pubkey": RECIPIENT,
            "grant_total_amount": 4000,
            "grant_release_per_period": 1000,
            "grant_schedule": "weekly",
            "grant_signed_day": 0,
            "grant_start_ts": T0,
            "grant_deadline_ts": DEADLINE,
            "grant_locked_until_ts": 0,
            "grant_window_start_ts": 0,
            "grant_window_end_ts": 0,
            "grant_inactivity_seconds": 0,
            "grant_version": 1,
        })
        return sign_payload(tx, SK_ALICE)

    def grant_draw_tx():
        tx = base_tx("fix4-grant-draw-1", "draw_grant", EXECUTOR)
        tx["grant_id"] = GRANT_ID.hex()
        tx["grant_draw_amount"] = 1000
        tx["fee_limit"] = "50"
        return sign_payload(tx, SK_CAROL)

    def emit(events, label, candidate):
        """Producer: record the block for the follower and checkpoint
        THIS node's state at exactly this point of the timeline."""
        events.append({"op": "block", "label": label,
                       "block": candidate.to_dict()})
        checkpoint(label)

    def write_events(events_path, events):
        with open(events_path, "w") as fh:
            json.dump({"events": events}, fh, indent=1, sort_keys=True,
                      default=str)

    def replay_events(events_path):
        with open(events_path) as fh:
            events = json.load(fh)["events"]
        for ev in events:
            if ev["op"] != "block":
                raise RuntimeError("unknown op " + ev["op"])
            ingest(ev["block"], ev["label"])
            checkpoint(ev["label"])

    EVENTS_P1 = os.path.join(WORKDIR, "events_p1.json")
    EVENTS_P2 = os.path.join(WORKDIR, "events_p2.json")

    if PHASE == 1:
        boot_fresh()
        checkpoint("boot")
        if ROLE == "proposer":
            events = []
            tx = queue_and_fetch(sp_create_tx(), "sp_create")
            emit(events, "sp_create", produce("sp_create", [tx], T0))
            tx = queue_and_fetch(
                route_tx("fix4-route-bob", RECIPIENT, EXECUTOR, 2000, SK_BOB),
                "route_bob")
            emit(events, "route_bob", produce("route_bob", [tx], T0 + 5))
            tx = queue_and_fetch(
                route_tx("fix4-route-carol", EXECUTOR, SECOND_HOP, 5000,
                         SK_CAROL),
                "route_carol")
            emit(events, "route_carol",
                 produce("route_carol", [tx], T0 + 6))
            tx = queue_and_fetch(transfer_tx(), "route_pay")
            emit(events, "route_pay", produce("route_pay", [tx], T0 + 20))
            tx = queue_and_fetch(sp_exec_tx(1), "sp_exec1")
            emit(events, "sp_exec1", produce("sp_exec1", [tx], T0 + 30))
            tx = queue_and_fetch(grant_create_tx(), "grant_create")
            emit(events, "grant_create",
                 produce("grant_create", [tx], T0 + 40))
            tx = queue_and_fetch(grant_draw_tx(), "grant_draw1")
            emit(events, "grant_draw1",
                 produce("grant_draw1", [tx], T0 + 50))
            write_events(EVENTS_P1, events)
        else:
            replay_events(EVENTS_P1)
    elif PHASE == 2:
        boot_restart()
        checkpoint("restarted")
        if ROLE == "proposer":
            events = []
            emit(events, "advance_day",
                 produce("advance_day", [], T0 + DAY + 10))
            tx = queue_and_fetch(sp_exec_tx(2), "sp_exec2")
            emit(events, "sp_exec2",
                 produce("sp_exec2", [tx], T0 + DAY + 10))
            emit(events, "grant_refund",
                 produce("grant_refund", [], DEADLINE))
            write_events(EVENTS_P2, events)
        else:
            replay_events(EVENTS_P2)
    else:
        boot_restart()
        checkpoint("restarted2")
    finish(0)


try:
    main()
except Exception:
    result["error"] = traceback.format_exc()
    finish(3)
'''


# --- Parent harness -----------------------------------------------------------

sys.path.insert(0, str(_REPO))
sys.path.insert(0, str(_REPO / "tests"))

from bls_keys import SK_ALICE, SK_BOB, SK_CAROL, SK_MALLORY, pubkey_hex

PAYER = pubkey_hex(SK_ALICE)
RECIPIENT = pubkey_hex(SK_BOB)
EXECUTOR = pubkey_hex(SK_CAROL)
SECOND_HOP = pubkey_hex(SK_MALLORY)

P1_LABELS = ("sp_create", "route_bob", "route_carol", "route_pay",
             "sp_exec1", "grant_create", "grant_draw1")
P2_LABELS = ("advance_day", "sp_exec2", "grant_refund")
TX_BY_LABEL = {
    "sp_create": "fix4-sp-create",
    "route_bob": "fix4-route-bob",
    "route_carol": "fix4-route-carol",
    "route_pay": "fix4-route-pay",
    "sp_exec1": "fix4-sp-exec-1",
    "grant_create": "fix4-grant-create",
    "grant_draw1": "fix4-grant-draw-1",
    "sp_exec2": "fix4-sp-exec-2",
}


def _child_src() -> str:
    return _CHILD_SRC % {
        "PAYER": PAYER, "RECIPIENT": RECIPIENT,
        "EXECUTOR": EXECUTOR, "SECOND_HOP": SECOND_HOP,
    }


def _run_child(workdir, role, phase, t0):
    script = workdir / f"bounty01_twonode_child_{role}_p{phase}.py"
    script.write_text(_child_src())
    env = dict(os.environ)
    env["TWONODE_ROLE"] = role
    env["TWONODE_PHASE"] = str(phase)
    env["TWONODE_REPO"] = str(_REPO)
    env["TWONODE_WORKDIR"] = str(workdir)
    env["TWONODE_T0"] = str(t0)
    env["TAU_FORCE_TEST"] = "0"
    env["TAU_MAX_BLOCK_FUTURE_DRIFT"] = "6048000"
    env["PYTHONPATH"] = os.pathsep.join(
        [str(_REPO), str(_REPO / "tests"), env.get("PYTHONPATH", "")])
    proc = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True, text=True, env=env, cwd=str(_REPO),
        timeout=1800,
    )
    out_file = workdir / f"record_{role}_p{phase}.json"
    if not out_file.exists():
        raise RuntimeError(
            f"{role} phase {phase} wrote no record (rc={proc.returncode})\n"
            f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")
    record = json.loads(out_file.read_text())
    if record.get("skip"):
        raise RuntimeError(f"{role} phase {phase} skipped: {record['skip']}")
    if "error" in record:
        raise RuntimeError(
            f"{role} phase {phase} failed:\n{record['error']}\n"
            f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")
    return record


class Checks:
    def __init__(self):
        self.passed = 0
        self.failed = 0

    def __call__(self, name, cond, detail=""):
        n = self.passed + self.failed + 1
        if cond:
            self.passed += 1
            print(f"CHECK {n:02d} PASS {name}")
        else:
            self.failed += 1
            print(f"CHECK {n:02d} FAIL {name} :: {detail}")
        sys.stdout.flush()
        return bool(cond)


def main():
    workdir = pathlib.Path(
        os.environ.get("TWONODE_WORKDIR")
        or tempfile.mkdtemp(prefix="bounty01_twonode_"))
    workdir.mkdir(parents=True, exist_ok=True)
    t0 = int(time.time()) - 3600
    print(f"e2e bounty01 twonode: workdir={workdir} t0={t0}")
    sys.stdout.flush()

    records = {}
    for phase in (1, 2, 3):
        for role in ("proposer", "follower"):
            records[(role, phase)] = _run_child(workdir, role, phase, t0)
            print(f"child done: {role} phase {phase}")
            sys.stdout.flush()

    prop1, foll1 = records[("proposer", 1)], records[("follower", 1)]
    prop2, foll2 = records[("proposer", 2)], records[("follower", 2)]
    prop3, foll3 = records[("proposer", 3)], records[("follower", 3)]

    check = Checks()

    # --- Phase 1: ingestion, admission, verdicts, checkpoint parity.
    for role, rec in (("proposer", prop1), ("follower", foll1)):
        for label in P1_LABELS:
            check(f"p1 {role} ingested {label}",
                  rec["ingest"].get(label) is True, str(rec["ingest"]))
    for label in ("sp_create", "route_bob", "route_carol", "route_pay",
                  "sp_exec1", "grant_create", "grant_draw1"):
        check(f"p1 admission {label} ok",
              prop1["admissions"][label]["ok"] is True,
              str(prop1["admissions"][label]))
    check("p1 verdict label sets equal",
          prop1["verdicts"].keys() == foll1["verdicts"].keys(),
          f"{sorted(prop1['verdicts'])} vs {sorted(foll1['verdicts'])}")
    for label in P1_LABELS:
        check(f"p1 verdict {label} identical on both nodes",
              prop1["verdicts"][label] == foll1["verdicts"][label],
              f"prop={prop1['verdicts'][label]} foll={foll1['verdicts'][label]}")
        v = prop1["verdicts"][label]
        tx_id = TX_BY_LABEL[label]
        check(f"p1 verdict {label} accepted {tx_id}, nothing invalid",
              tx_id in v["accepted"] and v["invalid"] == [], str(v))
    check("p1 checkpoint label sets equal",
          prop1["checkpoints"].keys() == foll1["checkpoints"].keys(),
          f"{sorted(prop1['checkpoints'])} vs {sorted(foll1['checkpoints'])}")
    for label in prop1["checkpoints"]:
        check(f"p1 checkpoint {label} identical on both nodes",
              prop1["checkpoints"][label] == foll1["checkpoints"][label],
              f"prop={prop1['checkpoints'][label]} "
              f"foll={foll1['checkpoints'][label]}")

    cp = prop1["checkpoints"]

    # --- Scenario (b): the 101 payment is split 81/20 by the seam and
    # the routed share is NOT routed again — on either node (the
    # streams above are equal, so the follower's numbers are these).
    before, after = cp["route_carol"]["balances"], cp["route_pay"]["balances"]
    check("route: recipient kept exactly 81 of 101",
          after[RECIPIENT] - before[RECIPIENT] == 81,
          f"delta={after[RECIPIENT] - before[RECIPIENT]}")
    check("route: destination received exactly 20",
          after[EXECUTOR] - before[EXECUTOR] == 20,
          f"delta={after[EXECUTOR] - before[EXECUTOR]}")
    check("route: routed share NOT re-routed (second hop +0)",
          after[SECOND_HOP] - before[SECOND_HOP] == 0,
          f"delta={after[SECOND_HOP] - before[SECOND_HOP]}")
    check("route: exactly one routing event on the payment block",
          prop1["verdicts"]["route_pay"]["routing_events"] == 1
          and foll1["verdicts"]["route_pay"]["routing_events"] == 1,
          f"prop={prop1['verdicts']['route_pay']['routing_events']} "
          f"foll={foll1['verdicts']['route_pay']['routing_events']}")
    check("route: both routes visible in the book view",
          cp["route_pay"]["routes"] == {
              "recipient": {"destination": EXECUTOR, "bps": 2000},
              "destination": {"destination": SECOND_HOP, "bps": 5000}},
          str(cp["route_pay"]["routes"]))

    # --- Scenario (a), first half: standing execution #1 settles.
    before, after = cp["route_pay"]["balances"], cp["sp_exec1"]["balances"]
    check("standing #1: recipient +250",
          after[RECIPIENT] - before[RECIPIENT] == 250,
          f"delta={after[RECIPIENT] - before[RECIPIENT]}")
    check("standing #1: payer -250",
          after[PAYER] - before[PAYER] == -250,
          f"delta={after[PAYER] - before[PAYER]}")
    check("standing #1: book shows (1, 250) and the period-0 fact",
          cp["sp_exec1"]["standing"]["total_executed"] == [1, 250]
          and cp["sp_exec1"]["standing"]["facts"]
          == [{"period": 0, "amount": 250}],
          str(cp["sp_exec1"]["standing"]))

    # --- Grant, first half: custody + one draw of 1,000.
    create_cost = (cp["sp_exec1"]["balances"][PAYER]
                   - cp["grant_create"]["balances"][PAYER])
    check("grant create: funder down by 4,000 custody + fee",
          create_cost > 4000, f"cost={create_cost}")
    check("grant create: book holds the full 4,000",
          cp["grant_create"]["grant"] == {
              "accounting": {"principal": 4000, "drawn": 0, "held": 4000,
                             "refunded": 0},
              "status": "active", "held_total": 4000},
          str(cp["grant_create"]["grant"]))
    draw_delta = (cp["grant_draw1"]["balances"][RECIPIENT]
                  - cp["grant_create"]["balances"][RECIPIENT])
    check("grant draw: beneficiary +1,000 exactly",
          draw_delta == 1000, f"delta={draw_delta}")
    check("grant draw: accounting drawn 1,000 / held 3,000",
          cp["grant_draw1"]["grant"]["accounting"] == {
              "principal": 4000, "drawn": 1000, "held": 3000,
              "refunded": 0},
          str(cp["grant_draw1"]["grant"]))

    # --- The restart (phases 2-3 boot through load + spec restore +
    # replay from block 0): the recovered state must be the state the
    # nodes had when they stopped.
    for role, rec in (("proposer", prop2), ("follower", foll2)):
        check(f"p2 {role} restart rebuild from block 0 ok",
              rec["rebuild"]["ok"] is True, str(rec["rebuild"]))
    final_p1 = cp["grant_draw1"]
    check("restart: proposer state identical after restart+replay",
          prop2["checkpoints"]["restarted"] == final_p1,
          f"restarted={prop2['checkpoints']['restarted']} final={final_p1}")
    check("restart: follower state identical after restart+replay",
          foll2["checkpoints"]["restarted"] == final_p1,
          f"restarted={foll2['checkpoints']['restarted']} final={final_p1}")

    # --- Phase 2: ingestion, verdicts, checkpoint parity.
    for role, rec in (("proposer", prop2), ("follower", foll2)):
        for label in P2_LABELS:
            check(f"p2 {role} ingested {label}",
                  rec["ingest"].get(label) is True, str(rec["ingest"]))
    check("p2 admission sp_exec2 ok",
          prop2["admissions"]["sp_exec2"]["ok"] is True,
          str(prop2["admissions"]["sp_exec2"]))
    for label in P2_LABELS:
        check(f"p2 verdict {label} identical on both nodes",
              prop2["verdicts"][label] == foll2["verdicts"][label],
              f"prop={prop2['verdicts'][label]} foll={foll2['verdicts'][label]}")
    for label in prop2["checkpoints"]:
        if label == "restarted":
            continue
        check(f"p2 checkpoint {label} identical on both nodes",
              prop2["checkpoints"][label] == foll2["checkpoints"][label],
              f"prop={prop2['checkpoints'][label]} "
              f"foll={foll2['checkpoints'][label]}")

    cp2 = prop2["checkpoints"]

    # --- Scenario (a), second half: paid twice, once after a restart,
    # then ended at the signed occurrence cap.
    before, after = cp2["advance_day"]["balances"], cp2["sp_exec2"]["balances"]
    check("standing #2 (after restart): recipient +250",
          after[RECIPIENT] - before[RECIPIENT] == 250,
          f"delta={after[RECIPIENT] - before[RECIPIENT]}")
    check("standing #2 (after restart): payer -250",
          after[PAYER] - before[PAYER] == -250,
          f"delta={after[PAYER] - before[PAYER]}")
    check("standing: book shows (2, 500), facts for periods 0 and 1",
          cp2["sp_exec2"]["standing"]["total_executed"] == [2, 500]
          and cp2["sp_exec2"]["standing"]["facts"] == [
              {"period": 0, "amount": 250}, {"period": 1, "amount": 250}],
          str(cp2["sp_exec2"]["standing"]))
    check("standing: authorization ended at its 2-occurrence cap",
          cp2["sp_exec2"]["standing"]["status"] == "ended",
          str(cp2["sp_exec2"]["standing"]))

    # --- Scenario (c): the deadline block is empty; the sweep refunds
    # exactly 3,000 and both nodes agree the state root (the streams
    # are equal, and the refund checkpoint's state hash is in both).
    refund_delta = (cp2["grant_refund"]["balances"][PAYER]
                    - cp2["sp_exec2"]["balances"][PAYER])
    check("grant refund: funder +3,000 exactly from the empty block",
          refund_delta == 3000, f"delta={refund_delta}")
    check("grant refund: accounting settled, nothing held",
          cp2["grant_refund"]["grant"] == {
              "accounting": {"principal": 4000, "drawn": 1000, "held": 0,
                             "refunded": 3000},
              "status": "refunded", "held_total": 0},
          str(cp2["grant_refund"]["grant"]))
    for role, rec in (("proposer", prop2), ("follower", foll2)):
        events = rec["verdicts"]["grant_refund"]["grant_events"]
        check(f"grant refund: {role} recorded the 3,000 refund event",
              len(events) == 1 and events[0]["action"] == "refunded"
              and events[0]["amount"] == 3000
              and events[0]["funder"] == PAYER,
              str(events))
    check("grant refund: both nodes agree the state root",
          prop2["checkpoints"]["grant_refund"]["state_hash"]
          == foll2["checkpoints"]["grant_refund"]["state_hash"],
          f"prop={prop2['checkpoints']['grant_refund']['state_hash']} "
          f"foll={foll2['checkpoints']['grant_refund']['state_hash']}")
    check("final height is 10 on both nodes",
          cp2["grant_refund"]["height"] == 10
          and foll2["checkpoints"]["grant_refund"]["height"] == 10,
          f"prop={cp2['grant_refund']['height']} "
          f"foll={foll2['checkpoints']['grant_refund']['height']}")

    # --- Scenario (d): a further restart (load + restore + replay
    # from block 0) still lands on the identical root.
    for role, rec in (("proposer", prop3), ("follower", foll3)):
        check(f"p3 {role} restart rebuild from block 0 ok",
              rec["rebuild"]["ok"] is True, str(rec["rebuild"]))
        check(f"p3 {role} state identical after replay + restart",
              rec["checkpoints"]["restarted2"] == cp2["grant_refund"],
              f"restarted2={rec['checkpoints']['restarted2']} "
              f"final={cp2['grant_refund']}")

    total = check.passed + check.failed
    print(f"E2E-BOUNTY01-TWONODE checks: {check.passed}/{total} passed, "
          f"{check.failed} failed")
    print(f"FINAL STATE ROOT proposer: {cp2['grant_refund']['state_hash']}")
    print(f"FINAL STATE ROOT follower: "
          f"{foll2['checkpoints']['grant_refund']['state_hash']}")
    print(f"FINAL HEAD HASH proposer: {cp2['grant_refund']['head_hash']}")
    print(f"FINAL HEAD HASH follower: "
          f"{foll2['checkpoints']['grant_refund']['head_hash']}")
    sys.stdout.flush()
    return 1 if check.failed else 0


if __name__ == "__main__":
    sys.exit(main())
