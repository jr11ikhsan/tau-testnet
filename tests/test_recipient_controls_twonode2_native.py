"""Bounty 03, issues #47 + #76: recipient controls across TWO nodes — SECOND
scenario (two recipients + follower restart), on the native tau-lang engine.

G4 depth (RIVAL-GAP-AUDIT §6.1/§8). The first two-node file
(test_recipient_controls_twonode_native.py) proves parity for ONE recipient
(allow-list, then a cap tightened 600s -> 300s). This file proves what that
one does not:

  (a) TWO recipients with INDEPENDENT clauses on both nodes: BOB's
      allow-list (admits only ALICE) and MALLORY's cap (600s / 100 blocks).
      A settlement, a park, a refusal and an over-cap refusal for one
      recipient must not move the other's verdicts — per-recipient
      isolation, agreed on both nodes.
  (b) the FOLLOWER RESTARTS as a new process on the same database
      (chain_state.load_state_from_db — the production restart path,
      mirroring the #191 two-node restart proof). Its rule registry
      (accepted_clauses, restored by _restore_rule_offers), escrow
      (restored by _restore_retractables) and balances must answer
      identically after the restart: same head, same balances/sequences/
      escrow, same getrecipientpolicy view for BOTH recipients.

Same harness shape as the first two-node file (two child processes, own
sqlite DB each, same genesis + miner identity, blocks crossing as
Block.to_dict()/from_dict(), ingestion through process_new_block, no live
sockets); the restart child is a third process on the follower's DB.
"""
import json
import os
import pathlib
import subprocess
import sys

import pytest

from bls_keys import SK_ALICE, SK_BOB, SK_MALLORY, pubkey_hex


def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _native_available(), reason="native tau module not built")

_REPO = pathlib.Path(__file__).resolve().parent.parent

SENDER = pubkey_hex(SK_ALICE)
RECIPIENT = pubkey_hex(SK_BOB)
RECIPIENT2 = pubkey_hex(SK_MALLORY)
STRANGER = pubkey_hex(SK_MALLORY)  # MALLORY pays BOB: unlisted there —
# the same key is a capped RECIPIENT on one side and a refused PAYER on
# the other, which is exactly the per-recipient isolation this file pins.

ALLOWLIST_BODY = (
    "(i16[t]:bv[64] = { #x0000 }:bv[64] || "
    "i3[t]:bv[384] = { #x" + SENDER + " }:bv[384]) "
    "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000000 }:bv[24])"
)

CAP_BODY = (
    "((i16[t]:bv[64] = { #x0002 }:bv[64] && i17[t]:bv[64] > { #x0258 }:bv[64]) || "
    "(i16[t]:bv[64] = { #x0003 }:bv[64] && i17[t]:bv[64] > { #x0064 }:bv[64])) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])"
)

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

ROLE = os.environ["TWONODE_ROLE"]
RESTART = os.environ.get("TWONODE_RESTART") == "1"
REPO = os.environ["TWONODE_REPO"]
WORKDIR = os.environ["TWONODE_WORKDIR"]
DB_PATH = os.path.join(WORKDIR, ROLE + ".sqlite")
EVENTS_PATH = os.path.join(WORKDIR, "twonode2_events.json")
OUT_PATH = os.path.join(
    WORKDIR, "twonode2_" + ROLE + ("-restart" if RESTART else "") + ".json")

SENDER = %(SENDER)r
RECIPIENT = %(RECIPIENT)r
RECIPIENT2 = %(RECIPIENT2)r
STRANGER = %(STRANGER)r
ALLOWLIST_BODY = %(ALLOWLIST_BODY)r
CAP_BODY = %(CAP_BODY)r

GENESIS_TAU = os.path.join(REPO, "genesis.tau")
TRANSFER_RULE_PATH = os.path.join(REPO, "rules", "04_handle_valid_transfer.tau")

result = {"role": ROLE, "restart": RESTART, "checkpoints": {},
          "verdicts": {}, "admissions": {}, "ingest": {}, "produced": {},
          "notes": []}


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
    from bls_keys import SK_ALICE, SK_BOB, SK_MALLORY, sign_payload
    from block import Block
    import block as block_mod
    from commands import createblock, getrecipientpolicy, sendtx
    from tau_testnet_cli import tx as cli_tx

    # --- Boot: the first two-node file's setUp, on this child's own DB —
    # except the restart child, which loads the follower's committed
    # state from the same DB instead of genesis + seeding.
    iface = tau_native.TauInterface(GENESIS_TAU)
    config.set_database_path(DB_PATH)
    if not config.MINER_PRIVKEY:
        _priv = config._load_miner_privkey_from_path(
            os.path.join(config.DATA_LOCAL_DIR, "test_miner.key"))
        _pub = config._load_miner_pubkey_from_path(
            os.path.join(config.DATA_LOCAL_DIR, "test_miner.pub"))
        if not _priv or not _pub:
            result["skip"] = (
                "data_local/test_miner.key absent; local miner identity "
                "required for real PoA mining (see config.DATA_LOCAL_DIR)")
            finish(0)
        config.MINER_PRIVKEY = _priv
        config.MINER_PUBKEY = _pub
    if db._db_conn:
        db._db_conn.close()
    db._db_conn = None
    chain_state._balances.clear()
    chain_state._sequence_numbers.clear()
    db.init_db()
    if RESTART:
        if not chain_state.load_state_from_db():
            raise RuntimeError("load_state_from_db failed on restart")
        # The flag is part of the restored lifecycle state; re-activate
        # only if the restore did not carry it (same spec, same audit).
        if not chain_state._lifecycle_manager.recipient_policy_active:
            chain_state._lifecycle_manager.activate_recipient_policy()
    else:
        chain_state.load_genesis("data/genesis.json")
        db.clear_mempool()
        chain_state._balances[SENDER] = 100000
        chain_state._balances[RECIPIENT] = 100000
        chain_state._balances[RECIPIENT2] = 100000
        chain_state._lifecycle_manager.active_validators = {config.MINER_PUBKEY.lower()}
        chain_state._lifecycle_manager.recompute_approval_threshold()
        chain_state._lifecycle_manager.activate_recipient_policy()
    tau_manager.tau_direct_interface = iface
    tau_manager.tau_ready.set()

    def seed_rule(rule_text, label):
        out = tau_manager.communicate_with_tau(
            rule_text=rule_text, target_output_stream_index=0,
            apply_rules_update=False, source="seed-" + label)
        if "error" in str(out).lower():
            raise RuntimeError("seeding " + label + " failed: " + str(out))

    if not RESTART:
        seed_rule(open(TRANSFER_RULE_PATH).read(), "transfer-rule")
        seed_rule(
            chain_state._preprocess_tau_spec_text(
                json.load(open("data/genesis.json"))["consensus_rules"]),
            "genesis-consensus")
    patch.dict("os.environ", {"TAU_FORCE_TEST": "0"}).start()
    patch("commands.createblock._BLS_AVAILABLE", True).start()
    patch("block.bls_signing_available", return_value=True).start()
    patch("consensus.engine.TauConsensusEngine.verify_block_header",
          return_value=True).start()
    patch("consensus.engine.TauConsensusEngine.query_eligibility",
          return_value=True).start()

    # --- Shared helpers.
    def install_clause(recipient, body):
        lm = chain_state._lifecycle_manager
        lm.rule_offers.accepted_clauses[(recipient.lower(), 5)] = body
        with db._db_lock:
            db._insert_clause_rows([{
                "acceptor_pubkey": recipient.lower(),
                "target_stream": 5,
                "clause_body": body,
            }])
            db._db_conn.commit()

    def head_dict():
        return db.get_canonical_head_block()

    def checkpoint(label):
        head = head_dict()
        view_bob = json.loads(getrecipientpolicy.execute(
            "getrecipientpolicy " + RECIPIENT + " " + SENDER
            + " 100 3600 seconds", None))
        view_mallory = json.loads(getrecipientpolicy.execute(
            "getrecipientpolicy " + RECIPIENT2 + " " + RECIPIENT
            + " 100 700 seconds", None))
        result["checkpoints"][label] = {
            "height": int(head["header"]["block_number"]),
            "head_hash": head["block_hash"],
            "state_hash": head["header"]["state_hash"],
            "balances": {a: chain_state._balances.get(a, 0)
                         for a in (SENDER, RECIPIENT, RECIPIENT2)},
            "sequences": {a: chain_state.get_sequence_number(a)
                          for a in (SENDER, RECIPIENT, RECIPIENT2)},
            "escrow": chain_state._lifecycle_manager
                .retractable_transfers.escrow_total(),
            "policy_view_bob": view_bob.get("data"),
            "policy_view_mallory": view_mallory.get("data"),
        }

    def dry_run(candidate):
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

    def verdict_of(res, tx_id):
        return {
            "accepted": sorted(res.accepted_tx_ids),
            "invalid": sorted(res.invalid_tx_ids),
            "reasons": {o.tx_id: o.reason for o in (res.outcomes or [])},
            "next_state_hash": res.next_snapshot.state_hash,
        }

    def ingest_refusal(block_dict, label):
        candidate = Block.from_dict(block_dict)
        res = dry_run(candidate)
        result["verdicts"][label] = verdict_of(res, None)
        result["ingest"][label] = bool(chain_state.process_new_block(candidate))

    # --- Proposer-only production helpers.
    def queue_transfer(sender, to, amount, sk):
        tx = json.dumps(sign_payload({
            "sender_pubkey": sender,
            "sequence_number": chain_state.get_sequence_number(sender),
            "expiration_time": int(time.time()) + 3600,
            "expire_at_height": 5000,
            "operations": {"1": [[sender, to, str(amount)]]},
            "fee_limit": "50",
        }, sk))
        return sendtx.queue_transaction(tx, propagate=False)

    def mine_transfer(label, sender, to, amount, sk):
        res = queue_transfer(sender, to, amount, sk)
        if not res.get("ok"):
            raise RuntimeError(label + ": transfer refused: " + str(res))
        block_res = createblock.create_block_from_mempool()
        result["produced"][label] = {
            "n_tx": len(block_res.get("transactions", [])),
            "raw": str(block_res)[:200],
        }
        if len(block_res.get("transactions", [])) != 1:
            raise RuntimeError(label + ": block did not carry exactly the "
                               "one transfer: " + str(block_res))

    def park_payload(sender, recipient, amount, release_at_time, tx_id=None):
        head = head_dict()
        payload = cli_tx.build_retractable_transfer_tx(
            sender_pubkey=sender,
            sequence_number=chain_state.get_sequence_number(sender),
            expiration_time=int(time.time()) + 3600,
            expire_at_height=int(head["header"]["block_number"]) + 50,
            recipient_pubkey=recipient, amount=amount, fee_limit="1000",
            release_at_time=release_at_time)
        if tx_id is not None:
            payload["tx_id"] = tx_id
        return payload

    def build_refusal_candidate(tx, label):
        head = head_dict()
        height = int(head["header"]["block_number"]) + 1
        ts = int(head["header"]["timestamp"])
        candidate = Block.create(
            block_number=height, previous_hash=head["block_hash"],
            transactions=[tx], proposer_pubkey=config.MINER_PUBKEY,
            timestamp=ts)
        res = dry_run(candidate)
        result["verdicts"][label] = verdict_of(res, None)
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

    if RESTART:
        # The restart proves the committed record, not a replay: one
        # checkpoint at the loaded tip, compared by the parent against
        # the follower's final checkpoint.
        checkpoint("restart")
        finish(0)

    install_clause(RECIPIENT, ALLOWLIST_BODY)
    install_clause(RECIPIENT2, CAP_BODY)

    if ROLE == "proposer":
        events = []

        def emit(ev):
            events.append(ev)

        # (a) Both recipients settle independently.
        mine_transfer("r2_warmup", SENDER, RECIPIENT, 1, SK_ALICE)
        emit({"op": "block", "label": "r2_warmup", "block": head_dict()})
        checkpoint("r2_warmup")
        mine_transfer("r2_settled", SENDER, RECIPIENT, 50, SK_ALICE)
        emit({"op": "block", "label": "r2_settled", "block": head_dict()})
        checkpoint("r2_settled")
        res = sendtx.queue_transaction(json.dumps(sign_payload(
            park_payload(RECIPIENT, RECIPIENT2, 200, int(time.time()) + 200),
            SK_BOB)), propagate=False)
        if not res.get("ok"):
            raise RuntimeError("r2_park: in-cap park refused: " + str(res))
        block_res = createblock.create_block_from_mempool()
        result["produced"]["r2_park"] = {
            "n_tx": len(block_res.get("transactions", [])),
            "raw": str(block_res)[:200]}
        if len(block_res.get("transactions", [])) != 1:
            raise RuntimeError("r2_park: block did not carry the park: "
                               + str(block_res))
        emit({"op": "block", "label": "r2_park", "block": head_dict()})
        checkpoint("r2_park")

        # (a) refusal: MALLORY pays BOB — unlisted for BOB's allow-list.
        res = queue_transfer(STRANGER, RECIPIENT, 100, SK_MALLORY)
        result["admissions"]["r2_refusal_admission"] = {
            "ok": bool(res.get("ok")), "text": str(res)[:400],
            "mempool": len(db.get_mempool_txs())}
        emit({"op": "admission", "label": "r2_refusal_admission"})
        checkpoint("r2_refusal_admission")
        tx = sign_payload({
            "tx_id": "twonode2-unlisted",
            "sender_pubkey": STRANGER,
            "sequence_number": chain_state.get_sequence_number(STRANGER),
            "expiration_time": int(time.time()) + 3600,
            "expire_at_height": 5000,
            "operations": {"1": [[STRANGER, RECIPIENT, "100"]]},
            "fee_limit": "50",
        }, SK_MALLORY)
        candidate = build_refusal_candidate(tx, "r2_refusal_apply")
        result["ingest"]["r2_refusal_apply"] = bool(
            chain_state.process_new_block(candidate))
        emit({"op": "refusal", "label": "r2_refusal_apply",
              "tx_id": "twonode2-unlisted", "block": candidate.to_dict()})
        checkpoint("r2_refusal_apply")

        # (a) over-cap: BOB parks 700s at MALLORY (cap 600) — refused at
        # admission carrying the verified cap, and at apply on both nodes.
        res = sendtx.queue_transaction(json.dumps(sign_payload(
            park_payload(RECIPIENT, RECIPIENT2, 100, int(time.time()) + 700),
            SK_BOB)), propagate=False)
        details = res.get("details") or {}
        policy = details.get("recipient_policy") or {}
        result["admissions"]["r2_overcap_admission"] = {
            "ok": bool(res.get("ok")), "text": str(res)[:600],
            "max_hold_seconds": policy.get("max_hold_seconds"),
            "mempool": len(db.get_mempool_txs())}
        emit({"op": "admission", "label": "r2_overcap_admission"})
        checkpoint("r2_overcap_admission")
        head = head_dict()
        tx = sign_payload(park_payload(
            RECIPIENT, RECIPIENT2, 100,
            int(head["header"]["timestamp"]) + 700,
            tx_id="twonode2-overcap-park"), SK_BOB)
        candidate = build_refusal_candidate(tx, "r2_overcap_apply")
        result["ingest"]["r2_overcap_apply"] = bool(
            chain_state.process_new_block(candidate))
        emit({"op": "refusal", "label": "r2_overcap_apply",
              "tx_id": "twonode2-overcap-park",
              "block": candidate.to_dict()})
        checkpoint("r2_overcap_apply")

        # Final plain transfer, then final parity is the parent's
        # checkpoint comparison.
        mine_transfer("r2_final", SENDER, RECIPIENT, 7, SK_ALICE)
        emit({"op": "block", "label": "r2_final", "block": head_dict()})
        checkpoint("r2_final")

        with open(EVENTS_PATH, "w") as fh:
            json.dump({"events": events}, fh, indent=1, sort_keys=True,
                      default=str)
    else:
        with open(EVENTS_PATH) as fh:
            events = json.load(fh)["events"]
        for ev in events:
            op, label = ev["op"], ev["label"]
            if op == "block":
                blk = Block.from_dict(ev["block"])
                result["ingest"][label] = bool(
                    chain_state.process_new_block(blk))
            elif op == "refusal":
                ingest_refusal(ev["block"], label)
            elif op == "admission":
                pass  # admission is proposer-side; the checkpoint records
                      # this node's untouched state at the same point.
            else:
                raise RuntimeError("unknown op " + op)
            checkpoint(label)
    finish(0)


try:
    main()
except Exception:
    result["error"] = traceback.format_exc()
    finish(3)
'''


def _child_src() -> str:
    return _CHILD_SRC % {
        "SENDER": SENDER, "RECIPIENT": RECIPIENT, "RECIPIENT2": RECIPIENT2,
        "STRANGER": STRANGER,
        "ALLOWLIST_BODY": ALLOWLIST_BODY, "CAP_BODY": CAP_BODY,
    }


def _run_child(tmp_path, role, restart=False):
    tag = f"{role}-restart" if restart else role
    script = tmp_path / f"twonode2_child_{tag}.py"
    script.write_text(_child_src())
    env = dict(os.environ)
    env["TWONODE_ROLE"] = role
    env["TWONODE_REPO"] = str(_REPO)
    env["TWONODE_WORKDIR"] = str(tmp_path)
    env["TAU_FORCE_TEST"] = "0"
    if restart:
        env["TWONODE_RESTART"] = "1"
    env["PYTHONPATH"] = os.pathsep.join(
        [str(_REPO), str(_REPO / "tests"), env.get("PYTHONPATH", "")])
    proc = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True, text=True, env=env, cwd=str(_REPO), timeout=600,
    )
    out_file = tmp_path / f"twonode2_{tag}.json"
    assert out_file.exists(), (
        f"{tag} child wrote no record (rc={proc.returncode})\n"
        f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")
    record = json.loads(out_file.read_text())
    return proc, record


def _assert_child_ok(proc, record, role):
    if record.get("skip"):
        pytest.skip(f"{role} child skipped: {record['skip']}")
    assert "error" not in record, (
        f"{role} child failed:\n{record.get('error')}\n"
        f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")


def test_recipient_controls_two_node_two_recipients_and_restart(tmp_path):
    """Two nodes, two recipients, one restart: the recipient gate's
    verdicts are identical on proposer and follower at every checkpoint,
    per recipient independently — and identical again after the follower
    restarts on its committed database, on the real engine."""
    proc_p, prop = _run_child(tmp_path, "proposer")
    _assert_child_ok(proc_p, prop, "proposer")
    proc_f, foll = _run_child(tmp_path, "follower")
    _assert_child_ok(proc_f, foll, "follower")
    proc_r, rest = _run_child(tmp_path, "follower", restart=True)
    _assert_child_ok(proc_r, rest, "follower-restart")
    assert rest["restart"] is True

    for label, ok in sorted(foll["ingest"].items()):
        assert ok, f"follower failed to ingest {label}"
    for label, ok in sorted(prop["ingest"].items()):
        assert ok, f"proposer failed to ingest {label}"
    for label, produced in sorted(prop["produced"].items()):
        assert produced["n_tx"] == 1, f"proposer's {label} block: {produced}"

    # Checkpoint streams identical on both nodes at every point.
    assert prop["checkpoints"].keys() == foll["checkpoints"].keys()
    for label in prop["checkpoints"]:
        assert prop["checkpoints"][label] == foll["checkpoints"][label], (
            f"checkpoint {label} diverges:\nproposer={prop['checkpoints'][label]}"
            f"\nfollower={foll['checkpoints'][label]}")

    cp = prop["checkpoints"]

    # (a) BOB's allow-list settled 50 (1 warmup + 50 + 7 final), and the
    # park moved 200 into escrow for MALLORY — independently.
    assert (cp["r2_settled"]["balances"][RECIPIENT]
            - cp["r2_warmup"]["balances"][RECIPIENT]) == 50
    assert cp["r2_park"]["escrow"] - cp["r2_settled"]["escrow"] == 200
    # The pre-flight views agree from the first checkpoint: BOB admits
    # the listed payer; MALLORY refuses a 700s park, carrying cap 600.
    assert cp["r2_warmup"]["policy_view_bob"]["evaluation"]["admitted"] is True
    assert cp["r2_warmup"]["policy_view_mallory"]["evaluation"][
        "admitted"] is False
    assert cp["r2_warmup"]["policy_view_mallory"]["evaluation"][
        "max_hold_seconds"] == 600

    # Refusal of the unlisted payer: admission on the proposer, apply on
    # both nodes, no fee, no sequence, nothing moved (height +1 only).
    adm = prop["admissions"]["r2_refusal_admission"]
    assert adm["ok"] is False, adm
    assert "recipient" in adm["text"].lower(), adm
    assert adm["mempool"] == 0, adm
    for record in (prop, foll):
        verdict = record["verdicts"]["r2_refusal_apply"]
        assert verdict["invalid"] == ["twonode2-unlisted"], verdict
        assert verdict["reasons"] == {
            "twonode2-unlisted": "recipient_policy_block"}, verdict
    assert prop["verdicts"]["r2_refusal_apply"] == \
        foll["verdicts"]["r2_refusal_apply"]
    assert cp["r2_refusal_apply"]["balances"] == \
        cp["r2_refusal_admission"]["balances"]
    assert cp["r2_refusal_apply"]["sequences"] == \
        cp["r2_refusal_admission"]["sequences"]
    assert cp["r2_refusal_apply"]["escrow"] == \
        cp["r2_refusal_admission"]["escrow"]
    assert cp["r2_refusal_apply"]["height"] == \
        cp["r2_refusal_admission"]["height"] + 1

    # Over-cap refusal: admission carries the verified 600 cap; apply
    # refuses identically on both nodes; escrow untouched.
    adm_c = prop["admissions"]["r2_overcap_admission"]
    assert adm_c["ok"] is False, adm_c
    assert "RECIPIENT_MAX_HOLD" in adm_c["text"], adm_c
    assert adm_c["max_hold_seconds"] == 600, adm_c
    assert adm_c["mempool"] == 0, adm_c
    for record in (prop, foll):
        verdict = record["verdicts"]["r2_overcap_apply"]
        assert verdict["invalid"] == ["twonode2-overcap-park"], verdict
        assert verdict["reasons"].get("twonode2-overcap-park"), verdict
    assert prop["verdicts"]["r2_overcap_apply"] == \
        foll["verdicts"]["r2_overcap_apply"]
    assert cp["r2_overcap_apply"]["escrow"] == \
        cp["r2_overcap_admission"]["escrow"]
    assert cp["r2_overcap_apply"]["height"] == \
        cp["r2_overcap_admission"]["height"] + 1

    # Final height: genesis + warmup + settled + park + dead refusal +
    # dead over-cap + final = 6.
    assert cp["r2_final"]["height"] == 6, cp["r2_final"]

    # (b) Restart: the restarted follower answers the final checkpoint
    # identically — same head, balances, sequences, escrow, and both
    # recipients' policy views — from the committed record alone.
    assert rest["checkpoints"]["restart"] == foll["checkpoints"]["r2_final"], (
        f"restart diverges:\nrestart={rest['checkpoints']['restart']}"
        f"\nfollower-final={foll['checkpoints']['r2_final']}")
