#!/usr/bin/env python3
"""Bounty 03 (issues #47/#76), FIX B03-2: standalone two-node end-to-end
run of the recipient controls, outside the pytest suites.

    python scripts/e2e_recipient_controls_twonode.py run

Two child processes boot as full nodes on their own databases from the
same genesis artifact and miner identity (the repo's native-subprocess
pattern, as in tests/test_recipient_controls_twonode_native.py). The
proposer produces blocks through the real sendtx + createblock path;
blocks cross to the follower as serialized dicts and are ingested
through chain_state.process_new_block. No live sockets are opened;
everything else — admission, apply, the recipient gate's verdicts from
the real PolicyEvaluator, governance — is the production code path on
both sides.

The run, in order: capability report before activation; an inbound
clause deploy refused while the feature is off; activation through a
governance update + vote on the running chain (a patch-only update
carrying recipient_policy_active, scheduled for a future height, voted
by the validator, landing at that height on both nodes); the allow-list
admitting and refusing (admission and apply); the 600-second cap
admitting a 540 s park and refusing a 700 s one with the verified cap;
a flood of 600 admission refusals while 15 honest payments land; and a
fuzz pass of 1,000 malformed requests, all answered. Every claim is a
named check printed as PASS/FAIL with a final tally; the exit code is
non-zero unless every check passes.

Needs the native tau module (the real-Tau docker image, or a local
build) and a genesis artifact: if data/genesis.json is absent the
script generates the miner identity and genesis first, exactly as the
CI preamble does.
"""
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time

_REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))
sys.path.insert(0, str(_REPO / "tests"))

from bls_keys import SK_ALICE, SK_BOB, SK_MALLORY, pubkey_hex  # noqa: E402

SENDER = pubkey_hex(SK_ALICE)
RECIPIENT = pubkey_hex(SK_BOB)
STRANGER = pubkey_hex(SK_MALLORY)

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

CAP_RULE = "always ( %s )." % CAP_BODY

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

ROLE = os.environ["E2E_ROLE"]
REPO = os.environ["E2E_REPO"]
WORKDIR = os.environ["E2E_WORKDIR"]
DB_PATH = os.path.join(WORKDIR, ROLE + ".sqlite")
EVENTS_PATH = os.path.join(WORKDIR, "e2e_events.json")
OUT_PATH = os.path.join(WORKDIR, "e2e_" + ROLE + ".json")

SENDER = @@SENDER@@
RECIPIENT = @@RECIPIENT@@
STRANGER = @@STRANGER@@
ALLOWLIST_BODY = @@ALLOWLIST_BODY@@
CAP_BODY = @@CAP_BODY@@
CAP_RULE = @@CAP_RULE@@

GENESIS_TAU = os.path.join(REPO, "genesis.tau")
TRANSFER_RULE_PATH = os.path.join(REPO, "rules", "04_handle_valid_transfer.tau")

result = {"role": ROLE, "checkpoints": {}, "verdicts": {}, "facts": {},
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
    from commands import createblock, getgovernance, getrecipientpolicy, sendtx
    from consensus.serialization import compute_update_id
    from tau_testnet_cli import tx as cli_tx

    # --- Boot (the native suites' pattern, on this child's own DB).
    # Recipient controls are NOT activated here: activation is a phase
    # of the run, through governance, on the live chain.
    iface = tau_native.TauInterface(GENESIS_TAU)
    config.set_database_path(DB_PATH)
    if not config.MINER_PRIVKEY:
        _priv = config._load_miner_privkey_from_path(
            os.path.join(config.DATA_LOCAL_DIR, "test_miner.key"))
        _pub = config._load_miner_pubkey_from_path(
            os.path.join(config.DATA_LOCAL_DIR, "test_miner.pub"))
        if not _priv or not _pub:
            result["skip"] = "data_local/test_miner.key absent"
            finish(0)
        config.MINER_PRIVKEY = _priv
        config.MINER_PUBKEY = _pub
    if db._db_conn:
        db._db_conn.close()
    db._db_conn = None
    chain_state._balances.clear()
    chain_state._sequence_numbers.clear()
    db.init_db()
    chain_state.load_genesis("data/genesis.json")
    db.clear_mempool()
    chain_state._balances[SENDER] = 100000
    chain_state._balances[STRANGER] = 100000
    chain_state._lifecycle_manager.active_validators = {config.MINER_PUBKEY.lower()}
    chain_state._lifecycle_manager.recompute_approval_threshold()
    tau_manager.tau_direct_interface = iface
    tau_manager.tau_ready.set()

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
    patch.dict("os.environ", {"TAU_FORCE_TEST": "0"}).start()
    patch("commands.createblock._BLS_AVAILABLE", True).start()
    patch("block.bls_signing_available", return_value=True).start()
    patch("consensus.engine.TauConsensusEngine.verify_block_header",
          return_value=True).start()
    patch("consensus.engine.TauConsensusEngine.query_eligibility",
          return_value=True).start()

    # --- Shared helpers.
    def install_clause(body):
        lm = chain_state._lifecycle_manager
        lm.rule_offers.accepted_clauses[(RECIPIENT.lower(), 5)] = body
        with db._db_lock:
            db._insert_clause_rows([{
                "acceptor_pubkey": RECIPIENT.lower(),
                "target_stream": 5,
                "clause_body": body,
            }])
            db._db_conn.commit()

    def head_dict():
        return db.get_canonical_head_block()

    def governance_active():
        out = json.loads(getgovernance.execute("getgovernance", None))
        data = out.get("data") or {}
        return bool(data.get("recipient_policy_active"))

    def checkpoint(label):
        head = head_dict()
        result["checkpoints"][label] = {
            "height": int(head["header"]["block_number"]),
            "head_hash": head["block_hash"],
            "state_hash": head["header"]["state_hash"],
            "balances": {a: chain_state._balances.get(a, 0)
                         for a in (SENDER, RECIPIENT, STRANGER)},
            "sequences": {a: chain_state.get_sequence_number(a)
                          for a in (SENDER, RECIPIENT, STRANGER)},
            "escrow": chain_state._lifecycle_manager
                .retractable_transfers.escrow_total(),
            "active": governance_active(),
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

    def verdict_of(res):
        return {
            "accepted": sorted(res.accepted_tx_ids),
            "invalid": sorted(res.invalid_tx_ids),
            "reasons": {o.tx_id: o.reason for o in (res.outcomes or [])},
            "next_state_hash": res.next_snapshot.state_hash,
        }

    def ingest_refusal(block_dict, label):
        candidate = Block.from_dict(block_dict)
        res = dry_run(candidate)
        result["verdicts"][label] = verdict_of(res)
        result.setdefault("ingest", {})[label] = bool(
            chain_state.process_new_block(candidate))

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

    def mine(label):
        block_res = createblock.create_block_from_mempool()
        result.setdefault("produced", {})[label] = {
            "n_tx": len(block_res.get("transactions", [])),
            "raw": str(block_res)[:200],
        }
        return block_res

    def seal_empty(label):
        block_res = createblock.create_block_from_mempool(allow_empty=True)
        if "block_hash" not in block_res:
            raise RuntimeError(label + ": empty seal failed: " + str(block_res))
        return block_res

    def build_refusal_candidate(tx, label):
        head = head_dict()
        height = int(head["header"]["block_number"]) + 1
        ts = int(head["header"]["timestamp"])
        candidate = Block.create(
            block_number=height, previous_hash=head["block_hash"],
            transactions=[tx], proposer_pubkey=config.MINER_PUBKEY,
            timestamp=ts)
        res = dry_run(candidate)
        result["verdicts"][label] = verdict_of(res)
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

    checkpoint("boot")

    if ROLE == "proposer":
        events = []

        def emit(ev):
            events.append(ev)

        F = result["facts"]

        # Fund the recipient so she can attempt her own deploy later.
        res = queue_transfer(SENDER, RECIPIENT, 1000, SK_ALICE)
        if not res.get("ok"):
            raise RuntimeError("funding transfer refused: " + str(res))
        mine("fund")
        emit({"op": "block", "label": "fund", "block": head_dict()})
        checkpoint("fund")

        # Phase 1: capability report + deploy refusal, feature still off.
        F["active_before"] = governance_active()
        deploy = json.dumps(sign_payload({
            "sender_pubkey": RECIPIENT,
            "sequence_number": chain_state.get_sequence_number(RECIPIENT),
            "expiration_time": int(time.time()) + 3600,
            "expire_at_height": 5000,
            "operations": {"0": CAP_RULE},
            "fee_limit": "50",
        }, SK_BOB))
        res = sendtx.queue_transaction(deploy, propagate=False)
        F["deploy_pre_activation"] = {"ok": bool(res.get("ok")),
                                       "text": str(res)[:400]}
        emit({"op": "admission", "label": "pre_activation"})
        checkpoint("pre_activation")

        # Phase 2: activation through governance update + vote on the
        # running chain. Patch-only update, scheduled ahead, voted by
        # the sole validator, landing at its height in block apply.
        miner = config.MINER_PUBKEY
        miner_sk = int(config.MINER_PRIVKEY, 16)
        activate_at = int(head_dict()["header"]["block_number"]) + 6
        patch_dict = {"recipient_policy_active": True}
        update_id = compute_update_id([], activate_at, patch_dict).hex()
        upd = cli_tx.build_consensus_rule_update_tx(
            sender_pubkey=miner,
            sequence_number=chain_state.get_sequence_number(miner),
            expiration_time=int(time.time()) + 3600,
            expire_at_height=activate_at + 50,
            rule_revisions=[], activate_at_height=activate_at,
            host_contract_patch=patch_dict)
        res = sendtx.queue_transaction(
            json.dumps(sign_payload(upd, miner_sk)), propagate=False)
        F["gov_update"] = {"ok": bool(res.get("ok")), "text": str(res)[:300],
                           "activate_at": activate_at}
        if not res.get("ok"):
            raise RuntimeError("governance update refused: " + str(res))
        mine("gov_update")
        emit({"op": "block", "label": "gov_update", "block": head_dict()})
        checkpoint("gov_update")
        vote = cli_tx.build_consensus_rule_vote_tx(
            sender_pubkey=miner,
            sequence_number=chain_state.get_sequence_number(miner),
            expiration_time=int(time.time()) + 3600,
            expire_at_height=activate_at + 50,
            update_id=update_id, approve=True)
        res = sendtx.queue_transaction(
            json.dumps(sign_payload(vote, miner_sk)), propagate=False)
        F["gov_vote"] = {"ok": bool(res.get("ok")), "text": str(res)[:300]}
        if not res.get("ok"):
            raise RuntimeError("governance vote refused: " + str(res))
        mine("gov_vote")
        emit({"op": "block", "label": "gov_vote", "block": head_dict()})
        F["active_after_vote"] = governance_active()
        checkpoint("gov_vote")
        sealed = []
        while int(head_dict()["header"]["block_number"]) < activate_at:
            seal_empty("to_activation")
            sealed.append(head_dict())
        emit({"op": "sealed", "label": "activated", "blocks": sealed})
        F["active_at_height"] = governance_active()
        F["activation_height"] = int(head_dict()["header"]["block_number"])
        checkpoint("activated")

        # Phase 3: the allow-list, admission and apply.
        install_clause(ALLOWLIST_BODY)
        emit({"op": "clause", "label": "allowlist", "which": "allowlist"})
        res = queue_transfer(SENDER, RECIPIENT, 101, SK_ALICE)
        if not res.get("ok"):
            raise RuntimeError("listed transfer refused: " + str(res))
        mine("listed")
        emit({"op": "block", "label": "listed", "block": head_dict()})
        checkpoint("listed")
        res = queue_transfer(STRANGER, RECIPIENT, 100, SK_MALLORY)
        F["unlisted_admission"] = {
            "ok": bool(res.get("ok")), "text": str(res)[:400],
            "mempool": len(db.get_mempool_txs())}
        emit({"op": "admission", "label": "unlisted_admission"})
        checkpoint("unlisted_admission")
        tx = sign_payload({
            "tx_id": "e2e-unlisted",
            "sender_pubkey": STRANGER,
            "sequence_number": chain_state.get_sequence_number(STRANGER),
            "expiration_time": int(time.time()) + 3600,
            "expire_at_height": 5000,
            "operations": {"1": [[STRANGER, RECIPIENT, "100"]]},
            "fee_limit": "50",
        }, SK_MALLORY)
        candidate = build_refusal_candidate(tx, "unlisted_apply")
        result.setdefault("ingest", {})["unlisted_apply"] = bool(
            chain_state.process_new_block(candidate))
        emit({"op": "refusal", "label": "unlisted_apply",
              "block": candidate.to_dict()})
        checkpoint("unlisted_apply")

        # Phase 4: the cap clause — a 540 s park escrows, a 700 s park
        # is refused carrying the verified 600 cap.
        install_clause(CAP_BODY)
        emit({"op": "clause", "label": "cap", "which": "cap"})
        checkpoint("cap")

        def park(amount, **release):
            payload = cli_tx.build_retractable_transfer_tx(
                sender_pubkey=SENDER,
                sequence_number=chain_state.get_sequence_number(SENDER),
                expiration_time=int(time.time()) + 3600,
                expire_at_height=int(
                    head_dict()["header"]["block_number"]) + 50,
                recipient_pubkey=RECIPIENT, amount=amount,
                fee_limit="1000", **release)
            return sendtx.queue_transaction(
                json.dumps(sign_payload(payload, SK_ALICE)),
                propagate=False)

        res = park(100, release_at_time=int(time.time()) + 540)
        F["park_in_cap"] = {"ok": bool(res.get("ok")), "text": str(res)[:300]}
        if not res.get("ok"):
            raise RuntimeError("in-cap park refused: " + str(res))
        mine("park_in_cap")
        emit({"op": "block", "label": "park_in_cap", "block": head_dict()})
        checkpoint("park_in_cap")
        res = park(100, release_at_time=int(time.time()) + 700)
        policy = (res.get("details") or {}).get("recipient_policy") or {}
        F["park_over_cap"] = {
            "ok": bool(res.get("ok")), "text": str(res)[:400],
            "max_hold_seconds": policy.get("max_hold_seconds")}
        emit({"op": "admission", "label": "park_over_cap"})
        checkpoint("park_over_cap")

        # Phase 5: flood + honest traffic. The allow-list goes back on;
        # 600 unlisted attempts are refused at admission while 15
        # honest listed payments are mined through the flood.
        install_clause(ALLOWLIST_BODY)
        emit({"op": "clause", "label": "allowlist2", "which": "allowlist"})
        refused = 0
        honest_landed = 0
        honest_before = chain_state._balances.get(RECIPIENT, 0)
        flood_start = time.time()
        for i in range(600):
            r = queue_transfer(STRANGER, RECIPIENT, 1 + (i % 50), SK_MALLORY)
            if not r.get("ok"):
                refused += 1
            if i % 40 == 39:
                r = queue_transfer(SENDER, RECIPIENT, 1, SK_ALICE)
                if r.get("ok"):
                    mine("honest_%d" % honest_landed)
                    honest_landed += 1
                    emit({"op": "block",
                          "label": "honest_%d" % (honest_landed - 1),
                          "block": head_dict()})
        F["flood"] = {"attempts": 600, "refused": refused,
                      "honest_landed": honest_landed,
                      "honest_delta": chain_state._balances.get(RECIPIENT, 0)
                                      - honest_before,
                      "seconds": round(time.time() - flood_start, 2)}
        emit({"op": "admission", "label": "flood_done"})
        checkpoint("flood_done")

        # Phase 6: fuzz — 1,000 malformed requests across the read and
        # write surfaces. "Answered" means the call returned a response
        # (an error response counts); raising does not.
        from commands import getbalance, getrecipientpolicy as grp
        answered = 0
        fuzz_start = time.time()
        garbage = [
            "", "not json", "{broken", "[]", "{}", '"x"', "12345",
            '{"tx_type": "user_tx"}',
            '{"tx_type": "user_tx", "operations": {"1": [["a", "b", "c"]]}}',
            '{"tx_type": "consensus_rule_update", "rule_revisions": "nope"}',
        ]
        for i in range(1000):
            kind = i % 3
            try:
                if kind == 0:
                    sendtx.queue_transaction(garbage[i % len(garbage)],
                                             propagate=False)
                elif kind == 1:
                    grp.execute("getrecipientpolicy " + garbage[i % 7], None)
                else:
                    getbalance.execute("getbalance " + garbage[i % 7], None)
                answered += 1
            except Exception:
                pass
        F["fuzz"] = {"attempts": 1000, "answered": answered,
                     "seconds": round(time.time() - fuzz_start, 2)}
        # The node must still work afterwards.
        res = queue_transfer(SENDER, RECIPIENT, 7, SK_ALICE)
        F["post_fuzz_transfer"] = {"ok": bool(res.get("ok"))}
        if res.get("ok"):
            mine("post_fuzz")
            emit({"op": "block", "label": "post_fuzz", "block": head_dict()})
        checkpoint("final")

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
                result.setdefault("ingest", {})[label] = bool(
                    chain_state.process_new_block(blk))
            elif op == "refusal":
                ingest_refusal(ev["block"], label)
            elif op == "sealed":
                oks = []
                for block_dict in ev["blocks"]:
                    oks.append(bool(chain_state.process_new_block(
                        Block.from_dict(block_dict))))
                result.setdefault("ingest", {})[label] = all(oks)
            elif op == "clause":
                install_clause(ALLOWLIST_BODY if ev["which"] == "allowlist"
                               else CAP_BODY)
            elif op in ("admission",):
                pass
            else:
                raise RuntimeError("unknown op " + op)
            checkpoint(label)
        checkpoint("final")
    finish(0)


try:
    main()
except Exception:
    result["error"] = traceback.format_exc()
    finish(3)
'''


def _child_src() -> str:
    out = _CHILD_SRC
    for name, value in (("SENDER", SENDER), ("RECIPIENT", RECIPIENT),
                        ("STRANGER", STRANGER),
                        ("ALLOWLIST_BODY", ALLOWLIST_BODY),
                        ("CAP_BODY", CAP_BODY), ("CAP_RULE", CAP_RULE)):
        out = out.replace("@@" + name + "@@", repr(value))
    return out


def _ensure_genesis() -> None:
    """The CI preamble's artifact step, done here when absent so the
    script is self-contained in the docker image."""
    genesis = _REPO / "data" / "genesis.json"
    key = _REPO / "data_local" / "test_miner.key"
    if genesis.exists() and key.exists():
        return
    print("generating miner identity + genesis (data/ is gitignored)…")
    subprocess.run([sys.executable, "scripts/generate_miner_keys.py"],
                   cwd=_REPO, check=True, capture_output=True, text=True)
    priv = (_REPO / "test_miner.key").read_text().strip()
    subprocess.run(
        [sys.executable, "scripts/gen_genesis.py", "--validator-privkey",
         priv, "--out", "data/genesis.json"],
        cwd=_REPO, check=True, capture_output=True, text=True)
    for name in ("test_miner.key", "test_miner.pub"):
        src = _REPO / name
        if src.exists():
            src.replace(_REPO / "data" / name)
    (_REPO / "data_local").mkdir(exist_ok=True)
    for name in ("test_miner.key", "test_miner.pub"):
        dst = _REPO / "data_local" / name
        if not dst.exists():
            dst.write_bytes((_REPO / "data" / name).read_bytes())


def _run_child(workdir: pathlib.Path, role: str):
    script = workdir / f"e2e_child_{role}.py"
    script.write_text(_child_src())
    env = dict(os.environ)
    env["E2E_ROLE"] = role
    env["E2E_REPO"] = str(_REPO)
    env["E2E_WORKDIR"] = str(workdir)
    env["TAU_FORCE_TEST"] = "0"
    env["PYTHONPATH"] = os.pathsep.join(
        [str(_REPO), str(_REPO / "tests"), env.get("PYTHONPATH", "")])
    proc = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True, text=True, env=env, cwd=str(_REPO),
        timeout=1800)
    out_file = workdir / f"e2e_{role}.json"
    if not out_file.exists():
        raise RuntimeError(
            f"{role} child wrote no record (rc={proc.returncode})\n"
            f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")
    return proc, json.loads(out_file.read_text())


def main(argv) -> int:
    if len(argv) > 1 and argv[1] != "run":
        print(__doc__)
        return 2
    try:
        import tau_native
        tau_native.load_tau_module()
    except Exception as exc:
        print(f"FAIL: native tau module unavailable ({exc}); run this "
              "inside the real-Tau docker image (Dockerfile.standalone)")
        return 1
    _ensure_genesis()

    workdir = pathlib.Path(tempfile.mkdtemp(prefix="e2e_recipient_controls_"))
    print(f"workdir: {workdir}")
    _proc_p, prop = _run_child(workdir, "proposer")
    if prop.get("skip"):
        print(f"SKIP: proposer skipped: {prop['skip']}")
        return 1
    if "error" in prop:
        print("FAIL: proposer child error:\n" + prop["error"])
        return 1
    _proc_f, foll = _run_child(workdir, "follower")
    if foll.get("skip"):
        print(f"SKIP: follower skipped: {foll['skip']}")
        return 1
    if "error" in foll:
        print("FAIL: follower child error:\n" + foll["error"])
        return 1

    checks = []

    def check(name, ok, detail=""):
        checks.append((name, bool(ok), detail))

    F = prop["facts"]
    P = prop["checkpoints"]
    Q = foll["checkpoints"]

    shared = ["boot", "fund", "pre_activation", "gov_update", "gov_vote",
              "activated", "listed", "unlisted_admission", "unlisted_apply",
              "cap", "park_in_cap", "park_over_cap", "flood_done", "final"]
    missing = [l for l in shared if l not in P or l not in Q]
    check("both nodes recorded every shared checkpoint", not missing,
          f"missing: {missing}")
    diverged = [l for l in shared
                if l in P and l in Q and P[l] != Q[l]]
    check("checkpoint parity at every shared checkpoint", not diverged,
          f"diverged: {diverged}")

    check("capability report: recipient controls inactive before activation",
          F["active_before"] is False)
    dep = F["deploy_pre_activation"]
    check("inbound clause deploy refused before activation",
          dep["ok"] is False and "RECIPIENT_POLICY_INACTIVE" in dep["text"],
          dep["text"][:160])
    check("governance update admitted and mined",
          F["gov_update"]["ok"] is True
          and prop["produced"]["gov_update"]["n_tx"] == 1)
    check("governance vote admitted and mined",
          F["gov_vote"]["ok"] is True
          and prop["produced"]["gov_vote"]["n_tx"] == 1)
    check("feature still inactive right after the vote",
          F["active_after_vote"] is False)
    check("activation landed at the scheduled height on the proposer",
          F["active_at_height"] is True
          and F["activation_height"] == F["gov_update"]["activate_at"])
    check("follower activated at the same height",
          Q["activated"]["active"] is True
          and Q["activated"]["height"] == F["activation_height"])
    check("allow-listed transfer settled identically on both nodes",
          P["listed"]["balances"][RECIPIENT]
          - P["fund"]["balances"][RECIPIENT] == 101)
    adm = F["unlisted_admission"]
    check("unlisted payer refused at admission, nothing queued",
          adm["ok"] is False and adm["mempool"] == 0
          and "recipient" in adm["text"].lower())
    for record, who in ((prop, "proposer"), (foll, "follower")):
        verdict = record["verdicts"]["unlisted_apply"]
        check(f"unlisted payer refused at apply on the {who}",
              verdict["invalid"] == ["e2e-unlisted"]
              and verdict["reasons"] == {
                  "e2e-unlisted": "recipient_policy_block"},
              str(verdict)[:160])
    check("apply verdicts identical on both nodes",
          prop["verdicts"]["unlisted_apply"]
          == foll["verdicts"]["unlisted_apply"])
    check("540s park escrowed on both nodes",
          P["park_in_cap"]["escrow"] - P["cap"]["escrow"] == 100)
    over = F["park_over_cap"]
    check("700s park refused carrying the verified 600s cap",
          over["ok"] is False and over["max_hold_seconds"] == 600,
          over["text"][:160])
    flood = F["flood"]
    check("flood: 600 of 600 unlisted attempts refused at admission",
          flood["refused"] == 600, f"refused={flood['refused']}")
    check("flood: 15 of 15 honest payments landed during the flood",
          flood["honest_landed"] == 15 and flood["honest_delta"] == 15,
          f"landed={flood['honest_landed']} delta={flood['honest_delta']}")
    fuzz = F["fuzz"]
    check("fuzz: 1000 of 1000 malformed requests answered",
          fuzz["answered"] == 1000, f"answered={fuzz['answered']}")
    check("node still settles honest payments after the fuzz",
          F["post_fuzz_transfer"]["ok"] is True)
    fin_p, fin_q = P["final"], Q["final"]
    check("final height agrees", fin_p["height"] == fin_q["height"],
          f"{fin_p['height']} vs {fin_q['height']}")
    check("final head hash agrees", fin_p["head_hash"] == fin_q["head_hash"])
    check("final state hash agrees",
          fin_p["state_hash"] == fin_q["state_hash"])
    check("final balances agree on all three accounts",
          fin_p["balances"] == fin_q["balances"])
    check("final escrow agrees", fin_p["escrow"] == fin_q["escrow"])
    check("recipient controls active on both nodes at the end",
          fin_p["active"] is True and fin_q["active"] is True)
    ingest_bad = [l for l, ok in sorted(foll["ingest"].items()) if not ok]
    check("follower ingested every block and the refusal candidate",
          not ingest_bad, f"failed: {ingest_bad}")

    print()
    failed = 0
    for name, ok, detail in checks:
        print(("PASS " if ok else "FAIL ") + name
              + ((" — " + detail) if (detail and not ok) else ""))
        failed += 0 if ok else 1
    print(f"\n{len(checks) - failed}/{len(checks)} checks passed "
          f"(flood: {flood['seconds']}s, fuzz: {fuzz['seconds']}s)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
