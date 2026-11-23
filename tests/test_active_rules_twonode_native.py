"""Issue #42 (B02-4): the rules-in-force view across TWO nodes, on the
native tau-lang engine.

Kept in its own file so the real-Tau CI job can register exactly this
file beside tests/test_active_rules_issue42_native.py, in the form the
Bounty 03 two-node suite established: two child processes, each a full
node with its OWN sqlite database, booted from the same genesis
artifact and miner identity. The proposer mines through the real
sendtx + createblock path; blocks cross as serialized dicts
(Block.to_dict / Block.from_dict -- the codebase's block wire format)
and the follower ingests them through chain_state.process_new_block,
the standard import path. No live sockets are opened; everything else
-- admission, apply, the journal, the commits -- is production code on
both sides.

Scenario: the named resend case plus one o5-only unit -- A
(o26 = {7} && o27 = {9}), B (o26 = {3}), A again, then an o5-only
rule -- one block each. Asserted on BOTH nodes, per height:

  * the getactiverules answer (spec hash + revision) from the stored
    snapshots agrees;
  * after the snapshots are wiped on both nodes, the journal-cut
    answer (B02-1) agrees too, carries `derived: "journal_cut"`, and
    at block 3 runs the first unit's terms (o26 = 7, o27 = 9);
  * the per-transaction rule outcomes (the survival ledger) agree;
  * getpaymentconditions (B02-5) for a clause-free pair agrees: same
    block, same spec, both sides neutral, allowed.

Then the follower is RESTARTED as a new process on the same database
(chain_state.load_state_from_db, the production restart path) and must
answer every height identically from the journal cut -- the snapshots
are still wiped -- proving the view is a function of the committed
record, not of any process's memory.
"""
import json
import os
import pathlib
import subprocess
import sys

import pytest


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

RULE_A = ("always ( o26[t]:bv[24] = { 7 }:bv[24] && "
          "o27[t]:bv[24] = { 9 }:bv[24] ).")
RULE_B = "always ( o26[t]:bv[24] = { 3 }:bv[24] )."
RULE_O5 = "always ( o5[t]:bv[24] = { 1 }:bv[24] )."
RULES = [RULE_A, RULE_B, RULE_A, RULE_O5]

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
EVENTS_PATH = os.path.join(WORKDIR, "twonode_events.jsonl")
OUT_PATH = os.path.join(
    WORKDIR, "twonode_" + ROLE + ("-restart" if RESTART else "") + ".json")

RULES = %(RULES)r

result = {"role": ROLE, "restart": RESTART, "answers": {}, "cuts": {},
          "receipts": {}, "heads": {}, "notes": []}


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
    from py_ecc.bls import G2Basic as bls
    from block import Block
    from commands import createblock, getactiverules, getpaymentconditions
    from commands import sendtx
    from commands.sendtx import _get_signing_message_bytes
    from consensus import active_rules
    from types import SimpleNamespace

    iface = tau_native.TauInterface(os.path.join(REPO, "genesis.tau"))
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
    tau_manager.tau_direct_interface = iface
    tau_manager.tau_ready.set()

    sk = bls.KeyGen(b"b02-twonode-sender".ljust(32, b"_"))
    sender = bls.SkToPk(sk).hex()
    stranger = bls.SkToPk(
        bls.KeyGen(b"b02-twonode-stranger".ljust(32, b"_"))).hex()
    result["sender"] = sender
    result["stranger"] = stranger

    if RESTART:
        if not chain_state.load_state_from_db():
            raise RuntimeError("load_state_from_db failed on restart")
    else:
        chain_state.load_genesis("data/genesis.json")
        db.clear_mempool()
        chain_state._balances[sender] = 1000000
        chain_state._lifecycle_manager.active_validators = {
            config.MINER_PUBKEY.lower()}
        chain_state._lifecycle_manager.recompute_approval_threshold()

        def seed_rule(rule_text, label):
            out = tau_manager.communicate_with_tau(
                rule_text=rule_text, target_output_stream_index=0,
                apply_rules_update=False, source="seed-" + label)
            if "error" in str(out).lower():
                raise RuntimeError("seeding " + label + " failed")

        seed_rule(open(os.path.join(
            REPO, "rules", "04_handle_valid_transfer.tau")).read(),
            "transfer-rule")
        seed_rule(chain_state._preprocess_tau_spec_text(
            json.load(open("data/genesis.json"))["consensus_rules"]),
            "genesis-consensus")
        patch.dict("os.environ", {"TAU_FORCE_TEST": "0"}).start()
        patch("commands.createblock._BLS_AVAILABLE", True).start()
        patch("block.bls_signing_available", return_value=True).start()
        patch("consensus.engine.TauConsensusEngine.verify_block_header",
              return_value=True).start()
        patch("consensus.engine.TauConsensusEngine.query_eligibility",
              return_value=True).start()
        patch("consensus.bls.verify", lambda *a, **k: True).start()

    container = SimpleNamespace(db=db, chain_state=chain_state)

    def answer(height):
        data = json.loads(getactiverules.execute(
            "getactiverules " + str(height), container))["data"]
        return {"spec_hash": data.get("spec_hash"),
                "spec_revision": data.get("spec_revision"),
                "derived": data.get("derived"),
                "effective_spec": data.get("effective_spec")}

    def collect_answers():
        tip = db.canonical_tip_height()
        out = {}
        for h in range(1, tip + 1):
            out[str(h)] = answer(h)
        result["heads"]["tip_height"] = tip
        head = db.get_canonical_head_block()
        result["heads"]["tip_hash"] = head["block_hash"] if head else None
        return out

    def collect_receipts():
        out = {}
        for r in active_rules.rule_receipts():
            out.setdefault(str(r["block_height"]), []).append(
                {"tx_hash": r["tx_hash"], "status": r["status"],
                 "outcome": r["outcome"]})
        for key in out:
            out[key].sort(key=lambda e: e["tx_hash"])
        return out

    def payment_probe():
        data = json.loads(getpaymentconditions.execute(
            "getpaymentconditions " + sender + " " + stranger + " 100",
            container))["data"]
        return {"allowed": data["allowed"],
                "block_height": data["block"]["height"],
                "spec_hash": data["spec"]["spec_hash"],
                "sender_has_clause": data["sender_side"]["has_clause"],
                "recipient_has_clause": data["recipient_side"]["has_clause"]}

    def submit(rule_text, seq):
        tx = {"tx_type": "user_tx", "sender_pubkey": sender,
              "sequence_number": seq,
              "expiration_time": int(time.time()) + 3600,
              "expire_at_height": 5000,
              "operations": {"0": rule_text}, "fee_limit": "100000"}
        tx["signature"] = bls.Sign(sk, hashlib.sha256(
            _get_signing_message_bytes(tx)).digest()).hex()
        out = sendtx.queue_transaction(json.dumps(tx), propagate=False)
        if not out.get("ok"):
            raise RuntimeError("queue failed: " + str(out))

    if ROLE == "proposer" and not RESTART:
        with open(EVENTS_PATH, "w") as events:
            for i, rule in enumerate(RULES):
                submit(rule, i)
                out = createblock.create_block_from_mempool()
                if "error" in out:
                    raise RuntimeError("createblock failed: " + str(out))
                head = db.get_canonical_head_block()
                events.write(json.dumps({"block": head}) + "\n")
                events.flush()
    elif ROLE == "follower" and not RESTART:
        with open(EVENTS_PATH) as events:
            for line in events:
                block = Block.from_dict(json.loads(line)["block"])
                res = chain_state.process_new_block(block)
                ok = res[0] if isinstance(res, tuple) else res
                if not ok:
                    raise RuntimeError("ingest failed: " + str(res))

    result["answers"] = collect_answers()
    result["receipts"] = collect_receipts()
    result["payment"] = payment_probe()
    if not RESTART:
        with db._db_lock:
            db._db_conn.execute("DELETE FROM spec_snapshots")
            db._db_conn.commit()
    result["cuts"] = collect_answers()
    finish(0)


try:
    main()
except Exception:
    result["error"] = traceback.format_exc()
    finish(3)
'''


def _run_child(role, workdir, restart=False):
    env = dict(os.environ)
    env["TWONODE_ROLE"] = role
    env["TWONODE_REPO"] = str(_REPO)
    env["TWONODE_WORKDIR"] = str(workdir)
    if restart:
        env["TWONODE_RESTART"] = "1"
    env["PYTHONPATH"] = str(_REPO) + os.pathsep + env.get("PYTHONPATH", "")
    # Child output goes to files, not pipes: if a child has to be killed
    # at the timeout, worker grandchildren holding a pipe open must not
    # be able to keep the parent blocked on pipe EOF.
    tag = f"{role}{'-restart' if restart else ''}"
    stdout_path = workdir / f"twonode_{tag}.stdout"
    stderr_path = workdir / f"twonode_{tag}.stderr"
    with open(stdout_path, "w") as out_fh, open(stderr_path, "w") as err_fh:
        proc = subprocess.run(
            [sys.executable, "-c", _CHILD_SRC % {"RULES": RULES}],
            cwd=str(_REPO), env=env, stdout=out_fh, stderr=err_fh,
            timeout=1800)
    out_name = f"twonode_{role}{'-restart' if restart else ''}.json"
    out_path = workdir / out_name
    stdout = stdout_path.read_text(errors="replace")
    stderr = stderr_path.read_text(errors="replace")
    assert out_path.exists(), (
        f"{role} child wrote no record; rc={proc.returncode}\n"
        f"stdout:\n{stdout}\nstderr:\n{stderr}")
    record = json.loads(out_path.read_text())
    if record.get("skip"):
        pytest.skip(record["skip"])
    assert "error" not in record, (
        f"{role} child failed:\n{record.get('error')}\n"
        f"stdout:\n{stdout}\nstderr:\n{stderr}")
    return record


def test_rules_view_agrees_across_two_nodes(tmp_path):
    proposer = _run_child("proposer", tmp_path)
    follower = _run_child("follower", tmp_path)
    restarted = _run_child("follower", tmp_path, restart=True)

    heights = [str(h) for h in range(1, len(RULES) + 1)]
    # Same head, same snapshot answers, same ledger on both nodes.
    assert proposer["heads"] == follower["heads"]
    for h in heights:
        for key in ("spec_hash", "spec_revision"):
            assert proposer["answers"][h][key] == follower["answers"][h][key]
        assert proposer["receipts"][h] == follower["receipts"][h]
    # The resend case in the ledger: block 2's unit displaced by block 3's.
    assert proposer["receipts"]["2"][0]["status"] == "displaced"
    assert proposer["receipts"]["3"][0]["status"] == "in_force"

    # Journal-cut answers agree across both nodes AND the restarted
    # follower, and run the first unit's terms at block 3.
    for record in (proposer, follower, restarted):
        for h in heights:
            cut = record["cuts"][h]
            assert cut["derived"] == "journal_cut"
            assert cut["spec_hash"] == proposer["answers"][h]["spec_hash"]
            assert cut["spec_revision"] == \
                proposer["answers"][h]["spec_revision"]
    at3 = proposer["cuts"]["3"]["effective_spec"]
    assert "o26[t]:bv[24] = { 7 }:bv[24]" in at3
    assert "o27[t]:bv[24] = { 9 }:bv[24]" in at3
    assert "{ 3 }" not in at3
    at2 = proposer["cuts"]["2"]["effective_spec"]
    assert "o26[t]:bv[24] = { 3 }:bv[24]" in at2

    # Two-sided payment conditions agree on all three processes.
    assert proposer["payment"] == follower["payment"] == \
        restarted["payment"]
    assert proposer["payment"]["allowed"] is True
    assert proposer["payment"]["sender_has_clause"] is False
    assert proposer["payment"]["recipient_has_clause"] is False
