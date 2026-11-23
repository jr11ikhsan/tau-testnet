"""Issue #42: the maintainers' probe on the native tau-lang engine.

Kept in its own file so the real-Tau CI job can register exactly this
file: the probe needs the native bindings, which the mock test job does
not have. The skip below is environment-driven -- in the real-Tau job's
image the bindings are present (its preflight imports them), so the
skip lifts and the probe runs for real. Everywhere else it skips,
exactly as it did when it lived in test_active_rules_issue42.py.
"""
import hashlib
import json
import os
import threading
import time
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from py_ecc.bls import G2Basic as bls

import chain_state
import db
import tau_admission
import tau_authority as auth
import tau_commit as tc
from commands import createblock, getactiverules, sendtx
from commands.sendtx import _get_signing_message_bytes
from consensus import active_rules
from consensus.engine import TauConsensusEngine

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _native_available():
    try:
        from tau_native import load_tau_module

        load_tau_module()
        return True
    except Exception:
        return False


@pytest.mark.skipif(
    not _native_available(),
    reason="native tau-lang bindings not available in this environment",
)
def test_displacement_probe_on_native_engine(tmp_path):
    """The Sep 27 probe on the real engine: two fresh interpreters fed the
    same units must run the same spec (o26 = 3, o27 = 9), with identical
    text and hash -- the determinism premise the snapshot view relies on."""
    from tau_native import TauInterface

    unit1 = ("always ( o26[t]:bv[24] = { 7 }:bv[24] && "
             "o27[t]:bv[24] = { 9 }:bv[24] ).")
    unit2 = "always ( o26[t]:bv[24] = { 3 }:bv[24] )."
    specs = []
    for _ in range(2):
        ti = TauInterface("genesis.tau")
        ti.communicate(rule_text=unit1, target_output_stream_index=0)
        ti.communicate(rule_text=unit2, target_output_stream_index=0)
        specs.append(ti.get_current_spec())
    assert specs[0] == specs[1]
    assert hashlib.sha256(specs[0].encode()).hexdigest() == \
        hashlib.sha256(specs[1].encode()).hexdigest()
    assert "o26" in specs[0] and "{ 3 }" in specs[0]
    assert "{ 7 }" not in specs[0].split("o27")[0]


# --- The same probe in production mode: worker-backed authority ------------
#
# A node outside test mode runs the authoritative worker (server.py:
# authority is enabled unless the mock configuration was requested). The
# in-process interpreter is then only an advisory mirror and is never fed
# the application-rule revisions, and the persisted `full_tau_spec` row is
# the append-only accumulation. The snapshot behind getactiverules must
# still serve the spec the engine runs.

PROBE_A = ("always ( o26[t]:bv[24] = { 7 }:bv[24] && "
           "o27[t]:bv[24] = { 9 }:bv[24] ).")
PROBE_B = "always ( o26[t]:bv[24] = { 3 }:bv[24] )."


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _reset_spec_mirror():
    reset = getattr(active_rules, "reset_spec_mirror", None)
    if reset is not None:
        reset()


@pytest.fixture
def authority(node_state):
    baseline = "always ( " + open(
        os.path.join(REPO, "genesis.tau")).read().strip() + " )."
    owner = auth.AuthoritativeTauOwner(
        ready=threading.Event(), program_baseline=baseline)
    auth.reset(owner)
    tc.registry().discard()
    tau_admission.reset()
    _reset_spec_mirror()
    owner.initialize(cwd=REPO, env=_env())
    yield owner
    _reset_spec_mirror()
    tc.registry().discard()
    tau_admission.reset()
    auth.reset(None)


@pytest.fixture
def _mining_allowed():
    with patch.object(TauConsensusEngine, "query_eligibility",
                      lambda *a, **k: True), \
         patch.object(TauConsensusEngine, "verify_block_header",
                      lambda *a, **k: True), \
         patch("consensus.bls.verify", lambda *a, **k: True):
        yield


def _sender(tag):
    sk = bls.KeyGen(tag.encode().ljust(32, b"_"))
    pk = bls.SkToPk(sk).hex()
    chain_state._balances[pk] = 1_000_000
    return sk, pk


def _submit(sk, pk, ops, seq):
    tx = {"tx_type": "user_tx", "sender_pubkey": pk,
          "sequence_number": seq,
          "expiration_time": int(time.time()) + 3600,
          "expire_at_height": 5000,
          "operations": ops, "fee_limit": "100000"}
    tx["signature"] = bls.Sign(sk, hashlib.sha256(
        _get_signing_message_bytes(tx)).digest()).hex()
    return sendtx.queue_transaction(json.dumps(tx), propagate=False)


def _mine():
    out = createblock.create_block_from_mempool()
    assert "error" not in out, out
    return out


@pytest.mark.skipif(
    not _native_available(),
    reason="native tau-lang bindings not available in this environment",
)
def test_active_rules_view_under_authority(authority, _mining_allowed):
    """The maintainers' probe mined through real blocks with the
    authoritative worker enabled: after `o26 = {7} && o27 = {9}` the
    recorded view runs o26 = 7; after `o26 = {3}` it runs o26 = 3 and
    o27 = 9, with the displaced {7} nowhere in the served text — the
    same answer direct mode gives, from the production configuration."""
    sk, pk = _sender("authority-probe")

    assert _submit(sk, pk, {"0": PROBE_A}, seq=0).get("ok")
    _mine()
    snap = active_rules.resolve_snapshot()
    assert snap is not None, "no snapshot recorded after the first block"
    assert "o26[t]:bv[24] = { 7 }:bv[24]" in snap["spec_text"], \
        snap["spec_text"]
    assert "o27[t]:bv[24] = { 9 }:bv[24]" in snap["spec_text"], \
        snap["spec_text"]

    assert _submit(sk, pk, {"0": PROBE_B}, seq=1).get("ok")
    _mine()
    snap = active_rules.resolve_snapshot()
    assert snap is not None, "no snapshot recorded after the second block"
    text = snap["spec_text"]
    assert "o26[t]:bv[24] = { 3 }:bv[24]" in text, text
    assert "o27[t]:bv[24] = { 9 }:bv[24]" in text, text
    assert "{ 7 }" not in text, text

    container = SimpleNamespace(db=db, chain_state=chain_state)
    data = json.loads(
        getactiverules.execute("getactiverules", container))["data"]
    assert data["effective_spec"] == text
    assert data["spec_hash"] == active_rules.spec_hash_of(text)


# --- B02 follow-ups: the resend case A,B,A and the journal forge ---------
#
# mendhow's #42 thread and kioway-dev's PR #137 both moved on exactly
# this ground -- the resend of a displaced unit, and whether the view
# survives a journal that was altered after the fact. These two tests
# run both cases on the real engine, under the authoritative worker.


def _answer_at(height=None):
    container = SimpleNamespace(db=db, chain_state=chain_state)
    raw = "getactiverules" if height is None else f"getactiverules {height}"
    return json.loads(getactiverules.execute(raw, container))["data"]


@pytest.mark.skipif(
    not _native_available(),
    reason="native tau-lang bindings not available in this environment",
)
def test_resend_a_b_a_under_authority(authority, _mining_allowed):
    """Send A (o26 = {7} && o27 = {9}), then B (o26 = {3}), then A again,
    one block each. The view at block 3 runs the first unit's terms
    again -- the resend is a new revision, not an accumulation replay
    (which would end at [A, B] with o26 = 3) -- and the ledger names
    the resend as B's displacer. Then the snapshots are wiped and the
    same heights must be answered from the journal cut (B02-1), with
    identical text and hash, marked derived."""
    sk, pk = _sender("authority-resend")
    assert _submit(sk, pk, {"0": PROBE_A}, seq=0).get("ok")
    _mine()
    assert _submit(sk, pk, {"0": PROBE_B}, seq=1).get("ok")
    _mine()
    assert _submit(sk, pk, {"0": PROBE_A}, seq=2).get("ok")
    _mine()

    at2 = _answer_at(2)
    assert "o26[t]:bv[24] = { 3 }:bv[24]" in at2["effective_spec"]
    at3 = _answer_at(3)
    assert "o26[t]:bv[24] = { 7 }:bv[24]" in at3["effective_spec"]
    assert "o27[t]:bv[24] = { 9 }:bv[24]" in at3["effective_spec"]
    assert "{ 3 }" not in at3["effective_spec"]

    receipts = {r["block_height"]: r for r in active_rules.rule_receipts()}
    first, displaced, resend = receipts[1], receipts[2], receipts[3]
    assert first["status"] == "in_force"
    assert displaced["status"] == "displaced"
    assert displaced["displaced_by"] == [resend["tx_hash"]]
    assert resend["status"] == "in_force"
    assert resend["spec_revision_after"] == 3

    snapshots = {h: _answer_at(h) for h in (1, 2, 3)}
    with db._db_lock:
        db._db_conn.execute("DELETE FROM spec_snapshots")
        db._db_conn.commit()
    assert db.get_latest_spec_snapshot() is None
    for h in (1, 2, 3):
        cut = _answer_at(h)
        assert cut["derived"] == "journal_cut"
        assert cut["effective_spec"] == snapshots[h]["effective_spec"]
        assert cut["spec_hash"] == snapshots[h]["spec_hash"]
        assert cut["spec_revision"] == snapshots[h]["spec_revision"]


@pytest.mark.skipif(
    not _native_available(),
    reason="native tau-lang bindings not available in this environment",
)
def test_forged_journal_fingerprint_rejected_under_authority(
        authority, _mining_allowed):
    """Rewrite one entry's recorded result fingerprint in the stored
    journal, recompute every link, and re-point the commit records at
    the recomputed links, so the stored chain verifies cleanly and the
    commits agree with it. The one thing the forge cannot fix is the
    fingerprint itself: reconstruction recomputes it from the replay,
    so the rebuild must refuse the journal and serve no spec text."""
    import tau_journal
    from dataclasses import replace

    sk, pk = _sender("authority-forge")
    assert _submit(sk, pk, {"0": PROBE_A}, seq=0).get("ok")
    _mine()
    assert _submit(sk, pk, {"0": PROBE_B}, seq=1).get("ok")
    _mine()

    _reset_spec_mirror()
    honest = active_rules._authority_spec_text()
    assert honest is not None
    assert "o26[t]:bv[24] = { 3 }:bv[24]" in honest

    entries = tau_journal.journal_from_rows(
        db.committed_journal_entries()).entries()
    target = next(
        (e for e in entries if e.kind == tau_journal.STEP), entries[-1])
    forged_fp = json.dumps(
        {"outcome": "ACCEPTED_UNCHANGED", "present": [],
         "progressed": False, "values": {}},
        sort_keys=True, separators=(",", ":"))
    old_links = {e.seq: e.link for e in entries}
    with db._db_lock:
        cur = db._db_conn.cursor()
        cur.execute(
            "UPDATE tau_journal_v1 SET result_fp = ? WHERE seq = ?",
            (forged_fp, target.seq))
        prev = None
        new_links = {}
        for entry in tau_journal.journal_from_rows(
                db.committed_journal_entries()).entries():
            fixed = replace(entry, prev=prev)
            fixed = replace(fixed, link=fixed.compute_link())
            new_links[entry.seq] = fixed.link
            cur.execute(
                "UPDATE tau_journal_v1 SET prev = ?, link = ? WHERE seq = ?",
                (fixed.prev, fixed.link, fixed.seq))
            prev = fixed.link
        for seq, old_link in old_links.items():
            cur.execute(
                "UPDATE block_commits_v1 SET journal_head = ? "
                "WHERE journal_head = ?",
                (new_links[seq], old_link))
        db._db_conn.commit()

    # The forged record verifies: links and commit pointers agree.
    tau_journal.journal_from_rows(
        db.committed_journal_entries()).verify_chain()
    # The rebuild still refuses it -- replay computes another fingerprint.
    _reset_spec_mirror()
    assert active_rules._authority_spec_text() is None
