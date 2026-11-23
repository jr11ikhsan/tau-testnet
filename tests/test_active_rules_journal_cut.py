"""Issue #42 follow-up (B02-1..B02-3): the journal-cut view, the named
resend case, and journal tamper handling.

The stored spec snapshots only exist for heights committed since the
view was introduced. These tests build a committed journal + chain by
hand (the shapes db.py writes at commit) in a database with NO
snapshots at all -- a database written by pristine code -- and require
`getactiverules` to answer old heights from the journal cut, with the
same text a snapshot-recording node serves.

The mirror interface is a pointwise fake (the pattern of
test_active_rules_issue42.py): the unit under test is the cut, the
chain verification and the plumbing, not Tau semantics. The same cases
on the real engine live in test_active_rules_issue42_native.py.
"""
import json
import re
from types import SimpleNamespace

import pytest

import chain_state
import config
import db
import tau_journal
from bls_keys import pubkey_hex
from commands import getactiverules
from consensus import active_rules

RULE_A = "always ( o26[t]:bv[24] = { #x000007 }:bv[24] && o27[t]:bv[24] = { #x000009 }:bv[24] )."
RULE_B = "always ( o26[t]:bv[24] = { #x000003 }:bv[24] )."

TEXT_A = "always ( o26[t]:bv[24] = { #x000007 }:bv[24] && o27[t]:bv[24] = { #x000009 }:bv[24] )."
TEXT_AB = "always ( o26[t]:bv[24] = { #x000003 }:bv[24] && o27[t]:bv[24] = { #x000009 }:bv[24] )."

_ASSIGN_RE = re.compile(r"o(\d+)\[t\]:bv\[24\] = \{ #x([0-9a-fA-F]+) \}:bv\[24\]")


class _PointwiseIface:
    """A TauInterface-shaped fake modelling pointwise revision."""

    def __init__(self):
        self.assignments = {}

    def communicate(self, rule_text=None, target_output_stream_index=0,
                    **kwargs):
        for stream, value in _ASSIGN_RE.findall(rule_text or ""):
            self.assignments[stream] = int(value, 16)
        return "F"

    def get_current_spec(self):
        parts = [
            f"o{s}[t]:bv[24] = {{ #x{v:06x} }}:bv[24]"
            for s, v in sorted(self.assignments.items(),
                               key=lambda kv: int(kv[0]))
        ]
        return "always ( " + " && ".join(parts) + " )."


@pytest.fixture
def fake_mirror(monkeypatch):
    monkeypatch.setattr(
        active_rules, "_new_mirror_iface", lambda: _PointwiseIface())


def _exec(module, raw, container):
    return json.loads(module.execute(raw, container))


def _container():
    return SimpleNamespace(db=db, chain_state=chain_state)


GENESIS_HASH = "aa" * 32


def _block_hash(height):
    return f"{height:064x}"


def build_chain(blocks):
    """Write a committed journal + canonical chain for `blocks`.

    `blocks` is a list of rule-text lists, one per block (height 1..N).
    One REVISION journal entry per rule text; spec_revision advances by
    one per entry. Commit records name the journal head each block
    committed. No spec snapshots are written -- that is the point.
    """
    journal = tau_journal.Journal(authoritative=True)
    per_block = []
    for texts in blocks:
        for text in texts:
            journal.record(
                tau_journal.REVISION, phase=tau_journal.PHASE_APPLY,
                rule_text=text, outcome="ACCEPTED_CHANGED")
        per_block.append(journal.entries()[-1].link if texts else
                         (per_block[-1] if per_block else None))
    revision = 0
    revisions = []
    for texts in blocks:
        revision += len(texts)
        revisions.append(revision)

    with db._db_lock:
        cur = db._db_conn.cursor()
        for entry in journal.entries():
            cur.execute(
                'INSERT INTO tau_journal_v1 (seq, kind, phase, rule_text, '
                'inputs, target, accumulate, units, outcome, result_fp, '
                'identity, prev, link, tip) '
                'VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                (entry.seq, entry.kind, entry.phase, entry.rule_text,
                 json.dumps(entry.inputs or {}, sort_keys=True),
                 entry.target, 1 if entry.accumulate else 0,
                 json.dumps([list(u) for u in entry.units]),
                 entry.outcome, entry.result_fingerprint,
                 json.dumps(entry.identity) if entry.identity else None,
                 entry.prev, entry.link, None),
            )
        cur.execute(
            'INSERT INTO blocks (block_hash, block_number, previous_hash, '
            'timestamp, block_data) VALUES (?,?,?,?,?)',
            (GENESIS_HASH, 0, "", 1700000000, "{}"),
        )
        prev = GENESIS_HASH
        for i, texts in enumerate(blocks):
            height = i + 1
            ts = 1700000000 + height * 100
            cur.execute(
                'INSERT INTO blocks (block_hash, block_number, '
                'previous_hash, timestamp, block_data) VALUES (?,?,?,?,?)',
                (_block_hash(height), height, prev, ts, "{}"),
            )
            cur.execute(
                'INSERT INTO block_commits_v1 (execution_id, tip, parent, '
                'journal_head, allocator_digest, plan_id, plan_json, '
                'spec_revision, time_point, committed_at) '
                'VALUES (?,?,?,?,?,?,?,?,?,?)',
                (f"exec-{height}", _block_hash(height), prev,
                 per_block[i], "digest", None, None, revisions[i], ts, ts),
            )
            prev = _block_hash(height)
        cur.execute(
            'INSERT OR REPLACE INTO chain_state (key, value) VALUES (?, ?)',
            ("canonical_head_hash", prev),
        )
        db._db_conn.commit()


def _tamper_journal(seq, *, rule_text):
    """Rewrite one committed journal row's rule_text in the stored DB,
    leaving its recorded link untouched -- the naive tamper. (The forge
    shape, where the links are recomputed too, is caught by the rebuild
    replay check and is exercised in the native suite.)"""
    with db._db_lock:
        cur = db._db_conn.cursor()
        cur.execute(
            'UPDATE tau_journal_v1 SET rule_text = ? WHERE seq = ?',
            (rule_text, seq))
        db._db_conn.commit()


# --- B02-1: pre-snapshot heights from the journal cut --------------------

def test_journal_cut_answers_heights_without_any_snapshots(
        temp_database, fake_mirror):
    """A database written by pristine code (journal + chain, zero
    snapshots) answers getactiverules for old heights from the journal
    cut, marked derived, with the block each answer is for."""
    build_chain([[RULE_A], [RULE_B]])
    assert db.get_latest_spec_snapshot() is None

    at1 = _exec(getactiverules, "getactiverules 1", _container())["data"]
    assert at1["available"] is True
    assert at1["derived"] == "journal_cut"
    assert at1["height"] == 1
    assert at1["block_hash"] == _block_hash(1)
    assert at1["spec_revision"] == 1
    assert at1["effective_spec"] == TEXT_A
    assert at1["spec_hash"] == active_rules.spec_hash_of(TEXT_A)

    at2 = _exec(getactiverules, "getactiverules 2", _container())["data"]
    assert at2["derived"] == "journal_cut"
    assert at2["effective_spec"] == TEXT_AB
    assert at2["spec_revision"] == 2

    # No height: the cut at the canonical tip answers.
    tip = _exec(getactiverules, "getactiverules", _container())["data"]
    assert tip["derived"] == "journal_cut"
    assert tip["effective_spec"] == TEXT_AB


def test_journal_cut_matches_snapshot_node_answers(tmp_path, fake_mirror):
    """The same chain on two databases -- one with snapshots recorded
    per block, one with none -- serves identical text and hash at every
    height; only the source marker differs."""
    answers = {}
    for label, with_snapshots in (("cut", False), ("snap", True)):
        if getattr(db, "_db_conn", None) is not None:
            db._db_conn.close()
            db._db_conn = None
        config.set_database_path(str(tmp_path / f"{label}.db"))
        db.init_db()
        build_chain([[RULE_A], [RULE_B]])
        if with_snapshots:
            db.record_spec_snapshot(
                1, 1, TEXT_A, active_rules.spec_hash_of(TEXT_A))
            db.record_spec_snapshot(
                2, 2, TEXT_AB, active_rules.spec_hash_of(TEXT_AB))
        answers[label] = {
            h: _exec(getactiverules, f"getactiverules {h}",
                     _container())["data"]
            for h in (1, 2)
        }
    for h in (1, 2):
        assert answers["cut"][h]["effective_spec"] == \
            answers["snap"][h]["effective_spec"]
        assert answers["cut"][h]["spec_hash"] == \
            answers["snap"][h]["spec_hash"]
        assert answers["cut"][h]["derived"] == "journal_cut"
        assert "derived" not in answers["snap"][h]


def test_journal_cut_restart_keeps_answers(temp_database, fake_mirror):
    """Restart (a fresh connection on the same database file) does not
    change a pre-snapshot answer."""
    build_chain([[RULE_A], [RULE_B]])
    before = _exec(getactiverules, "getactiverules 1", _container())["data"]
    db._db_conn.close()
    db._db_conn = None
    db.init_db()
    after = _exec(getactiverules, "getactiverules 1", _container())["data"]
    assert after == before


# --- B02-2: the named resend case A,B,A ----------------------------------

def test_resend_a_b_a_journal_cut_shows_first_unit_terms(
        temp_database, fake_mirror):
    """Send A (o26 = {7} && o27 = {9}), then B (o26 = {3}), then A
    again, one block each. The journal records revisions A, B, A -- the
    resend is NOT deduplicated the way an accumulation replay would
    ([A, B] gives o26 = 3) -- so the view at block 3 runs the first
    unit's terms again: o26 = 7, o27 = 9."""
    build_chain([[RULE_A], [RULE_B], [RULE_A]])

    at2 = _exec(getactiverules, "getactiverules 2", _container())["data"]
    assert at2["effective_spec"] == TEXT_AB  # B in force between the sends

    at3 = _exec(getactiverules, "getactiverules 3", _container())["data"]
    assert at3["effective_spec"] == TEXT_A
    assert "o26[t]:bv[24] = { #x000007 }" in at3["effective_spec"]
    assert "o27[t]:bv[24] = { #x000009 }" in at3["effective_spec"]
    assert at3["spec_revision"] == 3  # the resend advanced the revision


def test_resend_a_b_a_survival_ledger(temp_database):
    """The ledger over the resend: the first A unit is in force again at
    revision 3, B is displaced, and the displacer is the resend of A."""
    db.record_spec_snapshot(1, 1, TEXT_A, active_rules.spec_hash_of(TEXT_A))
    db.record_spec_snapshot(2, 2, TEXT_AB, active_rules.spec_hash_of(TEXT_AB))
    db.record_spec_snapshot(3, 3, TEXT_A, active_rules.spec_hash_of(TEXT_A))
    for tx, block, before, after in (
            ("a1" * 16, 1, 0, 1), ("b1" * 16, 2, 1, 2), ("a2" * 16, 3, 2, 3)):
        db.record_rule_outcomes(f"{block:064x}", block, {tx: {
            "outcome": "ACCEPTED_CHANGED",
            "spec_revision_before": before,
            "spec_revision_after": after,
        }})
    ledger = {e["tx_hash"]: e for e in active_rules.survival_ledger()}
    assert ledger["a1" * 16]["status"] == "in_force"
    assert ledger["b1" * 16]["status"] == "displaced"
    assert ledger["b1" * 16]["displaced_by"] == ["a2" * 16]
    assert ledger["a2" * 16]["status"] == "in_force"


# --- B02-2/B02-3: tampered journals ---------------------------------------

def test_tampered_journal_row_yields_no_cut(temp_database, fake_mirror):
    """Rewrite a rule_text in the stored journal without re-linking:
    the cut at (and after) the altered entry no longer verifies, so no
    derived answer is served for those heights. A cut BEFORE the
    altered entry still verifies and still answers."""
    build_chain([[RULE_A], [RULE_B]])
    _tamper_journal(1, rule_text=RULE_B)

    assert active_rules.journal_cut_at_height(1) is None
    assert active_rules.journal_cut_at_height(2) is None
    data = _exec(getactiverules, "getactiverules 2", _container())["data"]
    assert data["available"] is False


def test_tamper_after_the_cut_does_not_poison_earlier_height(
        temp_database, fake_mirror):
    build_chain([[RULE_A], [RULE_B]])
    _tamper_journal(2, rule_text=RULE_A)
    at1 = _exec(getactiverules, "getactiverules 1", _container())["data"]
    assert at1["available"] is True
    assert at1["effective_spec"] == TEXT_A
    assert active_rules.journal_cut_at_height(2) is None


def test_authority_mirror_refuses_tampered_journal(
        temp_database, fake_mirror, monkeypatch):
    """_authority_spec_text verifies the chain over the rows it reads
    before feeding the mirror: an altered row (links not recomputed)
    yields no text at all. The rebuild replay check is stubbed here --
    it is exercised for real in the native suite; this test isolates
    the chain-verification layer."""
    build_chain([[RULE_A], [RULE_B]])
    monkeypatch.setattr(
        active_rules, "_rebuild_replay_check", lambda journal: True)
    active_rules.reset_spec_mirror()
    assert active_rules._authority_spec_text() == TEXT_AB

    _tamper_journal(2, rule_text=RULE_A)
    active_rules.reset_spec_mirror()
    assert active_rules._authority_spec_text() is None
