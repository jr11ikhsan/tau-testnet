# Bounty 02 design — the active-rules view (issue #42)

Status: implemented in PR #191 (head `9c28c4f`) plus the G5 follow-up
(`fee_rules` view). This document is the design record inside the
repo: what the view answers, what it is built from, what it refuses
to guess, and where the evidence lives. Nothing here is a promise
about a future change; every mechanism named below is code + test in
this tree.

## §1 The problem

`gettaustate` returns the append-only accumulation of submitted rule
text. Pointwise revision is not append-only: a later unit displaces
whatever part of an earlier one it contradicts, so the accumulated
text can claim rules that are not in force (and hide the surviving
form of the ones that are). A wallet that reads the accumulation
cannot tell what the engine actually runs, which rule set a payment,
or who set the fee it pays.

The view answers three questions, from stored data, without
re-running the engine:

1. What spec is in force — at the tip, or at a height?
2. For each unit that installed part of it: is it still in force,
   partly displaced, or gone — and what displaced it?
3. For the fee stream o8: which units write it, and who sent them?

## §2 Snapshots and resolution

At block commit, whenever the engine's `spec_revision` has advanced
past the newest stored snapshot, the node's canonical spec text is
snapshotted (`db.record_spec_snapshots`). "Canonical" is the
codebase's own sense — the full-width text that is safe to persist
and hash, never the interpreter's possibly shrunk current spec.

Resolution:

* `height` selects the latest snapshot at or before it; with no
  height, the newest snapshot is served.
* A height before the first snapshot answers `available: false` —
  the view never guesses from later state and never falls back to the
  accumulation.
* For heights that predate the snapshots, the view falls back to the
  committed journal itself (`journal_cut_at_height`): every block
  commit records the journal head it committed, so the spec in force
  at any held height is the journal cut at that head, chain-verified
  and fed to a one-shot mirror. Answers derived that way carry
  `derived: "journal_cut"` so the source is explicit, never silent.
  The genesis journal entries are included in the height-0 cut (O-5),
  so height 0 answers from the journal it was committed with.

The Step 7 stopgap: a stored snapshot is only served when it agrees
with the journal cut at the snapshot's own height
(`consensus.active_rules.checked_snapshot_answer`). The snapshot and
the cut are two canonicalizations of the same committed record; when
they disagree, the cut's text and sha256 are served instead. The
permanent fix unifies the two canonicalizations; until then the
divergence is visible only through the `derived` marker.

## §3 The survival ledger

Two derivations, one story, different granularity. Both are derived
read-side from stored data — no extra state is recorded for either —
and both are as-of the snapshot served.

* **Command ledger** (`commands.getactiverules.derive_unit_ledger`):
  conjunct instances tracked across successive snapshots. A conjunct
  instance is born at the first snapshot whose text contains it and
  survives while every later snapshot still contains it; the first
  snapshot without it is the revision that displaced it. Instances
  born at the same revision form one unit. A unit reads `in_force`,
  `partially_displaced` or `displaced`, and a displaced conjunct
  names the revision that displaced it, the transaction that landed
  on that revision (from the recorded rule outcomes), and the
  conjunct that replaced it. A verbatim re-submission changes no
  snapshot, so it is not a separate unit: the ledger counts units as
  they land in the composed spec, which is the only existence a
  wallet can act on.
* **Module ledger** (`consensus.active_rules.survival_ledger`): units
  derived from the recorded rule outcomes (`db.list_rule_outcomes`
  lifts the revision interval out of each stored receipt). A unit's
  footprint is the fragments its apply step installed: the fragments
  of the first snapshot at or after its `spec_revision_after`, minus
  the fragments of the last snapshot at or before its
  `spec_revision_before`. Survival is footprint membership in the
  target snapshot; a fragment lost between two consecutive snapshots
  is attributed to the accepted units whose step produced a revision
  inside that interval. A unit that installed no new fragments (an
  `ACCEPTED_NOOP` receipt) is `in_force` with an empty footprint.

An empty module ledger is classified, never silently empty:
`NOT_FOUND` (no rule outcome recorded at all), `TAMPERED` (records
exist but a stored payload no longer parses and none carries a usable
interval), `UNAVAILABLE` (records exist, none carries a revision
interval — pre-field records, receipts whose counter was unreadable,
registry evidence). Numbers are never reconstructed after the fact.

## §4 Ask-3: the incident unit (evidence, not anecdote)

Bounty 02's ask-3 is the incident in which an unguarded rule unit
reached the shared spec. The evidence is three tests in
`tests/test_ask3_incident.py`, each pinning one half of the fix:

* `test_incident_unit_is_refused_at_admission` — the incident unit
  is refused at admission.
* `test_incident_unit_is_hard_rejected_at_apply_with_no_fee_and_no_effect`
  — at apply it is hard-rejected: no fee is charged and no effect is
  installed.
* `test_unguarded_total_form_o5_registers_a_clause_and_never_accumulates`
  — the unguarded total-form o5 registers a clause and never
  accumulates into the shared spec.

## §5 Resend A,B,A

A resend is not a replay. Submitting A, then B, then A again advances
the revision to 3; the resend is not deduped like a replayed
accumulation, and the second A displaces B
(`tests/test_active_rules_journal_cut.py`:
`test_resend_a_b_a_journal_cut_shows_first_unit_terms`,
`test_resend_a_b_a_served_unit_ledger`;
`tests/test_active_rules_revision_ledger.py`:
`test_resend_a_b_a_shows_each_steps_revision_pair`). The module
ledger at the resend's target reads B as `displaced` by the resend
and the first A unit's footprint as in force again — the resend
reinstalled exactly it.

## §6 Two nodes agree

`tests/test_active_rules_twonode_native.py`:
`test_rules_view_agrees_across_two_nodes` — two nodes serving the
same history answer the same view, including the resend case and an
unrelated unit. A view that disagreed across nodes would be useless
as a wallet's source of truth; this test is the one that says it does
not.

## §7 TAMPERED vs NOT_FOUND vs UNAVAILABLE (O-2)

The journal cut carries one of three explicit codes
(`consensus.active_rules`):

| Code | Meaning | View's answer |
|---|---|---|
| `NOT_FOUND` | No commit record (or none naming a cut) | The snapshot is served as usual; the cut is a check that runs when it can speak. |
| `UNAVAILABLE` | The mirror cannot speak for the cut | Same: the snapshot is served. |
| `TAMPERED` | A commit record exists but the journal it names no longer verifies | **HOLD.** The view answers `available: false` with `cut_status: "TAMPERED"` and a hard log. Nothing is served — not the snapshot, not the ledger, not `fee_rules`. |

The same split runs through the payment-conditions view
(`resolve_answer_with_status` + `execute` carrying `cut_status`):
a TAMPERED cut holds the view; a NOT_FOUND / UNAVAILABLE cut is
served around, with the status carried so the caller can say why.
Six tamper tests pin the boundary
(`tests/test_active_rules_journal_cut.py`): a tampered journal row
yields no cut; tampering after the cut does not poison an earlier
height; the authority mirror refuses a tampered journal; a height
without a commit record is NOT_FOUND; a deleted head row and a
deleted middle row are both TAMPERED.

## §8 Payment conditions

`getpaymentconditions <sender> <recipient> <amount> [<height>]` is
stage 2 of the design: a payer and a payee must never compare views
from different tips, so both sides of one payment are evaluated
against the SAME block. The answer names the block it answers for
(height, hash, the spec revision in force there) and is advisory: it
moves nothing. Each side's condition is that account's registered o5
clause, evaluated through the same helper admission and apply use
(`consensus.sender_policy.clause_blocks`). The clause registry is tip
state — one current clause per (account, stream), no per-block
history — so the clauses are read from the current registry and the
answer says so (`clauses_from: "current_registry"`).

## §9 fee_rules — the o8 attribution view (G5)

o8 is the custom-fee stream. The engine works it out from the whole
specification for every transaction, so a unit that never names an
account can still change what that account pays (#183). `fee_rules`
(`consensus.active_rules.fee_rules_for`, served by `getactiverules`,
`getaccountrules` and `getrulesinforce`, formatted by
`tau-testnet fee-rules`) lists every accepted unit that writes o8,
whoever sent it, in the order the units joined. Each row carries the
unit's o8 fragments and their sha256, whether they name the queried
account, who sent the installing transaction, the block + transaction
that first brought it in, and the fee fragments' own survival
(`status` + `displaced_by`).

Sources, in order:

1. The module survival ledger (§3) — one unit per ACCEPTED rule
   outcome, in apply order, with the installing transaction, the
   installed fragments, and the displacers.
2. The o8 filter — a fragment writes o8 when admission's
   `_streams_referenced` finds `o8` in it, the same helper the
   admission screen uses.
3. The sender — `sender_pubkey` of the installing transaction, read
   from this node's stored blocks (`tx_index` + the block's own
   transaction list, the read path `gettxstatus` uses). The
   transaction is signed, so any stored copy names the same sender;
   the canonical location is tried first.

What it knows that a bare accumulation listing cannot: which fee
rules were displaced, and by what. A displaced row stays listed with
its status and displacer — a reader who cannot tell a live fee rule
from a displaced one cannot tell what it pays.

Limitations, stated plainly (see also
[docs/rules_in_force.md](rules_in_force.md)):

* The record is node-local: a node that never applied the block, or
  applied it before the record existed, reads `sent_by: null` with
  `sent_by_status: "not_recorded"`. Genesis / pre-recording units
  have no installing transaction on record. Never a guess.
* At a past height, `fee_rules` is the history known at that height
  — the ledger at that height, not a stored per-block fee table.
* It is a view, not a screen: it admits, scopes, and rejects
  nothing. The unscoped-o8 refusal at admission
  (`UNSCOPED_USER_RULE`) and the fee-model screens are separate
  mechanisms.

## §10 What this design does NOT do

* No enforcement. Nothing here screens a rule, scopes a fee, or
  rejects a transaction. The admission screens (reserved outputs,
  unscoped o8, balance-reading fee rules) live in
  `consensus/admission.py` and are unchanged by this design.
* No consensus change. The view reads stored snapshots, recorded
  outcomes, and stored blocks; it writes nothing and changes no
  state hash. A node that never asks for the view behaves exactly as
  before.
* No new trust. The ledger and `fee_rules` are derived from what
  this node recorded. They are evidence about this node's history,
  not a second consensus.

## §11 Tests (claim → file)

| Claim | Tests |
|---|---|
| View text + hash equal engine + across replay | `tests/test_active_rules_view.py` |
| Ask-3 incident evidence | `tests/test_ask3_incident.py` |
| Resend A,B,A; tamper boundary; journal cut | `tests/test_active_rules_journal_cut.py` |
| Revision ledger from recorded outcomes | `tests/test_active_rules_revision_ledger.py` |
| Two-node agreement | `tests/test_active_rules_twonode_native.py` |
| Native receipt shape vs served view | `tests/test_active_rules_view_native.py`, `tests/test_active_rules_issue42_native.py`, `tests/test_active_rules_authority_native.py`, `tests/test_active_rules_probe_native.py` |
| Payment conditions, same-block | `tests/test_payment_conditions_issue42.py` |
| fee_rules: join order, senders, exclusion, as-of, displacement, unrecorded sender, CLI format | `tests/test_fee_rules_view.py` |

The mock suite runs without the native Tau engine (the Tau seam is
stubbed at `tau_manager`, the pattern of
`tests/test_apply_block_outcome_key.py`); the `*_native.py` files are
registered in the native-tau-tests CI job and check the same claims
against the real engine.

## §12 Open questions

* **Command names.** This line's rules-in-force view has always been
  `getactiverules`; `getaccountrules` and `getrulesinforce` are thin
  entry points over the same builder, added so the fee view is
  reachable under the names a reader of the B02 discussion expects.
  Whether the maintainer prefers one canonical name is a decision
  for gmikeyg, not for this PR — the three commands share one
  implementation, so renaming one later is a deletion, not a rewrite.
* **Engine pin / syntax screen / cumulative budget.** Out of scope
  for this design: they change what is admissible, and belong to the
  B01 work, not to a read-only view.
