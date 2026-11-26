# Rules in force — `getactiverules`, `getaccountrules`, `getrulesinforce`

Bounty 02, issue #42. The three commands serve one view — the rules
actually in force — from the node's canonical spec snapshots. They
share a single builder (`commands.getactiverules.view_data`), so they
cannot drift apart; only the entry point and the envelope name differ.

```bash
tau-testnet rpc "getactiverules [account] [height]"
tau-testnet rpc "getaccountrules <account>"
tau-testnet rpc "getrulesinforce [account] [height]"
tau-testnet fee-rules [account] [height]   # human-readable fee_rules
```

`height` selects the latest snapshot at or before it; with no height,
the newest snapshot is served. A height before the first snapshot
answers `available: false` — the view never guesses from later state
and never falls back to the accumulation. The design behind the view
is in [design-42-b02.md](design-42-b02.md).

## Fields

| Field | Meaning |
|---|---|
| `available` | `false` when no snapshot covers the height, or when the journal cut for the served snapshot is TAMPERED (the view is held — see below). |
| `spec_revision` / `height` | The revision and block height of the snapshot served. |
| `canonical_text` / `sha256` | The canonical spec text in force, and its sha256. This is the composition, not the append-only accumulation `gettaustate` returns: a later revision can displace part of an earlier one. |
| `derived` | Present only when the text came from the journal cut rather than a stored snapshot (`"journal_cut"`). |
| `requested_height` | Echoed when a height was asked for. |
| `account` / `rules` / `unattributed` | Present when an account was given. `rules` holds the top-level conjuncts whose guard binds i12 to exactly that account; every other conjunct is listed under `unattributed`, never dropped or guessed at. |
| `units` | The per-unit survival ledger: each unit is the set of conjuncts one revision's step introduced, with status `in_force`, `partially_displaced` or `displaced`, and for a displaced conjunct the revision that displaced it, the displacing transaction, and the conjunct that replaced it. Derived as of the snapshot served. |
| `fee_rules` | Every accepted unit that writes the fee stream o8, whoever sent it, in the order the units joined — see below. |
| `fee_rules_as_of` | `getrulesinforce` only: `"this block"` at the tip, `"as of height <height>"` otherwise. The fee rules are derived at the snapshot served, so at a past height they are the fee rules known at that height, not the current tip's. |
| `cut_status` | Present when the view is held: `"TAMPERED"`. |
| `message` | Human-readable reason when `available` is `false`. |

## `fee_rules` — the o8 attribution view

o8 is the custom-fee stream (`tau_defs.CUSTOM_FEE_STREAM_INDEX`). The
engine works it out from the whole specification for every
transaction, so a unit that never names an account can still change
what that account pays (#183). `fee_rules` answers "which units set
my fee, and who sent them" — a visibility view, not an enforcement
screen: it changes no fee, admits nothing, and rejects nothing.

Each row carries:

| Field | Meaning |
|---|---|
| `unit` | The unit's o8-writing installed fragments, joined in spec order. |
| `sha256` | sha256 over exactly that text. |
| `fragments` | Those fragments, individually. |
| `names_this_account` | Whether the unit's text names the queried account (`#x<account>`). `false` when no account was queried. |
| `sent_by` | The sender of the transaction that installed the unit, from this node's stored blocks — or `null` when the node has no block for it (a genesis unit, or one from before it began recording). `sent_by_status` says `"recorded"` or `"not_recorded"`. Never a guess. |
| `since` | The block number and transaction hash that first brought the unit in. |
| `status` | The survival of the fee fragments themselves at the served snapshot: `in_force`, `partially_displaced`, `displaced`. |
| `displaced_by` | The transaction hashes that displaced the fee fragments. |
| `tx_hash` / `block_number` / `spec_revision_before` / `spec_revision_after` | The ledger unit's own coordinates, so the row joins back to `units`. |

A displaced row stays listed — with its status and displacer — because
a reader who cannot tell a live fee rule from a displaced one cannot
tell what it pays. That is the one thing this view knows that a bare
accumulation listing cannot: which fee rules were replaced, and by
what.

## Limitations — stated, not hidden

* **Node-local.** `sent_by` comes from this node's stored blocks and
  recorded rule outcomes. A node that never applied the block cannot
  attribute the unit; a node that applied it before the record existed
  reads `sent_by: null`. The record is history, not consensus: two
  nodes with different histories can attribute the same unit
  differently, and neither is wrong — each reports what it recorded.
* **Genesis / pre-recording units.** Units that joined before this
  node began recording have no installing transaction on record and
  read `sent_by: null` with `sent_by_status: "not_recorded"`.
* **As-of, not per-block snapshots.** `fee_rules` at a past height is
  derived from the snapshot sequence at that height — the history
  known then. It is not a stored per-block fee table; a fee rule whose
  installing transaction arrived after the requested height is absent
  because the ledger at that height does not know it yet.
* **View only.** `fee_rules` does not screen, scope, or reject any
  rule. The unscoped-o8 refusal at admission (`UNSCOPED_USER_RULE`)
  and the fee-model screens are separate mechanisms; this view only
  shows what is in force.

## The TAMPERED hold

When the journal cut for the served snapshot is TAMPERED — the journal
the snapshot rests on no longer verifies — the whole view is held
(`available: false`, `cut_status: "TAMPERED"`), including `units` and
`fee_rules`. The view fails closed for integrity: it never serves a
snapshot whose journal is broken. When the cut cannot be derived
because no commit record exists (`NOT_FOUND`) or the mirror cannot
speak (`UNAVAILABLE`), the snapshot is served as usual — the cut is a
check that runs when it can speak, not a gate that withholds the view
for a missing record.
