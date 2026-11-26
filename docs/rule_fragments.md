# Rule fragments: syntax allow-list, shared-rule budget, engine pin

This document describes the three mechanisms added by the G1 package
(branch `bounty01-juara-g1-syntax-budget-pin`). All numbers in this
document are **proposed governance values**, not decisions: the final
numbers are for Muhammad / the coordinator to confirm (see
"DRAFT-EMAIL-BUDGET-NUMBERS.txt" in `~/workspace/tau-bounty/`).

## 1. Syntax allow-list (`consensus/rule_fragment.py`)

Admission screens every user rule text through `screen_user_rule_text`
(`consensus/admission.py`). The fragment screen runs **after** all legacy
screens (special stream, reserved output, temporal, fee-reads-balance,
reserved input, unscoped o8, width) so the rejection codes pinned by
existing tests (`TX_REJECTED`, `TEMPORAL_REFERENCE`,
`UNSCOPED_USER_RULE`, `WIDTH_MISMATCH`) do not change. Only text that
passes the legacy screens but violates the allow-list is rejected with
code `RULE_FRAGMENT`.

### Admitted shape

- Exactly one unit: `always ( <expr> ).` with an optional trailing
  period. `#` comments are stripped (the literals `#x`/`#b` keep their
  `#`).
- Operators: ternary `? :`, implication `->`, `||`, `&&`, `=`, `!=`,
  `<`, `<=`, `>`, `>=`, `+`, `-`, `*`, `/`, `%`, unary `!` and `-`,
  parentheses. Parsing uses a **precedence table, not a paren mandate**,
  because the genesis consensus rule itself mixes `=` and `&&` without
  parens (`genesis.tau`).
- Atoms: stream reads/writes `i<N>[t]` / `o<N>[t]` (untyped streams are
  allowed here -- typedness for o5/o8 stays in `screen_policy_widths`);
  braced literals `{ n }:bv[W]` (type mandatory); bare literals only
  `0` / `1`.
- Parser limits: width at most `bv[384]`, nesting at most 32, depth at
  most 256, `*`/`/`/`%` require one constant operand.

### Rejected

`u`, `this`, any name other than `i<N>`/`o<N>`, any step other than
`[t]` (code `TEMPORAL_REFERENCE`), untyped braced literals, width
above 384, bare literals other than 0/1, the `all` quantifier, unknown
tokens, unbalanced parens, anything that is not one `always` unit.

### Deliberately NOT in the allow-list (fail-closed)

Bitwise `&` / `|` and shifts `>>` / `<<`, and unparameterized `bv`
literals (`{ 1 }:bv`) are **not** admitted. The repo corpus contains
such shapes only in engine-level probes that bypass admission entirely
(`tests/test_o9_arithmetic_probe_native.py` uses `>>` via raw
`TauInterface`; `tests/test_tau_shrink_native.py` uses `&`/`|` the same
way) and in pure string/rendering tests (`{ 1 }:bv` in
`test_dht_formula.py` / `test_getupdateid.py`, `o9[t] = 5` in
`test_proposals_rendering.py`) -- the fp-check corpus sweep (193
distinct `always`-units, §7) confirmed none of them reaches
`screen_user_rule_text`. If a future user rule legitimately needs
shifts or bitwise ops, the screen rejects it fail-closed and governance
extends the allow-list; the engine remains the final judge for anything
admitted.

### Node counting

Each AST node counts 1; the `always` wrapper counts 1. Reference
numbers (pinned in `tests/test_rule_fragment.py`):

| rule | nodes | depth | byte_len |
|---|---|---|---|
| effect-1 typed rule (issue #183) | 15 | 5 | 146 |
| genesis consensus rule | 12 | 5 | — |
| payout clause (FIX 8/9 shape) | 12 | 5 | — |

## 2. Shared-rule budget (`consensus/shared_rule_budget.py`)

### What it counts

The cumulative number of accumulated user rules and their total AST
nodes **since genesis**. The counters are a **derivation of the
canonical application-rules text**, not an increment: `recount_shared_budget(text)`
splits the text into units, deduplicates, parses each unit, and sums
nodes. Units that fail to parse are skipped (never counted) -- that is
what grandfathers the genesis seed
`((!(i0[t] = 0))? ( u[t] = i0[t] && o0[t] = 0): o0[t] = 1)` and
pre-package rules. **The same text counted twice counts once.**

Not counted: o5 registry clauses (registry, not accumulation -- detected
the same way the engine does, via `clause_output_streams` containing
`USER_POLICY_STREAM_INDEX` = 5), offer/accept, rule-change requests,
governance revisions, the genesis seed. This is a different budget from
the per-block `max_rule_txs_per_block` (default 8, which *does* count
o5 because each o5 builds a clause) -- two budgets, two objects.

### Proposed limits (governance, not decided)

| key | proposed value |
|---|---|
| `occurrences` | 10 rules |
| `total_nodes` | 80 nodes |
| `rule_nodes` | 32 nodes per rule |
| `rule_depth` | 8 |
| `rule_bytes` | 1024 bytes |
| `width` | bv[384] |

### Enforcement, three layers

1. **Admission** -- `validate_user_tx_reserved_domains` rejects with
   code `RULE_BUDGET` and the detail `shared_rule_count` /
   `shared_rule_nodes` / limits. Skipped when the tip view carries no
   budget (unit tests without a chain), never fail-closed there.
2. **Apply** -- the engine re-charges from the working text after the
   rule lands, on the per-transaction lifecycle fork, so a W7 rollback
   discards the charge together with the fork. A proposer that slipped
   past admission gets its transaction rejected with reason
   `shared_rule_budget`. Replay is exempt (counters come from the
   snapshot text). If `_rule_prior_rules_state is None`, the apply-time
   charge is skipped with a warning and the header check carries the
   enforcement.
3. **Header** -- `verify_block_header` computes the prospective count
   from the parent counters plus the rule transactions in the block
   (only transactions that will accumulate: op-0 user_tx, passing the
   fragment screen, not o5; identical text inside one block counts
   once). **Known residual edge:** a transaction that repeats a unit
   already in the parent spec is over-counted by 1 by the header check
   (it sees the parent counters, not the parent text) -- a block is
   rejected fail-closed only at the exact boundary; the proposer
   rebuilds without the duplicate.

### Reorg

Because the counters derive from text, a reorg restores them exactly:
abandoning a branch un-counts its rules; the surviving branch keeps its
own count. `chain_state._swap_in_memory_state` recounts after adopting
a manager; `load_state_from_db` recounts on load and cross-checks the
stored counter rows (a mismatch warns, the text wins). The stored
counter rows in `db.py` are observability / cross-check only.

### Governance

Patch key `shared_rule_limits` (a complete 6-key object, validated by
`validate_shared_rule_limits`; ceilings: occurrences 10000,
total_nodes 1000000, rule_nodes 10000, rule_depth 256, rule_bytes
1048576, width 384). `apply_host_contract_patch` replaces the LIMITS
only and never touches the counters; a limit lowered below current use
only refuses further rules. Patch values are also validated at
admission (`_check_host_contract_patch`).

### State-hash binding, no regenesis

`build_mechanism_metadata` emits `shared_rule_limits` only when != the
proposed default and `shared_rule_count` / `shared_rule_nodes` only
when non-zero, following the repo's hash-compat pattern. At genesis
(0 rules, default limits) the mechanism metadata hash is byte-identical,
so `genesis.json` is **unchanged** and the golden vectors in
`tests/test_genesis_tooling.py` are unchanged. The budget is active
"since the first counted rule" (activation-by-first-rule).

Representation note: the mechanism hash and the db row carry the limits
as a **canonical JSON string** (sorted keys, no whitespace) because the
meta-hash encoder and `encode_host_contract_patch` only accept
int/str/bool/list values -- a dict branch was added to the patch encoder
for the governance patch path. The view metadata
(`derive_active_consensus`) carries the limits as a dict (not hashed).

## 3. Engine pin (`consensus/engine_profile.py`)

- Pinned ref: tau-lang `6ea436e8d3113a7d90635b9d06113e5bc506176c`
  (short `6ea436e8`), verified against `Dockerfile.standalone:7`
  (`ARG TAU_LANG_REF`) and the repo (`https://github.com/IDNI/tau-lang.git`).
  `tests/test_tau_engine_profile.py` fails if the two drift.
- `scrub_engine_environment()`: removes `OPENAI_API_KEY` /
  `ANTHROPIC_API_KEY`, drops PATH entries containing `ltlsynt` /
  `autfilt` / `ltlfilt`, removes `TAU_*` variables not in the keep-list
  `REPO_OWNED_TAU_ENV_VARS` (derived from the node's own
  `os.environ`/`os.getenv` reads and the `config.py` table -- including
  `TAU_FORCE_TEST`, `TAU_DB_PATH`, `TAU_LOG_LEVEL`, `TAU_NATIVE_PATH`,
  plus build-time `TAU_LANG_REF`, `TAU_BUILD_JOBS`, ...). Every removal
  is logged as a warning. Called at the start of `load_tau_module()`.
- `verify_pinned_engine_ref()`: reads `.git/HEAD` in pure Python (the
  runtime image ships no git binary). A verified mismatch raises
  `EngineProfileError` -- the engine does not start (fail-closed). When
  unverifiable (no `.git` / unreadable HEAD) it returns
  `(None, reason)` with a warning and the engine continues.
- `engine_profile(tau_lang_dir=None)` reports the pin and verification
  status for observability / logging.

### Honest limit (open item)

No manifest of the engine's ~100 options is built: the option registry
lives in tau-lang, not in this repo, and no unverified option list is
invented. What is pinned: the engine SOURCE (ref) and a clean load
environment. Whether that is enough, or a tau-lang option registry is
needed, is a decision for Muhammad / the coordinator.

## 4. Regenesis

There is **none** in this package: genesis is unchanged (see §2). If
#190 merges first (regenesis block 0 `204421c4…`), this package still
works -- the new genesis also has 0 counted rules and default limits,
so the budget starts from the same point.

## 5. Merge zones vs #190

~11 merge zones were identified in the audit (see
`~/workspace/tau-bounty/RIVAL-GAP-AUDIT-2026-11-27.md` §2). This package
does **not** touch `engine.py _release_due_retractables`,
`chain_state.py reorg_to`, `db.py set_chain_state_value` /
`_confirm_rule_clauses`, or `consensus/payout_rules.py` (FIX 8 is
untouched; #190 does not subsume it). It touches
`chain_state.py _canonical_state_kwargs` / `commit_state_to_db` (3 new
kwargs), `db.py` (3 new kwargs + rows in `_write_canonical_state_rows`),
`governance.py build_mechanism_metadata` / `consensus_meta_hash` /
`__init__` (field `self.shared_rule_budget`), `ci.yml` (2 native test
files), `admission.py` (additive fragment screen + budget check),
`facade.py` (read-only property `TipAdmissionView.shared_rule_budget`).
The governance key `shared_rule_limits` is the same on both sides, so
a merge composes semantically: keep both additions in each zone.

## 6. What still needs a decision

1. Final budget numbers (10/80/32/8/1024/384) -- proposed, not decided.
2. Syntax scope: precedence-table parsing (no paren mandate) + bare
   literals only 0/1.
3. Engine option manifest: pin ref + scrub, or a tau-lang option
   registry.
4. Merge order vs #190 / G2 (o8 screen, parallel lane) -- this package
   depends on neither.
5. File as a separate PR or fold into #186/#188/#189.
