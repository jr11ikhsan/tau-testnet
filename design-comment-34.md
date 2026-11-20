I'm working on **Bounty 01 (Programmable payments: #34, #35, #63)** and post this design for maintainer review before building, in the staged order the program page sets. The case → test mapping comes first, because that is what was asked for on this thread; the mechanisms follow it.

Status: design for maintainer review — no consensus code yet; build starts
on the staged order in section 5. Base: main c2b8c47.

## 0. Summary

Three consensus objects, all held in node-owned books on the
ConsensusLifecycleManager following the existing RetractableBook pattern
(`consensus/retractable.py:190-384`, a field of the manager at
`consensus/governance.py:453`, its `root()` fed into
`consensus_meta_hash` at `governance.py:547`, settlement in the
post-transaction sweep at `consensus/engine.py:903-913`): bounded open
set, resolved entries deleted so cost stays O(open set), entry identity a
pure hash of the signed fields, only-once settlement. The engine delta is
deliberately small: the new books, one hook inside the existing transfer
seam (`_execute_fee_era_transfer`, `engine.py:1883-2031`), and new
commands in the house style — no rewrite of the engine's transfer path:

| Object | Issue | What it does |
|---|---|---|
| Standing payment | #34 | Fixed amount + fixed recipient on a calendar schedule; signed once, executed by anyone, node is the gate. |
| Receive route | #35 | Recipient-side atomic split of an ordinary credit (floor rounding, single hop). |
| Payout rule | #63 | A Tau rule computes recipients/amounts inside declared caps; anyone triggers; all legs atomic or none. |
| Conditional grant | page stages 2–5 | Sender-side conditions on held money: per-period spend cap, time lock / scheduled availability / temporary restriction, expiry refund, combinable (AND; refund wins at expiry). |

Two maintainer additions from the #34/#35 threads are first-class, not
afterthoughts:

- **Paid-for-period fact (#34, gmikeyg 2026-10-01):** every settled
  occurrence writes a per-authorization, per-period fact that other rules
  can read, so membership / keep-alive rules can depend on whether the
  occurrence executed.
- **Required end condition (#34, gmikeyg 2026-10-01):** no open-ended
  authorization by default — create is rejected unless it carries a final
  period, an occurrence limit, or a maximum total.
- **Binding routes (#35, gmikeyg 2026-10-01):** a route may be locked;
  while locked the recipient alone cannot change or remove it (removal
  needs the destination's signature, or the lock runs to its expiry);
  expiry is mandatory for locked routes.

## 1. The five named cases first (gmikeyg, 2026-11-20)

| # | Case | Named test |
|---|---|---|
| 1 | 101 routed at 20% gives 20 and 81 with one fee | `test_route_101_at_20pct_gives_20_and_81_one_fee` |
| 2 | A 5% royalty on 101 pays 5, once | `test_royalty_5pct_on_101_pays_5_once` |
| 3 | A routed share never triggers another route | `test_routed_share_never_triggers_another_route` |
| 4 | A monthly payment on the 31st runs on the last day of a shorter month | `test_monthly_on_31st_runs_on_last_day_of_short_month` |
| 5 | The 5,000 grant (500/week from Dec 1, refund at the deadline) returns the right remainder | `test_grant_5000_week_cap_refund_returns_remainder` |

Case 2's "once" is an idempotency property of the book, not of the client:
the execution carries the settlement id in the payout book and a second
submission of the same execution is refused as already-settled.

Every named test in this design runs twice: once on the mock engine and
once on the native engine in the repo's real-Tau CI job, with the run
linked from the PR (the same public-evidence pattern as PR #134's fork CI
run). The 108-history shared-cap check ships as
`test_shared_cap_counts_exactly_once_across_108_histories` with whichever
parts of this design are taken.

## 2. Complete case → test mapping

### #34 (9 cases)

| Case | Named test |
|---|---|
| 1. At most once per eligible calendar period | `test_monthly_authorization_executes_at_most_once_per_period` |
| 2. Before/after window or second time in period rejected | `test_execution_outside_window_or_twice_in_period_rejected` |
| 3. Anyone may trigger; nobody can alter signed terms | `test_any_party_can_trigger_but_cannot_alter_signed_terms` |
| 4. Cancellation prevents every later execution | `test_cancel_prevents_all_later_executions` |
| 5. Insufficient funds: no debt, no partial, no false completion | `test_insufficient_funds_no_debt_no_partial_no_false_completion` |
| 6. Replays and cross-network reuse fail | `test_replay_and_cross_network_execution_rejected` |
| 7. Current policy / spend-cap / cooldown apply exactly once | `test_current_policy_cap_cooldown_apply_exactly_once` |
| 8. Admission and block application agree | `test_admission_and_apply_agree_on_authorization_state` |
| 9. Capability endpoints report support + schedule semantics | `test_capability_reports_support_and_schedule_semantics` |

Honesty note on case 7: consensus spend totals (#31) and cooldown (#30)
are not on main at c2b8c47. The design keeps per-authorization totals in
the authorization's own book (exact for the authorization itself) and
evaluates the payer's current o5 at execution; it does not claim the
#30/#31 counters end-to-end until those land, and says so in the PR.

### #35 (8 cases)

| Case | Named test |
|---|---|
| 1. 20% route credits 80% net / 20% destination, canonical rounding | `test_route_101_at_20pct_gives_20_and_81_one_fee` |
| 2. Same result online or offline | `test_route_applies_identically_online_or_offline` |
| 3. A normal transfer cannot bypass the route | `test_normal_transfer_cannot_bypass_route` |
| 4. Self-routes, invalid destinations, >100% sets, recursion rejected | `test_invalid_and_recursive_route_sets_rejected_safely` |
| 5. Update/removal follows protected policy-admin rules | `test_route_admin_follows_protected_policy_rules` |
| 6. Gross, net, routed amount and fees visible in receipts/history | `test_route_amounts_visible_in_receipt_and_history` |
| 7. Replay / block replay / snapshot restore preserve balances exactly | `test_route_replay_and_snapshot_restore_preserve_balances` |
| 8. Capability endpoints report support, credit classes, rounding, fees | `test_capability_reports_route_semantics` |

### #63

| Case | Named test |
|---|---|
| Rule computes recipients/amounts; node enforces declared caps | `test_payout_rule_outputs_checked_against_declared_caps` |
| All legs atomic or none | `test_payout_all_legs_atomic_or_none` |
| Royalty: 5% on 101 pays 5, once (idempotent settlement) | `test_royalty_5pct_on_101_pays_5_once` |
| Execution cannot pay an undeclared recipient | `test_payout_cannot_pay_undeclared_recipient` |
| Per-execution and per-period caps both bind | `test_payout_period_cap_binds_across_executions` |
| Rule removal follows the account's normal rules (+ #33 lock) | `test_payout_rule_removal_follows_account_rules` |

## 3. Shared design decisions (the page's design tasks)

### 3.1 Who pays the fee when a rule sends money
The codebase has no fee constants: a fee is what the active consensus
rules emit per transaction (`consensus/fees.py`), settled inside the
per-transaction loop against the transaction's signer, and node-initiated
sweep movements (the retractable release, the rule-change release) move
value with **no fee and no payer at all**. This design follows those
precedents exactly:
- `standing_payment_execute` / `payout_execute` are ordinary submitted
  transactions: the submitter pays the ordinary rule-emitted fee, like
  any other transaction. The payer is never charged a fee for an
  execution unless the signed authorization opts into payer-funded fees
  with a signed per-execution fee cap, debited inside the movement itself
  (the park precedent: one fee measured up front). The authorization's
  `fee_limit` field bounds exactly that optional debit; default 0.
- Movements the node itself makes in the sweep (grant expiry refunds)
  are fee-free, as the existing sweep movements are. A refund therefore
  returns the full remainder — the grant case's "right remainder" is not
  reduced by a fee nobody signed for.
- A routed credit is one ledger split of the original transfer: **one
  fee**, charged exactly as the unrouted transfer would be (case 1 above).

### 3.2 Triggers, and stopping rules from triggering each other
- Triggers are only: an explicit execute transaction, an ordinary
  transfer credit (routes), and the end-of-block sweep (due standing
  occurrences are *not* auto-executed — an execute transaction is always
  what moves money; the sweep only settles grant expiries/refunds and
  closes lapsed windows).
- Credit classes are explicit. Only ordinary user transfers (and claimed
  payments, #36) trigger a route. Credits produced by a route, a standing
  execution, a payout leg, a grant draw or a refund are a different class
  and never trigger a route, a payout, or another standing payment. This
  is the loop stopper, and it is a consensus class check, not a depth
  counter.

### 3.3 Periods and time
- Time source: the block header timestamp (UTC), the same value rules
  read; never node wall clock.
- Day = 86400s, week = 604800s from the authorization's anchor. Month =
  UTC calendar month; a missing day clamps to the month's last day and
  the following month returns to the signed day (the 31st case).
- One execution window per period, signed at creation. An expired window
  lapses: no unbounded catch-up; one execution can never collect multiple
  missed periods unless the signed terms explicitly permit it (default:
  not permitted).
- Per-authorization period totals live in the book, so a period cap is
  enforced by the node that settles, not by a wallet's memory.

### 3.4 Standing payments (#34)
- State: id + version, payer, fixed recipient, fixed amount, schedule +
  first due period, **required end condition**, execution window,
  completed-period markers + cumulative count, cancellation status, fee
  payer + fee limit, optional reference to the authorizing policy version.
- Installation follows the house pattern for account-installed rules: an
  ordinary transaction whose op-0 rule writes the object's stream,
  screened and stored as a registered clause (the o5 routing at
  `engine.py:1679-1797`), so protected/delegated administration (#33) and
  authenticated approvals (#29) apply unchanged.
- Lifecycle: create (payer-signed) → update = a new version that
  supersedes, never an invisible mutation → cancel (visible to admission
  from the latest committed state; a cancel/execute race resolves by
  canonical block order) → execute (anyone; only what is due).
- Execution re-checks the payer's **currently active** o5 against the real
  recipient and amount. Insufficient balance fails the occurrence without
  advancing its marker; retry inside the window is allowed and explicit.
- Settled occurrences write the paid-for-period fact (section 0) and are
  exposed by RPC: next due, last execution, status, total executed.

### 3.5 Receive routes (#35)
- v1 policy: owner, one destination, basis points 0..10000 with a product
  cap below 100%, optional minimum incoming amount, optional
  activation/expiry (mandatory expiry when locked).
- Rounding: floor on the routed share of the gross credit
  (101 at 20% → 20 routed, 81 net), computed once, atomically committed
  with the credit or not at all.
- Enforcement sits inside `_execute_fee_era_transfer`
  (`engine.py:1883-2031`), the single atomic gate every ordinary transfer
  passes, next to the existing registered-clause check
  (`engine.py:1982-2000`): the split is computed from the gross credit and
  staged in the same write set, so it commits with the credit or not at
  all, and no normal transfer can bypass it. Credits that never pass the
  seam (sweep releases, retract refunds, fee credits) are other credit
  classes and are out of route scope by 3.2's class rule.
- Single hop by credit class (3.2). Destination cannot equal the
  receiving account; malformed routes fail closed at installation and can
  never burn or duplicate value at apply time.
- Locked routes: change/removal requires the destination's signature or
  waits out the lock (3.4's administration pattern, #33-compatible).
- Routing never counts as the recipient's outgoing spend; the split
  appears as a distinct atomic routing receipt in account history.

### 3.6 Payout rules (#63)
- The owner installs one payout clause with declared caps (max per
  execution, max per period) and a declared recipient set (or a recipient
  rule). An execution submits inputs; the node steps the rule in an
  isolated policy pool; outputs are (recipient, amount) legs.
- The node — not the rule — checks: every recipient is in the declared
  set, the total is within both caps and the balance, and every leg passes
  the owner's own o5/fee gates. All legs apply atomically or none do.
- Settlement is recorded in the payout book keyed by the execution's
  settlement id, which is what makes "pays 5, once" a consensus property.

### 3.7 Conditional grants (page stages 2–5)
- A grant is held money in its own book entry, not a rule on the
  recipient's account: the recipient's own balance is never capped, and a
  refund never has to pull from a balance that may no longer hold it.
- Conditions attach to the grant and combine by AND; at expiry the refund
  wins. A combination that could never be drawn is refused at creation.
  - Spending limit: per-period cap on draws from this grant.
  - Custom allowance: the cap is per grant (hence per sender/recipient
    pair), not global to the recipient.
  - Recurring limits: the cap window resets at period start by the same
    calendar arithmetic as 3.3.
  - Time conditions: locked-until date, scheduled availability windows,
    and a temporary post-arrival restriction are all evaluated against
    the block timestamp at draw time.
  - Refunds: unspent remainder returns to the sender at expiry (sweep,
    fee per 3.1); a "hasn't spent within N" inactivity trigger is the
    same expiry evaluation with a last-draw timestamp.
- Worked example (the page's demo): Alice → Bob 5,000; cap 500/week;
  draws open December 1; unspent remainder refunds at the deadline.
  Named end-to-end test: `test_grant_5000_week_cap_refund_returns_remainder`
  plus a demo script on two nodes.

## 4. What this design deliberately does not do
- No cron: the chain never wakes itself; every movement traces to a
  submitted transaction or the block sweep over state a transaction
  created.
- No condition is enforced by wallet policy text, so #33 not being on
  main does not weaken any condition here; conditions live in node-held
  books.
- No claim on #30/#31 counters until they exist on main (see #34 case 7).

## 5. Build order (one PR per stage, page order)
1. Standing payments (#34) + payout rules (#63) core books and commands.
2. Receive routes (#35) on the transfer seam.
3. Grants: spend caps + recurring limits.
4. Grants: time conditions.
5. Grants: refunds + combination rules + the two-node demo.

Each PR: code, the named tests for its cases (mock + native CI run
linked), user/operator docs, and the case → test table updated in the PR
description.
