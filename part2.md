**Design for Bounty 01 — part 2 of 3** (continued from the comment above)

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

