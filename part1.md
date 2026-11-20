**Design for Bounty 01 — part 1 of 3** (jr11ikhsan; full text also at https://github.com/jr11ikhsan/tau-testnet/blob/bounty01-design/design-comment-34.md)

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

