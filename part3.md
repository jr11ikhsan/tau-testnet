**Design for Bounty 01 — part 3 of 3** (continued; end of design)

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
