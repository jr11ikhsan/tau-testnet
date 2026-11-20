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
