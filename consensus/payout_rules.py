"""Payout rules: rule-computed payouts under declared caps (#63).

An owner installs one payout rule: a declared recipient set, a declared leg
program, and declared caps (a maximum per execution and a maximum per
period). Anyone may then submit an execution carrying the rule's inputs;
the node — never the submitter — runs the stored program over those inputs,
checks the computed legs against the declared set, both caps and the
owner's balance, and settles every leg atomically or none.

CONSENSUS-FROZEN SURFACE
------------------------
The bounds below are module constants, not config: a per-node value would
make two honest nodes disagree about admissibility, which forks.

- The leg program is data the owner signed, stored in the entry: each leg
  names a recipient from the declared set and computes its amount from the
  execution's submitted base amount — a FIXED declared amount, or a share
  of the base in basis points with floor rounding (the royalty shape: 500
  bps of a 101 base pays exactly 5). The submitter supplies only the base
  amount and the settlement id; it cannot steer recipients or amounts
  beyond what the signed program computes.
- Settlement is recorded in the book keyed by the execution's settlement
  id — that is what makes "pays 5, once" a consensus property, not a
  client property. A second execution carrying an already-settled
  settlement id (a replay of the same transaction, or a fresh transaction
  naming the same settlement) settles nothing. Settlements are rooted with
  the book and survive removal and replacement of the rule, so reinstalling
  the same rule can never reset one.
- Caps: a declared cap of 0 leaves that dimension uncapped. A cap that is
  declared binds exactly: an execution whose total exceeds the
  per-execution cap, or that would push the period's paid total past the
  per-period cap, settles nothing. The period is a fixed-length window
  from the rule's signed anchor (period_seconds), the standing book's
  fixed-schedule arithmetic; per-period paid totals are book state.
- An execution that cannot settle settles NOTHING: no leg moves, no
  settlement is recorded, no period total advances — the same discipline
  as a standing payment's insufficient-funds occurrence, so a retry with
  valid inputs is a well-defined, explicit operation.
- Legs settle with the payout-leg credit class (the design's credit-class
  table): a payout credit never triggers a receive route, another payout,
  or a standing payment.
- FIX 1-B (recorded-receipt base): a rule may declare its base source as
  the node's own record of an incoming transfer instead of the amount an
  execution submits. When an ordinary (or claimed-payment) credit lands
  on the account of an owner whose rule is receipt-based, the node
  records a receipt in this book — sender, recipient, gross amount,
  timestamp, under an id derived from the containing transaction — at
  the post-settlement site, so a fee-rejected transfer records nothing.
  An execution of a receipt-based rule names a receipt id; the node
  fills the base from the recorded amount and the submitted
  `payout_base_amount` is ignored entirely, so no executor can inflate
  the base a royalty computes over. A receipt funds exactly one
  execution: settling consumes it, and a second execution naming it
  settles nothing. Receipts are rooted with the book and survive rule
  removal and replacement, like settlements. The base resolution lives
  in this book's evaluation — the one point both leg forms draw from:
  the declared form's `compute_legs` here, and the Tau clause form's
  input map (its i1 is the base the engine hands this book) on the
  clause lineage, which must be fed the resolved base from here.
- Removal follows the account's normal rules: an owner-signed removal
  transaction, screened by the book's can_remove at admission and apply
  verbatim. (A #33-style lock, if one is ever active on the account, binds
  through the same administration path as the other books; #33 is not on
  main at the base this book was built against.)
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

import tau_defs
from consensus.payment_calendar import SECONDS_PER_DAY
from consensus.serialization import (
    compute_payout_receipt_id,
    compute_payout_rule_book_root,
    compute_payout_rule_id,
)

TX_TYPE_INSTALL_PAYOUT_RULE = "install_payout_rule"
TX_TYPE_REMOVE_PAYOUT_RULE = "remove_payout_rule"
TX_TYPE_EXECUTE_PAYOUT_RULE = "execute_payout_rule"

PAYOUT_RULE_TX_TYPES = frozenset(
    {
        TX_TYPE_INSTALL_PAYOUT_RULE,
        TX_TYPE_REMOVE_PAYOUT_RULE,
        TX_TYPE_EXECUTE_PAYOUT_RULE,
    }
)

# Leg computation modes. A leg's amount is a pure function of the signed
# program and the execution's submitted base amount.
LEG_FIXED = 1
LEG_BPS_OF_BASE = 2
LEG_MODES = frozenset({LEG_FIXED, LEG_BPS_OF_BASE})
MAX_LEG_BPS = 10_000

# Base sources (FIX 1-B). Where the base a rule's basis-point legs
# compute over comes from: the amount an execution submits (the legacy
# source), or the node's own recorded receipt of an incoming transfer
# (the execution names the receipt; the node fills the amount).
BASE_SUBMITTED = 0
BASE_RECORDED_RECEIPT = 1
BASE_SOURCES = frozenset({BASE_SUBMITTED, BASE_RECORDED_RECEIPT})

# Bounded state: one rule per owner, and the rule itself is small.
MAX_RECIPIENTS = 32
MAX_LEGS = 32
MAX_PERIOD_SECONDS = 366 * SECONDS_PER_DAY

_PUBKEY_RE = re.compile(r"^[0-9a-f]{96}$")
_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_U64_MAX = 0xFFFFFFFFFFFFFFFF


class PayoutRuleShapeError(ValueError):
    """A payout-rule transaction does not have a shape the node can record."""


@dataclass(frozen=True)
class PayoutLeg:
    """One leg of the signed program: who is paid, and how the amount computes."""

    recipient_pubkey: str
    mode: int
    value: int

    def amount_for(self, base_amount: int) -> int:
        if self.mode == LEG_FIXED:
            return self.value
        return (base_amount * self.value) // MAX_LEG_BPS


@dataclass(frozen=True)
class PayoutRuleEntry:
    """The signed terms of one payout rule version. Nothing here mutates."""

    owner_pubkey: str
    recipients: Tuple[str, ...]
    legs: Tuple[PayoutLeg, ...]
    max_per_execution: int
    max_per_period: int
    period_seconds: int
    period_anchor_ts: int
    version: int
    base_source: int = BASE_SUBMITTED

    @property
    def rule_id(self) -> bytes:
        return compute_payout_rule_id(
            self.owner_pubkey,
            self.recipients,
            tuple(
                (leg.recipient_pubkey, leg.mode, leg.value) for leg in self.legs
            ),
            self.max_per_execution,
            self.max_per_period,
            self.period_seconds,
            self.period_anchor_ts,
            self.version,
            self.base_source,
        )


@dataclass(frozen=True)
class PayoutSettlement:
    """The record of one settled execution. History: never rewritten."""

    rule_id: bytes
    settlement_id: bytes
    base_amount: int
    total: int
    execution_ts: int
    receipt_id: bytes = b""


@dataclass(frozen=True)
class PayoutReceipt:
    """The node's record of one incoming transfer (FIX 1-B).

    Recorded when an ordinary or claimed-payment credit lands on the
    account of an owner whose payout rule is receipt-based: the gross
    amount that actually arrived, who sent it, and when. An execution
    names a receipt by id and the node — never the submitter — fills
    the execution's base from `amount`.
    """

    receipt_id: bytes
    recipient_pubkey: str
    sender_pubkey: str
    amount: int
    recorded_ts: int


@dataclass(frozen=True)
class PayoutDecision:
    """The outcome of presenting one execution to the book.

    `executed` False means nothing moved: no leg settled, no settlement
    was recorded, no period total advanced. `reason` names why, for
    receipts and tests. On success `legs` is the computed (recipient,
    amount) list with zero legs dropped, `total` their sum, and
    `period_index` the period the execution landed in.
    """

    executed: bool
    reason: str
    legs: Tuple[Tuple[str, int], ...]
    total: int
    period_index: int
    period_total_after: int


def period_index_at(entry: PayoutRuleEntry, ts: int) -> int:
    """Which period contains `ts`; -1 before the anchor."""
    if ts < entry.period_anchor_ts:
        return -1
    return (ts - entry.period_anchor_ts) // entry.period_seconds


def compute_legs(
    entry: PayoutRuleEntry, base_amount: int
) -> Tuple[Tuple[str, int], ...]:
    """The legs the stored program computes for `base_amount`.

    Pure and deterministic: the same entry and the same inputs give the
    same legs on every node. Legs that compute to zero are dropped — a
    zero leg moves no value and must not pose as a payment.
    """
    out = []
    for leg in entry.legs:
        amount = leg.amount_for(base_amount)
        if amount > 0:
            out.append((leg.recipient_pubkey, amount))
    return tuple(out)


# --- Parsing -------------------------------------------------------------------


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _pubkey_field(tx: Dict[str, Any], name: str) -> str:
    value = tx.get(name)
    if not isinstance(value, str) or not _PUBKEY_RE.match(value):
        raise PayoutRuleShapeError(f"{name} must be 96 lowercase hex characters")
    return value


def _u64_field(tx: Dict[str, Any], name: str, default: int = 0) -> int:
    value = tx.get(name, default)
    if not _is_int(value) or value < 0 or value > _U64_MAX:
        raise PayoutRuleShapeError(f"{name} must be an unsigned 64-bit integer")
    return value


def _id_field(tx: Dict[str, Any], name: str) -> bytes:
    value = tx.get(name)
    if not isinstance(value, str) or not _ID_RE.match(value):
        raise PayoutRuleShapeError(f"{name} must be 64 lowercase hex characters")
    return bytes.fromhex(value)


def _recipients_field(tx: Dict[str, Any]) -> Tuple[str, ...]:
    value = tx.get("payout_recipients")
    if not isinstance(value, list) or not value:
        raise PayoutRuleShapeError("payout_recipients must be a non-empty list")
    out = []
    for item in value:
        if not isinstance(item, str) or not _PUBKEY_RE.match(item):
            raise PayoutRuleShapeError(
                "payout_recipients entries must be 96 lowercase hex characters"
            )
        out.append(item)
    # The declared set is a set: canonical (sorted, unique) in the entry, so
    # two spellings of the same set are the same rule.
    return tuple(sorted(set(out)))


def _legs_field(tx: Dict[str, Any]) -> Tuple[PayoutLeg, ...]:
    value = tx.get("payout_legs")
    if not isinstance(value, list) or not value:
        raise PayoutRuleShapeError("payout_legs must be a non-empty list")
    out = []
    for item in value:
        if not isinstance(item, (list, tuple)) or len(item) != 3:
            raise PayoutRuleShapeError(
                "payout_legs entries must be [recipient, mode, value]"
            )
        recipient, mode, amount = item
        if not isinstance(recipient, str) or not _PUBKEY_RE.match(recipient):
            raise PayoutRuleShapeError(
                "payout_legs recipients must be 96 lowercase hex characters"
            )
        if not _is_int(mode) or not _is_int(amount):
            raise PayoutRuleShapeError("payout_legs mode and value must be integers")
        out.append(PayoutLeg(recipient, mode, amount))
    return tuple(out)


def parse_install_payout_rule(tx: Dict[str, Any]) -> PayoutRuleEntry:
    """Read an installation from ROOT fields only; a nested `payload` is unsigned data."""
    if not isinstance(tx, dict):
        raise PayoutRuleShapeError("transaction must be an object")
    return PayoutRuleEntry(
        owner_pubkey=_pubkey_field(tx, "sender_pubkey"),
        recipients=_recipients_field(tx),
        legs=_legs_field(tx),
        max_per_execution=_u64_field(tx, "payout_max_per_execution"),
        max_per_period=_u64_field(tx, "payout_max_per_period"),
        period_seconds=_u64_field(tx, "payout_period_seconds"),
        period_anchor_ts=_u64_field(tx, "payout_period_anchor_ts"),
        version=_u64_field(tx, "payout_version", default=1),
        base_source=_u64_field(tx, "payout_base_source", default=0),
    )


def parse_remove_payout_rule(tx: Dict[str, Any]) -> str:
    """Read a removal's owner from ROOT fields only; returns the owner pubkey."""
    if not isinstance(tx, dict):
        raise PayoutRuleShapeError("transaction must be an object")
    return _pubkey_field(tx, "sender_pubkey")


def parse_execute_payout_rule(
    tx: Dict[str, Any],
) -> Tuple[bytes, bytes, int]:
    """Read an execution from ROOT fields: (rule id, settlement id, base amount)."""
    if not isinstance(tx, dict):
        raise PayoutRuleShapeError("transaction must be an object")
    return (
        _id_field(tx, "payout_rule_id"),
        _id_field(tx, "payout_settlement_id"),
        _u64_field(tx, "payout_base_amount"),
    )


def parse_execute_payout_receipt_id(tx: Dict[str, Any]) -> Optional[bytes]:
    """The receipt an execution names (FIX 1-B), or None when it names none.

    A present-but-malformed field is a shape error, not an absence: an
    executor who names a receipt must name it exactly, or the execution
    is not the one they signed.
    """
    if not isinstance(tx, dict):
        raise PayoutRuleShapeError("transaction must be an object")
    if "payout_receipt_id" not in tx or tx.get("payout_receipt_id") is None:
        return None
    return _id_field(tx, "payout_receipt_id")


def validate_payout_rule_shape(
    entry: PayoutRuleEntry, now_ts: int
) -> Optional[str]:
    """Stateless admissibility of a payout rule. None when fine.

    Shared by admission and apply: they must reject the same inputs or the
    chain splits. Anything needing the book lives in `can_install`.
    """
    if not 1 <= len(entry.recipients) <= MAX_RECIPIENTS:
        return f"a payout rule declares 1..{MAX_RECIPIENTS} recipients"
    if len(set(entry.recipients)) != len(entry.recipients):
        return "the declared recipient set names an account twice"
    if entry.owner_pubkey in entry.recipients:
        return "a payout rule cannot pay its own owner"
    if not 1 <= len(entry.legs) <= MAX_LEGS:
        return f"a payout rule's program has 1..{MAX_LEGS} legs"
    declared = set(entry.recipients)
    for leg in entry.legs:
        if leg.recipient_pubkey not in declared:
            return "a leg pays a recipient outside the declared set"
        if leg.mode not in LEG_MODES:
            return "unknown leg mode"
        if leg.mode == LEG_FIXED:
            if not 1 <= leg.value <= tau_defs.MAX_TRANSFER_VALUE:
                return "a fixed leg must be in 1..MAX_TRANSFER_VALUE"
        elif not 1 <= leg.value <= MAX_LEG_BPS:
            return "a basis-point leg must be in 1..10000"
    if entry.max_per_execution > tau_defs.MAX_TRANSFER_VALUE:
        return "payout_max_per_execution exceeds the maximum transfer value"
    if entry.max_per_period > tau_defs.MAX_TRANSFER_VALUE:
        return "payout_max_per_period exceeds the maximum transfer value"
    if not 1 <= entry.period_seconds <= MAX_PERIOD_SECONDS:
        return f"payout_period_seconds must be in 1..{MAX_PERIOD_SECONDS}"
    if entry.version < 1:
        return "payout_version must start at 1"
    if entry.base_source not in BASE_SOURCES:
        return "payout_base_source must be 0 (submitted) or 1 (recorded receipt)"
    if entry.base_source == BASE_RECORDED_RECEIPT and not any(
        leg.mode == LEG_BPS_OF_BASE for leg in entry.legs
    ):
        return (
            "a receipt-based rule must declare a basis-point leg: the "
            "recorded receipt is the base those legs compute over"
        )
    return None


# --- The book ------------------------------------------------------------------

_EntryRow = Tuple[
    bytes, str, Tuple[str, ...], Tuple[Tuple[str, int, int], ...],
    int, int, int, int, int, Tuple[Tuple[int, int], ...], int,
]
_SettlementRow = Tuple[bytes, bytes, int, int, int, bytes]
_ReceiptRow = Tuple[bytes, str, str, int, int]


class PayoutRuleBook:
    """Payout rules, their per-period paid totals, and their settlements.

    Composed as a field of ConsensusLifecycleManager in the wiring slice, so
    the meta hash picks the book root up without a call site to forget (the
    RetractableBook pattern). Entries and settlements are frozen, so copies
    share them; only the period-total maps are duplicated.
    """

    def __init__(self) -> None:
        self._entries: Dict[str, PayoutRuleEntry] = {}
        self._by_id: Dict[bytes, str] = {}
        self._period_totals: Dict[bytes, Dict[int, int]] = {}
        self._settlements: Dict[Tuple[bytes, bytes], PayoutSettlement] = {}
        self._receipts: Dict[bytes, PayoutReceipt] = {}
        self._consumed_receipts: set = set()
        self._root: Optional[bytes] = None

    # -- copying / restoring ---------------------------------------------------

    def __deepcopy__(self, memo: Dict[int, Any]) -> "PayoutRuleBook":
        clone = PayoutRuleBook.__new__(PayoutRuleBook)
        clone._entries = dict(self._entries)
        clone._by_id = dict(self._by_id)
        clone._period_totals = {
            k: dict(v) for k, v in self._period_totals.items()
        }
        clone._settlements = dict(self._settlements)
        clone._receipts = dict(self._receipts)
        clone._consumed_receipts = set(self._consumed_receipts)
        clone._root = self._root
        memo[id(self)] = clone
        return clone

    @classmethod
    def restore(
        cls,
        rows: Iterable[_EntryRow],
        settlements: Iterable = (),
        receipts: Iterable[_ReceiptRow] = (),
    ) -> "PayoutRuleBook":
        """Rebuild from stored rows; refuses any row whose id does not recompute.

        Entry rows written before FIX 1-B carry no base source and
        settlement rows no receipt id; both restore with the legacy
        defaults, so an older stored book rebuilds identically.
        """
        book = cls()
        for row in rows:
            (rule_id, owner, recipients, legs, max_exec, max_period,
             period_seconds, anchor, version, period_totals) = row[:10]
            base_source = int(row[10]) if len(row) > 10 else BASE_SUBMITTED
            entry = PayoutRuleEntry(
                owner,
                tuple(recipients),
                tuple(PayoutLeg(r, m, v) for r, m, v in legs),
                max_exec, max_period, period_seconds, anchor, version,
                base_source,
            )
            if entry.rule_id != bytes(rule_id):
                raise ValueError(
                    f"stored payout rule id does not match its fields: {entry.rule_id.hex()}"
                )
            if owner in book._entries:
                raise ValueError(f"duplicate stored payout rule for owner: {owner}")
            totals: Dict[int, int] = {}
            for index, total in period_totals:
                if index in totals:
                    raise ValueError("duplicate stored period total")
                if total < 0:
                    raise ValueError("stored period total is negative")
                totals[int(index)] = int(total)
            book._entries[owner] = entry
            book._by_id[entry.rule_id] = owner
            book._period_totals[entry.rule_id] = totals
        for row in settlements:
            rule_id, settlement_id, base, total, exec_ts = row[:5]
            receipt_id = bytes(row[5]) if len(row) > 5 else b""
            record = PayoutSettlement(
                bytes(rule_id), bytes(settlement_id), base, total, exec_ts,
                receipt_id,
            )
            key = (record.rule_id, record.settlement_id)
            if key in book._settlements:
                raise ValueError("duplicate stored payout settlement")
            book._settlements[key] = record
            if record.receipt_id:
                book._consumed_receipts.add(record.receipt_id)
        for row in receipts:
            receipt_id, recipient, sender, amount, recorded_ts = row[:5]
            receipt = PayoutReceipt(
                bytes(receipt_id), recipient, sender, int(amount),
                int(recorded_ts),
            )
            if receipt.receipt_id in book._receipts:
                raise ValueError("duplicate stored payout receipt")
            book._receipts[receipt.receipt_id] = receipt
            # A stored row may carry consumption as a sixth element:
            # admission's one-entry rebuild needs it, because the
            # settlement that consumed the receipt may belong to a rule
            # version the rebuilt book does not hold.
            if len(row) > 5 and row[5]:
                book._consumed_receipts.add(receipt.receipt_id)
        return book

    def rows(self) -> List[_EntryRow]:
        out: List[_EntryRow] = []
        for entry in self._entries.values():
            totals = self._period_totals.get(entry.rule_id, {})
            out.append(
                (
                    entry.rule_id,
                    entry.owner_pubkey,
                    entry.recipients,
                    tuple(
                        (leg.recipient_pubkey, leg.mode, leg.value)
                        for leg in entry.legs
                    ),
                    entry.max_per_execution,
                    entry.max_per_period,
                    entry.period_seconds,
                    entry.period_anchor_ts,
                    entry.version,
                    tuple(sorted(totals.items())),
                    entry.base_source,
                )
            )
        return out

    def settlement_rows(self) -> List[_SettlementRow]:
        return [
            (s.rule_id, s.settlement_id, s.base_amount, s.total, s.execution_ts,
             s.receipt_id)
            for s in self._settlements.values()
        ]

    def receipt_rows(self) -> List[_ReceiptRow]:
        return [
            (r.receipt_id, r.recipient_pubkey, r.sender_pubkey, r.amount,
             r.recorded_ts)
            for r in self._receipts.values()
        ]

    def root(self) -> bytes:
        if self._root is None:
            self._root = compute_payout_rule_book_root(
                self.rows(), self.settlement_rows(), self.receipt_rows()
            )
        return self._root

    # -- queries -----------------------------------------------------------------

    def get(self, owner_pubkey: str) -> Optional[PayoutRuleEntry]:
        return self._entries.get(owner_pubkey)

    def get_by_id(self, rule_id: bytes) -> Optional[PayoutRuleEntry]:
        owner = self._by_id.get(bytes(rule_id))
        return self._entries.get(owner) if owner is not None else None

    def rule_count(self) -> int:
        return len(self._entries)

    def is_empty(self) -> bool:
        """True while no rule, no settlement and no receipt exists.

        Settlements are rooted with the entries and outlive their rule
        versions, so a book that has ever settled is never empty again —
        that is what the meta-hash gate in governance keys off. Receipts
        (FIX 1-B) outlive their rule the same way, for the same reason:
        a recorded base must stay provable after the rule is gone.
        """
        return not self._entries and not self._settlements and not self._receipts

    # -- receipts (FIX 1-B) ------------------------------------------------------

    def get_receipt(self, receipt_id: bytes) -> Optional[PayoutReceipt]:
        return self._receipts.get(bytes(receipt_id))

    def receipt_consumed(self, receipt_id: bytes) -> bool:
        return bytes(receipt_id) in self._consumed_receipts

    def receipts_for(self, recipient_pubkey: str) -> List[PayoutReceipt]:
        return sorted(
            (r for r in self._receipts.values()
             if r.recipient_pubkey == recipient_pubkey),
            key=lambda r: r.receipt_id,
        )

    def record_receipt(self, receipt: PayoutReceipt) -> bool:
        """Record one incoming transfer. True when newly recorded.

        Called by the engine at the post-settlement site for a credit
        that actually landed. Recording the same receipt twice (the
        same transaction re-presented to the same state) is a no-op;
        a conflicting record under an existing id is a hard error —
        two different transfers must never share a name.
        """
        existing = self._receipts.get(receipt.receipt_id)
        if existing is not None:
            if existing == receipt:
                return False
            raise ValueError(
                f"payout receipt id {receipt.receipt_id.hex()} already "
                "records a different transfer"
            )
        self._receipts[receipt.receipt_id] = receipt
        self._root = None
        return True

    def _entry(self, rule_id: bytes) -> PayoutRuleEntry:
        entry = self.get_by_id(rule_id)
        if entry is None:
            raise ValueError(f"no payout rule with id {bytes(rule_id).hex()}")
        return entry

    def is_settled(self, rule_id: bytes, settlement_id: bytes) -> bool:
        return (bytes(rule_id), bytes(settlement_id)) in self._settlements

    def settlement(
        self, rule_id: bytes, settlement_id: bytes
    ) -> Optional[PayoutSettlement]:
        return self._settlements.get((bytes(rule_id), bytes(settlement_id)))

    def settlements_for(self, rule_id: bytes) -> List[PayoutSettlement]:
        rule_id = bytes(rule_id)
        return sorted(
            (s for (rid, _), s in self._settlements.items() if rid == rule_id),
            key=lambda s: s.settlement_id,
        )

    def period_total(self, rule_id: bytes, period_index: int) -> int:
        return self._period_totals.get(bytes(rule_id), {}).get(period_index, 0)

    # -- installation / removal ----------------------------------------------------

    def can_install(
        self, entry: PayoutRuleEntry, now_ts: int
    ) -> Tuple[bool, str]:
        problem = validate_payout_rule_shape(entry, now_ts)
        if problem is not None:
            return False, problem
        if entry.rule_id in self._by_id:
            return False, "this payout rule already exists"
        existing = self._entries.get(entry.owner_pubkey)
        if existing is not None:
            if entry.version != existing.version + 1:
                return (
                    False,
                    "a replacement must be the next version "
                    f"({existing.version + 1}), got {entry.version}",
                )
        elif entry.version != 1:
            return False, "a first payout rule must be version 1"
        return True, ""

    def install(self, entry: PayoutRuleEntry, now_ts: int) -> bytes:
        """Install a rule; a new version supersedes the old one wholesale.

        The old version can no longer execute and its period totals are
        discarded with it (its terms may have changed), but its settlements
        stay recorded — history is not rewritten, and reinstalling the old
        version later cannot re-pay them.
        """
        ok, reason = self.can_install(entry, now_ts)
        if not ok:
            raise ValueError(reason)
        old = self._entries.get(entry.owner_pubkey)
        if old is not None:
            del self._by_id[old.rule_id]
            self._period_totals.pop(old.rule_id, None)
        self._entries[entry.owner_pubkey] = entry
        self._by_id[entry.rule_id] = entry.owner_pubkey
        self._period_totals[entry.rule_id] = {}
        self._root = None
        return entry.rule_id

    def can_remove(self, owner_pubkey: str, now_ts: int) -> Tuple[bool, str]:
        if owner_pubkey not in self._entries:
            return False, "no payout rule installed for this account"
        return True, ""

    def remove(self, owner_pubkey: str, now_ts: int) -> PayoutRuleEntry:
        """Remove the owner's rule. Its settlements stay recorded."""
        ok, reason = self.can_remove(owner_pubkey, now_ts)
        if not ok:
            raise ValueError(reason)
        entry = self._entries.pop(owner_pubkey)
        del self._by_id[entry.rule_id]
        self._period_totals.pop(entry.rule_id, None)
        self._root = None
        return entry

    # -- execution -------------------------------------------------------------------

    def _evaluate(
        self,
        entry: PayoutRuleEntry,
        settlement_id: bytes,
        base_amount: int,
        ts: int,
        owner_balance: int,
        receipt_id: Optional[bytes] = None,
    ) -> PayoutDecision:
        """Pure evaluation: the decision an execution would produce."""

        def refuse(reason: str, period_index: int = -1) -> PayoutDecision:
            current = period_index_at(entry, ts) if period_index < 0 else period_index
            return PayoutDecision(
                False, reason, (), 0, max(current, 0),
                self.period_total(entry.rule_id, current) if current >= 0 else 0,
            )

        # FIX 1-B: resolve the base before anything computes over it.
        # For a receipt-based rule the submitted base amount is ignored
        # entirely — the base is the recorded amount of the receipt the
        # execution names, filled in by the node — so no executor can
        # inflate the base a basis-point leg computes over.
        if entry.base_source == BASE_RECORDED_RECEIPT:
            if receipt_id is None:
                return refuse(
                    "this rule takes its base from a recorded receipt: "
                    "the execution must name payout_receipt_id"
                )
            receipt = self._receipts.get(bytes(receipt_id))
            if receipt is None:
                return refuse("no recorded receipt with the named id")
            if receipt.recipient_pubkey != entry.owner_pubkey:
                return refuse(
                    "the named receipt was not received by the rule's owner"
                )
            if bytes(receipt_id) in self._consumed_receipts:
                return refuse(
                    "this receipt has already funded an execution: "
                    "the royalty pays once"
                )
            base_amount = receipt.amount
        elif receipt_id is not None:
            return refuse(
                "this rule takes its base from the submitted amount: "
                "naming a receipt means nothing for it"
            )
        if not 1 <= base_amount <= tau_defs.MAX_TRANSFER_VALUE:
            return refuse("payout_base_amount must be in 1..MAX_TRANSFER_VALUE")
        if self.is_settled(entry.rule_id, settlement_id):
            return refuse(
                "this settlement is already recorded: the execution has paid, once"
            )
        period = period_index_at(entry, ts)
        if period < 0:
            return refuse("the execution precedes the rule's first period")
        legs = compute_legs(entry, base_amount)
        if not legs:
            return refuse("the rule computes no payment for these inputs", period)
        declared = set(entry.recipients)
        if any(recipient not in declared for recipient, _ in legs):
            return refuse("a computed leg pays an undeclared recipient", period)
        total = sum(amount for _, amount in legs)
        if entry.max_per_execution and total > entry.max_per_execution:
            return refuse(
                f"the computed total {total} exceeds the rule's declared "
                f"max per execution {entry.max_per_execution}",
                period,
            )
        paid_this_period = self.period_total(entry.rule_id, period)
        if entry.max_per_period and paid_this_period + total > entry.max_per_period:
            return refuse(
                f"the computed total {total} would push this period's paid "
                f"total past the rule's declared max per period "
                f"{entry.max_per_period}",
                period,
            )
        if total > owner_balance:
            return refuse(
                "insufficient funds: the execution settles nothing", period
            )
        return PayoutDecision(
            True, "executed", legs, total, period, paid_this_period + total
        )

    def evaluate_execution(
        self,
        rule_id: bytes,
        settlement_id: bytes,
        base_amount: int,
        ts: int,
        owner_balance: int,
        receipt_id: Optional[bytes] = None,
    ) -> PayoutDecision:
        """What an execution would do, without doing it."""
        entry = self._entry(rule_id)
        return self._evaluate(
            entry, bytes(settlement_id), base_amount, ts, owner_balance,
            receipt_id,
        )

    def execute(
        self,
        rule_id: bytes,
        settlement_id: bytes,
        base_amount: int,
        ts: int,
        owner_balance: int,
        receipt_id: Optional[bytes] = None,
    ) -> PayoutDecision:
        """Settle an execution, or settle nothing.

        On success the settlement is recorded under its settlement id and
        the period total advances by the computed total — the two writes
        that make a repeat execution of the same settlement a no-op. A
        refused execution changes no state.

        For a receipt-based rule the settlement records the RESOLVED
        base (the receipt's recorded amount, never the submitted one)
        and the receipt it came from, and the receipt is consumed: a
        later execution naming it settles nothing.
        """
        entry = self._entry(rule_id)
        settlement_id = bytes(settlement_id)
        decision = self._evaluate(
            entry, settlement_id, base_amount, ts, owner_balance, receipt_id
        )
        if not decision.executed:
            return decision
        settled_receipt_id = b""
        settled_base = base_amount
        if entry.base_source == BASE_RECORDED_RECEIPT:
            receipt = self._receipts[bytes(receipt_id)]
            settled_receipt_id = receipt.receipt_id
            settled_base = receipt.amount
        self._settlements[(entry.rule_id, settlement_id)] = PayoutSettlement(
            rule_id=entry.rule_id,
            settlement_id=settlement_id,
            base_amount=settled_base,
            total=decision.total,
            execution_ts=ts,
            receipt_id=settled_receipt_id,
        )
        if settled_receipt_id:
            self._consumed_receipts.add(settled_receipt_id)
        totals = self._period_totals.setdefault(entry.rule_id, {})
        totals[decision.period_index] = (
            totals.get(decision.period_index, 0) + decision.total
        )
        self._root = None
        return decision


# --- Capability reporting -------------------------------------------------------


def payout_rule_capabilities() -> Dict[str, Any]:
    """The payout-rule semantics a capability endpoint reports (#63).

    Built from the module's own values so the report can never drift from
    the code: if a bound changes, this record changes with it. (Support,
    leg modes, caps and settlement semantics, stated before send — the
    consensus-level record an endpoint serves, there being no
    capability-endpoint infrastructure in the codebase yet.)
    """
    return {
        "supported": True,
        "leg_modes": {"fixed": LEG_FIXED, "bps_of_base": LEG_BPS_OF_BASE},
        "base_sources": {
            "submitted": BASE_SUBMITTED,
            "recorded_receipt": BASE_RECORDED_RECEIPT,
        },
        "rounding": "floor on basis-point legs",
        "caps": (
            "declared per execution and per period; 0 leaves that "
            "dimension uncapped"
        ),
        "settlement": (
            "recorded by settlement id; a settled execution never pays twice"
        ),
        "credit_class": "payout_leg",
        "fee": "the submitter pays the ordinary fee",
        "max_recipients": MAX_RECIPIENTS,
        "max_legs": MAX_LEGS,
    }
