"""Cumulative shared-rule budget (Bounty 01, G1 package).

Clean-room implementation, written from the audit specification
(``RIVAL-GAP-AUDIT-2026-11-27.md`` §2) and from the base codebase -- NOT by
copying any rival PR's code.

What it is
----------
A cap on the SHARED application specification as a whole: how many user
rules have accumulated since genesis, and how many AST nodes they total.
This is a different object from the two limits it is most often confused
with, and the distinction is load-bearing:

- ``max_rule_txs_per_block`` (governance, default 8) caps rule-bearing
  transactions PER BLOCK, because each one costs a clause build. It COUNTS
  o5 policy rules (each one registers a clause).
- FIX 8 (``consensus/payout_rules.py``) caps PAYOUT money per period.
- THIS budget caps the SIZE of the accumulated shared spec SINCE GENESIS.
  It does NOT count o5 clauses (they live in the clause registry, not in
  the accumulated spec), offers/accepts, rule-change requests, governance
  revisions, or the genesis seed rule.

Numbers are a GOVERNANCE PROPOSAL, not a maintainer decision
------------------------------------------------------------
``PROPOSED_SHARED_RULE_LIMITS`` (10 rules / 80 nodes total, 32 nodes /
rule, depth 8, 1024 bytes / rule, width bv[384]) is the proposer's
suggestion, written down so governance has something concrete to vote on.
It is labelled PROPOSED everywhere it appears (code, docs, PR text) and a
draft email asking Muhammad / the coordinator for the final numbers lives
at ``~/workspace/tau-bounty/DRAFT-EMAIL-BUDGET-NUMBERS.txt``. Do NOT
present these numbers as decided.

Counters are DERIVED from canonical text, not incremented
---------------------------------------------------------
``recount_shared_budget`` recomputes (count, nodes) from the accumulated
application-rules text: split into units, dedup, parse each unit with the
fragment parser, sum. Units that FAIL the fragment parse are SKIPPED, not
counted -- that is what excludes the genesis seed
(``((!(i0[t] = 0)) ? ...`` -- contains ``u``, untyped) and grandfathers
pre-package rules that the new screen would refuse. Consequences,
deliberate and documented:

- A repeated identical text does NOT count twice: the accumulation itself
  dedups exact units (``chain_state.save_effective_tau_spec`` and the
  engine's staged path), so counting repetitions would make the counter
  lie about the state it claims to measure. This diverges from the rival
  entry's "same text 3x = 3x" on purpose.
- Live apply and replay compute the SAME numbers from the SAME text, so a
  reorg can never leave the counter disagreeing with the state: the
  counter follows the canonical head's text by construction.
- The recount is cheap by construction: at most ``occurrences`` counted
  units can exist (admission refuses the next one), each at most
  ``rule_bytes`` long.

Governance
----------
Limits change ONLY via ``host_contract_patch`` key ``shared_rule_limits``
(a complete 6-key object; validated by ``validate_shared_rule_limits``).
A patch NEVER touches the counters. Lowering a limit below current usage
does not evict anything already accumulated; it only refuses the NEXT
rule that would exceed it.

State-hash binding
------------------
Limits (when != the proposed defaults) and counters (when non-zero) are
emitted into ``build_mechanism_metadata`` and therefore into
``consensus_meta_hash``. At genesis (0 rules, default limits) NOTHING is
emitted, so the genesis meta hash is byte-identical to before this
package -- no regenesis is required (see ``docs/rule_fragments.md`` §4).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from consensus.rule_fragment import (
    FragmentError,
    FragmentInfo,
    parse_rule_fragment_or_body,
)

# --- Proposed limits ---------------------------------------------------------
# GOVERNANCE PROPOSAL -- NOT a maintainer decision. See the module docstring
# and DRAFT-EMAIL-BUDGET-NUMBERS.txt. If governance votes different numbers,
# only these defaults change; no code path depends on the values themselves.
PROPOSED_MAX_RULE_OCCURRENCES = 10
PROPOSED_MAX_TOTAL_NODES = 80
PROPOSED_MAX_RULE_NODES = 32
PROPOSED_MAX_RULE_DEPTH = 8
PROPOSED_MAX_RULE_BYTES = 1024
PROPOSED_MAX_RULE_WIDTH = 384

SHARED_RULE_LIMIT_KEYS = (
    "occurrences",
    "total_nodes",
    "rule_nodes",
    "rule_depth",
    "rule_bytes",
    "width",
)

PROPOSED_SHARED_RULE_LIMITS: Dict[str, int] = {
    "occurrences": PROPOSED_MAX_RULE_OCCURRENCES,
    "total_nodes": PROPOSED_MAX_TOTAL_NODES,
    "rule_nodes": PROPOSED_MAX_RULE_NODES,
    "rule_depth": PROPOSED_MAX_RULE_DEPTH,
    "rule_bytes": PROPOSED_MAX_RULE_BYTES,
    "width": PROPOSED_MAX_RULE_WIDTH,
}

# Hard ceilings for a governance vote: a limit must fit in these or the
# patch is refused. They exist so a fat-fingered (or hostile) patch cannot
# set a limit the node cannot even represent.
MAX_LIMIT_OCCURRENCES = 10000
MAX_LIMIT_TOTAL_NODES = 1000000
MAX_LIMIT_RULE_NODES = 10000
MAX_LIMIT_RULE_DEPTH = 256
MAX_LIMIT_RULE_BYTES = 1048576
MAX_LIMIT_WIDTH = 384

_LIMIT_CEILINGS = {
    "occurrences": MAX_LIMIT_OCCURRENCES,
    "total_nodes": MAX_LIMIT_TOTAL_NODES,
    "rule_nodes": MAX_LIMIT_RULE_NODES,
    "rule_depth": MAX_LIMIT_RULE_DEPTH,
    "rule_bytes": MAX_LIMIT_RULE_BYTES,
    "width": MAX_LIMIT_WIDTH,
}


@dataclass(frozen=True)
class SharedRuleLimits:
    """The six cumulative-budget limits (all ints, all >= 1)."""

    occurrences: int = PROPOSED_MAX_RULE_OCCURRENCES
    total_nodes: int = PROPOSED_MAX_TOTAL_NODES
    rule_nodes: int = PROPOSED_MAX_RULE_NODES
    rule_depth: int = PROPOSED_MAX_RULE_DEPTH
    rule_bytes: int = PROPOSED_MAX_RULE_BYTES
    width: int = PROPOSED_MAX_RULE_WIDTH

    def as_dict(self) -> Dict[str, int]:
        return {
            "occurrences": self.occurrences,
            "total_nodes": self.total_nodes,
            "rule_nodes": self.rule_nodes,
            "rule_depth": self.rule_depth,
            "rule_bytes": self.rule_bytes,
            "width": self.width,
        }

    def is_proposed_default(self) -> bool:
        return self.as_dict() == PROPOSED_SHARED_RULE_LIMITS


def validate_shared_rule_limits(value: Any) -> Optional[str]:
    """Return an error string if ``value`` is not a deployable limits object.

    The patch must carry the COMPLETE object (all six keys): a partial
    patch would leave the other four limits ambiguous across nodes, and
    ambiguity in consensus state is a fork.
    """
    if isinstance(value, bool) or not isinstance(value, dict):
        return "must be an object with the six keys " + ", ".join(
            repr(k) for k in SHARED_RULE_LIMIT_KEYS
        )
    missing = [k for k in SHARED_RULE_LIMIT_KEYS if k not in value]
    if missing:
        return "missing keys: " + ", ".join(sorted(missing))
    extra = sorted(set(value) - set(SHARED_RULE_LIMIT_KEYS))
    if extra:
        return "unknown keys: " + ", ".join(extra)
    for key in SHARED_RULE_LIMIT_KEYS:
        v = value[key]
        if isinstance(v, bool) or not isinstance(v, int):
            return f"{key}: must be an integer"
        if v < 1:
            return f"{key}: must be at least 1"
        if v > _LIMIT_CEILINGS[key]:
            return f"{key}: must be at most {_LIMIT_CEILINGS[key]}"
    return None


def normalize_shared_rule_limits(value: Dict[str, int]) -> SharedRuleLimits:
    """Canonical stored form of an already-validated limits object."""
    return SharedRuleLimits(
        occurrences=int(value["occurrences"]),
        total_nodes=int(value["total_nodes"]),
        rule_nodes=int(value["rule_nodes"]),
        rule_depth=int(value["rule_depth"]),
        rule_bytes=int(value["rule_bytes"]),
        width=int(value["width"]),
    )


@dataclass
class SharedRuleBudget:
    """Cumulative budget state: limits + counters since genesis.

    Lives as a FIELD on ``ConsensusLifecycleManager`` (like ``rule_offers``)
    so ``fork()``/``adopt()`` carry it per transaction/block, and so a
    rejected transaction's charge is discarded with its fork.
    """

    limits: SharedRuleLimits = field(default_factory=SharedRuleLimits)
    count: int = 0
    nodes: int = 0

    def as_metadata(self) -> Dict[str, Any]:
        """Mechanism-metadata view (hash-compat gating lives in
        ``build_mechanism_metadata``; this just reports the values)."""
        return {
            "shared_rule_limits": self.limits.as_dict(),
            "shared_rule_count": self.count,
            "shared_rule_nodes": self.nodes,
        }

    def would_exceed(self, info: FragmentInfo) -> Optional[str]:
        """Reason the fragment would breach the budget, or None."""
        if info.nodes > self.limits.rule_nodes:
            return (
                f"rule has {info.nodes} AST nodes, over the per-rule limit "
                f"of {self.limits.rule_nodes}"
            )
        if info.depth > self.limits.rule_depth:
            return (
                f"rule has depth {info.depth}, over the per-rule limit "
                f"of {self.limits.rule_depth}"
            )
        if info.byte_len > self.limits.rule_bytes:
            return (
                f"rule is {info.byte_len} bytes, over the per-rule limit "
                f"of {self.limits.rule_bytes}"
            )
        if info.max_width > self.limits.width:
            return (
                f"rule uses bv[{info.max_width}], over the width limit "
                f"bv[{self.limits.width}]"
            )
        if self.count + 1 > self.limits.occurrences:
            return (
                f"shared rule budget exhausted: {self.count} rules "
                f"accumulated since genesis, limit "
                f"{self.limits.occurrences}"
            )
        if self.nodes + info.nodes > self.limits.total_nodes:
            return (
                f"shared rule budget exhausted: {self.nodes} nodes "
                f"accumulated since genesis, adding {info.nodes} would "
                f"exceed the total limit of {self.limits.total_nodes}"
            )
        return None

    def charge(self, info: FragmentInfo) -> None:
        """Record one accumulated rule. Callers must have checked
        ``would_exceed`` first; charging past a limit is a bug, not a
        verdict, so it raises."""
        reason = self.would_exceed(info)
        if reason is not None:
            raise ValueError(f"shared rule budget overrun: {reason}")
        self.count += 1
        self.nodes += info.nodes

    def recount(self, application_rules_text: str) -> "SharedRuleBudget":
        """Recompute the counters from canonical accumulated text.

        Pure function of the text (see the module docstring): the counters
        this returns are what admission, apply and replay must all agree
        on. Returns a NEW budget with the same limits and recomputed
        counters; ``self`` is untouched.
        """
        count, nodes = recount_shared_budget(application_rules_text)
        return SharedRuleBudget(limits=self.limits, count=count, nodes=nodes)


# ---------------------------------------------------------------------------
# What counts
# ---------------------------------------------------------------------------

def counts_toward_shared_budget(rule_text: str) -> bool:
    """True when an accumulated op-0 user rule costs cumulative budget.

    False for o5 policy rules: they register in the clause registry instead
    of accumulating into the shared spec (detected the same way the
    engine's per-block budget detects them -- the clause output streams
    contain the user-policy stream index 5). False for empty text.
    Offer/accept, rule-change requests and governance revisions never reach
    this function: they are different transaction types that do not
    accumulate into the application-rules text at all.
    """
    if not isinstance(rule_text, str) or not rule_text.strip():
        return False
    try:
        from consensus.rule_offers import clause_output_streams
        import tau_defs

        if tau_defs.USER_POLICY_STREAM_INDEX in clause_output_streams(
            rule_text
        ):
            return False
    except Exception:
        # If the clause helper is unavailable, fail CLOSED: an unclassifiable
        # rule must not silently escape the budget. (In practice the helper
        # is pure stdlib regex and cannot fail on a string.)
        return True
    return True


def split_accumulated_units(application_rules_text: str) -> List[str]:
    """Distinct non-empty units of an accumulated application-rules text.

    The accumulation joins units with ``"\\n"`` (see
    ``chain_state.save_effective_tau_spec``); a unit is one line. Exact
    duplicates collapse to one -- the accumulation itself dedups them.
    """
    seen: List[str] = []
    for line in (application_rules_text or "").split("\n"):
        unit = line.strip()
        if not unit or unit in seen:
            continue
        seen.append(unit)
    return seen


def recount_shared_budget(
    application_rules_text: str,
) -> Tuple[int, int]:
    """(count, nodes) of the accumulated text, derived, not incremented.

    Parses each distinct unit with the fragment parser -- either the
    canonical ``always ( ... )`` form or a bare rule body (the node
    accepts bare bodies, e.g. ``o12[t]:bv[24] = i1[t]:bv[24].``) -- and
    sums the node counts. Units that fail both parses are SKIPPED: the
    genesis seed and grandfathered pre-package rules are not part of the
    counted spec (see the module docstring). A unit that parses but is
    an o5 clause is also skipped -- o5 text never accumulates in
    practice, but the recount must not depend on that.
    """
    count = 0
    nodes = 0
    for unit in split_accumulated_units(application_rules_text):
        if not counts_toward_shared_budget(unit):
            continue
        try:
            info = parse_rule_fragment_or_body(unit)
        except FragmentError:
            continue
        count += 1
        nodes += info.nodes
    return count, nodes


def check_shared_rule_budget(
    rule_text: str, budget: "SharedRuleBudget"
) -> Optional[str]:
    """Admission/apply verdict for one candidate rule against a budget.

    Returns an error string, or None when the rule may accumulate. A rule
    that does not count toward the budget (o5) always passes. A rule that
    parses as neither an ``always`` unit nor a bare body is NOT a budget
    matter either: it is unmeasurable, the compile gate judges it, and
    the recount skips it -- so the budget check must agree by passing it
    (refusing it here as RULE_BUDGET would relabel the compile gate's
    pinned codes, e.g. TX_REJECTED for ``invalid rule here``).
    """
    if not counts_toward_shared_budget(rule_text):
        return None
    try:
        info = parse_rule_fragment_or_body(rule_text)
    except FragmentError:
        return None
    return budget.would_exceed(info)
