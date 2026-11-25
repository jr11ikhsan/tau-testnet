"""Pre-flight read of one address's recipient policy (issues #47/#76).

Read-only. Answers the two questions a payer's wallet asks before it parks
money at someone: does this recipient restrict inbound payments at all, and
would THIS payment — this sender, this amount, this hold, these condition
terms (allowance / refund delay / expiry, parts 3-4) — be admitted?

The second question is answered by running the gate itself
(`sender_policy.recipient_clause_blocks`, the same helper admission and
apply use) against a hypothetical transfer, so the answer cannot drift from
what the chain will do. When the recipient's rule is a threshold rule, a
refusal carries the cap verified against this payer's own evaluation —
`max_hold_seconds` / `max_hold_blocks` — which is the number a wallet may
print ("accepts payments held for up to ..."). A rule-shaped cap is
reported honestly as `cap_kind: "rule"` with no number.
"""
import time

import api_response
import tau_defs
from consensus import sender_policy
from consensus.approvals import _normalize_pubkey, ApprovalShapeError

_CMD = "getrecipientpolicy"

_UNIT_CONTEXTS = {
    "seconds": tau_defs.CONTEXT_INCOMING_TIME_PARK,
    "second": tau_defs.CONTEXT_INCOMING_TIME_PARK,
    "s": tau_defs.CONTEXT_INCOMING_TIME_PARK,
    "blocks": tau_defs.CONTEXT_INCOMING_HEIGHT_PARK,
    "block": tau_defs.CONTEXT_INCOMING_HEIGHT_PARK,
    "b": tau_defs.CONTEXT_INCOMING_HEIGHT_PARK,
}


def _condition_facts_from(parts):
    """(facts, terms_summary) from the optional condition-term arguments
    (allowance_amount allowance_period refund_delay expiry_seconds), or
    (all-zero facts, summary) when they are absent. Raises ValueError on
    a malformed term, exactly as the park parser would refuse it."""
    from consensus.retractable import ConditionTerms, parse_condition_terms

    if parts is None:
        terms = ConditionTerms()
    else:
        tx = {}
        amount, period, refund_delay, expiry = parts
        if amount is not None:
            tx["allowance_amount"] = amount
        if period is not None:
            tx["allowance_period_seconds"] = period
        if refund_delay is not None:
            tx["refund_delay"] = refund_delay
        if expiry is not None:
            tx["expiry_seconds"] = expiry
        terms = parse_condition_terms(tx)
    facts = sender_policy.condition_facts(terms)
    summary = {
        "allowance_30d": facts[tau_defs.ALLOWANCE_STREAM_INDEX],
        "refund_delay": facts[tau_defs.REFUND_DELAY_STREAM_INDEX],
        "expiry_seconds": facts[tau_defs.EXPIRY_STREAM_INDEX],
    }
    return facts, summary


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) not in (2, 6, 10):
        return api_response.error_response(
            _CMD,
            f"Usage: {_CMD} <address> [sender amount hold unit "
            f"[allowance_amount allowance_period refund_delay "
            f"expiry_seconds]]",
            "INVALID_PARAMS",
        )
    try:
        address = _normalize_pubkey(parts[1])
    except ApprovalShapeError as exc:
        return api_response.error_response(_CMD, str(exc), "INVALID_PARAMS")

    from consensus.facade import TipAdmissionView

    tip = TipAdmissionView()
    if not tip.recipient_policy_active:
        return api_response.error_response(
            _CMD, "Recipient controls are not active on this chain.",
            "FEATURE_INACTIVE",
        )

    clause = tip.clause_for(address, tau_defs.USER_POLICY_STREAM_INDEX)
    inbound_capable = bool(clause) and sender_policy.clause_is_inbound_capable(clause)
    data = {
        "address": address,
        "has_clause": clause is not None,
        "inbound_capable": inbound_capable,
        # No inbound-capable clause means the neutral default: the recipient
        # is judged exactly as before this feature existed.
        "neutral_default": not inbound_capable,
        # The condition-fact streams (parts 3-4) the gate feeds, so a
        # wallet can phrase those asks too. Allocation PROVISIONAL — see
        # tau_defs.
        "condition_streams": {
            "allowance": tau_defs.ALLOWANCE_STREAM_INDEX,
            "refund_delay": tau_defs.REFUND_DELAY_STREAM_INDEX,
            "expiry": tau_defs.EXPIRY_STREAM_INDEX,
        },
    }

    if len(parts) >= 6:
        try:
            sender = _normalize_pubkey(parts[2])
            amount = int(parts[3])
            hold = int(parts[4])
        except (ApprovalShapeError, ValueError) as exc:
            return api_response.error_response(_CMD, str(exc), "INVALID_PARAMS")
        context = _UNIT_CONTEXTS.get(parts[5].lower())
        if context is None:
            return api_response.error_response(
                _CMD, "unit must be 'seconds' or 'blocks'", "INVALID_PARAMS"
            )
        # The optional condition terms: "-" (or the whole group omitted)
        # means the payment carries no such term, feeding 0.
        term_parts = None
        if len(parts) == 10:
            def _term(text):
                return None if text == "-" else int(text)

            try:
                term_parts = tuple(_term(p) for p in parts[6:10])
            except ValueError as exc:
                return api_response.error_response(
                    _CMD, str(exc), "INVALID_PARAMS")
        try:
            facts, facts_summary = _condition_facts_from(term_parts)
        except ValueError as exc:
            return api_response.error_response(
                _CMD, f"malformed condition terms: {exc}", "INVALID_PARAMS")
        import chain_state

        values = {
            1: str(amount),
            2: str(chain_state.get_balance(sender)),
            3: "{ #x" + sender + " }:bv[384]",
            4: "{ #x" + address + " }:bv[384]",
            12: "{ #x" + sender + " }:bv[384]",
            5: str(int(time.time())),
        }
        blocked, info = sender_policy.recipient_clause_blocks(
            tip.clause_for, address, values,
            hold=hold, context=context, pool="admission",
            facts=facts,
        )
        data["evaluation"] = {
            "sender": sender,
            "amount": amount,
            "hold": hold,
            "unit": "seconds" if context == tau_defs.CONTEXT_INCOMING_TIME_PARK
                    else "blocks",
            "condition_facts": facts_summary,
            "admitted": not blocked,
        }
        if blocked:
            data["evaluation"].update({
                k: v for k, v in (info or {}).items() if k != "o5"
            })

    return api_response.success_response(_CMD, data)
