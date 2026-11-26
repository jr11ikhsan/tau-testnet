"""The rules-in-force view at a block (issue #42, bounty 02).

    getrulesinforce [account] [height]

The same data as `getactiverules [account] [height]`, under the
rules-in-force name: the canonical spec in force at the requested
height, the per-unit survival ledger, and `fee_rules` -- every
accepted unit that writes the fee stream o8, whoever sent it (see
`consensus.active_rules.fee_rules_for`).

`fee_rules` is derived at the snapshot being served, so asked at a
past height it reports the fee rules known AT that height, never from
later state; `fee_rules_as_of` says so (`"this block"` at the tip,
`"as of height <height>"` otherwise). That is the honest as-of the
view can give: the ledger is derived from the snapshot sequence, and
the sequence at a past height is exactly the history known then. A
view that served the current-tip accumulation at a historical block
would have to label it current-tip; this one does not need to.

This is a thin entry point over `commands.getactiverules.view_data`,
so the two commands cannot drift apart. Read-only; held
(`available: False`) when the journal cut for the served snapshot is
TAMPERED, exactly as `getactiverules` holds it (O-2).
"""
import api_response
from commands import getactiverules

_CMD = "getrulesinforce"
_USAGE = "Usage: getrulesinforce [account] [height]"


def execute(raw_command: str, container):
    parts = raw_command.split()
    if not 1 <= len(parts) <= 3:
        return api_response.error_response(
            _CMD, _USAGE, "INVALID_PARAMS",
        )
    try:
        account, height = getactiverules.parse_args(parts)
    except ValueError as exc:
        return api_response.error_response(
            _CMD, str(exc), "INVALID_PARAMS",
        )
    try:
        data = getactiverules.view_data(container.db, account, height)
    except RuntimeError as exc:
        return api_response.error_response(
            _CMD, str(exc), "INTERNAL_ERROR",
        )
    data["fee_rules_as_of"] = (
        "this block" if height is None else f"as of height {height}"
    )
    return api_response.success_response(_CMD, data)
