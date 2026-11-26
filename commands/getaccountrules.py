"""The account-rules view (issue #42, bounty 02).

    getaccountrules <account>

The per-account entry point over the active-rules view: the rules that
name this account, plus `fee_rules` -- every accepted unit that writes
the fee stream o8, whoever sent it (see
`consensus.active_rules.fee_rules_for`). A fee rule of one account can
change what another pays (#183), so the account's own rules alone
cannot answer "what sets my fee"; the two lists are served together.

This is a thin entry point, not a second view: the data comes from
`commands.getactiverules.view_data`, so the account view and the
rules-in-force view cannot drift apart. The only differences from
`getactiverules <account>` are the required account argument and the
command name in the envelope. The view is read-only, served from the
current tip, and held (`available: False`) when the journal cut for
the served snapshot is TAMPERED -- exactly as `getactiverules` holds
it (O-2).
"""
import api_response
from commands import getactiverules

_CMD = "getaccountrules"
_USAGE = "Usage: getaccountrules <account>"


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) != 2 or not getactiverules._is_account_token(parts[1]):
        return api_response.error_response(
            _CMD, _USAGE, "INVALID_PARAMS",
        )
    account = getactiverules._normalize_account(parts[1])
    try:
        data = getactiverules.view_data(container.db, account, None)
    except RuntimeError as exc:
        return api_response.error_response(
            _CMD, str(exc), "INTERNAL_ERROR",
        )
    return api_response.success_response(_CMD, data)
