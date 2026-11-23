"""The web wallet's "Rule for incoming payments" builder must compose the
same clause the CLI composes — byte-for-byte.

Issues #47/#76 (Bounty 03, FIX B03-3): the CLI's `policy receive` composers
(tau_testnet_cli/cli.py: compose_allowlist_clause / compose_max_hold_clause
/ compose_combined_clause) are the canonical text the node's deploy screens
and cap extractor read. The web wallet (web-wallet/app.js:
composeRecipientAllowlistClause / composeRecipientMaxHoldClause /
composeRecipientCombinedClause) is the same composer in JavaScript; this
test runs the wallet functions under node and compares their output with
the CLI's for every combination of the three shapes — valid and invalid
inputs alike — so the two surfaces can never drift apart silently.
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from tau_testnet_cli.cli import (
    compose_allowlist_clause,
    compose_combined_clause,
    compose_max_hold_clause,
)

APP_JS = Path(__file__).resolve().parent.parent / "web-wallet/app.js"

pytestmark = pytest.mark.skipif(
    shutil.which("node") is None, reason="node is not installed")

_JS_FUNCTIONS = [
    "recipientBv64Hex",
    "recipientCtxIs",
    "recipientSenderIs",
    "recipientCheckedPubkeys",
    "recipientCheckedCap",
    "composeRecipientAllowlistClause",
    "composeRecipientMaxHoldClause",
    "composeRecipientCombinedClause",
    "explainRecipientRefusal",
]


def _function_source(src: str, name: str) -> str:
    m = re.search(rf"^function {name}\(.*?^\}}\n", src, re.S | re.M)
    assert m, f"function {name} not found in app.js"
    return m.group(0)


def _run_js(cases):
    src = APP_JS.read_text(encoding="utf-8")
    script = (
        "\n".join(_function_source(src, n) for n in _JS_FUNCTIONS)
        + "\nconst fs = require('fs');\n"
        + "const cases = JSON.parse(fs.readFileSync(0, 'utf8'));\n"
        + "const out = cases.map(c => {\n"
        + "  try {\n"
        + "    if (c.kind === 'allowlist') return composeRecipientAllowlistClause(c.senders);\n"
        + "    if (c.kind === 'maxhold') return composeRecipientMaxHoldClause(c.seconds, c.blocks);\n"
        + "    if (c.kind === 'combined') return composeRecipientCombinedClause(c.senders, c.seconds, c.blocks);\n"
        + "    if (c.kind === 'explain') return explainRecipientRefusal(c.code);\n"
        + "    throw new Error('unknown kind');\n"
        + "  } catch (e) { return 'ERROR: ' + e.message; }\n"
        + "});\n"
        + "process.stdout.write(JSON.stringify(out));\n"
    )
    res = subprocess.run(
        ["node", "-e", script],
        input=json.dumps(cases).encode(),
        capture_output=True,
        check=True,
        timeout=60,
    )
    return json.loads(res.stdout)


ALICE = "aa" * 48
BOB = "bb" * 48
CAROL = "cc" * 48

# (case for the JS side, expected text from the CLI side)
PARITY_CASES = [
    pytest.param({"kind": "allowlist", "senders": [ALICE]},
                 compose_allowlist_clause([ALICE]), id="allowlist-one"),
    pytest.param({"kind": "allowlist", "senders": [ALICE, BOB, CAROL]},
                 compose_allowlist_clause([ALICE, BOB, CAROL]),
                 id="allowlist-three"),
    pytest.param({"kind": "maxhold", "seconds": 600, "blocks": None},
                 compose_max_hold_clause(600, None), id="maxhold-seconds"),
    pytest.param({"kind": "maxhold", "seconds": None, "blocks": 100},
                 compose_max_hold_clause(None, 100), id="maxhold-blocks"),
    pytest.param({"kind": "maxhold", "seconds": 0, "blocks": 0},
                 compose_max_hold_clause(0, 0), id="maxhold-zero-both"),
    pytest.param({"kind": "maxhold", "seconds": 600, "blocks": 100},
                 compose_max_hold_clause(600, 100), id="maxhold-both"),
    pytest.param({"kind": "maxhold", "seconds": 3600, "blocks": 99999},
                 compose_max_hold_clause(3600, 99999), id="maxhold-large"),
    pytest.param({"kind": "maxhold", "seconds": 16777215, "blocks": None},
                 compose_max_hold_clause(16777215, None), id="maxhold-wide-hex"),
    pytest.param({"kind": "maxhold", "seconds": 1, "blocks": 1},
                 compose_max_hold_clause(1, 1), id="maxhold-one"),
    pytest.param({"kind": "combined", "senders": [ALICE],
                  "seconds": 600, "blocks": 100},
                 compose_combined_clause([ALICE], 600, 100),
                 id="combined-full"),
    pytest.param({"kind": "combined", "senders": [ALICE, BOB],
                  "seconds": None, "blocks": None},
                 compose_combined_clause([ALICE, BOB], None, None),
                 id="combined-list-only"),
    pytest.param({"kind": "combined", "senders": [ALICE],
                  "seconds": 0, "blocks": None},
                 compose_combined_clause([ALICE], 0, None),
                 id="combined-zero-seconds"),
    pytest.param({"kind": "combined", "senders": [ALICE],
                  "seconds": None, "blocks": 7},
                 compose_combined_clause([ALICE], None, 7),
                 id="combined-blocks-only"),
]


@pytest.mark.parametrize("case,expected", PARITY_CASES)
def test_wallet_recipient_composer_matches_the_cli_byte_for_byte(case, expected):
    (got,) = _run_js([case])
    assert got == expected


def test_wallet_recipient_composer_rejects_what_the_cli_rejects():
    """Invalid inputs must fail on the wallet side too — never compose a
    clause the CLI would refuse to print."""
    bad = [
        {"kind": "allowlist", "senders": []},
        {"kind": "allowlist", "senders": ["xyz"]},
        {"kind": "allowlist", "senders": ["aa" * 47]},  # 94 hex chars
        {"kind": "maxhold", "seconds": None, "blocks": None},
        {"kind": "maxhold", "seconds": -1, "blocks": None},
        {"kind": "maxhold", "seconds": None, "blocks": -5},
        {"kind": "maxhold", "seconds": 1.5, "blocks": None},
        {"kind": "combined", "senders": [], "seconds": 600, "blocks": None},
        {"kind": "combined", "senders": [ALICE], "seconds": -1, "blocks": None},
    ]
    got = _run_js(bad)
    assert len(got) == len(bad)
    for case, out in zip(bad, got):
        assert out.startswith("ERROR: "), f"{case} composed: {out}"


def test_wallet_recipient_composer_normalizes_pubkey_case():
    """The CLI lowercases pubkeys before composing; the wallet must too,
    so an address pasted in upper case composes the identical clause."""
    (got,) = _run_js([{"kind": "allowlist", "senders": [ALICE.upper()]}])
    assert got == compose_allowlist_clause([ALICE])


def test_wallet_explains_recipient_refusals_in_actionable_words():
    """The refusal codes a payer can hit are translated into a sentence
    that says what to do next — and an unknown code explains nothing
    rather than inventing an explanation."""
    codes = ["RECIPIENT_MAX_HOLD", "RECIPIENT_POLICY",
             "recipient_policy_block", "RECIPIENT_POLICY_INACTIVE",
             "SOMETHING_ELSE"]
    got = _run_js([{"kind": "explain", "code": c} for c in codes])
    by_code = dict(zip(codes, got))
    assert "shorter hold" in by_code["RECIPIENT_MAX_HOLD"]
    assert "ask them to allow your address" in by_code["RECIPIENT_POLICY"]
    assert by_code["recipient_policy_block"] == by_code["RECIPIENT_POLICY"]
    assert "not active on this chain" in by_code["RECIPIENT_POLICY_INACTIVE"]
    assert by_code["SOMETHING_ELSE"] == ""
