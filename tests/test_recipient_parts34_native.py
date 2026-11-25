"""Bounty 03 parts 3-4 (issues #47 + #76) on the native tau-lang engine:
the recipient gate judging real parks by their signed condition terms —
the 30-day-normalised allowance (i28), the encoded refund delay (i29),
the expiry (i32) — with the real PolicyEvaluator making every verdict.

Same boot harness as the expanded recipient suite (imported, not
copied): recipient controls activated, clauses installed directly in
the lifecycle manager, parks admitted by the real sendtx path and
mined by the real createblock path. Exact allowance boundaries are
pinned through the node's own pre-flight (the 10-argument
getrecipientpolicy form takes the terms explicitly, so 2_000 vs 2_142
per 30 days is deterministic there); real parks keep wide margins.

The skip is environment-driven exactly as in the sibling suites — the
bindings are present in the real-Tau CI job's image and the skip lifts.
Everywhere else it skips.
"""
import json
import os
import sys
import time
import unittest

import pytest

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    import tau_native
    tau_native.load_tau_module()
    _NATIVE_TAU = True
except Exception:
    _NATIVE_TAU = False

from bls_keys import SK_ALICE
from commands import getrecipientpolicy
from test_recipient_controls_native_expand import (
    RECIPIENT,
    SENDER,
    _RecipientNativeHarness,
)

# The mock suite's canonical bodies (tests/test_recipient_parts34.py),
# evaluated here by the real engine instead of a scripted verdict.
ALLOWANCE_CAP_BODY = (
    "(i28[t]:bv[64] > { #x07d0 }:bv[64]) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000001 }:bv[24])"
)

REFUND_BODY = (
    "((i29[t]:bv[64] = { #x0000 }:bv[64]) || "
    "(i29[t]:bv[64] > { #xe11 }:bv[64])) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000001 }:bv[24])"
)

EXPIRY_BODY = (
    "((i32[t]:bv[64] > { #x0000 }:bv[64]) && "
    "(i32[t]:bv[64] < { #x15180 }:bv[64])) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000001 }:bv[24])"
)


class _Parts34Harness(_RecipientNativeHarness):
    def _preflight_terms(self, *terms, sender=SENDER, recipient=RECIPIENT,
                         amount=100):
        """The 10-argument pre-flight: hold 0 as a plain final payment,
        plus the four term slots ("-" = the payment carries no term)."""
        args = " ".join(str(t) for t in terms)
        pre = json.loads(getrecipientpolicy.execute(
            f"getrecipientpolicy {recipient} {sender} {amount} 0 seconds "
            f"{args}", None))
        self.assertEqual(pre["status"], "ok", pre)
        return pre["data"]["evaluation"]

    def _park_terms(self, **terms):
        return self._park_full(
            SENDER, RECIPIENT, 100, SK_ALICE,
            release_at_time=int(time.time()) + 3600, **terms)


@pytest.mark.skipif(not _NATIVE_TAU, reason="native tau module not available")
class TestAllowanceNative(_Parts34Harness, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self._install_clause(RECIPIENT, ALLOWANCE_CAP_BODY)
        self._warm()

    def test_preflight_allowance_boundary_is_exact(self):
        # Exactly at the cap: 2_000 per 30 days, admitted.
        ev = self._preflight_terms(2000, 2592000, "-", "-")
        assert ev["admitted"] is True
        assert ev["condition_facts"]["allowance_30d"] == 2000
        # The documented weekly example: 500 per week = 2_142 per 30
        # days, over the cap — refused, with the verified cap printed.
        ev = self._preflight_terms(500, 604800, "-", "-")
        assert ev["admitted"] is False
        assert ev["reason"] == "recipient_allowance_limit"
        assert ev["allowance_30d"] == 2142
        assert ev["cap_kind"] == "threshold"
        assert ev["max_allowance_30d"] == 2000
        # No terms at all: every fact 0, admitted.
        ev = self._preflight_terms("-", "-", "-", "-")
        assert ev["admitted"] is True
        assert ev["condition_facts"] == {
            "allowance_30d": 0, "refund_delay": 0, "expiry_seconds": 0}

    def test_park_over_allowance_refused_under_admitted(self):
        res, _ = self._park_terms(
            allowance_amount=500, allowance_period_seconds=604800)
        assert res["ok"] is False, res
        assert "RECIPIENT_ALLOWANCE_LIMIT" in json.dumps(res), res
        before = self._escrow_total()
        res, _ = self._park_terms(
            allowance_amount=300, allowance_period_seconds=604800)
        assert res["ok"] is True, res
        self._mine(1)
        assert self._escrow_total() == before + 100


@pytest.mark.skipif(not _NATIVE_TAU, reason="native tau module not available")
class TestRefundNative(_Parts34Harness, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self._install_clause(RECIPIENT, REFUND_BODY)
        self._warm()

    def test_refund_delay_parks(self):
        # Refundable after 7_200 s: past the clause's one-hour bound.
        res, _ = self._park_terms(refund_delay=7201)
        assert res["ok"] is False, res
        assert "RECIPIENT_REFUND_DELAY" in json.dumps(res), res
        # Never refundable: this clause requires refundability.
        res, _ = self._park_terms(refund_delay=0)
        assert res["ok"] is False, res
        # Refundable after 1_800 s: admitted and parked.
        before = self._escrow_total()
        res, _ = self._park_terms(refund_delay=1801)
        assert res["ok"] is True, res
        self._mine(1)
        assert self._escrow_total() == before + 100


@pytest.mark.skipif(not _NATIVE_TAU, reason="native tau module not available")
class TestExpiryNative(_Parts34Harness, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self._install_clause(RECIPIENT, EXPIRY_BODY)
        self._warm()

    def test_expiry_parks(self):
        # Expires in an hour: too soon for this recipient.
        res, _ = self._park_terms(expiry_seconds=3600)
        assert res["ok"] is False, res
        assert "RECIPIENT_EXPIRY" in json.dumps(res), res
        # Never expires: admitted and parked.
        before = self._escrow_total()
        res, _ = self._park_terms()
        assert res["ok"] is True, res
        self._mine(1)
        assert self._escrow_total() == before + 100


if __name__ == "__main__":
    unittest.main()
