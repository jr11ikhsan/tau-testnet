"""Bounty 01, issue #35: receive routes on the native tau-lang engine.

Kept in its own file so the real-Tau CI job can register exactly this file:
the seam-level route proof needs the native bindings, which the mock test
job does not have. The skip below is environment-driven — in the real-Tau
job's image the bindings are present (its preflight imports them), so the
skip lifts and the proof runs for real. Everywhere else it skips, exactly
as the issue-#42 native probe does.

STATUS: the engine seam (the `_execute_fee_era_transfer` hook) lands in the
wiring slice of the build plan in DESIGN-01-TAKEOVER.md. Until then this
file carries only the availability gate, so registering it in CI today
would prove nothing; it is registered when the seam test lands.
"""
import pytest


def _native_available():
    try:
        from tau_native import load_tau_module

        load_tau_module()
        return True
    except Exception:
        return False


@pytest.mark.skipif(
    not _native_available(),
    reason="native tau-lang bindings not available in this environment",
)
def test_native_bindings_available_for_route_seam():
    assert _native_available()
