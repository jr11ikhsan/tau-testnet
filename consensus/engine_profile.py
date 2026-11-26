"""Pinned engine profile (Bounty 01, G1 package).

Clean-room implementation, written from the audit specification
(``RIVAL-GAP-AUDIT-2026-11-27.md`` §2 + ``PR190-POSITION-CHECK-2026-11-26.md``
§0) and from this repo's own build files -- NOT by copying any rival PR's
code.

What is pinned
---------------
The Tau engine the node runs is built from tau-lang at exactly one git
ref. That ref is already pinned at build time in ``Dockerfile.standalone``
(``ARG TAU_LANG_REF``); this module makes the same pin visible to, and
checked by, the Python runtime:

- ``PINNED_TAU_LANG_REF`` -- the full 40-hex ref, read by the author of
  this package from ``Dockerfile.standalone:7`` and cross-checked by
  ``tests/test_tau_engine_profile.py`` (Dockerfile vs constant must agree,
  or the test fails). Short form ``6ea436e8``.
- ``verify_pinned_engine_ref`` -- at load time, read the checked-out ref
  from the tau-lang worktree's ``.git/HEAD`` (pure Python; the runtime
  image does not install a ``git`` binary). A verifiable MISMATCH raises
  ``EngineProfileError`` and the engine does not start (fail-closed). An
  UNVERIFIABLE checkout (no ``.git`` / unreadable HEAD) warns and
  continues -- unverifiable is not the same as wrong, and mock/test runs
  have no tau-lang checkout at all.
- ``scrub_engine_environment`` -- before the native module is imported,
  remove what could steer the engine away from the tested build:
  credential variables (``OPENAI_API_KEY``, ``ANTHROPIC_API_KEY``),
  ``PATH`` entries pointing at external solver binaries (``ltlsynt`` /
  ``autfilt`` / ``ltlfilt``), and any ``TAU_*`` variable NOT on the
  repo-owned keep-list below. Every removal is logged (warning) so a
  scrubbed variable is visible, never silent.

What is deliberately NOT claimed here
-------------------------------------
A forced manifest of ~100 engine OPTION values is NOT implemented. The
option registry lives in tau-lang, which is not part of this repo, and
this package will not invent a list of option names/values it cannot
verify from inside this repo. What is pinned here -- the engine SOURCE
ref plus a clean load environment -- is the part verifiable from this
repo. If governance wants option-level forcing as well, it needs the
tau-lang option registry as an input; that is an open item, recorded in
``JUARA-L1-G1-190PACKAGE-LOG.md`` §6, not a silent gap.

Keep-list provenance
--------------------
``REPO_OWNED_TAU_ENV_VARS`` was derived on 2026-11-27 by searching this
repo for ``os.environ`` / ``os.getenv`` reads and for the ``config.py``
environment table. It is the set of ``TAU_*`` names the node's own code
reads. If a new ``TAU_*`` variable is added to the node, add it here in
the same commit -- otherwise the scrub will (loudly) remove it at load.
"""

from __future__ import annotations

import logging
import os
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Pinned tau-lang ref. Verified by the author of this package against
# Dockerfile.standalone:7 (ARG TAU_LANG_REF) on 2026-11-27; the cross-check
# is enforced by tests/test_tau_engine_profile.py.
PINNED_TAU_LANG_REF = "6ea436e8d3113a7d90635b9d06113e5bc506176c"
PINNED_TAU_LANG_REF_SHORT = PINNED_TAU_LANG_REF[:8]
PINNED_TAU_LANG_REPO = "https://github.com/IDNI/tau-lang.git"

# Solver binaries whose PATH presence could shadow the pinned engine's own
# toolchain. Matched as substrings of a single PATH entry.
_SOLVER_PATH_MARKERS = ("ltlsynt", "autfilt", "ltlfilt")

# Credential variables that must never reach the engine process.
_CREDENTIAL_ENV_VARS = ("OPENAI_API_KEY", "ANTHROPIC_API_KEY")

# TAU_* names the node's OWN code reads (os.environ / os.getenv reads +
# the config.py environment table, searched 2026-11-27). The scrub keeps
# exactly these; any other TAU_* present at load time is treated as an
# engine-option override and removed. Extend this set in the same commit
# that adds a new TAU_* variable to the node.
REPO_OWNED_TAU_ENV_VARS = frozenset({
    # os.environ / os.getenv reads.
    "TAU_ADMISSION_STANDBY",
    "TAU_APPROVAL_BOT_PRIVKEY",
    "TAU_APPROVAL_SCAN_MODEL",
    "TAU_BLOCK_PRODUCTION_LOCK_TIMEOUT",
    "TAU_BOOTSTRAP_REDIAL_INTERVAL",
    "TAU_CHAIN_INGEST_LOCK_TIMEOUT",
    "TAU_DB_PATH",
    "TAU_DEBUG_STEP_IO",
    "TAU_E2E_CONTROL",
    "TAU_E2E_PYTHON",
    "TAU_ENV",
    "TAU_FORCE_FRESH_START",
    "TAU_FORCE_TEST",
    "TAU_HASH_TRACE",
    "TAU_HEAD_REANNOUNCE_INTERVAL",
    "TAU_LOG_DATEFMT",
    "TAU_LOG_FORMAT",
    "TAU_LOG_LEVEL",
    "TAU_MAX_BLOCK_FUTURE_DRIFT",
    "TAU_NATIVE_PATH",
    "TAU_NATIVE_PYTHON",
    "TAU_NO_WIDTH_REEXEC",
    "TAU_POLICY_CACHE_SIZE",
    "TAU_POLICY_PIN_SECONDS",
    "TAU_REBUILD_JOURNAL",
    "TAU_RESTORE_RULES_ON_STARTUP",
    "TAU_WORKER_RESULT_FD",
    "TAU_WS_ALLOWED_ORIGINS",
    "TAU_WS_CERT_PATH",
    "TAU_WS_KEY_PATH",
    # config.py environment table.
    "TAU_ADMISSION_BUDGET",
    "TAU_ALLOW_REMOTE_CREATEBLOCK",
    "TAU_ANNOUNCE_ADDRS",
    "TAU_BLOCK_MAX_RULE_TXS",
    "TAU_BLOCK_SIGNATURE_SCHEME",
    "TAU_BOOTSTRAP_PEERS",
    "TAU_BUFFER_SIZE",
    "TAU_BURST_PER_PEER",
    "TAU_CLIENT_WAIT_TIMEOUT",
    "TAU_COMM_DEBUG_PATH",
    "TAU_COMM_TIMEOUT",
    "TAU_CONN_GRACE_PERIOD",
    "TAU_CONN_HIGH_WATER",
    "TAU_CONN_LOW_WATER",
    "TAU_DHT_BOOTSTRAP",
    "TAU_DHT_TTL",
    "TAU_DHT_VALIDATORS",
    "TAU_GOVERNANCE_OPEN_ADMISSION",
    "TAU_HOST",
    "TAU_IDENTITY_KEY_PATH",
    "TAU_MAX_CONNECTIONS",
    "TAU_MAX_MEMPOOL_TXS",
    "TAU_MAX_RPC_COMMAND_BYTES",
    "TAU_MEMPOOL_RULE_LANE_MAX_FRACTION",
    "TAU_MINER_PRIVKEY",
    "TAU_MINER_PRIVKEY_PATH",
    "TAU_MINER_PUBKEY",
    "TAU_MINER_PUBKEYS",
    "TAU_MINER_PUBKEY_PATH",
    "TAU_MINING_BUDGET",
    "TAU_MINING_ENABLED",
    "TAU_NETWORK_ID",
    "TAU_NETWORK_LISTEN",
    "TAU_PEERSTORE_PATH",
    "TAU_PORT",
    "TAU_PROCESS_TIMEOUT",
    "TAU_PROGRAM_FILE",
    "TAU_RATE_LIMIT_PER_PEER",
    "TAU_READY_SIGNAL",
    "TAU_REORG_RESTORE_MAX_VERIFY",
    "TAU_SHUTDOWN_TIMEOUT",
    "TAU_STATE_LOCATOR_NAMESPACE",
    "TAU_VALIDATION_CEILING",
    "TAU_VALIDATOR_VOTE_QUORUM",
    # Build-time (Dockerfile / ./dev build); not engine options, kept so a
    # build-time value surviving into the runtime environment is not scrubbed.
    "TAU_LANG_REF",
    "TAU_LANG_REPO",
    "TAU_BUILD_JOBS",
    "TAU_JOBS",
    "TAU_PYTHON",
    "TAU_PYTHON_VERSION",
    "TAU_BUILD_TESTS",
    "TAU_BUILD_EXECUTABLE",
    "TAU_BUILD_BINDING_PYTHON_NANOBIND",
})


class EngineProfileError(Exception):
    """The engine that would load does not match the pinned profile."""


def scrub_engine_environment(env: Optional[Dict[str, str]] = None) -> List[str]:
    """Remove engine-steering variables from ``env`` (default: os.environ).

    Removes credential variables, ``PATH`` entries naming external solver
    binaries, and unknown ``TAU_*`` variables. Returns the sorted list of
    variable names removed (``PATH`` is reported as ``"PATH"`` when any
    entry was dropped). Removals are logged at warning level.
    """
    if env is None:
        env = os.environ
    removed: List[str] = []
    for name in _CREDENTIAL_ENV_VARS:
        if name in env:
            del env[name]
            removed.append(name)
    for name in sorted(k for k in env if k.startswith("TAU_")):
        if name not in REPO_OWNED_TAU_ENV_VARS:
            del env[name]
            removed.append(name)
    path = env.get("PATH")
    if path:
        kept = [
            entry
            for entry in path.split(os.pathsep)
            if not any(m in entry for m in _SOLVER_PATH_MARKERS)
        ]
        if len(kept) != len(path.split(os.pathsep)):
            env["PATH"] = os.pathsep.join(kept)
            removed.append("PATH")
    for name in sorted(removed):
        logger.warning(
            "engine profile: scrubbed environment variable %s before "
            "loading the native Tau module",
            name,
        )
    return sorted(removed)


def _read_checkout_ref(tau_lang_dir: str) -> Optional[str]:
    """Full HEAD sha of a tau-lang checkout, or None if not determinable.

    Reads ``.git/HEAD`` directly (no git binary). A detached checkout
    (what the Dockerfile produces) stores the sha in HEAD itself; a
    branch checkout stores ``ref: refs/heads/<name>``, resolved via the
    loose ref file and then ``packed-refs``.
    """
    git_dir = os.path.join(tau_lang_dir, ".git")
    head_path = os.path.join(git_dir, "HEAD")
    try:
        with open(head_path, "r", encoding="utf-8") as fh:
            head = fh.read().strip()
    except (OSError, UnicodeDecodeError):
        return None
    if len(head) == 40 and all(c in "0123456789abcdef" for c in head.lower()):
        return head.lower()
    if head.startswith("ref:"):
        ref = head[4:].strip()
        for candidate in (
            os.path.join(git_dir, ref),
            os.path.join(git_dir, "packed-refs"),
        ):
            try:
                with open(candidate, "r", encoding="utf-8") as fh:
                    content = fh.read()
            except (OSError, UnicodeDecodeError):
                continue
            if candidate.endswith("packed-refs"):
                for line in content.splitlines():
                    parts = line.split()
                    if len(parts) == 2 and parts[1] == ref:
                        return parts[0].lower()
            else:
                sha = content.strip().split()[0] if content.strip() else ""
                if len(sha) == 40:
                    return sha.lower()
    return None


def _candidate_tau_lang_dirs() -> List[str]:
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    workspace = os.path.dirname(here)
    return [
        os.path.join(workspace, "tau-lang"),
        "/app/tau-lang",
        os.path.join(here, "tau-lang"),
    ]


def verify_pinned_engine_ref(
    tau_lang_dir: Optional[str] = None,
) -> Tuple[Optional[bool], str]:
    """Check the tau-lang checkout against the pinned ref.

    Returns ``(True, detail)`` when the checkout is at the pinned ref,
    ``(False, detail)`` never returned -- a verifiable mismatch RAISES
    ``EngineProfileError`` instead -- and ``(None, reason)`` when no
    checkout could be verified (no ``.git`` / unreadable HEAD).
    """
    dirs = [tau_lang_dir] if tau_lang_dir else _candidate_tau_lang_dirs()
    checked_any = False
    for candidate in dirs:
        if not candidate or not os.path.isdir(candidate):
            continue
        checked_any = True
        ref = _read_checkout_ref(candidate)
        if ref is None:
            continue
        if ref != PINNED_TAU_LANG_REF:
            raise EngineProfileError(
                f"tau-lang checkout at {candidate} is at {ref}, not the "
                f"pinned engine ref {PINNED_TAU_LANG_REF}; refusing to "
                "start the engine"
            )
        return True, f"tau-lang checkout at {candidate} is at the pinned ref"
    if checked_any:
        return None, "no readable .git/HEAD in any tau-lang checkout"
    return None, "no tau-lang checkout found"


def engine_profile(tau_lang_dir: Optional[str] = None) -> Dict[str, object]:
    """Observability view of the pinned profile (for logging / tests)."""
    verified, detail = verify_pinned_engine_ref(tau_lang_dir)
    return {
        "tau_lang_ref": PINNED_TAU_LANG_REF,
        "tau_lang_ref_short": PINNED_TAU_LANG_REF_SHORT,
        "tau_lang_repo": PINNED_TAU_LANG_REPO,
        "ref_verified": verified,
        "ref_detail": detail,
    }
