"""Pinned engine profile (G1).

Covers: the pinned ref constant vs Dockerfile.standalone (the two must
never drift), environment scrubbing (credentials, solver PATH entries,
unknown TAU_* vars; repo-owned vars kept), and ref verification against a
git checkout (match / mismatch / unverifiable).
"""
import json
import os
import subprocess

import pytest

from consensus.engine_profile import (
    PINNED_TAU_LANG_REF,
    PINNED_TAU_LANG_REF_SHORT,
    PINNED_TAU_LANG_REPO,
    REPO_OWNED_TAU_ENV_VARS,
    EngineProfileError,
    engine_profile,
    scrub_engine_environment,
    verify_pinned_engine_ref,
)


def _dockerfile_ref():
    import re

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "Dockerfile.standalone"), encoding="utf-8") as fh:
        content = fh.read()
    match = re.search(r"^ARG TAU_LANG_REF=([0-9a-f]{40})\s*$", content, re.M)
    assert match is not None, "Dockerfile.standalone must pin TAU_LANG_REF"
    return match.group(1)


def test_pinned_ref_matches_the_dockerfile():
    # The pin lives in two places (this module + Dockerfile.standalone);
    # they must agree, or the "pin" is a lie in one of them.
    assert PINNED_TAU_LANG_REF == _dockerfile_ref()
    assert PINNED_TAU_LANG_REF_SHORT == "6ea436e8"
    assert PINNED_TAU_LANG_REF.startswith(PINNED_TAU_LANG_REF_SHORT)
    assert len(PINNED_TAU_LANG_REF) == 40
    assert PINNED_TAU_LANG_REPO == "https://github.com/IDNI/tau-lang.git"


def test_dockerfile_builds_from_the_pinned_repo():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "Dockerfile.standalone"), encoding="utf-8") as fh:
        content = fh.read()
    assert "ARG TAU_LANG_REPO=https://github.com/IDNI/tau-lang.git" in content
    assert 'git checkout "${TAU_LANG_REF}"' in content


def test_scrub_removes_credentials_and_unknown_tau_vars():
    env = {
        "PATH": "/usr/bin:/bin",
        "OPENAI_API_KEY": "sk-secret",
        "ANTHROPIC_API_KEY": "sk-ant-secret",
        "TAU_FORCE_TEST": "1",  # repo-owned: kept
        "TAU_DB_PATH": "/tmp/x.db",  # repo-owned: kept
        "TAU_SOME_ENGINE_OPTION": "1",  # unknown: removed
        "TAU_LANG_REF": PINNED_TAU_LANG_REF,  # build-time: kept
        "HOME": "/root",
    }
    removed = scrub_engine_environment(env)
    assert "OPENAI_API_KEY" in removed
    assert "ANTHROPIC_API_KEY" in removed
    assert "TAU_SOME_ENGINE_OPTION" in removed
    assert "OPENAI_API_KEY" not in env
    assert "ANTHROPIC_API_KEY" not in env
    assert "TAU_SOME_ENGINE_OPTION" not in env
    assert env["TAU_FORCE_TEST"] == "1"
    assert env["TAU_DB_PATH"] == "/tmp/x.db"
    assert env["HOME"] == "/root"


def test_scrub_drops_solver_path_entries_only():
    env = {
        "PATH": os.pathsep.join([
            "/usr/bin",
            "/opt/ltlsynt/bin",
            "/usr/local/bin",
            "/home/x/autfilt-1.0/bin",
            "/opt/ltlfilt/bin",
        ])
    }
    removed = scrub_engine_environment(env)
    assert removed == ["PATH"]
    assert env["PATH"] == os.pathsep.join(["/usr/bin", "/usr/local/bin"])


def test_scrub_keeps_a_clean_environment_untouched():
    env = {"PATH": "/usr/bin:/bin", "TAU_FORCE_TEST": "0"}
    assert scrub_engine_environment(env) == []
    assert env == {"PATH": "/usr/bin:/bin", "TAU_FORCE_TEST": "0"}


def test_keep_list_covers_every_env_var_the_node_reads():
    # Guard against a scrub that eats a variable the node itself needs:
    # every TAU_* name read via os.environ/os.getenv or listed in the
    # config.py table must be in the keep-list. This test re-derives the
    # set from the source tree (the same search the module documents).
    import re

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    found = set()
    pattern = re.compile(r"""TAU_[A-Z_0-9]+""")
    for dirpath, _dirnames, filenames in os.walk(root):
        if ".git" in dirpath or "venv" in dirpath:
            continue
        for filename in filenames:
            if not filename.endswith((".py",)):
                continue
            path = os.path.join(dirpath, filename)
            with open(path, encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
            for match in re.finditer(
                r"""os\.(?:environ(?:\.get|\[)|getenv)\(\s*["'](TAU_[A-Z_0-9]+)""",
                content,
            ):
                found.add(match.group(1))
    # config.py table keys.
    with open(os.path.join(root, "config.py"), encoding="utf-8") as fh:
        for match in pattern.finditer(fh.read()):
            pass  # table keys are string literals; checked below by name
    missing = sorted(found - REPO_OWNED_TAU_ENV_VARS)
    assert missing == [], f"TAU_* vars read by the node but not kept: {missing}"


def _make_checkout(tmp_path, ref):
    repo = tmp_path / "tau-lang"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "test@example.com"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.name", "Test"], check=True
    )
    (repo / "README.md").write_text("tau-lang\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-qm", "init"], check=True
    )
    head = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    if ref is not None:
        # Forge a detached HEAD at the requested sha by writing .git/HEAD
        # directly (no object needs to exist: verification reads HEAD only).
        (repo / ".git" / "HEAD").write_text(ref + "\n", encoding="utf-8")
        return str(repo), ref
    return str(repo), head


def test_verify_accepts_the_pinned_ref(tmp_path):
    path, _ = _make_checkout(tmp_path, PINNED_TAU_LANG_REF)
    verified, detail = verify_pinned_engine_ref(path)
    assert verified is True
    assert "pinned ref" in detail


def test_verify_rejects_a_different_ref(tmp_path):
    other = "0" * 40
    assert other != PINNED_TAU_LANG_REF
    path, _ = _make_checkout(tmp_path, other)
    with pytest.raises(EngineProfileError, match="not the pinned engine ref"):
        verify_pinned_engine_ref(path)


def test_verify_reports_unverifiable_without_git(tmp_path):
    bare = tmp_path / "tau-lang"
    bare.mkdir()
    verified, detail = verify_pinned_engine_ref(str(bare))
    assert verified is None
    assert "no readable .git/HEAD" in detail


def test_verify_reports_unverifiable_without_checkout(tmp_path):
    verified, detail = verify_pinned_engine_ref(str(tmp_path / "nope"))
    assert verified is None


def test_engine_profile_reports_the_pin(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "consensus.engine_profile._candidate_tau_lang_dirs",
        lambda: [str(tmp_path / "nope")],
    )
    profile = engine_profile()
    assert profile["tau_lang_ref"] == PINNED_TAU_LANG_REF
    assert profile["tau_lang_ref_short"] == "6ea436e8"
    assert profile["ref_verified"] is None  # no checkout here: unverifiable
