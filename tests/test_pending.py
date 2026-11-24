"""Pending decisions: a git run by a program with no controlling terminal
(editor, build tool, cron) cannot be asked and nobody reads its stderr. It
records what it saw in `<key>.pending`, waits up to GITWARY_WAIT seconds,
and the user decides from `gitwary pending` in a terminal. Allowing = the
reviewed state becomes the reference, the waiter recognises it and runs;
refusing = the record disappears, the waiter refuses. A process that has a
terminal is refused at once, as before (a blocked shell prompt would freeze).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from tests.conftest import GW, GITWARY
from tests.test_prompt import modify, run_with_tty


def start_waiter(gw: GW, repo: Path, wait: str = "20", *args: str) -> subprocess.Popen:
    """gitwary git status with no controlling terminal (new session), as an
    editor would run it."""
    return subprocess.Popen([sys.executable, str(GITWARY), "git", *(args or ("status",))],
                            cwd=repo, env=dict(gw.env, GITWARY_WAIT=wait),
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, start_new_session=True, text=True)


def pending(gw: GW, repo: Path) -> dict | None:
    p = Path(str(gw.key_for(repo)) + ".pending")
    return json.loads(p.read_text()) if p.is_file() else None


def wait_until(pred, timeout: float = 15) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(0.05)
    return False


def waiting_pids(gw: GW, repo: Path) -> list[int]:
    d = pending(gw, repo)
    return [w["pid"] for w in d["waiters"]] if d else []


# ------------------------------------------------------------------- waiting
def test_wait_then_allow(gw: GW, repo: Path, tmp_path: Path) -> None:
    modify(gw, repo)
    p = start_waiter(gw, repo)
    assert wait_until(lambda: p.pid in waiting_pids(gw, repo)), p.stderr.read() if p.poll() else ""
    d = pending(gw, repo)
    assert d["kind"] == "changed" and d["root"] == str(repo)
    w = [w for w in d["waiters"] if w["pid"] == p.pid][0]
    assert w["caller"] and w["caller"][0]["pid"] == os.getpid(), w      # the program that ran git: us
    r = gw.run("pending")
    assert r.rc == 0 and "changed" in r.out and "1 waiting" in r.out and str(repo) in r.out, r.text
    rc, _, tty = run_with_tty(gw, ["pending", str(repo)], tmp_path, "y")
    assert rc == 0 and "[y/N]" in tty and "pager = cat" in tty, tty       # the diff, then the question
    assert "git waiting" in tty and f"[{os.getpid()}]" in tty, tty       # the caller chain
    out, err = p.communicate(timeout=15)
    assert p.returncode == 0 and "On branch" in out, (out, err)
    assert "allowed through gitwary pending" in err
    assert pending(gw, repo) is None
    assert not gw.check(repo).blocked, "reference = the shown state"


def test_wait_then_refuse(gw: GW, repo: Path, tmp_path: Path) -> None:
    modify(gw, repo)
    p = start_waiter(gw, repo)
    assert wait_until(lambda: p.pid in waiting_pids(gw, repo))
    rc, _, tty = run_with_tty(gw, ["pending", str(repo)], tmp_path, "n")
    assert rc == 0 and "[y/N]" in tty and "refused" in tty, tty
    out, err = p.communicate(timeout=15)
    assert p.returncode != 0 and "On branch" not in out, (out, err)
    assert "refused through gitwary pending" in err, err
    assert pending(gw, repo) is None
    assert gw.check(repo).blocked, "reference unchanged"


def test_wait_timeout_keeps_the_record(gw: GW, repo: Path) -> None:
    modify(gw, repo)
    t0 = time.monotonic()
    p = start_waiter(gw, repo, "2")
    out, err = p.communicate(timeout=20)
    assert p.returncode != 0 and "On branch" not in out
    assert time.monotonic() - t0 >= 2, "waited for GITWARY_WAIT"
    assert "no decision within 2 s" in err and "gitwary pending" in err, err
    d = pending(gw, repo)
    assert d is not None and d["kind"] == "changed" and d["waiters"] == []   # left for the next time
    r = gw.run("pending")
    assert "0 waiting" in r.out and str(repo) in r.out, r.text


def test_state_moved_since_blocked(gw: GW, repo: Path, tmp_path: Path) -> None:
    """The decision blesses the live state, shown; the waiter computed another
    one and refuses; the next git passes."""
    modify(gw, repo)
    p = start_waiter(gw, repo)
    assert wait_until(lambda: p.pid in waiting_pids(gw, repo))
    gw.git("config", "core.editor", "vi", cwd=repo)                 # moved again
    rc, _, tty = run_with_tty(gw, ["pending", str(repo)], tmp_path, "y")
    assert rc == 0 and "moved since git was blocked" in tty and "editor = vi" in tty, tty
    out, err = p.communicate(timeout=15)
    assert p.returncode != 0 and "On branch" not in out, (out, err)
    r = start_waiter(gw, repo, "0")                                  # the live state is the reference
    out, err = r.communicate(timeout=15)
    assert r.returncode == 0 and "On branch" in out, err


def test_wait_zero_records_without_blocking(gw: GW, repo: Path) -> None:
    modify(gw, repo)
    t0 = time.monotonic()
    p = start_waiter(gw, repo, "0")
    out, err = p.communicate(timeout=15)
    assert p.returncode != 0 and time.monotonic() - t0 < 10
    d = pending(gw, repo)
    assert d is not None and d["kind"] == "changed" and d["waiters"] == []


def test_no_wait_and_no_record_with_a_terminal(gw: GW, repo: Path) -> None:
    """A shell prompt's `$(git status)`: stdout on a pipe, a controlling
    terminal. Refused at once, nothing recorded — the user is at that terminal."""
    modify(gw, repo)
    t0 = time.monotonic()
    rc, out, tty = run_with_tty(gw, ["git", "status"], repo, None, stdout_pipe=True,
                                env={"GITWARY_WAIT": "20"})
    assert rc != 0 and "On branch" not in out and time.monotonic() - t0 < 10
    assert "[y/N]" not in tty and "gitwary trust" in tty, tty
    assert pending(gw, repo) is None


def test_two_waiters_same_state(gw: GW, repo: Path, tmp_path: Path) -> None:
    modify(gw, repo)
    a = start_waiter(gw, repo)
    b = start_waiter(gw, repo)
    assert wait_until(lambda: {a.pid, b.pid} <= set(waiting_pids(gw, repo)))
    assert "2 waiting" in gw.run("pending").out
    rc, _, tty = run_with_tty(gw, ["pending", str(repo)], tmp_path, "y")
    assert rc == 0, tty
    for p in (a, b):
        out, err = p.communicate(timeout=15)
        assert p.returncode == 0 and "On branch" in out, err


# --------------------------------------------- never trusted and structural
def test_never_trusted_is_recorded_not_waited(gw: GW, tmp_path: Path) -> None:
    r = tmp_path / "fresh"
    assert gw.git("init", "-q", str(r)).rc == 0
    t0 = time.monotonic()
    p = start_waiter(gw, r, "20")
    out, err = p.communicate(timeout=15)
    assert p.returncode != 0 and "never trusted" in err and time.monotonic() - t0 < 10
    d = pending(gw, r)
    assert d is not None and d["kind"] == "never" and d["waiters"] == []
    assert "never" in gw.run("pending").out
    res = gw.run("pending", str(r))
    assert res.rc == 0 and "never trusted" in res.out and "[y/N]" not in res.text, res.text
    gw.trust(r)
    assert pending(gw, r) is None, "trust clears the record"


def test_structural_refusal_is_recorded(gw: GW, repo: Path, tmp_path: Path) -> None:
    os.rename(repo / ".git", tmp_path / "realgit")
    os.symlink(tmp_path / "realgit", repo / ".git")
    p = start_waiter(gw, repo, "20")
    out, err = p.communicate(timeout=15)
    assert p.returncode != 0 and "symlink" in err, err
    d = pending(gw, repo)
    assert d is not None and d["kind"] == "structural" and "symlink" in d["message"]
    res = gw.run("pending", str(repo))
    assert res.rc == 0 and "symlink" in res.out and "[y/N]" not in res.text
    assert gw.run("pending", "-c", str(repo)).rc == 0
    assert pending(gw, repo) is None


# ------------------------------------------------------------------ cleanup
def test_record_cleared_when_state_comes_back(gw: GW, repo: Path) -> None:
    modify(gw, repo)
    start_waiter(gw, repo, "0").communicate(timeout=15)
    assert pending(gw, repo) is not None
    assert gw.run("restore", "-y", cwd=repo).rc == 0
    p = start_waiter(gw, repo, "0")
    out, _ = p.communicate(timeout=15)
    assert p.returncode == 0 and "On branch" in out
    assert pending(gw, repo) is None


def test_forget_removes_the_record(gw: GW, repo: Path) -> None:
    modify(gw, repo)
    start_waiter(gw, repo, "0").communicate(timeout=15)
    assert pending(gw, repo) is not None
    assert gw.run("forget", str(repo)).rc == 0
    assert pending(gw, repo) is None
    assert not gw.key_for(repo).exists()


def test_pending_without_terminal_shows_but_cannot_decide(gw: GW, repo: Path) -> None:
    modify(gw, repo)
    start_waiter(gw, repo, "0").communicate(timeout=15)
    r = gw.run("pending", str(repo))                 # stdout captured: no question possible
    assert r.rc != 0 and "pager = cat" in r.out and "from a terminal" in r.err, r.text
    assert pending(gw, repo) is not None and gw.check(repo).blocked


def test_nothing_pending(gw: GW, repo: Path) -> None:
    r = gw.run("pending")
    assert r.rc == 0 and "nothing pending" in r.out
    r = gw.run("pending", str(repo))
    assert r.rc == 0 and "nothing pending" in r.err


# ------------------------------------------------------------ state directory
def state_files(gw: GW) -> set[str]:
    return {p.name for p in gw.state.iterdir()}


def test_no_lock_file_litter(gw: GW, repo: Path) -> None:
    """[57] `<key>.pending.lock` was created by every `trust` (clear_pending
    took the lock with nothing pending) and never removed: one file per
    repository, for ever. The lock is taken on the state directory itself:
    nothing to create, nothing to delete."""
    k = gw.key_for(repo).name
    assert state_files(gw) <= {k, k + ".d", k + ".idx"}, state_files(gw)
    modify(gw, repo)
    start_waiter(gw, repo, "0").communicate(timeout=15)
    assert pending(gw, repo) is not None
    assert gw.run("pending", "-c", str(repo)).rc == 0
    assert state_files(gw) <= {k, k + ".d", k + ".idx"}, state_files(gw)


def test_prune_removes_orphan_records_and_legacy_locks(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[57] The record of a never-trusted repository has no manifest, so
    `prune` never saw it: once the repository was deleted, `<key>.pending`
    (and the lock file of earlier versions) stayed for ever."""
    gone, kept = tmp_path / "gone", tmp_path / "kept"
    for r in (gone, kept):
        assert gw.git("init", "-q", str(r)).rc == 0
        start_waiter(gw, r, "0").communicate(timeout=15)
        assert pending(gw, r) is not None and pending(gw, r)["kind"] == "never"
    legacy = [Path(str(gw.key_for(r)) + ".pending.lock") for r in (gone, kept, repo)]
    for p in legacy:
        p.touch()
    shutil.rmtree(gone)
    r = gw.run("prune")
    assert r.rc == 0 and str(gone) in r.out, r.text
    assert pending(gw, gone) is None and pending(gw, kept) is not None
    assert not any(p.exists() for p in legacy), "lock files of earlier versions are removed"
    assert gw.key_for(repo).is_file() and not gw.check(repo).blocked


def _start(pid: int) -> int:
    """The start time a marker carries for `pid` (DESIGN-exec-path.md 3.2)."""
    import gitwary
    return gitwary._proc_lineage(pid)[1]


def test_child_git_never_waits(gw: GW, repo: Path) -> None:
    """DESIGN-exec-path.md: a child git (a marker in its environment, here
    for another repository) refuses a changed repository at once — no wait
    for `gitwary pending`, however long GITWARY_WAIT — and records."""
    gw.git("config", "core.hooksPath", "/nowhere", cwd=repo)
    h = os.fsencode("/elsewhere/.git").hex()
    env = dict(gw.env, GITWARY_WAIT="30", GITWARY_JUDGED=f"{os.getpid()}.{_start(os.getpid())}:repo={h},{h},{os.fsencode('/elsewhere').hex()},{os.fsencode('/elsewhere').hex()}")
    t0 = time.monotonic()
    r = subprocess.run([sys.executable, str(GITWARY), "git", "status"], cwd=repo, env=env,
                       capture_output=True, text=True, start_new_session=True)
    assert r.returncode != 0 and time.monotonic() - t0 < 5, r.stderr
    assert "has changed" in r.stderr and gw.key_for(repo).with_suffix(".pending").exists()


def test_dead_marker_is_no_marker(gw: GW, repo: Path) -> None:
    """[104] a marker whose process is gone is no marker: the user's
    semantics — a changed repository without a terminal records and waits
    for `gitwary pending` (GITWARY_WAIT) instead of a child's immediate
    refusal."""
    gw.git("config", "core.hooksPath", "/nowhere", cwd=repo)
    dead = subprocess.Popen(["true"])
    dead.wait()
    h = os.fsencode("/elsewhere/.git").hex()
    env = dict(gw.env, GITWARY_WAIT="2",
               GITWARY_JUDGED=f"{dead.pid}.0:repo={h},{h},{os.fsencode('/elsewhere').hex()},{os.fsencode('/elsewhere').hex()}")
    t0 = time.monotonic()
    r = subprocess.run([sys.executable, str(GITWARY), "git", "status"], cwd=repo, env=env,
                       capture_output=True, text=True, start_new_session=True)
    assert r.returncode != 0 and time.monotonic() - t0 >= 2 and "no decision within" in r.stderr, r.stderr
