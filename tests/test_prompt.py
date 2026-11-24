"""Exec-mode shortcuts when the repository differs from the reference:

1. auto-accept of a pure branch-tracking addition/removal
   (`branch.<x>.remote` / `.merge`, what `push -u`, `branch -u`,
   `checkout -b` write) — no prompt, reference updated;
2. otherwise, diff shown then a question on /dev/tty, default answer N;
   never without a terminal, never when stderr or stdout is not a terminal, never with
   GITBLOCKER_NO_PROMPT, never for "never trusted" nor for a structural
   refusal; the answer is not read from stdin (git would consume it).
"""
from __future__ import annotations

import os
import select
import subprocess
import sys
import time
from pathlib import Path

import pytest

from tests.conftest import GB, GITBLOCKER, write_exec

# ------------------------------------------------------------------ auto-accept

def with_origin(gb: GB, repo: Path, subsrc: Path) -> None:
    """Trusted repository with an `origin` remote (remote add requires a trust)."""
    assert gb.git("remote", "add", "origin", str(subsrc), cwd=repo).rc == 0
    gb.trust(repo)
    assert not gb.check(repo).blocked


def test_push_u_accepted_without_prompt(gb: GB, repo: Path, subsrc: Path) -> None:
    """`push -u` writes the config AFTER the check: the next command sees the
    difference and accepts it on its own."""
    with_origin(gb, repo, subsrc)
    assert gb.run("git", "checkout", "-qb", "feat", cwd=repo).rc == 0
    r = gb.run("git", "push", "-qu", "origin", "feat", cwd=repo)
    assert r.rc == 0, r.text
    assert "branch.feat.remote=origin" in gb.git("config", "--list", cwd=repo).out
    r = gb.run("git", "status", cwd=repo)
    assert r.rc == 0 and "On branch" in r.out, r.text
    assert "branch tracking for feat" in r.err and "has changed" not in r.err
    assert not gb.check(repo).blocked, "reference updated"
    assert "branch tracking" not in gb.run("git", "status", cwd=repo).err, "only once"
    # Removing the tracking: accepted too.
    assert gb.run("git", "branch", "--unset-upstream", cwd=repo).rc == 0
    r = gb.run("git", "status", cwd=repo)
    assert r.rc == 0 and "branch tracking for feat" in r.err
    assert not gb.check(repo).blocked


def test_vscode_merge_base_accepted_without_prompt(gb: GB, repo: Path, subsrc: Path) -> None:
    """VS Code's git extension writes `branch.<x>.vscode-merge-base` on opening
    a repository (seen with code-server): accepted like branch tracking, and
    refused as soon as the value is not a ref name."""
    with_origin(gb, repo, subsrc)
    assert gb.run("git", "checkout", "-qb", "feat", cwd=repo).rc == 0
    assert gb.run("git", "push", "-qu", "origin", "feat", cwd=repo).rc == 0
    assert gb.run("git", "status", cwd=repo).rc == 0 and not gb.check(repo).blocked
    gb.git("config", "branch.feat.vscode-merge-base", "origin/main", cwd=repo)
    r = gb.run("git", "status", cwd=repo)
    assert r.rc == 0 and "branch tracking for feat" in r.err and "has changed" not in r.err, r.text
    assert not gb.check(repo).blocked
    gb.git("config", "branch.feat.vscode-merge-base", "--upload-pack=evil", cwd=repo)
    assert gb.run("git", "status", cwd=repo).blocked
    assert gb.check(repo).blocked


def test_branch_u_from_linked_worktree(gb: GB, repo: Path, subsrc: Path, tmp_path: Path) -> None:
    """From a linked worktree, git writes into the main repository's config
    (scope `common`): same shortcut."""
    with_origin(gb, repo, subsrc)
    wt = tmp_path / "wt"
    assert gb.git("worktree", "add", "-q", str(wt), "-b", "wtb", cwd=repo).rc == 0
    gb.trust(repo)
    gb.trust(wt)                                 # the linked worktree has its own key
    assert gb.git("fetch", "-q", "origin", cwd=repo).rc == 0
    assert gb.run("git", "branch", "-u", "origin/main", cwd=wt).rc == 0
    assert gb.check(wt).blocked, "common:config has changed"
    r = gb.run("git", "status", cwd=wt)
    assert r.rc == 0 and "branch tracking for wtb" in r.err, r.text
    assert not gb.check(wt).blocked
    r = gb.run("git", "status", cwd=repo)        # the main repository sees the same difference
    assert r.rc == 0 and "branch tracking for wtb" in r.err, r.text
    assert not gb.check(repo).blocked


def test_check_mode_still_reports(gb: GB, repo: Path, subsrc: Path) -> None:
    """`gitblocker` alone (diagnostic) re-trusts nothing: it reports."""
    with_origin(gb, repo, subsrc)
    gb.git("config", "branch.feat.remote", "origin", cwd=repo)
    gb.git("config", "branch.feat.merge", "refs/heads/feat", cwd=repo)
    assert gb.check(repo).blocked
    assert gb.run("git", "status", cwd=repo).rc == 0     # exec: accepted
    assert not gb.check(repo).blocked


@pytest.mark.parametrize("extra", [
    ("core.fsmonitor", "/tmp/evil"),
    ("branch.feat.rebase", "true"),
    ("remote.evil.url", "/tmp/evil"),
    ("alias.st", "!id"),
])
def test_branch_plus_anything_else_refused(gb: GB, repo: Path, subsrc: Path, extra) -> None:
    with_origin(gb, repo, subsrc)
    gb.git("config", "branch.feat.remote", "origin", cwd=repo)
    gb.git("config", "branch.feat.merge", "refs/heads/feat", cwd=repo)
    gb.git("config", *extra, cwd=repo)
    r = gb.run("git", "status", cwd=repo)
    assert r.blocked and "On branch" not in r.out, r.text
    assert "has changed" in r.err
    assert gb.check(repo).blocked, "not re-trusted"


def test_branch_tracking_to_unknown_remote_refused(gb: GB, repo: Path, subsrc: Path) -> None:
    with_origin(gb, repo, subsrc)
    gb.git("config", "branch.feat.remote", "elsewhere", cwd=repo)
    gb.git("config", "branch.feat.merge", "refs/heads/feat", cwd=repo)
    assert gb.run("git", "status", cwd=repo).blocked


def test_branch_tracking_plus_hook_refused(gb: GB, repo: Path, subsrc: Path) -> None:
    from tests.conftest import write_exec
    with_origin(gb, repo, subsrc)
    gb.git("config", "branch.feat.remote", "origin", cwd=repo)
    gb.git("config", "branch.feat.merge", "refs/heads/feat", cwd=repo)
    write_exec(repo / ".git/hooks/pre-commit")
    assert gb.run("git", "status", cwd=repo).blocked


# ----------------------------------------------------------------------- prompt

def run_with_tty(gb: GB, args: list[str], cwd: Path, answer: str | None,
                 stdin_data: bytes | None = None, env: dict | None = None,
                 stdout_pipe: bool = False, pretype: bytes | None = None):
    """Run gitblocker with a pseudo-terminal as controlling terminal (so /dev/tty
    can be opened), stderr and stdout on that terminal (as when the user types
    the command); `stdout_pipe` captures stdout instead, as a `$(git …)` in a
    shell prompt does; stdin = pipe if `stdin_data`, else the terminal.
    Answers `answer` on the terminal when the question appears; `pretype` is
    typed on the terminal right at start, before anything is displayed.
    Returns (rc, captured stdout or "", tty output)."""
    import pty
    import fcntl
    import termios
    master, slave = pty.openpty()

    def preexec() -> None:
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)

    p = subprocess.Popen(
        [sys.executable, str(GITBLOCKER), *args], cwd=cwd, env={**gb.env, **(env or {})},
        stdin=subprocess.PIPE if stdin_data is not None else slave,
        stdout=subprocess.PIPE if stdout_pipe else slave, stderr=slave,
        preexec_fn=preexec, close_fds=True)
    os.close(slave)
    if pretype is not None:
        os.write(master, pretype)
    if stdin_data is not None:
        # gitblocker never reads stdin (the question goes through /dev/tty): the
        # data waits in the pipe for the git that gitblocker execs.
        p.stdin.write(stdin_data)
        p.stdin.close()
        p.stdin = None      # Python 3.13's communicate() flushes a non-None stdin: closed → ValueError
    tty_out = b""
    deadline = time.monotonic() + 30
    asked = False
    while time.monotonic() < deadline:
        r, _, _ = select.select([master], [], [], 0.2)
        if r:
            try:
                chunk = os.read(master, 4096)
            except OSError:
                break
            if not chunk:
                break
            tty_out += chunk
        if not asked and answer is not None and b"[y/N]" in tty_out:
            os.write(master, answer.encode() + b"\n")
            asked = True
        if p.poll() is not None and not r:
            break
    out, _ = p.communicate(timeout=30)
    os.close(master)
    return p.returncode, (out or b"").decode(errors="replace"), tty_out.decode(errors="replace")


def modify(gb: GB, repo: Path) -> None:
    gb.git("config", "core.pager", "cat", cwd=repo)    # change that cannot be auto-accepted


@pytest.mark.parametrize("answer, accepted", [("y", True), ("yes", True), ("Y", True),
                                              ("", False), ("n", False), ("no", False)])
def test_prompt_answers(gb: GB, repo: Path, answer: str, accepted: bool) -> None:
    modify(gb, repo)
    rc, out, tty = run_with_tty(gb, ["git", "status"], repo, answer)
    assert "[y/N]" in tty and "pager = cat" in tty, tty      # diff shown before the question
    if accepted:
        assert rc == 0 and "On branch" in tty, (rc, tty)
        assert not gb.check(repo).blocked, "reference updated"
    else:
        assert rc != 0 and "On branch" not in tty, (rc, tty)
        assert gb.check(repo).blocked, "reference unchanged"


def test_prompt_trusts_exactly_what_was_shown(gb: GB, repo: Path) -> None:
    """The trusted state is the one of the displayed diff, not a recomputed one."""
    import json
    modify(gb, repo)
    rc, out, tty = run_with_tty(gb, ["git", "status"], repo, "y")
    assert rc == 0
    man = json.loads(gb.key_for(repo).read_text())
    cfg = [e for e in man["entries"] if e["scope"] == "local" and e["path"] == "config"]
    import hashlib
    assert cfg and cfg[0]["sha"] == hashlib.sha256((repo / ".git/config").read_bytes()).hexdigest()


def test_prompt_does_not_eat_git_stdin(gb: GB, repo: Path) -> None:
    modify(gb, repo)
    rc, out, tty = run_with_tty(gb, ["git", "hash-object", "--stdin"], repo, "y",
                                stdin_data=b"hello\n")
    assert rc == 0, tty
    assert "ce013625030ba8dba906f756967f9e9ca394464a" in tty, tty


def test_pretyped_input_does_not_answer(gb: GB, repo: Path) -> None:
    """A `y` typed before the diff was on screen is discarded (input queue
    flushed before the question): the answer is the Enter typed afterwards,
    i.e. the default N. Without the flush, readline would return the early
    `y` and git would run."""
    modify(gb, repo)
    rc, out, tty = run_with_tty(gb, ["git", "status"], repo, "", pretype=b"y\n")
    assert "[y/N]" in tty, tty
    assert rc != 0 and "On branch" not in tty, (rc, tty)
    assert gb.check(repo).blocked, "reference unchanged"


def test_no_prompt_without_tty(gb: GB, repo: Path) -> None:
    modify(gb, repo)
    r = gb.run("git", "status", cwd=repo)            # neither tty nor interactive stdin
    assert r.blocked and "On branch" not in r.out
    # From a terminal (developer's shell) the refusal names `gitblocker trust`;
    # without a controlling terminal (CI, editor) it records a pending
    # decision and names `gitblocker pending` (GITBLOCKER_WAIT=0 in the suite).
    assert "gitblocker trust" in r.err or "gitblocker pending" in r.err, r.err
    assert "[y/N]" not in r.err


def test_no_prompt_when_disabled(gb: GB, repo: Path) -> None:
    modify(gb, repo)
    rc, out, tty = run_with_tty(gb, ["git", "status"], repo, "y", env={"GITBLOCKER_NO_PROMPT": "1"})
    assert rc != 0 and "[y/N]" not in tty and "On branch" not in tty


def test_no_prompt_when_stderr_not_tty(gb: GB, repo: Path) -> None:
    """stderr redirected: the diff was not seen, no question."""
    import pty, fcntl, termios
    modify(gb, repo)
    master, slave = pty.openpty()

    def preexec() -> None:
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
    p = subprocess.Popen([sys.executable, str(GITBLOCKER), "git", "status"], cwd=repo, env=gb.env,
                         stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         preexec_fn=preexec, close_fds=True)
    os.close(slave)
    os.write(master, b"y\n")
    out, errb = p.communicate(timeout=30)
    os.close(master)
    assert p.returncode != 0 and b"On branch" not in out and b"[y/N]" not in errb


def test_no_prompt_when_stdout_not_tty(gb: GB, repo: Path) -> None:
    """stdout on a pipe, stderr on the terminal: what a shell prompt's `$(git
    status)` looks like. A question there would block every prompt redraw on
    a modified repository: the diff is shown, git is refused, nothing asked."""
    modify(gb, repo)
    rc, out, tty = run_with_tty(gb, ["git", "status"], repo, "y", stdout_pipe=True)
    assert rc != 0 and "[y/N]" not in tty and "On branch" not in out, (rc, out, tty)
    assert "pager = cat" in tty and "gitblocker trust" in tty, tty
    assert gb.check(repo).blocked, "reference unchanged"


def test_no_prompt_for_never_trusted(gb: GB, tmp_path: Path) -> None:
    r = tmp_path / "fresh"
    assert gb.git("init", "-q", str(r)).rc == 0
    rc, out, tty = run_with_tty(gb, ["git", "status"], r, "y")
    assert rc != 0 and "[y/N]" not in tty and "never trusted" in tty


def test_no_prompt_for_structural_refusal(gb: GB, repo: Path) -> None:
    (repo / ".git/hooks/evil").symlink_to("/etc/passwd")
    gb.git("config", "core.hooksPath", ".git/hooks", cwd=repo)
    rc, out, tty = run_with_tty(gb, ["git", "status"], repo, "y")
    assert rc != 0 and "[y/N]" not in tty and "On branch" not in out


# --------------------- adopting a nested repository through gitblocker ([149])
def test_absorbgitdirs_through_gitblocker_runs_nothing(gb: GB, repo: Path, tmp_path: Path) -> None:
    """[149] the refusal's way out — declare the nested repository, `git
    submodule absorbgitdirs`, trust — was refused by the same check, and the
    raw git it left runs the nested repository's fsmonitor. Through
    gitblocker, with the pin: the `.gitmodules` the user wrote is asked
    about, nothing of the nested repository runs, its gitdir moves."""
    from tests.test_nested import plant_nested
    mark = tmp_path / "EXEC"
    plant_nested(gb, repo, mark)
    assert gb.run("git", "add", "-A", cwd=repo).rc == 0
    r = gb.check(repo)
    assert r.blocked and "absorbgitdirs -- vendor" in r.err and "rm --cached vendor" in r.err, r.text
    (repo / ".gitmodules").write_text('[submodule "vendor"]\n\tpath = vendor\n\turl = ./vendor\n')
    rc, _, tty = run_with_tty(gb, ["git", "submodule", "absorbgitdirs", "--", "vendor"], repo, "y")
    assert rc == 0, tty
    assert not mark.exists(), "the nested repository's config ran"
    assert (repo / "vendor/.git").is_file() and (repo / ".git/modules/vendor/HEAD").exists()
    r = gb.run("trust", cwd=repo)
    assert r.rc == 0, r.text
    assert not gb.check(repo).blocked


def test_absorbgitdirs_runs_no_pager_of_what_it_absorbs(gb: GB, repo: Path, tmp_path: Path) -> None:
    """[177] the way out the refusal names, typed on a terminal. git moves
    the nested gitdir under `.git/modules/`, then starts a git in it to
    absorb what is nested there — a child the marker covers, the gitdir
    being under `modules/` by then — and that git paged with the
    `pager.submodule--helper` of a config nobody had seen: of the vendored
    repository, or of one the sandbox planted inside it, `vendor/deep`,
    while the refusal said to inspect `vendor/.git/config`. Nothing runs;
    both are absorbed; the next command shows each config, whole."""
    from tests.test_nested import plant_nested
    mark = tmp_path / "PAGED"
    (repo / ".gitmodules").write_text('[submodule "vendor"]\n\tpath = vendor\n\turl = ./vendor\n')
    gb.trust(repo)                                     # the user declared it; nothing is nested there yet
    vendor = plant_nested(gb, repo, tmp_path / "EXEC", evil=False)
    deep = vendor / "deep"
    assert gb.git("init", "-q", str(deep)).rc == 0
    (deep / "d").write_text("d\n")
    assert gb.git("add", "d", cwd=deep).rc == 0 and gb.git("commit", "-qm", "d", cwd=deep).rc == 0
    pager = tmp_path / "pager.sh"
    write_exec(pager, f"#!/bin/sh\n: > '{mark}'\ncat >/dev/null 2>&1\n")
    assert gb.git("config", "pager.submodule--helper", str(pager), cwd=deep).rc == 0
    (vendor / ".gitmodules").write_text('[submodule "deep"]\n\tpath = deep\n\turl = ./deep\n')
    assert gb.git("add", "deep", cwd=vendor).rc == 0
    assert gb.git("add", "vendor", cwd=repo).rc == 0
    r = gb.check(repo)
    assert r.blocked and "absorbgitdirs -- vendor" in r.err, r.text
    rc, _, tty = run_with_tty(gb, ["git", "submodule", "absorbgitdirs", "--", "vendor"], repo, None)
    assert rc == 0, tty
    assert not mark.exists(), f"the pager of a repository nobody judged ran\n{tty}"
    assert (repo / ".git/modules/vendor/modules/deep/HEAD").exists(), tty
    rc, _, tty = run_with_tty(gb, ["git", "status"], repo, "n")
    assert rc != 0 and "[y/N]" in tty and "submodule--helper" in tty, tty      # shown, whole ([168])
    assert not mark.exists()


def test_absorbgitdirs_refused_without_the_pin(gb: GB, repo: Path, tmp_path: Path) -> None:
    """[149] GITBLOCKER_KEEP_FSMONITOR leaves the fsmonitor armed: no way through."""
    from tests.test_nested import plant_nested
    plant_nested(gb, repo, tmp_path / "EXEC")
    assert gb.run("git", "add", "-A", cwd=repo).rc == 0
    (repo / ".gitmodules").write_text('[submodule "vendor"]\n\tpath = vendor\n\turl = ./vendor\n')
    rc, _, tty = run_with_tty(gb, ["git", "submodule", "absorbgitdirs"], repo, "y",
                              env={"GITBLOCKER_KEEP_FSMONITOR": "1"})
    assert rc != 0 and "nested repository" in tty and not (tmp_path / "EXEC").exists(), tty
