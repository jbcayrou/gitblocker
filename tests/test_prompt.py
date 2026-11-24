"""Exec-mode shortcuts when the repository differs from the reference:

1. auto-accept of a pure branch-tracking addition/removal
   (`branch.<x>.remote` / `.merge`, what `push -u`, `branch -u`,
   `checkout -b` write) — no prompt, reference updated;
2. otherwise, diff shown then a question on /dev/tty, default answer N;
   never without a terminal, never when stderr or stdout is not a terminal, never with
   GITWARY_NO_PROMPT, never for "never trusted" nor for a structural
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

from tests.conftest import GW, GITWARY

# ------------------------------------------------------------------ auto-accept

def with_origin(gw: GW, repo: Path, subsrc: Path) -> None:
    """Trusted repository with an `origin` remote (remote add requires a trust)."""
    assert gw.git("remote", "add", "origin", str(subsrc), cwd=repo).rc == 0
    gw.trust(repo)
    assert not gw.check(repo).blocked


def test_push_u_accepted_without_prompt(gw: GW, repo: Path, subsrc: Path) -> None:
    """`push -u` writes the config AFTER the check: the next command sees the
    difference and accepts it on its own."""
    with_origin(gw, repo, subsrc)
    assert gw.run("git", "checkout", "-qb", "feat", cwd=repo).rc == 0
    r = gw.run("git", "push", "-qu", "origin", "feat", cwd=repo)
    assert r.rc == 0, r.text
    assert "branch.feat.remote=origin" in gw.git("config", "--list", cwd=repo).out
    r = gw.run("git", "status", cwd=repo)
    assert r.rc == 0 and "On branch" in r.out, r.text
    assert "branch tracking for feat" in r.err and "has changed" not in r.err
    assert not gw.check(repo).blocked, "reference updated"
    assert "branch tracking" not in gw.run("git", "status", cwd=repo).err, "only once"
    # Removing the tracking: accepted too.
    assert gw.run("git", "branch", "--unset-upstream", cwd=repo).rc == 0
    r = gw.run("git", "status", cwd=repo)
    assert r.rc == 0 and "branch tracking for feat" in r.err
    assert not gw.check(repo).blocked


def test_vscode_merge_base_accepted_without_prompt(gw: GW, repo: Path, subsrc: Path) -> None:
    """VS Code's git extension writes `branch.<x>.vscode-merge-base` on opening
    a repository (seen with code-server): accepted like branch tracking, and
    refused as soon as the value is not a ref name."""
    with_origin(gw, repo, subsrc)
    assert gw.run("git", "checkout", "-qb", "feat", cwd=repo).rc == 0
    assert gw.run("git", "push", "-qu", "origin", "feat", cwd=repo).rc == 0
    assert gw.run("git", "status", cwd=repo).rc == 0 and not gw.check(repo).blocked
    gw.git("config", "branch.feat.vscode-merge-base", "origin/main", cwd=repo)
    r = gw.run("git", "status", cwd=repo)
    assert r.rc == 0 and "branch tracking for feat" in r.err and "has changed" not in r.err, r.text
    assert not gw.check(repo).blocked
    gw.git("config", "branch.feat.vscode-merge-base", "--upload-pack=evil", cwd=repo)
    assert gw.run("git", "status", cwd=repo).blocked
    assert gw.check(repo).blocked


def test_branch_u_from_linked_worktree(gw: GW, repo: Path, subsrc: Path, tmp_path: Path) -> None:
    """From a linked worktree, git writes into the main repository's config
    (scope `common`): same shortcut."""
    with_origin(gw, repo, subsrc)
    wt = tmp_path / "wt"
    assert gw.git("worktree", "add", "-q", str(wt), "-b", "wtb", cwd=repo).rc == 0
    gw.trust(repo)
    gw.trust(wt)                                 # the linked worktree has its own key
    assert gw.git("fetch", "-q", "origin", cwd=repo).rc == 0
    assert gw.run("git", "branch", "-u", "origin/main", cwd=wt).rc == 0
    assert gw.check(wt).blocked, "common:config has changed"
    r = gw.run("git", "status", cwd=wt)
    assert r.rc == 0 and "branch tracking for wtb" in r.err, r.text
    assert not gw.check(wt).blocked
    r = gw.run("git", "status", cwd=repo)        # the main repository sees the same difference
    assert r.rc == 0 and "branch tracking for wtb" in r.err, r.text
    assert not gw.check(repo).blocked


def test_check_mode_still_reports(gw: GW, repo: Path, subsrc: Path) -> None:
    """`gitwary` alone (diagnostic) re-trusts nothing: it reports."""
    with_origin(gw, repo, subsrc)
    gw.git("config", "branch.feat.remote", "origin", cwd=repo)
    gw.git("config", "branch.feat.merge", "refs/heads/feat", cwd=repo)
    assert gw.check(repo).blocked
    assert gw.run("git", "status", cwd=repo).rc == 0     # exec: accepted
    assert not gw.check(repo).blocked


@pytest.mark.parametrize("extra", [
    ("core.fsmonitor", "/tmp/evil"),
    ("branch.feat.rebase", "true"),
    ("remote.evil.url", "/tmp/evil"),
    ("alias.st", "!id"),
])
def test_branch_plus_anything_else_refused(gw: GW, repo: Path, subsrc: Path, extra) -> None:
    with_origin(gw, repo, subsrc)
    gw.git("config", "branch.feat.remote", "origin", cwd=repo)
    gw.git("config", "branch.feat.merge", "refs/heads/feat", cwd=repo)
    gw.git("config", *extra, cwd=repo)
    r = gw.run("git", "status", cwd=repo)
    assert r.blocked and "On branch" not in r.out, r.text
    assert "has changed" in r.err
    assert gw.check(repo).blocked, "not re-trusted"


def test_branch_tracking_to_unknown_remote_refused(gw: GW, repo: Path, subsrc: Path) -> None:
    with_origin(gw, repo, subsrc)
    gw.git("config", "branch.feat.remote", "elsewhere", cwd=repo)
    gw.git("config", "branch.feat.merge", "refs/heads/feat", cwd=repo)
    assert gw.run("git", "status", cwd=repo).blocked


def test_branch_tracking_plus_hook_refused(gw: GW, repo: Path, subsrc: Path) -> None:
    from tests.conftest import write_exec
    with_origin(gw, repo, subsrc)
    gw.git("config", "branch.feat.remote", "origin", cwd=repo)
    gw.git("config", "branch.feat.merge", "refs/heads/feat", cwd=repo)
    write_exec(repo / ".git/hooks/pre-commit")
    assert gw.run("git", "status", cwd=repo).blocked


# ----------------------------------------------------------------------- prompt

def run_with_tty(gw: GW, args: list[str], cwd: Path, answer: str | None,
                 stdin_data: bytes | None = None, env: dict | None = None,
                 stdout_pipe: bool = False, pretype: bytes | None = None):
    """Run gitwary with a pseudo-terminal as controlling terminal (so /dev/tty
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
        [sys.executable, str(GITWARY), *args], cwd=cwd, env={**gw.env, **(env or {})},
        stdin=subprocess.PIPE if stdin_data is not None else slave,
        stdout=subprocess.PIPE if stdout_pipe else slave, stderr=slave,
        preexec_fn=preexec, close_fds=True)
    os.close(slave)
    if pretype is not None:
        os.write(master, pretype)
    if stdin_data is not None:
        # gitwary never reads stdin (the question goes through /dev/tty): the
        # data waits in the pipe for the git that gitwary execs.
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


def modify(gw: GW, repo: Path) -> None:
    gw.git("config", "core.pager", "cat", cwd=repo)    # change that cannot be auto-accepted


@pytest.mark.parametrize("answer, accepted", [("y", True), ("yes", True), ("Y", True),
                                              ("", False), ("n", False), ("no", False)])
def test_prompt_answers(gw: GW, repo: Path, answer: str, accepted: bool) -> None:
    modify(gw, repo)
    rc, out, tty = run_with_tty(gw, ["git", "status"], repo, answer)
    assert "[y/N]" in tty and "pager = cat" in tty, tty      # diff shown before the question
    if accepted:
        assert rc == 0 and "On branch" in tty, (rc, tty)
        assert not gw.check(repo).blocked, "reference updated"
    else:
        assert rc != 0 and "On branch" not in tty, (rc, tty)
        assert gw.check(repo).blocked, "reference unchanged"


def test_prompt_trusts_exactly_what_was_shown(gw: GW, repo: Path) -> None:
    """The trusted state is the one of the displayed diff, not a recomputed one."""
    import json
    modify(gw, repo)
    rc, out, tty = run_with_tty(gw, ["git", "status"], repo, "y")
    assert rc == 0
    man = json.loads(gw.key_for(repo).read_text())
    cfg = [e for e in man["entries"] if e["scope"] == "local" and e["path"] == "config"]
    import hashlib
    assert cfg and cfg[0]["sha"] == hashlib.sha256((repo / ".git/config").read_bytes()).hexdigest()


def test_prompt_does_not_eat_git_stdin(gw: GW, repo: Path) -> None:
    modify(gw, repo)
    rc, out, tty = run_with_tty(gw, ["git", "hash-object", "--stdin"], repo, "y",
                                stdin_data=b"hello\n")
    assert rc == 0, tty
    assert "ce013625030ba8dba906f756967f9e9ca394464a" in tty, tty


def test_pretyped_input_does_not_answer(gw: GW, repo: Path) -> None:
    """A `y` typed before the diff was on screen is discarded (input queue
    flushed before the question): the answer is the Enter typed afterwards,
    i.e. the default N. Without the flush, readline would return the early
    `y` and git would run."""
    modify(gw, repo)
    rc, out, tty = run_with_tty(gw, ["git", "status"], repo, "", pretype=b"y\n")
    assert "[y/N]" in tty, tty
    assert rc != 0 and "On branch" not in tty, (rc, tty)
    assert gw.check(repo).blocked, "reference unchanged"


def test_no_prompt_without_tty(gw: GW, repo: Path) -> None:
    modify(gw, repo)
    r = gw.run("git", "status", cwd=repo)            # neither tty nor interactive stdin
    assert r.blocked and "On branch" not in r.out
    # From a terminal (developer's shell) the refusal names `gitwary trust`;
    # without a controlling terminal (CI, editor) it records a pending
    # decision and names `gitwary pending` (GITWARY_WAIT=0 in the suite).
    assert "gitwary trust" in r.err or "gitwary pending" in r.err, r.err
    assert "[y/N]" not in r.err


def test_no_prompt_when_disabled(gw: GW, repo: Path) -> None:
    modify(gw, repo)
    rc, out, tty = run_with_tty(gw, ["git", "status"], repo, "y", env={"GITWARY_NO_PROMPT": "1"})
    assert rc != 0 and "[y/N]" not in tty and "On branch" not in tty


def test_no_prompt_when_stderr_not_tty(gw: GW, repo: Path) -> None:
    """stderr redirected: the diff was not seen, no question."""
    import pty, fcntl, termios
    modify(gw, repo)
    master, slave = pty.openpty()

    def preexec() -> None:
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
    p = subprocess.Popen([sys.executable, str(GITWARY), "git", "status"], cwd=repo, env=gw.env,
                         stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         preexec_fn=preexec, close_fds=True)
    os.close(slave)
    os.write(master, b"y\n")
    out, errb = p.communicate(timeout=30)
    os.close(master)
    assert p.returncode != 0 and b"On branch" not in out and b"[y/N]" not in errb


def test_no_prompt_when_stdout_not_tty(gw: GW, repo: Path) -> None:
    """stdout on a pipe, stderr on the terminal: what a shell prompt's `$(git
    status)` looks like. A question there would block every prompt redraw on
    a modified repository: the diff is shown, git is refused, nothing asked."""
    modify(gw, repo)
    rc, out, tty = run_with_tty(gw, ["git", "status"], repo, "y", stdout_pipe=True)
    assert rc != 0 and "[y/N]" not in tty and "On branch" not in out, (rc, out, tty)
    assert "pager = cat" in tty and "gitwary trust" in tty, tty
    assert gw.check(repo).blocked, "reference unchanged"


def test_no_prompt_for_never_trusted(gw: GW, tmp_path: Path) -> None:
    r = tmp_path / "fresh"
    assert gw.git("init", "-q", str(r)).rc == 0
    rc, out, tty = run_with_tty(gw, ["git", "status"], r, "y")
    assert rc != 0 and "[y/N]" not in tty and "never trusted" in tty


def test_no_prompt_for_structural_refusal(gw: GW, repo: Path) -> None:
    (repo / ".git/hooks/evil").symlink_to("/etc/passwd")
    gw.git("config", "core.hooksPath", ".git/hooks", cwd=repo)
    rc, out, tty = run_with_tty(gw, ["git", "status"], repo, "y")
    assert rc != 0 and "[y/N]" not in tty and "On branch" not in out


# --------------------- adopting a nested repository through gitwary ([149])
def test_absorbgitdirs_through_gitwary_runs_nothing(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[149] the refusal's way out — declare the nested repository, `git
    submodule absorbgitdirs`, trust — was refused by the same check, and the
    raw git it left runs the nested repository's fsmonitor. Through
    gitwary, with the pin: the `.gitmodules` the user wrote is asked
    about, nothing of the nested repository runs, its gitdir moves."""
    from tests.test_nested import plant_nested
    mark = tmp_path / "EXEC"
    plant_nested(gw, repo, mark)
    assert gw.run("git", "add", "-A", cwd=repo).rc == 0
    r = gw.check(repo)
    assert r.blocked and "absorbgitdirs -- vendor" in r.err and "rm --cached vendor" in r.err, r.text
    (repo / ".gitmodules").write_text('[submodule "vendor"]\n\tpath = vendor\n\turl = ./vendor\n')
    rc, _, tty = run_with_tty(gw, ["git", "submodule", "absorbgitdirs", "--", "vendor"], repo, "y")
    assert rc == 0, tty
    assert not mark.exists(), "the nested repository's config ran"
    assert (repo / "vendor/.git").is_file() and (repo / ".git/modules/vendor/HEAD").exists()
    r = gw.run("trust", cwd=repo)
    assert r.rc == 0, r.text
    assert not gw.check(repo).blocked


def test_absorbgitdirs_refused_without_the_pin(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[149] GITWARY_KEEP_FSMONITOR leaves the fsmonitor armed: no way through."""
    from tests.test_nested import plant_nested
    plant_nested(gw, repo, tmp_path / "EXEC")
    assert gw.run("git", "add", "-A", cwd=repo).rc == 0
    (repo / ".gitmodules").write_text('[submodule "vendor"]\n\tpath = vendor\n\turl = ./vendor\n')
    rc, _, tty = run_with_tty(gw, ["git", "submodule", "absorbgitdirs"], repo, "y",
                              env={"GITWARY_KEEP_FSMONITOR": "1"})
    assert rc != 0 and "nested repository" in tty and not (tmp_path / "EXEC").exists(), tty
