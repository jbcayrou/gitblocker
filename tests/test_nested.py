"""Nested repositories: the index gitlink is the barrier.

git opens a nested repository only once a gitlink references it; the
`git add -A` that creates the gitlink executes nothing (pytest version of the
proof in tests/nested_git_is_a_threat.sh), the next command is refused.
`.gitmodules` is read without walking the tree. The legitimate way out is a
real submodule (`git submodule absorbgitdirs`).
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from tests.conftest import GG, write_exec
from tests.test_attacks import assert_blocked_now


def plant_nested(gg: GG, repo: Path, mark: Path, evil: bool = True) -> Path:
    """The container: a nested repository with one commit and, if `evil`, a
    config/hooks that leave a trace if they execute."""
    sub = repo / "vendor"
    sub.mkdir()
    gg.git("init", "-q", cwd=sub)
    (sub / "v").write_text("v\n")
    gg.git("add", "v", cwd=sub)
    gg.git("commit", "-qm", "v", cwd=sub)
    if evil:
        gg.git("config", "core.fsmonitor", f"sh -c 'touch {mark}; exit 1'", cwd=sub)
        hooks = sub.parent.parent / "hooks"
        gg.git("config", "core.hooksPath", str(hooks), cwd=sub)
        for h in ("post-index-change", "pre-commit", "post-checkout"):
            write_exec(hooks / h, f"#!/bin/sh\ntouch {mark}\n")
    return sub


def test_first_add_does_not_execute(gg: GG, repo: Path, tmp_path: Path) -> None:
    """The assumption that makes the no-walk design acceptable: the `git add
    -A` that creates the gitlink does not execute the nested repository's
    config. Positive control afterwards: the next command, outside gitguard,
    does."""
    mark = tmp_path / "EXEC"
    plant_nested(gg, repo, mark)
    assert not gg.check(repo).blocked            # no gitlink: nothing to see
    for cmd in (["status", "--short"], ["diff"], ["stash", "-u"], ["clean", "-nd"]):
        assert gg.run("git", *cmd, cwd=repo).rc == 0, cmd
        assert not mark.exists(), f"git {' '.join(cmd)} executed the nested config"
    r = gg.run("git", "add", "-A", cwd=repo)
    assert r.rc == 0, r.text
    assert not mark.exists(), "the first `git add -A` executes the nested config: " \
                              "a tree walk before the add would be needed again"
    assert "160000" in gg.git("ls-files", "--stage", cwd=repo).out, "gitlink expected"
    assert_blocked_now(gg, repo, "nested repository")   # the next command refuses
    # Control: outside gitguard, git does execute from here on.
    gg.git("status", "--short", cwd=repo)
    assert mark.exists(), "invalid control: git no longer executes the nested config"


def test_nested_repo_repair(gg: GG, repo: Path, tmp_path: Path) -> None:
    """Documented repair: delete vendor/.git BEFORE `git rm --cached`."""
    sub = plant_nested(gg, repo, tmp_path / "EXEC")
    assert gg.run("git", "add", "-A", cwd=repo).rc == 0
    r = gg.check(repo)
    assert r.blocked and "vendor/.git" in r.err and "absorbgitdirs" in r.err, r.text
    assert "GITGUARD_PRUNE" not in r.err          # no longer a thing
    shutil.rmtree(sub / ".git")
    assert gg.run("git", "rm", "-qf", "--cached", "vendor", cwd=repo).rc == 0
    assert not gg.check(repo).blocked
    assert not (tmp_path / "EXEC").exists()


def test_vendored_repo_becomes_a_submodule(gg: GG, repo: Path, tmp_path: Path) -> None:
    """The legitimate way out named by the refusal: declare the directory in
    .gitmodules, `git submodule absorbgitdirs` — through gitguard since
    [149], the `.gitmodules` just written trusted first — then trust."""
    plant_nested(gg, repo, tmp_path / "EXEC", evil=False)
    assert gg.run("git", "add", "-A", cwd=repo).rc == 0
    assert gg.check(repo).blocked
    (repo / ".gitmodules").write_text('[submodule "vendor"]\n\tpath = vendor\n\turl = ./vendor\n')
    r = gg.run("git", "submodule", "absorbgitdirs", cwd=repo)
    assert r.blocked and "has changed" in r.err and "nested repository" not in r.err, r.text
    from tests.test_prompt import run_with_tty
    rc, _, tty = run_with_tty(gg, ["git", "submodule", "absorbgitdirs"], repo, "y")
    assert rc == 0, tty
    assert (repo / "vendor/.git").is_file()
    r = gg.run("trust", cwd=repo)
    assert r.rc == 0, r.text
    assert not gg.check(repo).blocked
    assert gg.run("git", "status", "--short", cwd=repo).rc == 0


def test_gitmodules_declared_planted_gitdir_still_refused(gg: GG, repo: Path) -> None:
    """[6] .gitmodules declares a directory whose .git is a planted directory:
    read without any tree walk, gitlink or not."""
    sub = repo / "build" / "x"
    sub.mkdir(parents=True)
    gg.git("init", "-q", cwd=sub)
    gg.git("config", "core.fsmonitor", "/tmp/evil", cwd=sub)
    (repo / ".gitmodules").write_text('[submodule "x"]\n\tpath = build/x\n\turl = ./x\n')
    assert gg.check(repo).blocked


def test_undeclared_nested_repo_without_gitlink_is_invisible(gg: GG, repo: Path) -> None:
    """No walk: a nested repository with no gitlink and no .gitmodules entry
    is not seen (git does not open it either); GITGUARD_SCAN_TREE no longer
    changes anything."""
    (repo / "vendor").mkdir()
    gg.git("init", "-q", cwd=repo / "vendor")
    assert not gg.check(repo).blocked
    gg.env["GITGUARD_SCAN_TREE"] = "1"
    assert not gg.check(repo).blocked


# ---------------------------------------------- [154] what a tree does not inherit
# A submodule or a linked worktree takes the trust of the repository whose
# `.git` holds its gitdir when that repository is in its trusted state and
# every file the tree's own check watches is in its reference. Each test is
# one way of not being there: the tree stays "never trusted".
def _sub(gg: GG, repo: Path, tmp_path: Path) -> Path:
    from tests.attacks._helpers import add_submodule
    sub = add_submodule(gg, repo, tmp_path)
    gg.trust(repo)
    return sub


def _refused(gg: GG, tree: Path) -> None:
    r = gg.run("git", "status", "--short", cwd=tree)
    assert r.blocked and "never trusted" in r.err and "trusted with" not in r.err, r.text
    assert not gg.key_for(tree).is_file()


def test_no_inheritance_from_a_changed_superproject(gg: GG, repo: Path, tmp_path: Path) -> None:
    """The sandbox rewrites the submodule's config after the trust: the
    superproject is not in its trusted state, nothing is inherited — the
    diff is the superproject's to show."""
    sub = _sub(gg, repo, tmp_path)
    gg.git("config", "core.pager", "sh evil.sh", cwd=sub)
    _refused(gg, sub)
    r = gg.check(repo)
    assert r.blocked and "modules/sub/config" in r.err, r.text


def test_no_inheritance_when_a_named_file_went_missing(gg: GG, repo: Path, tmp_path: Path) -> None:
    """A file the submodule's config names in its tree is gone: nothing of
    the submodule's own fingerprint differs from the reference (one entry
    less), the superproject's does."""
    from tests.attacks._helpers import add_submodule
    sub = add_submodule(gg, repo, tmp_path)
    gg.git("config", "core.hooksPath", ".hk", cwd=sub)
    write_exec(sub / ".hk/pre-push", "#!/bin/sh\nexit 0\n")
    gg.trust(repo)
    (sub / ".hk/pre-push").unlink()
    _refused(gg, sub)


def test_no_inheritance_from_a_superproject_never_trusted(gg: GG, repo: Path, tmp_path: Path) -> None:
    sub = _sub(gg, repo, tmp_path)
    assert gg.run("forget", str(repo)).rc == 0
    _refused(gg, sub)


def test_no_inheritance_under_a_redirecting_environment(gg: GG, repo: Path, tmp_path: Path) -> None:
    """`GIT_WORK_TREE`, `GIT_DIR`…: the tree git works in is not the one
    the gitdir names; judged by hand, as before ([72])."""
    sub = _sub(gg, repo, tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    gg.env["GIT_WORK_TREE"] = str(other)
    r = gg.run("git", "status", "--short", cwd=sub)
    assert r.blocked and "never trusted" in r.err, r.text


def test_no_inheritance_for_a_worktree_the_main_tree_has_not_seen(gg: GG, repo: Path,
                                                                 tmp_path: Path) -> None:
    """`worktree add` by something gitguard did not run: its `worktrees/<id>`
    is not in the main tree's reference yet."""
    wt = tmp_path / "wt"
    assert gg.git("worktree", "add", "-q", str(wt), cwd=repo).rc == 0
    _refused(gg, wt)


def test_no_inheritance_when_the_worktree_hook_differs(gg: GG, repo: Path, tmp_path: Path) -> None:
    """A relative `core.hooksPath` resolves in the worktree's own tree
    ([120]): another branch's hooks, or the sandbox's, were shown to
    nobody. The same file is the same bytes and the same mode, as the
    reference compares everywhere."""
    gg.git("config", "core.hooksPath", ".githooks", cwd=repo)
    write_exec(repo / ".githooks/pre-commit", "#!/bin/sh\nexit 0\n")
    gg.git("add", "-A", cwd=repo)
    gg.git("commit", "-qm", "hooks", cwd=repo)
    (repo / ".githooks/pre-commit").unlink()
    assert gg.git("checkout", "--", ".githooks", cwd=repo).rc == 0     # the mode git gives, in both trees
    wt = tmp_path / "wt"
    assert gg.git("worktree", "add", "-q", str(wt), cwd=repo).rc == 0
    gg.trust(repo)
    hook = wt / ".githooks/pre-commit"
    mode = hook.stat().st_mode
    hook.chmod(0o700)
    _refused(gg, wt)
    hook.write_text("#!/bin/sh\necho other\n")
    hook.chmod(mode)
    _refused(gg, wt)
    hook.write_text("#!/bin/sh\nexit 0\n")
    write_exec(wt / ".githooks/post-checkout", "#!/bin/sh\necho new\n")
    _refused(gg, wt)
    (wt / ".githooks/post-checkout").unlink()
    r = gg.run("git", "status", "--short", cwd=wt)                    # the control: nothing differs, it inherits
    assert r.rc == 0 and f"trusted with {repo}" in r.err, r.text


# ------------------------------- [155] what a `git worktree` command does not get accepted
def _hooked_add(gg: GG, repo: Path, tmp_path: Path, hook: str) -> Path:
    """`worktree add` through gitguard while something else writes into the
    gitdir: a trusted post-checkout hook stands for the sandbox, running in
    the new worktree before the command returns."""
    write_exec(repo / ".git/hooks/post-checkout", "#!/bin/sh\n" + hook)
    gg.trust(repo)
    wt = tmp_path / "wt"
    r = gg.run("git", "worktree", "add", "-q", str(wt), cwd=repo)
    assert r.rc == 0 and "reference updated" not in r.err, r.text
    return wt


def test_worktree_add_accepts_nothing_else_written_meanwhile(gg: GG, repo: Path, tmp_path: Path) -> None:
    """Another file of the gitdir changed during the command: nothing is
    accepted, the next command shows the pointers and the rest."""
    wt = _hooked_add(gg, repo, tmp_path, f"echo '#!/bin/sh' > '{repo}/.git/hooks/pre-commit'\n")
    r = gg.check(repo)
    assert r.blocked and "hooks/pre-commit" in r.err and "worktrees/wt/gitdir" in r.err, r.text
    assert gg.run("git", "status", "--short", cwd=wt).blocked


def test_worktree_add_accepts_one_worktree(gg: GG, repo: Path, tmp_path: Path) -> None:
    """A second worktree planted during the command, pointers and gitfile
    consistent: `add` writes one."""
    adm = repo / ".git/worktrees/evil"
    _hooked_add(gg, repo, tmp_path,
                f"mkdir -p '{adm}' '{repo}/src' && echo 'ref: refs/heads/main' > '{adm}/HEAD' && "
                f"echo ../.. > '{adm}/commondir' && echo '{repo}/src/.git' > '{adm}/gitdir' && "
                f"echo 'gitdir: {adm}' > '{repo}/src/.git'\n")
    r = gg.check(repo)
    assert r.blocked and "worktrees/evil/gitdir" in r.err, r.text
    assert gg.run("git", "status", "--short", cwd=repo / "src").blocked


@pytest.mark.parametrize("pointer, content", [
    ("gitdir", "{repo}/src/.git"),             # a tree whose gitfile does not point back
    ("gitdir", "{repo}/src"),                  # not a `.git`
    ("gitdir", "../../../../wt/.git"),         # relative: not what git writes without the extension
    ("commondir", "../../"),                   # git reads the same directory; not git's bytes
    ("commondir", "{repo}/.git"),
])
def test_worktree_add_accepts_only_what_git_writes(gg: GG, repo: Path, tmp_path: Path,
                                                   pointer: str, content: str) -> None:
    """The pointers of the new worktree rewritten during the command."""
    (repo / "src").mkdir()
    value = content.format(repo=repo)
    _hooked_add(gg, repo, tmp_path, f"printf '%s\\n' '{value}' > '{repo}/.git/worktrees/wt/{pointer}'\n")
    r = gg.check(repo)
    assert r.blocked and "worktrees/wt/gitdir" in r.err, r.text


def test_worktree_command_on_a_changed_repository_is_asked_first(gg: GG, repo: Path, tmp_path: Path) -> None:
    """Not in its trusted state: the command does not run, as any other."""
    write_exec(repo / ".git/hooks/pre-commit")
    r = gg.run("git", "worktree", "add", "-q", str(tmp_path / "wt"), cwd=repo)
    assert r.blocked and not (tmp_path / "wt").exists(), r.text


def test_worktree_add_by_another_git_is_still_asked(gg: GG, repo: Path, tmp_path: Path) -> None:
    """The same pointers, written by a git gitguard did not run (the
    sandbox's, an IDE's bundled one): shown, asked."""
    assert gg.git("worktree", "add", "-q", str(tmp_path / "wt"), cwd=repo).rc == 0
    r = gg.run("git", "status", "--short", cwd=repo)
    assert r.blocked and "worktrees/wt/commondir" in r.err, r.text


def test_worktree_add_from_a_linked_worktree_is_still_asked(gg: GG, repo: Path, tmp_path: Path) -> None:
    """Run from a linked worktree, the pointers land in the main
    repository's gitdir, under two references (this worktree's, the main
    tree's): left to the next command of each."""
    w1 = tmp_path / "w1"
    assert gg.run("git", "worktree", "add", "-q", str(w1), cwd=repo).rc == 0
    assert gg.run("git", "status", "--short", cwd=w1).rc == 0
    r = gg.run("git", "worktree", "add", "-q", str(tmp_path / "w2"), cwd=w1)
    assert r.rc == 0 and "reference updated" not in r.err, r.text
    assert gg.check(repo).blocked and gg.check(w1).blocked


# ------------------------------------- [163] what a clone in progress does not cover
# A clone judges nothing, the repository does not exist yet; its children
# inherit in the gitdir it creates and in the gitdirs git puts under that
# one's `modules/`. Not in a gitdir found in what the clone checks out:
# content the remote chose. A sound git never opens one; a git with a bug
# that writes a `.git` from a tree does, and that family comes back. The
# tests take the real git plus that one write.
def _git_writing_dotgit_from_a_tree(tmp_path: Path) -> Path:
    """The real git, plus the write of the bug: once it has checked out a
    submodule whose tree holds `payload/`, the gitfile `.git` there is a
    symlink to it. Under a dashed name too (`git-upload-pack`: a link to
    `git` in an exec path)."""
    import shlex
    from tests.conftest import REAL_GIT
    git = shlex.quote(REAL_GIT)
    g = tmp_path / "that-git"
    write_exec(g, f"""#!/bin/sh
case "${{0##*/}}" in git-*) b=${{0##*/}}; set -- "${{b#git-}}" "$@";; esac
co=
for a in "$@"; do [ "$a" = checkout ] && co=1; done
[ -n "$co" ] || exec {git} "$@"
{git} "$@"; rc=$?
[ -f .git ] && [ ! -L .git ] && [ -d payload ] && rm -f .git && ln -s payload .git
exit $rc
""")
    return g


def _superproject_with_a_gitdir_in_a_submodule_tree(gg: GG, tmp_path: Path, mark: Path) -> Path:
    """What the victim clones: `top`, whose submodule `sub` holds in its
    tree a gitdir, `payload/` — a config with `submodule.x.update = !<cmd>`
    and an index with the gitlink `x`: the first `git submodule update` run
    with that gitdir runs the command."""
    from tests.attacks._helpers import make_source
    x = make_source(gg, tmp_path, "x")
    sha = gg.git("rev-parse", "HEAD", cwd=x).out.strip()
    scratch, sub, top = tmp_path / "scratch", tmp_path / "sub", tmp_path / "top"
    for r in (scratch, sub, top):
        assert gg.git("init", "-q", str(r)).rc == 0
    assert gg.git("update-index", "--add", "--cacheinfo", f"160000,{sha},x", cwd=scratch).rc == 0
    p = sub / "payload"
    for d in ("objects", "refs"):
        (p / d).mkdir(parents=True)
        (p / d / "keep").write_text("")
    (p / "HEAD").write_text("ref: refs/heads/main\n")
    shutil.copy(scratch / ".git/index", p / "index")
    (p / "config").write_text("[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
                              f'[submodule "x"]\n\turl = file://{x}\n\tactive = true\n'
                              f'\tupdate = "!touch {mark}; :"\n')
    (sub / ".gitmodules").write_text(f'[submodule "x"]\n\tpath = x\n\turl = file://{x}\n')
    assert gg.git("add", "-A", cwd=sub).rc == 0
    assert gg.git("commit", "-qm", "sub", cwd=sub).rc == 0
    (top / "README").write_text("top\n")
    assert gg.git("add", "README", cwd=top).rc == 0
    assert gg.git("submodule", "add", "-q", f"file://{sub}", "sub", cwd=top).rc == 0
    assert gg.git("commit", "-qm", "top", cwd=top).rc == 0
    return top


def test_clone_does_not_cover_a_gitdir_of_the_tree(gg: GG, tmp_path: Path) -> None:
    """`clone --recurse-submodules`: the checkout of `sub` leaves `sub/.git`
    pointing into its tree, and the clone recurses there. The marker
    covered whatever sat under the new path, that gitdir included, and
    its config ran — while the same clone in two commands refused it.
    The child is judged: never trusted, nothing runs, no auto-trust."""
    mark = tmp_path / "RAN"
    top = _superproject_with_a_gitdir_in_a_submodule_tree(gg, tmp_path, mark)
    bug = GG({**gg.env, "GITGUARD_REAL_GIT": str(_git_writing_dotgit_from_a_tree(tmp_path))},
             gg.state, gg.raw_exec)
    dst = tmp_path / "dst"
    r = bug.run("git", "clone", "-q", "--recurse-submodules", f"file://{top}", str(dst), cwd=tmp_path)
    assert (dst / "sub/.git").is_symlink(), f"the bug was not played, the test proves nothing\n{r.text}"
    assert not mark.exists(), f"the config of a gitdir of the tree ran\n{r.text}"
    assert r.rc != 0 and "never trusted" in r.err and "new repository trusted" not in r.err, r.text
    assert gg.check(dst).blocked and gg.run("git", "status", "--short", cwd=dst / "sub").blocked


def test_clone_gitdir_of_the_tree_control_that_git_runs_it(gg: GG, tmp_path: Path) -> None:
    """Positive control: the same clone by that git alone, its children
    too (the raw exec path with it as `git`)."""
    import os
    import subprocess
    mark = tmp_path / "RAN"
    top = _superproject_with_a_gitdir_in_a_submodule_tree(gg, tmp_path, mark)
    git = _git_writing_dotgit_from_a_tree(tmp_path)
    ep = tmp_path / "exec-with-the-bug"
    ep.mkdir()
    for n in os.listdir(gg.raw_exec):
        os.symlink(git if n == "git" else os.readlink(gg.raw_exec / n), ep / n)
    dst = tmp_path / "dst"
    r = subprocess.run([str(git), "clone", "-q", "--recurse-submodules", f"file://{top}", str(dst)],
                       cwd=tmp_path, env={**gg.raw_env, "GIT_EXEC_PATH": str(ep)},
                       capture_output=True, text=True)
    assert (dst / "sub/.git").is_symlink() and mark.exists(), \
        f"git no longer runs the config of a gitdir its submodule's `.git` leads to: [163] may be moot\n{r.stderr}"


# ------------------------------------------ [164] what a child git does not take
# A git run by another git applies the closed list of accepted changes
# (branch tracking, a remote with a network URL) in a repository its marker
# does not cover, as a git typed in a shell does. Nothing else: it asks
# nothing, waits for nobody, and refuses.
@pytest.mark.parametrize("lines", [
    '[remote "evil"]\n\turl = {vol}/evil\n\tfetch = +refs/heads/*:refs/remotes/evil/*\n',
    '[remote "evil"]\n\turl = ext::sh -c "touch {mark}"\n',
    '[alias]\n\tlog = !touch {mark}\n',
    '[remote "up"]\n\turl = https://example.invalid/x.git\n[core]\n\tpager = touch {mark}\n',
])
def test_a_child_takes_nothing_beyond_the_closed_list(gg: GG, repo: Path, tmp_path: Path, lines: str) -> None:
    """A trusted hook runs git in another repository, whose config the
    sandbox rewrote: a local remote, a remote helper, an alias, a network
    remote with a pager beside it."""
    from tests.attacks._helpers import make_source
    other, mark = make_source(gg, tmp_path, "other"), tmp_path / "RAN"
    gg.trust(other)
    write_exec(repo / ".git/hooks/pre-commit", "#!/bin/sh\nunset GIT_DIR GIT_INDEX_FILE GIT_WORK_TREE "
               f"GIT_PREFIX\ncd '{other}' && git log -1 --format=%s\n")
    gg.trust(repo)
    with open(other / ".git/config", "a") as f:
        f.write(lines.format(vol=tmp_path, mark=mark))
    (repo / "f").write_text("b\n")
    r = gg.run("git", "commit", "-qam", "second", cwd=repo)
    assert r.rc != 0 and "has changed" in r.err and "reference updated" not in r.err, r.text
    assert not mark.exists(), f"the child ran the planted config\n{r.text}"
    assert gg.check(other).blocked


# --------------------------------------- [165] what a tree does not take back
# A submodule or a linked worktree whose reference no longer matches takes
# its holder's trust again on the terms of the first use ([154]): the
# holder in its trusted state, every watched file of the tree in the
# holder's reference. Each test is one way of not being there: the tree
# is refused on its own reference, as before.
def _worktree_in_use(gg: GG, repo: Path, tmp_path: Path) -> Path:
    wt = tmp_path / "wt"
    assert gg.run("git", "worktree", "add", "-q", str(wt), cwd=repo).rc == 0
    r = gg.run("git", "status", "--short", cwd=wt)
    assert r.rc == 0 and f"trusted with {repo}" in r.err, r.text
    return wt


def _changed(gg: GG, tree: Path) -> None:
    r = gg.run("git", "status", "--short", cwd=tree)
    assert r.blocked and "has changed" in r.err and "trusted with" not in r.err, r.text


def test_no_trust_taken_again_from_a_changed_main_tree(gg: GG, repo: Path, tmp_path: Path) -> None:
    """A hook planted in the common dir, a `config.worktree` planted for
    the worktree: changes of the main tree, which is not in its trusted
    state — the worktree shows them, nothing runs."""
    wt, mark = _worktree_in_use(gg, repo, tmp_path), tmp_path / "RAN"
    write_exec(repo / ".git/hooks/pre-commit", f"#!/bin/sh\ntouch '{mark}'\n")
    _changed(gg, wt)
    assert gg.run("git", "commit", "-q", "--allow-empty", "-m", "x", cwd=wt).blocked and not mark.exists()
    (repo / ".git/hooks/pre-commit").unlink()
    assert gg.run("git", "status", "--short", cwd=wt).rc == 0
    gg.git("config", "extensions.worktreeConfig", "true", cwd=repo)
    (repo / ".git/worktrees/wt/config.worktree").write_text(f"[core]\n\tfsmonitor = touch '{mark}'\n")
    _changed(gg, wt)
    assert not mark.exists()


def test_no_trust_taken_again_for_a_file_the_main_tree_never_held(gg: GG, repo: Path, tmp_path: Path) -> None:
    """A relative `core.hooksPath` resolves in the worktree's own tree: a
    hook rewritten or added there is in nobody's reference."""
    gg.git("config", "core.hooksPath", ".githooks", cwd=repo)
    write_exec(repo / ".githooks/pre-commit", "#!/bin/sh\nexit 0\n")
    gg.git("add", "-A", cwd=repo)
    gg.git("commit", "-qm", "hooks", cwd=repo)
    (repo / ".githooks/pre-commit").unlink()
    assert gg.git("checkout", "--", ".githooks", cwd=repo).rc == 0     # the mode git gives, in both trees
    gg.trust(repo)
    wt, mark = _worktree_in_use(gg, repo, tmp_path), tmp_path / "RAN"
    hook = wt / ".githooks/pre-commit"
    mode = hook.stat().st_mode
    hook.write_text(f"#!/bin/sh\ntouch '{mark}'\n")
    hook.chmod(mode)
    _changed(gg, wt)
    hook.write_text("#!/bin/sh\nexit 0\n")
    hook.chmod(mode)
    assert gg.run("git", "status", "--short", cwd=wt).rc == 0
    write_exec(wt / ".githooks/post-checkout", f"#!/bin/sh\ntouch '{mark}'\n")
    _changed(gg, wt)
    assert not mark.exists()


def test_an_entry_of_the_tree_alone_that_goes_missing_is_not_asked(gg: GG, repo: Path, tmp_path: Path) -> None:
    """The price of [165], recorded: a hook that exists in one worktree
    only, trusted there by hand, then removed by the sandbox. The tree is
    back to what the main tree's reference holds and takes its trust
    again, with one line and no question ("removed …" before). Rewritten
    instead of removed, it is refused."""
    gg.git("config", "core.hooksPath", ".githooks", cwd=repo)
    write_exec(repo / ".githooks/pre-commit", "#!/bin/sh\nexit 0\n")
    gg.trust(repo)
    wt = tmp_path / "wt"
    assert gg.run("git", "worktree", "add", "-q", str(wt), cwd=repo).rc == 0
    write_exec(wt / ".githooks/pre-commit", "#!/bin/sh\nexit 0\n")
    write_exec(wt / ".githooks/pre-push", "#!/bin/sh\nexit 0\n")      # the user's, in this worktree only
    assert gg.run("git", "status", "--short", cwd=wt).blocked         # not the main tree's: no inheritance
    gg.trust(wt)
    mark = tmp_path / "RAN"
    write_exec(wt / ".githooks/pre-push", f"#!/bin/sh\ntouch '{mark}'\n")
    _changed(gg, wt)
    (wt / ".githooks/pre-push").unlink()
    r = gg.run("git", "status", "--short", cwd=wt)
    assert r.rc == 0 and f"trusted with {repo}" in r.err, r.text


# ------------------------- [167] what the refusal of a tree says about its holder
def test_refusal_names_the_holder_that_is_not_in_its_trusted_state(gg: GG, repo: Path, tmp_path: Path) -> None:
    """The superproject moved (here: a config of the submodule rewritten;
    for a user, the `submodule update --init` just typed): the submodule
    said "never trusted … gitguard trust", sending the user to bless
    blind a tree whose question waits in the superproject."""
    sub = _sub(gg, repo, tmp_path)
    gg.git("config", "core.pager", "cat", cwd=sub)
    r = gg.run("git", "status", "--short", cwd=sub)
    assert r.blocked and "never trusted" in r.err and f"inside {repo}" in r.err, r.text
    assert "has changed since its last trust" in r.err and "gitguard trust" not in r.err, r.text
    assert gg.run("forget", str(repo)).rc == 0
    r = gg.run("git", "status", "--short", cwd=sub)
    assert r.blocked and f"inside {repo}" in r.err and "never trusted either" in r.err, r.text
    assert not gg.key_for(sub).is_file()


def test_refusal_stays_plain_for_a_tree_its_trusted_holder_does_not_cover(gg: GG, repo: Path,
                                                                        tmp_path: Path) -> None:
    """A copy of the submodule's gitfile planted elsewhere: the
    superproject is in its trusted state and there is nothing to settle
    there — the message does not say otherwise."""
    sub = _sub(gg, repo, tmp_path)
    (repo / "src").mkdir()
    (repo / "src/.git").write_text(f"gitdir: {repo}/.git/modules/{sub.name}\n")
    r = gg.run("git", "status", "--short", cwd=repo / "src")
    assert r.blocked and "never trusted" in r.err and "gitguard trust" in r.err, r.text
    assert "is inside" not in r.err, r.text


# ---------------------------- [168] what is shown of a config under a nested root
def test_the_diff_of_a_submodule_config_is_shown_in_the_superproject(gg: GG, repo: Path, tmp_path: Path) -> None:
    """The superproject's question on a submodule's config was one line,
    `modified modules/sub/config`: the same line for the user's branch and
    for a filter the sandbox added. The check, `gitguard diff` and the
    review of `gitguard trust` show the lines."""
    sub = _sub(gg, repo, tmp_path)
    gg.git("config", "filter.x.clean", "sh evil.sh", cwd=sub)
    for cmd in ([], ["diff"], ["git", "status"]):
        r = gg.run(*cmd, cwd=repo)
        assert "modules/sub/config" in r.text and "clean = sh evil.sh" in r.text, r.text
    r = gg.run("trust", cwd=repo)
    assert "clean = sh evil.sh" in r.text, r.text


def test_the_diff_of_a_worktree_config_is_shown(gg: GG, repo: Path, tmp_path: Path) -> None:
    """`config.worktree`: the main tree's, a linked worktree's, seen from
    the main tree and from the worktree."""
    gg.git("config", "extensions.worktreeConfig", "true", cwd=repo)
    wt = tmp_path / "wt"
    assert gg.git("worktree", "add", "-q", str(wt), cwd=repo).rc == 0
    gg.trust(repo)
    assert gg.run("git", "status", "--short", cwd=wt).rc == 0
    (repo / ".git/config.worktree").write_text("[core]\n\tpager = sh main.sh\n")
    (repo / ".git/worktrees/wt/config.worktree").write_text("[core]\n\tpager = sh linked.sh\n")
    for tree in (repo, wt):
        r = gg.check(tree)
        assert r.blocked and "pager = sh main.sh" in r.err and "pager = sh linked.sh" in r.err, r.text


def test_a_config_added_under_a_nested_root_is_shown_whole(gg: GG, repo: Path, tmp_path: Path) -> None:
    """A submodule added since the trust: its config is new, and is what
    git will read there."""
    from tests.attacks._helpers import add_submodule
    add_submodule(gg, repo, tmp_path)
    gg.git("config", "-f", str(repo / ".git/modules/sub/config"), "core.pager", "sh evil.sh")
    r = gg.check(repo)
    assert r.blocked and "modules/sub/config" in r.err and "pager = sh evil.sh" in r.err, r.text
