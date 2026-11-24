"""Legitimate git operations: none may raise an alert (false-positive guard)."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from tests.attacks._helpers import add_submodule, commit, conflicting_notes, git_has, make_source
from tests.conftest import GW, write_exec


def test_no_repo_passes(gw: GW, tmp_path: Path) -> None:
    assert not gw.check(tmp_path).blocked


def test_commit(gw: GW, repo: Path) -> None:
    commit(gw, repo)
    assert not gw.check(repo).blocked


def test_branch_tag_gc(gw: GW, repo: Path) -> None:
    gw.git("branch", "x", cwd=repo)
    gw.git("tag", "-a", "-m", "t", "v1", cwd=repo)
    gw.git("gc", "-q", cwd=repo)
    assert not gw.check(repo).blocked


def test_branch_named_like_watched_files(gw: GW, repo: Path) -> None:
    gw.git("branch", "config", cwd=repo)
    gw.git("branch", "hooks/x", cwd=repo)
    gw.git("commit", "-q", "--allow-empty", "-m", "e", cwd=repo)
    assert not gw.check(repo).blocked


def test_merge_checkout_fetch(gw: GW, repo: Path) -> None:
    commit(gw, repo)
    gw.git("checkout", "-qb", "br", cwd=repo)
    commit(gw, repo, "g", "x")
    gw.git("checkout", "-q", "main", cwd=repo)
    gw.git("merge", "-q", "--no-ff", "-m", "m", "br", cwd=repo)
    gw.git("fetch", "-q", ".", cwd=repo)
    assert not gw.check(repo).blocked


def test_stash(gw: GW, repo: Path) -> None:
    commit(gw, repo)
    (repo / "f").write_text("c\n")
    gw.git("stash", "-q", cwd=repo)
    gw.git("stash", "pop", "-q", cwd=repo)
    assert not gw.check(repo).blocked


def test_rebase_cherry_pick_revert(gw: GW, repo: Path) -> None:
    for i in range(3):
        commit(gw, repo, "g", str(i))
    gw.git("rebase", "-q", "HEAD~1", cwd=repo)
    gw.git("revert", "-q", "--no-edit", "HEAD", cwd=repo)
    assert not gw.check(repo).blocked


def test_rebase_builtin_strategy_in_progress(gw: GW, repo: Path) -> None:
    """An interrupted rebase that recorded a builtin `strategy` (`-s resolve`)
    must not alert: only a non-builtin name is an exec vector. [51]"""
    import shlex, subprocess, sys
    for i in range(3):
        commit(gw, repo, "g", str(i))
    editor = repo.parent / "seq-editor.py"
    editor.write_text("import sys\np = sys.argv[1]\nl = open(p).read().split('\\n')\n"
                      "l.insert(1, 'break')\nopen(p, 'w').write('\\n'.join(l))\n")
    env = dict(gw.env, GIT_SEQUENCE_EDITOR=f"{shlex.quote(sys.executable)} {shlex.quote(str(editor))}")
    subprocess.run(["git", "rebase", "-i", "-s", "resolve", "HEAD~2"], cwd=repo,
                   env=env, capture_output=True, text=True)
    strat = repo / ".git/rebase-merge/strategy"
    assert strat.is_file() and strat.read_text().strip() == "resolve"
    gw.trust(repo)
    assert not gw.check(repo).blocked


def test_cherry_pick_builtin_strategy_in_progress(gw: GW, repo: Path) -> None:
    """A stopped `cherry-pick --strategy=recursive` keeps `strategy = recursive`
    in sequencer/opts: builtin, must not alert. [51]"""
    from tests.attacks.tool_itself import _interrupted_cherry_pick
    opts = _interrupted_cherry_pick(gw, repo)
    assert "strategy = recursive" in opts.read_text()
    gw.trust(repo)
    assert not gw.check(repo).blocked


def test_bisect_in_progress(gw: GW, repo: Path) -> None:
    """BISECT_* present: excluded (and the glob was a bash trap)."""
    for i in range(3):
        commit(gw, repo, "g", str(i))
    gw.git("bisect", "start", "HEAD", "HEAD~2", cwd=repo)
    assert not gw.check(repo).blocked
    r = gw.run("diff", cwd=repo)
    assert "no changes" in r.out
    gw.git("bisect", "reset", cwd=repo)


def test_notes_repack_commit_graph(gw: GW, repo: Path) -> None:
    gw.git("notes", "add", "-m", "n", "HEAD", cwd=repo)
    gw.git("repack", "-adq", cwd=repo)
    gw.git("commit-graph", "write", cwd=repo)
    gw.git("reflog", "expire", "--all", cwd=repo)
    gw.git("prune", cwd=repo)
    assert not gw.check(repo).blocked


def test_worktree(gw: GW, repo: Path, tmp_path: Path) -> None:
    wt = tmp_path / "wt"
    assert gw.git("worktree", "add", "-q", str(wt), "-b", "wt", cwd=repo).rc == 0
    gw.trust(wt)
    assert not gw.check(wt).blocked
    commit(gw, wt)
    assert not gw.check(wt).blocked
    gw.trust(repo)
    (wt / "f").write_text("zz\n")
    gw.git("commit", "-qam", "c3", cwd=wt)
    assert not gw.check(repo).blocked, "commit in a worktree seen from the main repository"


def test_submodule_commit(gw: GW, repo: Path, tmp_path: Path) -> None:
    sub = add_submodule(gw, repo, tmp_path)
    gw.trust(repo)
    commit(gw, sub, "t", "t")
    assert not gw.check(repo).blocked


def test_hookspath_ordinary_commits(gw: GW, repo: Path) -> None:
    (repo / ".githooks").mkdir()
    gw.git("config", "core.hooksPath", ".githooks", cwd=repo)
    gw.trust(repo)
    commit(gw, repo)
    assert not gw.check(repo).blocked


def _tracked_hooks_upstream(gw: GW, repo: Path) -> None:
    """A tracked hooks directory the trusted config names (`core.hooksPath
    = .githooks`), and a branch `up` whose last commit changes the hook (a
    colleague's lint), forked from where the user stays. Trusted there."""
    hooks = repo / ".githooks"
    hooks.mkdir()
    (hooks / "pre-commit").write_text("#!/bin/sh\nexit 0\n")
    gw.git("config", "core.hooksPath", ".githooks", cwd=repo)
    gw.git("add", ".githooks", cwd=repo)
    gw.git("commit", "-qm", "hooks", cwd=repo)
    gw.git("checkout", "-qb", "up", cwd=repo)
    commit(gw, repo, "g", "1")
    (hooks / "pre-commit").write_text("#!/bin/sh\n# a colleague's lint\nexit 0\n")
    gw.git("commit", "-qam", "lint", cwd=repo)
    commit(gw, repo, "g", "2")
    gw.git("checkout", "-q", "-", cwd=repo)
    gw.trust(repo)


@pytest.mark.parametrize("cmd", [["merge", "--no-edit", "--autostash", "up"],
                                 ["rebase", "--autostash", "up"]])
def test_autostash_across_a_tracked_hook_change_keeps_the_work(gw: GW, repo: Path,
                                                              cmd: list[str]) -> None:
    """[124] The command checks out a commit that changes a file the trusted
    config names in the tree, then applies the autostash through child gits
    (`stash apply`, `stash store` when it fails) in the same repository. A
    child that re-judged the tree there refused both: the uncommitted work
    vanished, rc 0. The change is judged at the next command."""
    _tracked_hooks_upstream(gw, repo)
    (repo / "f").write_text("my uncommitted work\n")
    r = gw.run("git", "-c", "core.editor=true", *cmd, cwd=repo)
    assert r.rc == 0 and "✗" not in r.err, r.text
    assert (repo / "f").read_text() == "my uncommitted work\n"
    assert "colleague" in (repo / ".githooks/pre-commit").read_text()
    c = gw.check(repo)
    assert c.blocked and "pre-commit" in c.err, c.text


def test_rebase_exec_and_bisect_run_across_a_tracked_hook_change(gw: GW, repo: Path) -> None:
    """[124] `rebase --exec` and `bisect run` run the user's command, which
    runs git, after each checkout; some checkouts change the tracked hook.
    Every one of those gits is in the judged repository: none refuses."""
    _tracked_hooks_upstream(gw, repo)
    gw.git("checkout", "-qb", "topic", cwd=repo)
    commit(gw, repo, "t", "1")
    gw.trust(repo)
    r = gw.run("git", "rebase", "-q", "--exec", "git log -1 --format=%s", "up", cwd=repo)
    assert r.rc == 0 and "✗" not in r.err, r.text
    gw.git("checkout", "-q", "up", cwd=repo)
    gw.trust(repo)
    first = gw.git("rev-list", "--max-parents=0", "HEAD", cwd=repo).out.strip()
    assert gw.run("git", "bisect", "start", "HEAD", first, cwd=repo).rc == 0
    gw.trust(repo)            # the midpoint's hook: the prompt of the next command, as on master
    script = "test \"$(git show HEAD:g 2>/dev/null)\" != 2"     # bad from the last commit on
    r = gw.run("git", "bisect", "run", "sh", "-c", script, cwd=repo)
    assert r.rc == 0 and "✗" not in r.err, r.text
    bad = gw.git("rev-parse", "refs/bisect/bad", cwd=repo).out.strip()
    assert bad == gw.git("rev-parse", "up", cwd=repo).out.strip()


def test_second_submodule_add(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[124] `submodule add` rewrites `.gitmodules` (a tree-side reference of
    the trusted config once a submodule exists), then stages it through a
    child `git add` in the same repository: that child does not refuse."""
    add_submodule(gw, repo, tmp_path)
    gw.trust(repo)
    src = make_source(gw, tmp_path)
    r = gw.run("git", "submodule", "add", "-q", str(src), "lib2", cwd=repo)
    assert r.rc == 0 and "✗" not in r.err, r.text
    assert gw.git("diff", "--cached", "--quiet", "--", ".gitmodules", cwd=repo).rc == 1


@pytest.mark.parametrize("filt", [["--msg-filter", "sed s/c/C/"],
                                  ["--index-filter", "git rm -q --cached --ignore-unmatch g"],
                                  ["--tree-filter", "echo x >> f"]])
def test_filter_branch(gw: GW, repo: Path, filt: list[str]) -> None:
    """[115] filter-branch runs its gits with `GIT_DIR=<repo>/.git` from
    `.git-rewrite/t`: the judged gitdir with another work tree. Nothing the
    config names lives in a tree here: covered, as before [111]."""
    gw.env["FILTER_BRANCH_SQUELCH_WARNING"] = "1"
    commit(gw, repo, "g", "1")
    commit(gw, repo, "f", "2")
    gw.trust(repo)
    r = gw.run("git", "filter-branch", "-f", *filt, "--", "HEAD~2..HEAD", cwd=repo)
    assert r.rc == 0 and "✗" not in r.err, r.text
    assert "nothing pending" in gw.run("pending", cwd=repo).out


def test_worktree_add_with_tracked_hooks(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[120] A linked worktree of a branch whose tracked hooks are the
    trusted ones: the content the parent hashed, at the same place in the
    other tree. `worktree add`'s `reset --hard` there is covered."""
    write_exec(repo / ".githooks/pre-commit", "#!/bin/sh\nexit 0\n")
    gw.git("add", ".githooks", cwd=repo)
    gw.git("commit", "-qm", "hooks", cwd=repo)
    gw.git("config", "core.hooksPath", ".githooks", cwd=repo)
    gw.trust(repo)
    wt = tmp_path / "wt"
    r = gw.run("git", "worktree", "add", "-q", "-b", "x", str(wt), cwd=repo)
    assert r.rc == 0 and "✗" not in r.err, r.text
    assert (wt / ".githooks/pre-commit").is_file()


def test_submodule_with_lfsconfig(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[125] A submodule holding a `.lfsconfig`: its child gits name it in
    their tree (git-lfs reads it there), and the parent hashes it as it
    does the submodule's config. Watched at the root only, every `git
    status` of the superproject died "never trusted" in the submodule."""
    sub = add_submodule(gw, repo, tmp_path)
    (sub / ".lfsconfig").write_text("[lfs]\n\turl = https://example.invalid/lfs\n")
    gw.git("add", ".lfsconfig", cwd=sub)
    gw.git("commit", "-qm", "lfs", cwd=sub)
    gw.trust(repo)
    r = gw.run("git", "status", "--short", cwd=repo)
    assert r.rc == 0 and "✗" not in r.err, r.text
    r = gw.run("git", "-c", "protocol.file.allow=always", "submodule", "update", "--remote", cwd=repo)
    assert r.rc == 0 and "✗" not in r.err, r.text
    (sub / ".lfsconfig").write_text("[lfs \"customtransfer.x\"]\n\tpath = /tmp/x\n")
    c = gw.check(repo)
    assert c.blocked and "sub/.lfsconfig" in c.err, c.text


def test_nested_submodule_children(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[125] A submodule's submodule: `.gitmodules` and the gitfile of the
    inner one are the tree's structure, named by nobody; its children are
    covered."""
    sub = add_submodule(gw, repo, tmp_path)
    add_submodule(gw, sub, tmp_path / "i", name="inner")
    gw.git("commit", "-qam", "sub", cwd=repo)
    gw.trust(repo)
    r = gw.run("git", "status", "--short", cwd=repo)
    assert r.rc == 0 and "✗" not in r.err, r.text
    r = gw.run("git", "submodule", "foreach", "--recursive", "git status --short", cwd=repo)
    assert r.rc == 0 and "✗" not in r.err, r.text


def test_submodule_with_relative_hookspath(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[120] A submodule whose own config names hooks in its tree: the
    parent's scan resolves that config against the submodule's tree and
    hashes them ([39]); its children are covered."""
    sub = add_submodule(gw, repo, tmp_path)
    write_exec(sub / ".githooks/pre-commit", "#!/bin/sh\nexit 0\n")
    gw.git("config", "core.hooksPath", ".githooks", cwd=sub)
    gw.trust(repo)
    (sub / "s").write_text("changed\n")
    r = gw.run("git", "status", "--short", cwd=repo)
    assert r.rc == 0 and "✗" not in r.err and "sub" in r.out, r.text


def test_hookspath_system_readonly_ignored(gw: GW, repo: Path) -> None:
    gw.git("config", "core.hooksPath", "/usr/share/git-core/templates/hooks", cwd=repo)
    gw.trust(repo)
    assert not gw.check(repo).blocked


def test_hookspath_nonexistent_ignored(gw: GW, repo: Path) -> None:
    gw.git("config", "core.hooksPath", "/nonexistent/hooks", cwd=repo)
    gw.trust(repo)
    assert not gw.check(repo).blocked


def test_include_chain_unchanged(gw: GW, repo: Path) -> None:
    (repo / "level1").write_text("[include]\n\tpath = level2\n")
    (repo / "level2").write_text("[core]\n")
    gw.git("config", "include.path", "../level1", cwd=repo)
    gw.trust(repo)
    assert not gw.check(repo).blocked


def test_access_through_symlinked_path(gw: GW, repo: Path, tmp_path: Path) -> None:
    os.symlink(repo, tmp_path / "link")
    assert not gw.check(tmp_path / "link").blocked, "same key through a symlinked path"


def test_recurse_submodules_clone(gw: GW, repo: Path, tmp_path: Path) -> None:
    add_submodule(gw, repo, tmp_path)
    dst = tmp_path / "superclone"
    r = gw.run("git", "-c", "protocol.file.allow=always", "clone", "-q",
               "--recurse-submodules", str(repo), str(dst), cwd=tmp_path)
    assert r.rc == 0, r.text
    assert not gw.check(dst).blocked, "gitfiles under .git/modules → auto-trust OK"
    commit(gw, dst / "sub", "t", "t")
    assert not gw.check(dst).blocked


def test_hookspath_symlink_to_tree_script_unchanged(gw, repo, tmp_path):
    """hooksPath hook = symlink to a tree script: legitimate as long as neither
    the link nor the target changes (ordinary commits afterwards)."""
    import os
    from tests.conftest import write_exec
    write_exec(repo / "scripts/hook.sh", "#!/bin/sh\nexit 0\n")
    (repo / ".githooks").mkdir()
    os.symlink("../scripts/hook.sh", repo / ".githooks/pre-commit")
    gw.git("config", "core.hooksPath", ".githooks", cwd=repo)
    gw.trust(repo)
    (repo / "f").write_text("b\n")
    gw.git("add", "-A", cwd=repo)
    assert gw.git("commit", "-qm", "c", cwd=repo).rc == 0
    r = gw.check(repo)
    assert not r.blocked, r.text


def test_vanished_or_unreadable_object_dir_is_not_a_refusal(gw: GW, repo: Path) -> None:
    """A detached `git gc --auto` removes `objects/xx` directories during the
    walk: gitwary used to refuse ("unreadable directory"). Objects are
    volatile and not executable: the scan must not even descend there."""
    d = repo / ".git/objects/ab"
    d.mkdir(exist_ok=True)
    (d / "x").write_text("")
    d.chmod(0)                           # simulates scandir failing on this directory
    try:
        r = gw.check(repo)
        assert not r.blocked, r.text
    finally:
        d.chmod(0o755)


def test_dir_only_marker_head_file_is_not_a_gitdir(gw: GW, repo: Path) -> None:
    """[23] a directory that only contains a HEAD file is not a gitdir."""
    (repo / "docs").mkdir()
    (repo / "docs/HEAD").write_text("x\n")
    assert not gw.check(repo).blocked


def test_safe_directory_global_does_not_watch_siblings(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[25] safe.directory to the repository's parent: a directory is not an
    executed file, it must not enter the fingerprint."""
    gw.git("config", "--global", "safe.directory", str(tmp_path))
    r = gw.trust(repo)
    assert "ext:" not in r.out, r.out
    (tmp_path / "sibling").mkdir()
    (tmp_path / "sibling/new").write_text("x\n")
    assert not gw.check(repo).blocked


def test_local_remote_commits_do_not_alert(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[25] remote.origin.url = local repository: commits over there, no alert
    here. Only its config and hooks/ are watched [45], never the directory."""
    other = make_source(gw, tmp_path, "other")
    gw.git("remote", "add", "origin", str(other), cwd=repo)
    r = gw.trust(repo)
    o = other.resolve()
    refs = [l for l in r.out.splitlines() if "references outside the gitdir" in l]   # not the diff
    ext = {t[4:] for t in refs[0].split() if t.startswith("ext:")}
    assert ext == {f"{o}/.git/config", f"{o}/.git/hooks"}, r.out
    (other / "b").write_text("b\n")
    gw.git("add", "b", cwd=other)
    gw.git("commit", "-qm", "b", cwd=other)
    assert not gw.check(repo).blocked


def test_alias_with_directory_argument(gw: GW, repo: Path) -> None:
    """[25] alias = !make -C src: src/ does not enter the fingerprint."""
    (repo / "src").mkdir()
    (repo / "src/a.c").write_text("")
    gw.git("config", "alias.b", "!make -C src", cwd=repo)
    r = gw.trust(repo)
    assert "wt:" not in r.out, r.out
    (repo / "src/b.c").write_text("")
    assert not gw.check(repo).blocked


def test_submodule_gc_and_update_server_info(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[26] gc / update-server-info in a submodule: info/refs,
    objects/info/packs and commit-graph are volatile under modules/ too."""
    sub = add_submodule(gw, repo, tmp_path)
    gw.trust(repo)
    commit(gw, sub, "t", "t")
    assert gw.git("gc", "-q", cwd=sub).rc == 0
    assert gw.git("update-server-info", cwd=sub).rc == 0
    assert gw.git("commit-graph", "write", cwd=sub).rc == 0
    r = gw.check(repo)
    assert not r.blocked, r.text


def test_worktree_inside_main_tree(gw: GW, repo: Path) -> None:
    """[27] git worktree add .worktrees/wt: gitfile to .git/worktrees/, legitimate."""
    assert gw.git("worktree", "add", "-q", ".worktrees/wt", "-b", "wt", cwd=repo).rc == 0
    gw.trust(repo)
    assert not gw.check(repo).blocked
    commit(gw, repo / ".worktrees/wt", "g", "g")
    assert not gw.check(repo).blocked


def test_nested_submodule_and_slashed_name_still_anchored(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[29] roots are only recognised under modules/ and worktrees/: a submodule
    named lib/foo (modules/lib/foo) must remain a root (otherwise its
    refs/logs alert on every commit)."""
    sub = add_submodule(gw, repo, tmp_path, "lib/foo")
    gw.trust(repo)
    commit(gw, sub, "t", "t")
    assert gw.git("gc", "-q", cwd=sub).rc == 0
    r = gw.check(repo)
    assert not r.blocked, r.text


def test_push_fetch_local_remote_no_alert(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[45] a local remote's config and hooks/ are watched: an ordinary push
    and fetch to/from it must not alert."""
    bare = tmp_path / "remote.git"
    assert gw.git("init", "-q", "--bare", str(bare)).rc == 0
    gw.git("remote", "add", "origin", str(bare), cwd=repo)
    gw.trust(repo)
    for args in (["push", "-q", "origin", "HEAD:refs/heads/main"], ["fetch", "-q", "origin"],
                 ["push", "-q", "origin", "HEAD:refs/heads/other"]):
        r = gw.run("git", *args, cwd=repo)
        assert r.rc == 0, r.text
    assert not gw.check(repo).blocked, gw.check(repo).text


def test_remote_of_remote_not_followed(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[45] pushing to A does not push to A's remotes: A's own remotes are not
    pulled into the fingerprint."""
    far = tmp_path / "far.git"
    near = tmp_path / "near.git"
    gw.git("init", "-q", "--bare", str(far))
    gw.git("init", "-q", "--bare", str(near))
    gw.git("--git-dir", str(near), "remote", "add", "up", str(far))
    gw.git("remote", "add", "origin", str(near), cwd=repo)
    gw.trust(repo)
    (far / "hooks/pre-receive").write_text("#!/bin/sh\n")
    assert not gw.check(repo).blocked


def test_env_index_file_scratch_index(gw: GW, repo: Path, tmp_path: Path) -> None:
    """A script's scratch index (`GIT_INDEX_FILE=tmp git add … && git
    write-tree`, pre-commit's stash dance): read like git reads it, no
    alert when it holds no gitlink; the gitdir's index is untouched. [54]"""
    (repo / "g").write_text("g\n")
    gw.env["GIT_INDEX_FILE"] = str(tmp_path / "scratch.idx")
    assert gw.git("read-tree", "HEAD", cwd=repo).rc == 0
    assert gw.git("add", "g", cwd=repo).rc == 0
    assert gw.git("write-tree", cwd=repo).rc == 0
    assert not gw.check(repo).blocked
    assert not gw.run("git", "status", cwd=repo).blocked
    gw.env["GIT_INDEX_FILE"] = "scratch-in-tree.idx"               # relative to the root
    assert gw.git("add", "g", cwd=repo).rc == 0
    assert not gw.check(repo).blocked
    del gw.env["GIT_INDEX_FILE"]
    assert not gw.check(repo).blocked


def test_env_common_dir_own_gitdir(gw: GW, repo: Path, tmp_path: Path) -> None:
    """GIT_COMMON_DIR naming the repository's own gitdir, or the main
    repository from its linked worktree: the same files, no alert. [54]"""
    gw.env["GIT_COMMON_DIR"] = str(repo / ".git")
    assert not gw.check(repo).blocked
    assert not gw.run("git", "status", cwd=repo).blocked
    del gw.env["GIT_COMMON_DIR"]
    assert gw.git("worktree", "add", "-q", str(tmp_path / "wt"), cwd=repo).rc == 0
    gw.trust(tmp_path / "wt")                      # a linked worktree has its own key
    assert not gw.check(tmp_path / "wt").blocked
    gw.env["GIT_COMMON_DIR"] = str(repo / ".git")  # what its commondir file already says
    assert not gw.check(tmp_path / "wt").blocked
    assert not gw.run("git", "status", cwd=tmp_path / "wt").blocked


@pytest.mark.parametrize("name", [".github/workflows/ci.yml", ".gitignore", ".gitattributes",
                                  "dir/.gitkeep", "a.git/x", "x.git", "..x", "x..", "...",
                                  ".git-blame-ignore-revs", "d/.gitmodules-like", "g.it/x"])
def test_index_names_close_to_git_rules(gw: GW, repo: Path, name: str) -> None:
    """Names git accepts in an index, next to the ones [55] must refuse
    (`.git`, `.`, `..`, empty, absolute): no alert, through the wrapper too."""
    p = repo / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("x\n")
    assert gw.git("add", name, cwd=repo).rc == 0
    assert gw.git("commit", "-qm", name, cwd=repo).rc == 0
    assert not gw.check(repo).blocked
    assert not gw.run("git", "checkout", "--", ".", cwd=repo).blocked


def test_global_config_change_without_a_path_is_silent(gw: GW, repo: Path) -> None:
    """[56] The global config is parsed for the paths it names, never hashed:
    whoever can write ~/.gitconfig can write the state directory, and every
    `git config --global` / `git lfs install` turned every repository
    "modified" at once."""
    for k, v in [("user.email", "x@y"), ("alias.st", "status"),
                 ("filter.lfs.clean", "git-lfs clean -- %f"), ("filter.lfs.smudge", "git-lfs smudge -- %f"),
                 ("filter.lfs.process", "git-lfs filter-process"), ("filter.lfs.required", "true")]:
        assert gw.git("config", "--global", k, v).rc == 0
    assert not gw.check(repo).blocked
    assert not gw.run("git", "status", cwd=repo).blocked
    assert "ok" in gw.run("list").out and "modified" not in gw.run("list").out
    assert not (gw.key_for(repo).with_name(gw.key_for(repo).name + ".d") / "global").exists()


@pytest.mark.parametrize("key, extra", [
    ("user.signingKey", ("gpg.format", "ssh")),
    ("gpg.ssh.allowedSignersFile", None),
    ("commit.template", None),
    ("core.excludesFile", None),
    ("http.https://x.example.sslKey", None),
])
def test_data_key_file_rotation_is_silent(gw: GW, repo: Path, tmp_path: Path, key: str, extra) -> None:
    """[56] A file git reads as data (DATA_KEYS: a signing key, a template, an
    excludes file…) is not watched: rewriting it — a key rotation — is not a
    change of the repository, and a private key is never copied into the
    state directory."""
    f = tmp_path / "home" / "datafile"
    f.write_text("SECRET\n")
    f.chmod(0o600)
    if extra:
        assert gw.git("config", "--global", *extra).rc == 0
    assert gw.git("config", "--global", key, str(f)).rc == 0
    r = gw.trust(repo)
    assert "ext:" not in r.text, r.text
    bak = gw.key_for(repo).with_name(gw.key_for(repo).name + ".d")
    assert not any(p.name == "datafile" for p in bak.rglob("*")), "the data file was copied"
    f.write_text("ROTATED\n")
    assert not gw.check(repo).blocked
    assert not gw.run("git", "status", cwd=repo).blocked


# ------------------------------- false positives [63] [64] [65]
def test_sha256_repository_can_be_trusted(gw: GW, tmp_path: Path) -> None:
    """[63] `git init --object-format=sha256`: the index entries hold 32-byte
    object ids, the parser assumed 20 and refused the index as forged."""
    r = tmp_path / "s256"
    assert gw.git("init", "-q", "--object-format=sha256", str(r)).rc == 0
    commit(gw, r)
    gw.trust(r)
    commit(gw, r, "g", "x")
    assert not gw.check(r).blocked


@pytest.mark.skipif(not git_has("reftable"), reason="git without the reftable backend")
def test_reftable_commit_and_branch(gw: GW, tmp_path: Path) -> None:
    """[64] `git init --ref-format=reftable`: every ref update rewrites
    `reftable/tables.list` and the tables, which were fingerprinted."""
    r = tmp_path / "rt"
    assert gw.git("init", "-q", "--ref-format=reftable", str(r)).rc == 0
    commit(gw, r)
    gw.trust(r)
    commit(gw, r, "g", "x")
    gw.git("branch", "b2", cwd=r)
    assert not gw.check(r).blocked, gw.run("diff", cwd=r).text


def test_hookspath_above_the_state_directory(gw: GW, repo: Path) -> None:
    """[65] core.hooksPath = .. with the state directory under that parent
    (here `tmp_path/state`; in real life `~/.local/state/gitwary` under a
    hooksPath of `~`): the manifest that `trust` writes is itself watched, so
    the repository alerts again right after every `trust`."""
    gw.git("config", "core.hooksPath", "..", cwd=repo)
    gw.trust(repo)
    assert not gw.check(repo).blocked, gw.run("diff", cwd=repo).text


def test_hookspath_above_the_tree_ignores_tree_edits(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[65] core.hooksPath = .. with the state directory elsewhere:
    git runs only `../<hook>`, yet editing a tracked file of the repository
    alerts (the parent is walked recursively, the tree included)."""
    import tempfile
    gw.env["GITWARY_STATE"] = tempfile.mkdtemp(dir=tmp_path.parent)
    gw.git("config", "core.hooksPath", "..", cwd=repo)
    gw.trust(repo)
    commit(gw, repo)
    assert not gw.check(repo).blocked, gw.run("diff", cwd=repo).text


def test_nested_submodules_recursive(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[60] a submodule with its own submodule (`--recursive`): the inner
    gitfile points under `.git/modules/<sub>/modules/`, nothing alerts —
    after the clone, a commit in the inner one and a superproject status."""
    inner_src = make_source(gw, tmp_path, "innersrc")
    mid = make_source(gw, tmp_path, "midsrc")
    assert gw.git("submodule", "add", "-q", str(inner_src), "inner", cwd=mid).rc == 0
    assert gw.git("commit", "-qm", "inner", cwd=mid).rc == 0
    assert gw.git("submodule", "add", "-q", str(mid), "mid", cwd=repo).rc == 0
    assert gw.git("submodule", "update", "-q", "--init", "--recursive", cwd=repo).rc == 0
    assert gw.git("commit", "-qm", "mid", cwd=repo).rc == 0
    g = (repo / "mid/inner/.git").read_text()
    assert "modules/mid/modules/inner" in g, g
    gw.trust(repo)
    commit(gw, repo / "mid/inner", "t", "t")
    assert gw.run("git", "status", cwd=repo).rc == 0
    r = gw.check(repo)
    assert not r.blocked, r.text


def test_sha256_submodule_in_sha1_superproject(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[63] each gitdir has its own object format: a SHA-256 submodule's
    index is read with 32-byte ids, the superproject's with 20."""
    src = tmp_path / "s256src"
    assert gw.git("init", "-q", "--object-format=sha256", str(src)).rc == 0
    commit(gw, src)
    r = gw.git("submodule", "add", "-q", str(src), "sub", cwd=repo)
    if r.rc:
        pytest.skip(f"this git refuses mixed object formats: {r.err.strip()}")
    gw.git("commit", "-qm", "sub", cwd=repo)
    gw.trust(repo)
    assert not gw.check(repo).blocked


def test_sha256_submodule_with_a_linked_worktree(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[63] the index of a submodule's linked worktree
    (`modules/<x>/worktrees/<w>/index`) has the submodule's object format,
    found through its `commondir`, not the superproject's."""
    src = tmp_path / "s256src"
    assert gw.git("init", "-q", "--object-format=sha256", str(src)).rc == 0
    commit(gw, src)
    r = gw.git("submodule", "add", "-q", str(src), "sub", cwd=repo)
    if r.rc:
        pytest.skip(f"this git refuses mixed object formats: {r.err.strip()}")
    gw.git("commit", "-qm", "sub", cwd=repo)
    assert gw.git("worktree", "add", "-q", str(tmp_path / "subwt"), cwd=repo / "sub").rc == 0
    assert (repo / ".git/modules/sub/worktrees").is_dir()
    gw.trust(repo)
    assert not gw.check(repo).blocked, gw.check(repo).text


# ---------------------------------------- adversarial review of 2026-10-22
def test_global_program_path_that_is_a_symlink(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[75] `gpg.program = /opt/homebrew/bin/gpg` (Homebrew symlinks
    every binary), `core.editor = /usr/bin/vim` (Debian alternatives), a
    stow-managed `~/.gitconfig.local`: add() refuses any config path that is
    itself a symlink, so every repository is refused, `trust` included."""
    real = tmp_path / "opt/Cellar/gpg/bin/gpg"
    write_exec(real, "#!/bin/sh\nexit 0\n")
    link = tmp_path / "opt/bin/gpg"
    link.parent.mkdir(parents=True)
    link.symlink_to(real)
    gw.git("config", "--global", "gpg.program", str(link))
    r = gw.run("trust", cwd=repo)
    assert r.rc == 0, r.text
    assert not gw.check(repo).blocked


def test_global_program_path_that_is_a_hard_link(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[88] `gpg.program = /opt/homebrew/bin/gpg` where the binary has other
    names (Homebrew's Cellar hard-links some, on the same volume as $HOME
    on macOS), a hard-linked dotfile: the hard-link refusal covers the tree
    and the gitdir only — the sandbox can link nothing else — so a program
    named outside them is watched by its bytes, never refused."""
    real = tmp_path / "opt/Cellar/gpg/bin/gpg"
    write_exec(real, "#!/bin/sh\nexit 0\n")
    other = tmp_path / "opt/Cellar/gpg/bin/gpg2"
    os.link(real, other)
    link = tmp_path / "opt/bin/gpg"           # Homebrew's symlink to the Cellar
    link.parent.mkdir(parents=True)
    link.symlink_to(real)
    for prog in (real, link):
        gw.git("config", "--global", "gpg.program", str(prog))
        r = gw.run("trust", cwd=repo)
        assert r.rc == 0, r.text
        assert not gw.check(repo).blocked, gw.check(repo).text


def test_template_dir_under_the_prefix(gw: GW, repo: Path) -> None:
    """[128] `init.templateDir = %(prefix)/share/git-core/templates`, the
    value git documents as its default: resolved to the installed
    templates (watched if the user can write there, else nothing), never
    the literal `<root>/%(prefix)/…`; every command silent."""
    assert gw.git("config", "--global", "init.templateDir",
                  "%(prefix)/share/git-core/templates").rc == 0
    r = gw.run("trust", cwd=repo)
    assert r.rc == 0 and "%(prefix)" not in r.text, r.text
    assert not gw.run("git", "status", "--short", cwd=repo).blocked


def test_ext_hook_with_another_name_outside_the_gitdir(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[127] a hook outside the tree (`core.hooksPath = ../shared-hooks`)
    whose inode has a second name next to it (a hooks directory built by
    `ln`, or a package manager's store): git writes nothing there by name,
    the file is watched by its bytes, never refused. Only another name in
    the gitdir is."""
    hook = tmp_path / "shared-hooks/commit-msg"
    write_exec(hook, "#!/bin/sh\nexit 0\n")
    os.link(hook, tmp_path / "shared-hooks/commit-msg.orig")
    assert gw.git("config", "core.hooksPath", "../shared-hooks", cwd=repo).rc == 0
    r = gw.run("trust", cwd=repo)
    assert r.rc == 0, r.text
    assert not gw.check(repo).blocked, gw.check(repo).text
    (repo / "f").write_text("b\n")
    assert not gw.run("git", "commit", "-qam", "x", cwd=repo).blocked
    (repo / ".git/COMMIT_EDITMSG").unlink(missing_ok=True)
    os.link(hook, repo / ".git/COMMIT_EDITMSG")      # a name in the gitdir, volatile: refused
    r = gw.check(repo)
    assert r.blocked and "hard link into the gitdir" in r.err, r.text


def test_linked_worktree_of_a_submodule(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[76] `git -C sub worktree add ../subwt`: git ignores the
    common config's core.worktree in a linked worktree; open_repo applied
    it and took `.git/modules/sub` for the tree (a volatile-zone refusal,
    or an internal ValueError)."""
    add_submodule(gw, repo, tmp_path)
    wt = tmp_path / "subwt"
    assert gw.git("worktree", "add", "-q", str(wt), cwd=repo / "sub").rc == 0
    top = gw.git("rev-parse", "--show-toplevel", cwd=wt).out.strip()
    assert Path(top).resolve() == wt.resolve()
    r = gw.run("trust", cwd=wt)
    assert r.rc == 0, r.text
    assert not gw.run("git", "status", cwd=wt).blocked


def test_global_relative_hookspath_with_remote_and_submodule_is_quiet(gw: GW, repo: Path,
                                                                       tmp_path: Path) -> None:
    """[68] a global `core.hooksPath = .githooks` resolved in a local remote
    and in a submodule too: with the directories absent, or present and
    unchanged, nothing is reported."""
    from tests.attacks._helpers import add_submodule
    hub = tmp_path / "hub.git"
    gw.git("init", "-q", "--bare", str(hub))
    gw.git("remote", "add", "hub", str(hub), cwd=repo)
    sub = add_submodule(gw, repo, tmp_path)
    gw.git("config", "--global", "core.hooksPath", ".githooks")
    gw.trust(repo)
    assert not gw.check(repo).blocked
    for d in (repo, hub, sub):
        write_exec(d / ".githooks/pre-commit", "#!/bin/sh\nexit 0\n")
    gw.trust(repo)
    assert not gw.check(repo).blocked
    assert not gw.run("git", "status", cwd=repo).blocked


def test_checkout_summary_still_reports_a_submodule(gw: GW, repo: Path, subsrc: Path) -> None:
    """[66] a real submodule: the `git status --porcelain=2` git runs in it
    is gitwary, covered by the superproject's judgment (its gitdir is
    under `modules/`): the summary of local changes names the submodule
    with new commits and modified content, as the real git does."""
    assert gw.git("submodule", "add", "-q", str(subsrc), "sub", cwd=repo).rc == 0
    gw.git("commit", "-qm", "sub", cwd=repo)
    gw.trust(repo)
    gw.git("checkout", "-qb", "other", cwd=repo)
    # new commit in the submodule, and a dirty file there
    (repo / "sub/t").write_text("t\n")
    gw.git("add", "t", cwd=repo / "sub")
    gw.git("commit", "-qm", "t", cwd=repo / "sub")
    (repo / "sub/s").write_text("dirty\n")
    r = gw.run("git", "checkout", "main", cwd=repo)
    assert r.rc == 0 and "M\tsub" in r.out, r.text
    assert not gw.check(repo).blocked
    r = gw.run("git", "status", cwd=repo)
    assert r.rc == 0 and "sub (new commits, modified content)" in r.out, r.text
    r = gw.run("git", "diff", "--submodule=short", cwd=repo)
    assert "-dirty" in r.out, r.text


def test_stash_pop_in_a_repository_with_a_submodule(gw: GW, repo: Path, subsrc: Path) -> None:
    """[66] ordinary `stash` / `stash pop` with a submodule present: quiet,
    and the status printed by `pop` still lists the restored change."""
    assert gw.git("submodule", "add", "-q", str(subsrc), "sub", cwd=repo).rc == 0
    gw.git("commit", "-qm", "sub", cwd=repo)
    gw.trust(repo)
    (repo / "f").write_text("c\n")
    assert gw.run("git", "stash", "-q", cwd=repo).rc == 0
    r = gw.run("git", "stash", "pop", cwd=repo)
    assert r.rc == 0 and "modified:   f" in r.out, r.text
    assert not gw.check(repo).blocked


def test_every_command_reports_a_dirty_submodule(gw: GW, repo: Path, subsrc: Path) -> None:
    """[66] no switch any more: status, diff, commit's dry run, a shell
    alias (`!git status`, an inner git that inherits the judgment) all
    report a submodule whose own tree is dirty, and `git config --list`
    shows nothing gitwary added."""
    assert gw.git("submodule", "add", "-q", str(subsrc), "sub", cwd=repo).rc == 0
    gw.git("commit", "-qm", "sub", cwd=repo)
    gw.git("config", "--global", "alias.st", "status", cwd=repo)
    gw.git("config", "--global", "alias.s", "st", cwd=repo)
    gw.git("config", "--global", "alias.sst", "!git status", cwd=repo)
    gw.trust(repo)
    (repo / "sub/s").write_text("dirty\n")
    for args in (["status"], ["st"], ["s"]):
        r = gw.run("git", *args, cwd=repo)
        assert r.rc in (0, 1) and "modified content" in r.out, (args, r.text)
    r = gw.run("git", "commit", "--dry-run", cwd=repo)
    assert r.rc in (0, 1) and "modified content" in r.out, r.text
    r = gw.run("git", "status", "--short", cwd=repo)
    assert " m sub" in r.out, r.text
    r = gw.run("git", "diff", "--submodule=log", cwd=repo)
    assert "contains modified content" in r.out, r.text
    r = gw.run("git", "config", "--list", cwd=repo)
    assert "ignoresubmodules" not in r.out.lower(), r.text
    r = gw.run("git", "sst", cwd=repo)
    assert r.rc == 0 and "On branch" in r.out and "modified content" in r.out, r.text
    r = gw.run("git", "log", "-1", "--format=%s", cwd=repo)
    assert r.rc == 0 and r.out.strip() == "sub", r.text
    assert not gw.check(repo).blocked


def test_autocorrected_word_runs(gw: GW, repo: Path) -> None:
    """[78] `git stauts` with help.autocorrect on: git corrects it; gitwary
    has nothing to resolve — no refusal, no prompt."""
    gw.git("config", "--global", "help.autocorrect", "immediate", cwd=repo)
    r = gw.run("git", "stauts", cwd=repo)
    assert r.rc == 0 and "On branch" in r.out, r.text
    assert not gw.check(repo).blocked


def test_branch_edit_description_leaves_its_file(gw: GW, repo: Path) -> None:
    """[83] `git branch --edit-description` leaves .git/EDIT_DESCRIPTION
    behind (its template, rewritten at each edit): volatile. Setting a
    description changes `.git/config`, a trust like any config change; a
    later edit that keeps it is quiet."""
    ed = "sh -c 'echo described > \"$1\"' --"
    assert gw.git("-c", f"core.editor={ed}", "branch", "--edit-description", cwd=repo).rc == 0
    gw.trust(repo)
    (repo / ".git/EDIT_DESCRIPTION").write_text("an older template\n")
    assert gw.git("-c", "core.editor=true", "branch", "--edit-description", cwd=repo).rc == 0
    assert (repo / ".git/EDIT_DESCRIPTION").exists()
    assert not gw.check(repo).blocked, gw.check(repo).text


def test_sparse_checkout_patterns(gw: GW, repo: Path) -> None:
    """[83] `git sparse-checkout set/add` rewrite .git/info/sparse-checkout:
    volatile. Turning sparse checkout on changes `.git/config` (a trust)."""
    for d in ("a", "b", "c"):
        (repo / d).mkdir()
        (repo / d / "f").write_text(d + "\n")
    gw.git("add", "-A", cwd=repo)
    gw.git("commit", "-qm", "dirs", cwd=repo)
    assert gw.git("sparse-checkout", "set", "a", cwd=repo).rc == 0
    gw.trust(repo)
    assert gw.git("sparse-checkout", "set", "b", cwd=repo).rc == 0
    assert gw.git("sparse-checkout", "add", "c", cwd=repo).rc == 0
    assert not gw.check(repo).blocked, gw.check(repo).text
    assert gw.git("sparse-checkout", "reapply", cwd=repo).rc == 0
    assert not gw.check(repo).blocked


def test_editor_aborted_leaves_edit_buffers(gw: GW, repo: Path) -> None:
    """[100] `add -e` and `notes add` with an editor that fails (`:cq`),
    `replace --edit` with one that changes nothing, leave ADD_EDIT.patch,
    NOTES_EDITMSG and REPLACE_EDITOBJ at the gitdir root: data git never
    runs; the next command used to be refused. Found by the inventory of
    git's source (tests/inventory.py), not by a review."""
    gw.env["GIT_EDITOR"] = "false"
    (repo / "f").write_text("b\n")
    gw.git("add", "-e", cwd=repo)
    gw.git("notes", "add", "HEAD", cwd=repo)
    gw.env["GIT_EDITOR"] = "true"
    gw.git("replace", "--edit", "HEAD", cwd=repo)
    left = [n for n in ("ADD_EDIT.patch", "NOTES_EDITMSG", "REPLACE_EDITOBJ")
            if (repo / ".git" / n).exists()]
    assert left, "git left no edit buffer behind: scenario void"
    r = gw.check(repo)
    assert not r.blocked, (left, r.text)


@pytest.mark.parametrize("where", ["main", "linked"])
@pytest.mark.parametrize("end", ["--commit", "--abort"])
def test_notes_merge_stopped_on_a_conflict(gw: GW, repo: Path, tmp_path: Path,
                                           where: str, end: str) -> None:
    """[153] a `notes merge` that stops on a conflict leaves the two refs
    NOTES_MERGE_PARTIAL and NOTES_MERGE_REF and the note to resolve,
    NOTES_MERGE_WORKTREE/<oid>, at the gitdir root (a linked worktree's
    own): every command was asked about until `--commit` or `--abort`.
    The directory git leaves empty afterwards is no entry."""
    tree = repo
    if where == "linked":
        tree = tmp_path / "wt"
        assert gw.git("worktree", "add", "-q", str(tree), "-b", "wt", cwd=repo).rc == 0
    conflicting_notes(gw, repo)
    for t in {tree, repo}:
        gw.trust(t)
    r = gw.run("git", "notes", "merge", "other", cwd=tree)
    assert r.rc != 0 and "gitwary:" not in r.err, r.text
    gitdir = repo / ".git" if where == "main" else repo / ".git/worktrees/wt"
    notes = list((gitdir / "NOTES_MERGE_WORKTREE").iterdir())
    assert len(notes) == 1, "git left no note to resolve: scenario void"
    for t in (tree, repo):
        r = gw.run("git", "status", "--short", cwd=t)
        assert r.rc == 0 and not r.err, r.text
    notes[0].write_text("resolved\n")
    r = gw.run("git", "notes", "merge", end, cwd=tree)
    assert r.rc == 0, r.text
    assert not list((gitdir / "NOTES_MERGE_WORKTREE").iterdir())
    r = gw.check(repo)
    assert not r.blocked, r.text
    want = "resolved" if end == "--commit" else "ours"
    assert gw.git("notes", "show", "HEAD", cwd=repo).out.strip() == want


def test_compat_object_format_map_follows_the_objects(gw: GW, tmp_path: Path) -> None:
    """[153] `extensions.compatObjectFormat` (experimental, git ≥ 2.45): git
    keeps the two names of every loose object in objects/loose-object-idx,
    rewritten with each of them — every commit was asked about. Found by
    the inventory once it followed `repo_common_path_replace`."""
    r = tmp_path / "compat"
    assert gw.git("init", "-q", "--object-format=sha256", str(r)).rc == 0
    gw.git("config", "extensions.compatObjectFormat", "sha1", cwd=r)
    (r / "f").write_text("a\n")
    gw.git("add", "f", cwd=r)
    if gw.git("commit", "-qm", "one", cwd=r).rc or not (r / ".git/objects/loose-object-idx").is_file():
        pytest.skip("this git has no extensions.compatObjectFormat")
    gw.trust(r)
    (r / "f").write_text("b\n")
    r1 = gw.run("git", "commit", "-qam", "two", cwd=r)
    assert r1.rc == 0, r1.text
    r2 = gw.run("git", "status", "--short", cwd=r)
    assert r2.rc == 0 and not r2.err, r2.text


# ------------------------------------------------- [101] clones through index-pack
def _bundle(gw: GW, repo: Path, tmp_path: Path) -> Path:
    b = tmp_path / "r.bundle"
    assert gw.git("bundle", "create", "-q", str(b), "--all", cwd=repo).rc == 0
    return b


@pytest.mark.parametrize("form", ["file", "depth", "bare", "mirror", "bundle", "separate"])
def test_clone_through_index_pack(gw: GW, repo: Path, tmp_path: Path, form: str) -> None:
    """[101] every clone but one of a plain local path (which hard-links the
    objects) runs fetch-pack → index-pack, a child with `GIT_DIR=<new>/.git`
    and the user's cwd: it must inherit the `new` marker, whatever the
    layout (`--bare`: the gitdir is the new path itself; `--separate-git-dir`:
    the gitdir is elsewhere). Every form died "never trusted" in index-pack
    and the suite never ran one."""
    dst = tmp_path / "dst"
    src = _bundle(gw, repo, tmp_path) if form == "bundle" else f"file://{repo}"
    opts = {"file": [], "depth": ["--depth", "1"], "bare": ["--bare"], "mirror": ["--mirror"],
            "bundle": [], "separate": [f"--separate-git-dir={tmp_path / 'g'}"]}[form]
    r = gw.run("git", "clone", "-q", *opts, str(src), str(dst), cwd=tmp_path)
    assert r.rc == 0 and "never trusted" not in r.err and "✗" not in r.err, r.text
    if form in ("file", "depth", "bundle"):
        assert not gw.check(dst).blocked, "auto-trust of the clone"
    assert gw.git("log", "-1", "--oneline", cwd=dst).rc == 0


def test_clone_from_inside_a_trusted_repository(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[101] the user's cwd is a trusted repository K: the clone's index-pack
    child, with `GIT_DIR=<new>/.git` and K's root as cwd, computed the new
    gitdir's manifest under K's key and reported a false diff of K."""
    src = make_source(gw, tmp_path)
    dst = repo / "vendor"
    r = gw.run("git", "clone", "-q", f"file://{src}", str(dst), cwd=repo)
    assert r.rc == 0 and "has changed" not in r.err and "✗" not in r.err, r.text
    assert not gw.check(dst).blocked
    assert not gw.check(repo).blocked, "no gitlink yet: nothing to see (the [14] barrier is the next add)"


def test_recurse_submodules_clone_over_file_url(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[101] `clone --recurse-submodules file://…`: the superproject's
    index-pack, then one clone per submodule, each with its index-pack,
    all under the `new` marker; the auto-trust covers the result."""
    add_submodule(gw, repo, tmp_path)
    dst = tmp_path / "superclone"
    r = gw.run("git", "clone", "-q", "--recurse-submodules", f"file://{repo}", str(dst), cwd=tmp_path)
    assert r.rc == 0 and "✗" not in r.err and r.err.count("trusted:") == 1, r.text
    assert not gw.check(dst).blocked
    assert (dst / "sub/s").exists()


# ------------------------- [163] a clone covers the gitdir it creates, not its tree
@pytest.mark.parametrize("form", ["nested", "separate", "jobs", "work-tree"])
def test_clone_children_run_in_the_gitdir_it_creates(gw: GW, repo: Path, tmp_path: Path, form: str) -> None:
    """[163] the `new` marker covers the gitdir the clone creates and the
    gitdirs under its `modules/`, no longer whatever sits under the new
    path. Every child of an ordinary clone is there: a submodule's own
    submodule, under a `--separate-git-dir`, cloned shallow and in
    parallel, and with `GIT_WORK_TREE` (the gitdir is the new path
    itself, without `--bare`). One elsewhere would die "never trusted"."""
    inner, mid = make_source(gw, tmp_path, "inner"), make_source(gw, tmp_path, "mid")
    for r, src, path in ((mid, inner, "deep/inner"), (repo, mid, "libs/mid")):
        assert gw.git("submodule", "add", "-q", f"file://{src}", path, cwd=r).rc == 0
        assert gw.git("commit", "-qm", path, cwd=r).rc == 0
    dst, tree = tmp_path / "dst", tmp_path / "dst"
    opts = {"nested": [], "separate": [f"--separate-git-dir={tmp_path / 'g'}"],
            "jobs": ["-j4", "--depth", "1", "--shallow-submodules"], "work-tree": []}[form]
    if form == "work-tree":
        tree = tmp_path / "wt"
        gw.env["GIT_WORK_TREE"] = str(tree)
    r = gw.run("git", "clone", "-q", "--recurse-submodules", *opts, f"file://{repo}", str(dst), cwd=tmp_path)
    assert r.rc == 0 and "never trusted" not in r.err and "✗" not in r.err, r.text
    assert (tree / "libs/mid/deep/inner/s").exists()
    if form != "work-tree":
        assert r.err.count("trusted:") == 1 and not gw.check(dst).blocked, r.text


def test_clone_by_a_hook_into_the_tree_of_a_clone_is_trusted_on_its_own(gw: GW, repo: Path,
                                                                        tmp_path: Path) -> None:
    """[163] a hook of the user's own (a global `core.hooksPath`) clones a
    tool into the tree being checked out. That repository is no part of
    the clone in progress — its gitdir is not under the new one — and is
    trusted like any clone a child runs ([107]). The marker claimed it,
    as it did everything under the new path: no state of its own, and
    the first git run there was refused, never trusted."""
    src = make_source(gw, tmp_path)
    hooks = tmp_path / "hooks"
    write_exec(hooks / "post-checkout", "#!/bin/sh\n[ -n \"$IN_HOOK\" ] && exit 0\n"
               f"IN_HOOK=1 git clone -q file://{src} vendor/tool\n")
    gw.git("config", "--global", "core.hooksPath", str(hooks))
    dst = tmp_path / "dst"
    r = gw.run("git", "clone", "-q", f"file://{repo}", str(dst), cwd=tmp_path)
    assert r.rc == 0 and "✗" not in r.err and r.err.count("trusted:") == 2, r.text
    r = gw.run("git", "status", "--short", cwd=dst / "vendor/tool")
    assert r.rc == 0 and not r.err, r.text
    assert not gw.check(dst).blocked


# ------------------------------------- [102] coverage by the judged gitdir, not by name
def test_submodule_in_linked_worktree(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[102] a linked worktree's submodule lives in
    `<common>/worktrees/<wt>/modules/<name>`: part of the worktree's
    fingerprint (the walk descends it), so the worktree's judgment covers
    the child git that enters it. The marker covered by the name `.git`
    and by key: `.git/worktrees/wt/modules/sub` mapped to the main
    repository's key, never to the worktree's, and every `status` in the
    worktree died "never trusted" in the submodule."""
    add_submodule(gw, repo, tmp_path)
    wt = tmp_path / "wt"
    assert gw.git("worktree", "add", "-q", str(wt), "-b", "wt", cwd=repo).rc == 0
    assert gw.git("submodule", "update", "--init", "-q", cwd=wt).rc == 0
    gw.trust(wt)
    for cmd in (["status", "--short"], ["diff"], ["commit", "-qam", "x", "--allow-empty"]):
        r = gw.run("git", *cmd, cwd=wt)
        assert r.rc == 0 and "gitwary:" not in r.err, (cmd, r.text)


def test_submodule_with_separate_git_dir(gw: GW, tmp_path: Path) -> None:
    """[102] `init --separate-git-dir`: the gitdir is not named `.git`; its
    `modules/<name>` is in the fingerprint all the same. The child entering
    the submodule must inherit."""
    w, g = tmp_path / "w", tmp_path / "g"
    assert gw.git("init", "-q", f"--separate-git-dir={g}", str(w)).rc == 0
    commit(gw, w)
    add_submodule(gw, w, tmp_path)
    gw.trust(w)
    r = gw.run("git", "status", "--short", cwd=w)
    assert r.rc == 0 and "gitwary:" not in r.err, r.text


def test_dotfiles_layout_commit(gw: GW, tmp_path: Path) -> None:
    """[102] the dotfiles layout: `GIT_DIR=~/.cfg GIT_WORK_TREE=~`. Each
    commit spawns `git maintenance run --auto` with the same gitdir and
    tree: the same repository, covered."""
    home, cfg = tmp_path / "home2", tmp_path / "home2/.cfg"
    home.mkdir()
    assert gw.git("init", "-q", "--bare", str(cfg)).rc == 0
    assert gw.git(f"--git-dir={cfg}", f"--work-tree={home}", "config", "core.bare", "false").rc == 0
    (home / ".profile").write_text("x\n")
    assert gw.git(f"--git-dir={cfg}", f"--work-tree={home}", "add", ".profile").rc == 0
    gw.env.update(GIT_DIR=str(cfg), GIT_WORK_TREE=str(home))
    gw.trust(home)
    r = gw.run("git", "commit", "-qm", "p", cwd=home)
    assert r.rc == 0 and "gitwary:" not in r.err, r.text


def test_submodule_of_submodule_worked_in_directly(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[102] the user works inside a submodule that has its own submodule:
    the judged gitdir is `.git/modules/sub`, the child's
    `.git/modules/sub/modules/inner`, under it. By name, the child's owner
    was the superproject, not `sub`: refused."""
    sub = add_submodule(gw, repo, tmp_path)
    inner_src = make_source(gw, tmp_path, "innersrc")
    r = gw.git("-c", "protocol.file.allow=always", "submodule", "add", "-q", str(inner_src), "inner", cwd=sub)
    assert r.rc == 0, r.text
    assert gw.git("commit", "-qm", "inner", cwd=sub).rc == 0
    gw.trust(sub)
    r = gw.run("git", "status", "--short", cwd=sub)
    assert r.rc == 0 and "gitwary:" not in r.err, r.text


# ------------------------------------------------- PINNED_CONFIG: no false positive
def test_boolean_fsmonitor_names_no_path(gw: GW, repo: Path) -> None:
    """The fsmonitor pin puts `core.fsmonitor=false` in every child's
    GIT_CONFIG_PARAMETERS, which the child's scan reads like a `-c`: a file
    named `false` (or `1`) at the root must not become a watched path the
    parent, unpinned at its scan, does not have. A boolean core.fsmonitor
    is the daemon or nothing (lookup_fsmonitor_settings); a hook path is
    watched as before. On a config without git's own booleans (`core.bare
    = false` already watches a root file named `false`: a broader, older
    rule)."""
    for n in ("false", "1", "true", "hook"):
        (repo / n).write_text("x\n")
    (repo / ".git/config").write_text("[core]\n\trepositoryformatversion = 0\n")
    def watched(params: str) -> list[str]:
        gw.env["GIT_CONFIG_PARAMETERS"] = params
        r = gw.run("trust", cwd=repo)
        assert r.rc == 0, r.text
        lines = [l for l in r.text.splitlines() if "references outside the gitdir" in l]
        return sorted({w[3:].split("/")[-1] for l in lines for w in l.split() if w.startswith("wt:")})
    assert watched("") == []
    for v in ("false", "true", "1", "0", "yes", ""):
        assert watched(f"'core.fsmonitor'='{v}'") == [], v
    assert watched("'core.fsmonitor'='./hook'") == ["hook"]
    assert watched("'core.fsmonitor'='hook'") == ["hook"]
    assert watched("") == []                    # a transient value leaves with its command [48]
    del gw.env["GIT_CONFIG_PARAMETERS"]
    assert not gw.run("git", "status", "--short", cwd=repo).blocked     # pinned, nothing seen


# ------------------------------------------------- [129] [130] values that name no file
def _watched_at_trust(gw: GW, repo: Path) -> list[str]:
    r = gw.run("trust", cwd=repo)
    assert r.rc == 0, r.text
    return [l.strip() for l in r.text.splitlines() if "references outside the gitdir" in l]


def test_tree_file_named_like_a_boolean_or_number_value_is_silent(gw: GW, repo: Path) -> None:
    """[129] `git init` writes `core.filemode = true`, `core.bare = false`,
    `core.logAllRefUpdates = true`, `core.repositoryformatversion = 0`; a
    user sets `gc.auto = 0`, `commit.gpgSign = yes`. A tree file of one of those
    names (a binary `true`, a build output `0`) is nothing git runs from a
    value it reads as a boolean or a number (VALUE_KEYS, the inventory): not
    watched at trust, and changing it refuses nothing. A program key naming
    it stays watched (the generic rule, test_claims.py's PROGRAM_KEYS), and
    so does a boolean key holding a path (core.fsmonitor = ./hook)."""
    assert gw.git("config", "gc.auto", "0", cwd=repo).rc == 0
    assert gw.git("config", "--global", "commit.gpgSign", "yes", cwd=repo).rc == 0
    names = ("true", "false", "0", "yes")
    for n in names:
        (repo / n).write_text("ELF\n")
    assert _watched_at_trust(gw, repo) == []
    for n in names:
        (repo / n).write_text("ELF, rebuilt\n")
    r = gw.run("git", "status", "--short", cwd=repo)
    assert not r.blocked and "gitwary:" not in r.err, r.text
    (repo / "hook").write_text("x\n")
    assert gw.git("config", "core.fsmonitor", "./hook", cwd=repo).rc == 0
    assert any("wt:" in l and l.endswith("hook → watched too") for l in _watched_at_trust(gw, repo))


@pytest.mark.xfail(strict=True, reason="[129] accepted limitation (DESIGN.md, Known limitations): "
                   "a string value's token names a tree file")
def test_tree_file_named_like_a_string_value_is_silent(gw: GW, repo: Path) -> None:
    """[129] OPEN — the global config of the suite holds `init.defaultBranch
    = main` and `user.name = t`: a tree file named `main` or `t` is watched.
    git reads those keys through git_config_string, the reader of
    core.editor too, so nothing in its source proves them harmless; a
    curated list is the fix if a real case comes up (the xfail record)."""
    names = ("main", "t")
    for n in names:
        (repo / n).write_text("ELF\n")
    r = gw.run("trust", cwd=repo)
    assert r.rc == 0, r.text
    watched = [l.strip() for l in r.text.splitlines() if "references outside the gitdir" in l]
    assert watched == [], watched
    for n in names:
        (repo / n).write_text("ELF, rebuilt\n")
    r = gw.run("git", "status", "--short", cwd=repo)
    assert not r.blocked and "gitwary:" not in r.err, r.text


@pytest.mark.parametrize("scope", ["local", "global", "env"])
def test_config_token_longer_than_name_max_is_no_path(gw: GW, repo: Path, scope: str) -> None:
    """[130] a JWT in `http.<url>.extraHeader` (a token of 300+ bytes, longer
    than NAME_MAX): nothing of that length is a file, so it must not crash
    the scan (Path.exists raised ENAMETOOLONG before Python 3.14) — `trust`
    must succeed and the next command run. Local, global, and the
    environment / `-c` (every source config_refs reads)."""
    value = "Authorization: Bearer " + "A" * 300
    if scope == "env":
        gw.env["GIT_CONFIG_PARAMETERS"] = f"'http.https://example.com/.extraheader'='{value}'"
    else:
        args = ["--global"] if scope == "global" else []
        assert gw.git("config", *args, "http.https://example.com/.extraheader", value, cwd=repo).rc == 0
    r = gw.run("trust", cwd=repo)
    assert r.rc == 0 and "internal error" not in r.text, r.text
    r = gw.run("git", "status", "--short", cwd=repo)
    assert not r.blocked and "gitwary:" not in r.err, r.text


def test_tree_file_named_like_a_wildcard_boolean_value_is_silent(gw: GW, repo: Path) -> None:
    """[139] `notes.rewrite.<command> = false`: git reads every key of that
    wildcard section as a boolean (notes-utils.c, `starts_with(k,
    "notes.rewrite.")`), the inventory lists it as `notes.rewrite.`, and
    _value_key compared the full key for equality: a tree file named
    `false` was watched. Not watched, and changing it refuses nothing."""
    assert gw.git("config", "notes.rewrite.amend", "false", cwd=repo).rc == 0
    (repo / "false").write_text("ELF\n")
    assert _watched_at_trust(gw, repo) == []
    (repo / "false").write_text("ELF, rebuilt\n")
    r = gw.run("git", "status", "--short", cwd=repo)
    assert not r.blocked and "gitwary:" not in r.err, r.text


# ------------------------------- clones of clones (audit #4, 2026-11-04)
def test_working_clone_as_remote_is_silent_and_serves(gw: GW, tmp_path: Path) -> None:
    """[143] `git clone a b` where a is itself a clone: a's config holds
    `branch.main.merge = refs/heads/main`, a refname. Read against a's
    gitdir it named the loose ref file, watched as ext and rewritten by
    every commit in a; and the served children (`pack-objects`,
    `unpack-objects`, GIT_DIR=.) refused it as a volatile-zone path, so
    pull, fetch, push into a and `clone file://` of a all failed."""
    src = make_source(gw, tmp_path, "src")
    a, b, c = tmp_path / "a", tmp_path / "b", tmp_path / "c"
    assert gw.run("git", "clone", "-q", str(src), str(a), cwd=tmp_path).rc == 0
    assert gw.run("git", "clone", "-q", str(a), str(b), cwd=tmp_path).rc == 0
    assert not gw.check(b).blocked
    commit(gw, a, "x", "1")
    r = gw.check(b)
    assert not r.blocked, r.text
    r = gw.run("git", "pull", "-q", cwd=b)
    assert r.rc == 0, r.text
    commit(gw, a, "x", "2")
    r = gw.run("git", "fetch", "-q", str(a), cwd=b)
    assert r.rc == 0, r.text
    r = gw.run("git", "clone", "-q", f"file://{a}", str(c), cwd=tmp_path)
    assert r.rc == 0, r.text
    commit(gw, b, "y", "1")
    r = gw.run("git", "push", "-q", str(a), "HEAD:refs/heads/dev", cwd=b)
    assert r.rc == 0, r.text
    assert not gw.check(b).blocked and not gw.check(a).blocked


@pytest.mark.parametrize("name", ["config.lock", "config.worktree.lock", "index.lock",
                                  "HEAD.lock", "packed-refs.lock", "objects/maintenance.lock"])
def test_lock_of_a_file_git_locks_is_silent(gw: GW, repo: Path, name: str) -> None:
    """[144] the lock files git takes on the files it rewrites, met by a
    check run while another git holds them: not an added file."""
    gw.trust(repo)
    p = repo / ".git" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("")
    r = gw.check(repo)
    assert not r.blocked, r.text


# --------------------------- a network remote added by a tool ([145], 2026-11-04)
def test_remote_add_network_url_is_accepted_without_terminal(gw: GW, tmp_path: Path) -> None:
    """[145] pre-commit installs a hook repository with `init --template=`,
    `remote add origin https://…`, `fetch`: three sibling gits of a tool with
    no terminal. The fetch met the config `remote add` wrote and was
    refused. A network URL runs nothing: accepted like branch tracking."""
    d = tmp_path / "cache" / "repoA"
    assert gw.run("git", "init", "-q", "--template=", str(d), cwd=tmp_path).rc == 0
    assert gw.run("git", "remote", "add", "origin", "https://example.invalid/hooks.git", cwd=d).rc == 0
    r = gw.run("git", "fetch", "-q", "origin", "--depth=1", "v1", cwd=d)
    assert "has changed" not in r.err and "remote origin" in r.err, r.text   # git fails on the network only
    assert not gw.check(d).blocked
    # GitHub's first-push sequence in a repository of the user's own.
    repo = tmp_path / "proj"
    assert gw.run("git", "init", "-q", str(repo), cwd=tmp_path).rc == 0
    commit(gw, repo, "a", "1")
    assert gw.run("git", "remote", "add", "origin", "git@github.com:user/proj.git", cwd=repo).rc == 0
    r = gw.run("git", "status", cwd=repo)
    assert r.rc == 0 and "remote origin" in r.err and "has changed" not in r.err, r.text
    assert not gw.check(repo).blocked


def test_remote_add_local_path_still_prompts(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[145] the counterpart: a local remote enters the watch ([45] [61]),
    so its addition is shown, not accepted."""
    hub = make_source(gw, tmp_path, "hub")
    gw.trust(repo)
    assert gw.run("git", "remote", "add", "hub", str(hub), cwd=repo).rc == 0
    r = gw.run("git", "status", cwd=repo)
    assert r.rc == 1 and "has changed" in r.err, r.text


# ---------------- a recursive switch that fails half-way ([146], 2026-11-04)
def test_failed_recursive_switch_can_be_repaired(gw: GW, tmp_path: Path) -> None:
    """[146] `checkout --recurse-submodules` to a branch that adds a submodule
    never initialised fails in git itself and leaves `libs/c/.git` pointing
    at a `modules/libs/c` holding only `config`. That was refused as a
    structure: `status`, `log`, `trust`, `restore`, everything, with a
    message naming no way out. It is an added file, shown and judged; the
    repository stays usable while the user repairs it git's way."""
    P = tmp_path
    G = lambda *a, cwd=P: gw.git("-c", "protocol.file.allow=always", *a, cwd=cwd)
    c = make_source(gw, P, "c")
    assert G("init", "-q", "--bare", str(P / "c.git")).rc == 0
    assert G("push", "-q", str(P / "c.git"), "HEAD:refs/heads/main", cwd=c).rc == 0
    up = make_source(gw, P, "up")
    assert G("init", "-q", "--bare", str(P / "super.git")).rc == 0
    assert G("remote", "add", "origin", str(P / "super.git"), cwd=up).rc == 0
    assert G("push", "-q", "origin", "HEAD:refs/heads/main", cwd=up).rc == 0
    assert G("checkout", "-qb", "feat", cwd=up).rc == 0
    assert G("submodule", "add", "-q", "../c.git", "libs/c", cwd=up).rc == 0
    assert G("commit", "-qm", "add c", cwd=up).rc == 0
    assert G("push", "-q", "origin", "feat", cwd=up).rc == 0
    w = P / "work"
    r = gw.run("git", "-c", "protocol.file.allow=always", "clone", "-q", "--recurse-submodules",
               f"file://{P}/super.git", str(w), cwd=P)
    assert r.rc == 0, r.text
    r = gw.run("git", "-c", "protocol.file.allow=always", "checkout", "--recurse-submodules", "feat", cwd=w)
    embryo = w / ".git/modules/libs/c"
    assert r.rc != 0 and (w / "libs/c/.git").is_file() and (embryo / "config").is_file() \
        and not (embryo / "HEAD").exists(), ("scenario void: git did not fail as expected", r.text)
    r = gw.run("git", "status", "--short", cwd=w)
    assert "points to no gitdir" not in r.err, r.text           # judged, not refused as structure
    assert "added     modules/libs/c/config" in r.err, r.text   # the embryo shown, file by file
    gw.trust(w)
    r = gw.run("git", "log", "--oneline", "-1", cwd=w)
    assert r.rc == 0, r.text                                     # the repository is usable meanwhile
    # git's own way out (the raw git needs it too: `submodule update` dies
    # on the embryo, "could not get a repository handle"): remove the
    # half-written `.gitmodules`, switch again, remove the embryo, then
    # initialise. Each step through gitwary, trusted as the user would.
    gw.trust(w)
    (w / ".gitmodules").unlink()
    gw.trust(w)                                                  # a watched file removed: one prompt
    r = gw.run("git", "checkout", "-q", "feat", cwd=w)
    assert r.rc == 0, r.text
    import shutil
    shutil.rmtree(embryo)
    (w / "libs/c/.git").unlink()
    gw.trust(w)
    r = gw.run("git", "-c", "protocol.file.allow=always", "submodule", "update", "--init", cwd=w)
    assert r.rc == 0, r.text
    assert (embryo / "HEAD").exists()
    r = gw.run("git", "status", "--short", cwd=w)
    assert "points to no gitdir" not in r.text, r.text


# ------------------------------------- a stopped `rebase -x` ([147], 2026-11-04)
def _stopped_rebase_x(gw: GW, wt: Path, proof: Path) -> None:
    for i in range(3):
        commit(gw, wt, "r", str(i))
    r = gw.git("rebase", "-x", f"touch {proof}; false", "HEAD~2", cwd=wt)
    assert r.rc != 0 and proof.exists(), ("the exec did not stop the rebase", r.text)
    proof.unlink()


def test_stopped_rebase_exec_leaves_ordinary_commands_alone(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[147] `rebase -x 'make test'` that stops on a failing test (its normal
    outcome) refused every command — `status`, `log`, `rebase --abort` —
    and every linked worktree's. Only `--continue` / `--skip` run the line:
    they alone are refused, the line shown, the documented way through
    honoured."""
    proof = tmp_path / "RAN"
    other = tmp_path / "wt2"
    assert gw.git("worktree", "add", "-q", "-b", "other", str(other), cwd=repo).rc == 0
    gw.trust(repo)
    gw.trust(other)
    _stopped_rebase_x(gw, repo, proof)
    for cmd in (["status"], ["log", "--oneline", "-1"], ["diff", "--stat"], ["rebase", "--show-current-patch"]):
        r = gw.run("git", *cmd, cwd=repo)
        # `--show-current-patch` exits 1 after an `exec` stop (no patch): git's.
        assert "gitwary" not in r.err and (r.rc == 0 or cmd[0] == "rebase"), (cmd, r.text)
    r = gw.run("git", "status", cwd=other)
    assert r.rc == 0 and "gitwary" not in r.err, r.text           # another worktree: untouched
    r = gw.run("git", "rebase", "--continue", cwd=repo)
    assert r.rc != 0 and "exec touch" in r.err and not proof.exists(), r.text
    r = gw.run("git", "rebase", "--abort", cwd=repo)
    assert r.rc == 0, r.text
    assert not gw.check(repo).blocked


def test_stopped_rebase_exec_continues_with_the_variable(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[147] the way through named by the refusal: the user's own `-x`."""
    proof = tmp_path / "RAN"
    gw.trust(repo)
    _stopped_rebase_x(gw, repo, proof)
    env = {**gw.env, "GITWARY_ALLOW_REBASE_EXEC": "1"}
    import subprocess
    from tests.conftest import GITWARY
    r = subprocess.run([sys.executable, str(GITWARY), "git", "rebase", "--continue"], cwd=repo,
                       env=env, capture_output=True, text=True)
    assert proof.exists(), r.stderr                                # git ran the user's line


# ------------------------------------------ the way out of a split index ([148])
def test_split_index_way_out_through_gitwary(gw: GW, repo: Path) -> None:
    """[148] `core.splitIndex = true` trusted, then the first `status` writes a
    split index and every command is refused ([31]). The refusal named
    `update-index --no-split-index`, which it refused itself, and the
    orphan `sharedindex.*` git leaves behind kept the repository refused
    for ever. Now: a warning at trust, the two commands of the way out go
    through, the orphan is volatile."""
    assert gw.git("config", "core.splitIndex", "true", cwd=repo).rc == 0
    r = gw.trust(repo)
    assert "core.splitIndex = true" in r.err, r.text
    assert gw.run("git", "status", cwd=repo).rc == 0          # writes the split index
    r = gw.run("git", "status", cwd=repo)
    assert r.blocked and "update-index --no-split-index" in r.err, r.text
    r = gw.run("git", "update-index", "--no-split-index", cwd=repo)
    assert r.rc == 0, r.text
    r = gw.run("git", "config", "--unset", "core.splitIndex", cwd=repo)
    assert r.rc == 0, r.text
    assert list((repo / ".git").glob("sharedindex.*")), "git removed the orphan: scenario void"
    gw.trust(repo)                                             # the config changed: the user's own
    r = gw.run("git", "status", cwd=repo)
    assert r.rc == 0 and "gitwary" not in r.err, r.text
    assert not gw.check(repo).blocked


def test_insteadof_between_network_urls_is_silent(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[151] the everyday `insteadOf` rules, one network URL for another
    (`https://github.com/` → ssh, a `gh:` shorthand): nothing local to
    watch, no alert, and `remote add` keeps its auto-accept ([145])."""
    gw.git("config", "--global", "url.git@github.com:.insteadOf", "https://github.com/")
    gw.git("config", "--global", "url.ssh://git@github.com/.pushInsteadOf", "gh:")
    gw.git("remote", "add", "origin", "https://github.com/x/y.git", cwd=repo)
    gw.git("remote", "add", "short", "gh:x/y", cwd=repo)
    r = gw.trust(repo)
    assert "watched too" not in r.text, r.text
    assert not gw.check(repo).blocked
    assert gw.git("remote", "add", "up", "https://github.com/x/z.git", cwd=repo).rc == 0
    r = gw.run("git", "status", "--short", cwd=repo)
    assert r.rc == 0 and "reference updated" in r.err, r.text


def test_mirror_behind_insteadof_is_watched_and_usable(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[151] a local mirror behind `insteadOf`, trusted: push and fetch
    work, and the mirror's own commits do not alert (its config and hooks
    are watched, not its objects)."""
    hub = tmp_path / "mirrors/hub.git"
    gw.git("init", "-q", "--bare", str(hub))
    gw.git("config", "--global", f"url.{tmp_path}/mirrors/.insteadOf", "https://example.invalid/")
    gw.git("remote", "add", "origin", "https://example.invalid/hub.git", cwd=repo)
    r = gw.trust(repo)
    assert str(hub / "config") in r.text, r.text
    for cmd in (["push", "-q", "origin", "main"], ["fetch", "-q", "origin"], ["status", "--short"]):
        r = gw.run("git", *cmd, cwd=repo)
        assert r.rc == 0, (cmd, r.text)


def test_multi_line_alias_indented_with_tabs_is_silent(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[152] the everyday shape of a tab between two words: the
    continuation lines of an alias, indented with tabs, in the global and
    in the local config. Two readings, the same words: no alert, the alias
    runs, `push -u` keeps its auto-accept, and its script is watched."""
    write_exec(repo / "tools/run", "#!/bin/sh\necho RUN \"$@\"\n")
    alias = b"[alias]\n\tlg = log \\\n\t\t--oneline \\\n\t\t-1\n\tzz = !./tools/run \\\n\t\t--flag\n"
    for cfg in (Path(gw.env["HOME"]) / ".gitconfig", repo / ".git/config"):
        cfg.write_bytes(cfg.read_bytes() + alias)
    gw.trust(repo)
    assert not gw.check(repo).blocked
    r = gw.run("git", "zz", cwd=repo)
    assert r.rc == 0 and "RUN --flag" in r.out, r.text
    assert gw.run("git", "lg", cwd=repo).rc == 0
    hub = tmp_path / "hub.git"
    gw.git("init", "-q", "--bare", str(hub))
    gw.git("remote", "add", "origin", str(hub), cwd=repo)
    gw.trust(repo)
    r = gw.run("git", "push", "-q", "-u", "origin", "main", cwd=repo)
    assert r.rc == 0, r.text
    r = gw.run("git", "status", "--short", cwd=repo)
    assert r.rc == 0 and "reference updated" in r.err, r.text
    write_exec(repo / "tools/run")
    assert gw.check(repo).blocked


# ------------------------------- [154] a tree trusted with the repository that holds its gitdir
def _inherits(gw: GW, tree: Path, holder: Path) -> None:
    """The first git run from `tree` is let through and says whose trust
    it took; from then on the tree has its own reference and is silent."""
    r = gw.run("git", "status", "--short", cwd=tree)
    assert r.rc == 0 and f"trusted with {holder}" in r.err, r.text
    assert gw.key_for(tree).is_file()
    r = gw.run("git", "status", "--short", cwd=tree)
    assert r.rc == 0 and "gitwary:" not in r.err, r.text


@pytest.mark.parametrize("how", ["clone", "trust"])
def test_submodule_is_trusted_with_its_superproject(gw: GW, repo: Path, tmp_path: Path, how: str) -> None:
    """[154] Every file a submodule's own check watches is in the
    fingerprint of its superproject: `clone --recurse-submodules`
    auto-trusted them, a `trust` of the superproject showed them. A git
    run from the submodule died "never trusted" all the same, until a
    `gitwary trust` in each. Then the submodule is judged under its own
    reference, as before."""
    add_submodule(gw, repo, tmp_path)
    top = repo
    if how == "clone":
        top = tmp_path / "cl"
        r = gw.run("git", "clone", "-q", "--recurse-submodules", str(repo), str(top), cwd=tmp_path)
        assert r.rc == 0 and f"new repository trusted: {top}" in r.err, r.text
    else:
        gw.trust(repo)
    _inherits(gw, top / "sub", top)
    assert gw.run("git", "commit", "-q", "--allow-empty", "-m", "in sub", cwd=top / "sub").rc == 0
    gw.git("config", "core.pager", "cat", cwd=top / "sub")
    r = gw.check(top / "sub")
    assert r.blocked and "has changed" in r.err and "pager" in r.err, r.text


def test_submodule_with_its_own_hooks_is_trusted_with_its_superproject(gw: GW, repo: Path,
                                                                     tmp_path: Path) -> None:
    """[154] what the submodule's config names in its tree — a hooks
    directory, a `.lfsconfig` — and what a global relative `core.hooksPath`
    names there are hashed by the superproject ([39] [68] [125]): covered."""
    sub = add_submodule(gw, repo, tmp_path)
    gw.git("config", "core.hooksPath", ".hk", cwd=sub)
    write_exec(sub / ".hk/pre-push", "#!/bin/sh\nexit 0\n")
    (sub / ".lfsconfig").write_text("[lfs]\n\turl = https://example.invalid/lfs\n")
    gw.git("config", "--global", "core.hooksPath", ".githooks")
    for tree in (repo, sub):
        write_exec(tree / ".githooks/pre-commit", "#!/bin/sh\nexit 0\n")
    gw.trust(repo)
    _inherits(gw, sub, repo)


def test_nested_submodule_is_trusted_with_the_superproject(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[154] a submodule's submodule: its gitdir is under the superproject's
    too. The tree's own structure (`.gitmodules`, the gitfiles) is named by
    nobody ([125]) and is not asked of the superproject."""
    sub = add_submodule(gw, repo, tmp_path)
    inner = add_submodule(gw, sub, tmp_path / "i", name="inner")
    gw.git("commit", "-qam", "sub", cwd=repo)
    gw.trust(repo)
    _inherits(gw, inner, repo)
    _inherits(gw, sub, repo)


def test_linked_worktree_is_trusted_with_the_main_tree(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[154] a linked worktree reads the main repository's config and
    hooks: once the main tree's reference holds its `worktrees/<id>` (the
    question `worktree add` raises, answered), a git run from the worktree
    has nothing left to show. Hooks the config names in the tree are the
    worktree's own copy: covered when they are the bytes trusted at the
    same place in the main tree, with the same mode — both as git checks
    them out (0775 under the umask 002 of a Debian 13 or Ubuntu account,
    where a hook left at 0755 in the main tree is another file)."""
    gw.git("config", "core.hooksPath", ".githooks", cwd=repo)
    write_exec(repo / ".githooks/pre-commit", "#!/bin/sh\nexit 0\n")
    gw.git("add", "-A", cwd=repo)
    gw.git("commit", "-qm", "hooks", cwd=repo)
    (repo / ".githooks/pre-commit").unlink()
    assert gw.git("checkout", "--", ".githooks", cwd=repo).rc == 0
    wt = tmp_path / "wt"
    assert gw.git("worktree", "add", "-q", str(wt), cwd=repo).rc == 0
    gw.trust(repo)
    _inherits(gw, wt, repo)
    assert gw.run("git", "commit", "-q", "--allow-empty", "-m", "in wt", cwd=wt).rc == 0
    assert not gw.check(repo).blocked


# --------------------------------- [155] the pointers a `git worktree` command writes
def _silent(gw: GW, repo: Path, *cmd: str) -> None:
    """The `git worktree` command runs, says it updated the reference, and
    the next command has nothing to ask."""
    r = gw.run("git", *cmd, cwd=repo)
    assert r.rc == 0 and "reference updated" in r.err and "✗" not in r.err, r.text
    c = gw.check(repo)
    assert not c.blocked, c.text


@pytest.mark.parametrize("where", ["outside", "inside"])
def test_worktree_commands_through_gitwary_ask_nothing(gw: GW, repo: Path, tmp_path: Path,
                                                        where: str) -> None:
    """[155] `worktree add` writes `worktrees/<id>/commondir` and `gitdir`,
    `move` rewrites the second, `remove` and `prune` delete both: every one
    was asked about at the next command, and the new tree was "never
    trusted". Run through gitwary on a repository in its trusted state,
    the command's own pointers are accepted, and the tree takes the main
    tree's trust ([154]). Outside the tree, or inside it (`.claude/
    worktrees/x`, where agents put theirs)."""
    base = tmp_path if where == "outside" else repo / ".claude/worktrees"
    wt, wt2 = base / "x", base / "y"
    _silent(gw, repo, "worktree", "add", "-q", str(wt))
    r = gw.run("git", "status", "--short", cwd=wt)
    assert r.rc == 0 and f"trusted with {repo}" in r.err, r.text
    _silent(gw, repo, "worktree", "add", "-q", "-b", "other", str(base / "z"))
    _silent(gw, repo, "worktree", "move", str(wt), str(wt2))
    r = gw.run("git", "status", "--short", cwd=wt2)
    assert r.rc == 0 and f"trusted with {repo}" in r.err, r.text
    _silent(gw, repo, "worktree", "remove", str(wt2))
    import shutil
    shutil.rmtree(base / "z")
    _silent(gw, repo, "worktree", "prune")
    assert not (repo / ".git/worktrees").exists()


def test_worktree_add_with_a_tracking_branch_asks_nothing(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[155] `worktree add -b feat <path> origin/main` also writes the
    branch's tracking into `config`, the auto-accepted change of `checkout
    -b`: one command, both accepted."""
    hub = tmp_path / "hub.git"
    gw.git("init", "-q", "--bare", str(hub))
    gw.git("remote", "add", "origin", str(hub), cwd=repo)
    gw.git("push", "-q", "origin", "main", cwd=repo)
    gw.trust(repo)
    wt = tmp_path / "wt"
    _silent(gw, repo, "worktree", "add", "-q", "-b", "feat", str(wt), "origin/main")
    assert "feat" in gw.git("config", "--get-regexp", r"^branch\.", cwd=repo).out


# ----------------- [164] a child git takes what the closed list takes (2026-11-24)
def test_hook_child_accepts_the_network_remote_its_sibling_added(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[164] pre-commit's first use of a hook repository happens inside the
    first `git commit`: `init --template=`, `remote add origin https://…`,
    `fetch`, three gits run by the commit's hook. Children of a judged git,
    they took none of the accepted changes ([145] was reached from a shell
    only): the fetch was refused on the remote its sibling had just added,
    the hook failed, pre-commit deleted its cache and the next commit
    failed the same way. The closed list holds for a child too."""
    cache, log = tmp_path / "cache/repoA", tmp_path / "fetch.err"
    write_exec(repo / ".git/hooks/pre-commit", f"""#!/bin/sh
unset GIT_DIR GIT_INDEX_FILE GIT_WORK_TREE GIT_PREFIX
git init -q --template= '{cache}' || exit 11
cd '{cache}' || exit 12
git remote add origin https://example.invalid/hooks.git || exit 13
git fetch -q origin --depth=1 v1 2>'{log}'
exit 0
""")
    gw.trust(repo)
    (repo / "f").write_text("b\n")
    r = gw.run("git", "commit", "-qam", "second", cwd=repo)
    assert r.rc == 0, r.text
    err = log.read_text()
    assert "has changed" not in err and "remote origin" in err, err     # git fails on the network only
    assert not gw.check(cache).blocked
    assert gw.git("rev-list", "--count", "HEAD", cwd=repo).out.strip() == "2"


# ------------- [165] a tree follows what its holder's reference took (2026-11-24)
def test_a_worktree_follows_the_worktree_commands_of_the_main_tree(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[165] a linked worktree that took the main tree's trust ([154]) has
    a reference of its own, which holds the whole common dir — the other
    worktrees' pointers too. `worktree add`, `move`, `remove` asked nothing
    in the main tree ([155]) and were a "has changed" in every other
    worktree in use: a refusal for the agent that works there with no
    terminal, and a `gitwary restore` typed there deleted the pointers of
    the worktree just created. The rule of the first use holds at every
    use: the main tree in its trusted state holds every file the worktree
    watches."""
    a, b, c = (tmp_path / n for n in "abc")
    _silent(gw, repo, "worktree", "add", "-q", str(a))
    _inherits(gw, a, repo)
    for cmd in (["add", "-q", str(b)], ["move", str(b), str(c)], ["remove", str(c)]):
        _silent(gw, repo, "worktree", *cmd)
        _inherits(gw, a, repo)
        r = gw.run("restore", "-y", cwd=a)
        assert r.rc == 0 and "nothing to restore" in r.text, r.text
        assert not gw.check(repo).blocked


def test_hooks_generated_in_a_worktree_after_its_first_command(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[165] husky: `npm install` in a fresh worktree runs `git config
    core.hooksPath .husky/_` first — the worktree's first use, it takes
    the main tree's trust with an empty hooks directory — then writes the
    hooks there, the bytes and modes trusted at the same place in the
    main tree. They were refused as added files."""
    def husky(tree: Path) -> None:
        assert gw.run("git", "config", "core.hooksPath", ".husky/_", cwd=tree).rc == 0
        for name in ("pre-commit", "h"):
            write_exec(tree / ".husky/_" / name, "#!/bin/sh\nexit 0\n")
    husky(repo)
    gw.trust(repo)
    wt = tmp_path / "wt"
    _silent(gw, repo, "worktree", "add", "-q", str(wt))
    husky(wt)
    r = gw.run("git", "commit", "-q", "--allow-empty", "-m", "in wt", cwd=wt)
    assert r.rc == 0 and f"trusted with {repo}" in r.err, r.text
    r = gw.run("git", "status", "--short", cwd=wt)
    assert r.rc == 0 and "gitwary:" not in r.err, r.text


def test_a_submodule_follows_what_the_superproject_was_trusted_with(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[165] a change of the submodule's config the user reviewed in the
    superproject (its diff is shown there, [168]) was asked a second time
    by the submodule's own reference."""
    sub = add_submodule(gw, repo, tmp_path)
    gw.trust(repo)
    _inherits(gw, sub, repo)
    gw.git("config", "core.pager", "cat", cwd=sub)
    assert gw.check(sub).blocked and gw.check(repo).blocked
    gw.trust(repo)
    _inherits(gw, sub, repo)


# -------- [166] branch tracking written in a submodule, seen from the superproject (2026-11-24)
@pytest.mark.parametrize("first", ["submodule", "superproject"])
def test_branch_tracking_in_a_submodule_asks_nothing_in_the_superproject(gw: GW, repo: Path, tmp_path: Path,
                                                                         first: str) -> None:
    """[166] `checkout -b feat origin/main` in a submodule writes the
    branch's tracking in `modules/<x>/config`: accepted from the submodule
    (its `config`), asked from the superproject, where the same bytes are
    a nested file — a refusal with no terminal, for every branch created
    in a submodule. The closed list is the same list whichever of the two
    reads the file first."""
    sub = add_submodule(gw, repo, tmp_path)
    gw.trust(repo)
    _inherits(gw, sub, repo)
    assert gw.run("git", "checkout", "-q", "-b", "feat", "origin/main", cwd=sub).rc == 0
    assert "feat" in gw.git("config", "--get-regexp", r"^branch\.", cwd=sub).out
    order = [sub, repo] if first == "submodule" else [repo, sub]
    r = gw.run("git", "status", "--short", cwd=order[0])
    assert r.rc == 0 and "branch tracking for feat" in r.err and "has changed" not in r.err, r.text
    if first == "superproject":
        assert "modules/sub" in r.err, r.text                # which config it was
    r = gw.run("git", "status", "--short", cwd=order[1])
    assert r.rc == 0 and "has changed" not in r.err and "✗" not in r.err, r.text
    assert not gw.check(repo).blocked and not gw.check(sub).blocked


def test_branch_tracking_in_both_configs_is_one_acceptance(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[166] a branch created in the superproject and one in the submodule
    before the next command of the superproject: two configs, each moved
    by tracking alone."""
    sub = add_submodule(gw, repo, tmp_path)
    hub = tmp_path / "hub.git"
    gw.git("init", "-q", "--bare", str(hub))
    gw.git("remote", "add", "origin", str(hub), cwd=repo)
    gw.git("push", "-q", "origin", "main", cwd=repo)
    gw.trust(repo)
    assert gw.git("checkout", "-q", "-b", "one", "origin/main", cwd=repo).rc == 0
    assert gw.git("checkout", "-q", "-b", "two", "origin/main", cwd=sub).rc == 0
    r = gw.run("git", "status", "--short", cwd=repo)
    assert r.rc == 0 and "one" in r.err and "two" in r.err and "has changed" not in r.err, r.text
    assert not gw.check(repo).blocked


# ------------------- a repository git borrows objects from ([156], 2026-11-13)
def _objects(repo: Path) -> int:
    """Object files the repository holds itself: loose objects and packs."""
    od = repo / "objects" if (repo / "objects").is_dir() else repo / ".git/objects"
    return sum(1 for p in od.rglob("*") if p.is_file() and "info" not in p.relative_to(od).parts)


def _traced(gw: GW, *args: str, cwd: Path) -> str:
    """The command through gitwary with git's trace on: no refusal, no
    false change, and the trace, which says where git ran a child."""
    gw.env["GIT_TRACE"] = "1"
    r = gw.run("git", *args, cwd=cwd)
    del gw.env["GIT_TRACE"]
    assert r.rc == 0 and "✗" not in r.err and "has changed" not in r.err, r.text
    return r.err


def _enters(trace: str, gitdir: Path) -> bool:
    return f"--git-dir={gitdir.resolve()} for-each-ref" in trace


def _upstream(gw: GW, tmp_path: Path) -> Path:
    src = make_source(gw, tmp_path, "upstream")
    for i in range(3):
        commit(gw, src, f"u{i}", str(i))
    return src


@pytest.mark.parametrize("form", ["bare", "worktree", "shared", "chain", "dissociate"])
def test_clone_reference_borrows_and_stays_silent(gw: GW, tmp_path: Path, form: str) -> None:
    """[156] `clone --reference <mirror>`: git asks the mirror what it holds
    through a child, `git --git-dir=<mirror> for-each-ref`, during the
    clone and at every later fetch. Refused, the clone downloaded what the
    mirror already had and every fetch printed a false "has changed" with
    the mirror's config. A bare mirror, a working clone, the source itself
    (`--shared`), a mirror that borrows from another, `--dissociate`."""
    src = _upstream(gw, tmp_path)
    mirror, dst = tmp_path / "mirror.git", tmp_path / "dst"
    if form == "worktree":
        mirror = tmp_path / "mirror"
        assert gw.git("clone", "-q", str(src), str(mirror)).rc == 0
    elif form == "chain":
        first = tmp_path / "first.git"
        assert gw.git("clone", "-q", "--mirror", str(src), str(first)).rc == 0
        assert gw.git("clone", "-q", "--mirror", "--reference", str(first), str(src), str(mirror)).rc == 0
        assert (mirror / "objects/info/alternates").is_file()
    elif form != "shared":
        assert gw.git("clone", "-q", "--mirror", str(src), str(mirror)).rc == 0
    opts = ["--shared"] if form == "shared" else ["--reference", str(mirror)]
    if form == "dissociate":
        opts.append("--dissociate")
    url = str(src) if form == "shared" else f"file://{src}"
    # `--shared`: the source is the alternate, everything it has is already
    # there and git negotiates nothing — no child to enter it.
    borrowed = {"bare": [mirror], "worktree": [mirror / ".git"], "shared": [],
                "chain": [mirror, tmp_path / "first.git"], "dissociate": [mirror]}[form]

    trace = _traced(gw, "clone", "-q", *opts, url, str(dst), cwd=tmp_path)
    for g in borrowed:
        assert _enters(trace, g), f"the clone no longer enters {g}\n{trace}"
    if form != "dissociate":
        assert _objects(dst) == 0, "the clone copied what it borrows"
    assert not gw.check(dst).blocked, "auto-trust of the clone"
    # A fetch that negotiates (the mirror is behind): git enters it again.
    commit(gw, src, "ahead", "1")
    trace = _traced(gw, "fetch", "-q", cwd=dst)
    assert "gitwary:" not in trace, trace
    for g in borrowed if form in ("bare", "worktree", "chain") else []:
        assert _enters(trace, g), f"the fetch no longer enters {g}\n{trace}"
    # One whose objects the mirror already holds: nothing is copied.
    commit(gw, src, "later", "1")
    if form == "worktree":
        assert gw.git("pull", "-q", cwd=mirror).rc == 0
    elif form in ("bare", "chain"):
        assert gw.git("fetch", "-q", cwd=mirror).rc == 0
    before = _objects(dst)
    r = gw.run("git", "fetch", "-q", cwd=dst)
    assert r.rc == 0 and not r.err, r.text
    if form in ("bare", "worktree", "chain", "shared"):
        assert _objects(dst) == before, "the fetch copied what the mirror holds"
    r = gw.run("git", "status", "--short", cwd=dst)
    assert r.rc == 0 and not r.err, r.text


def test_reference_added_to_a_trusted_repository(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[156] an alternate written by hand into a trusted repository (`echo
    <mirror>/objects >> .git/objects/info/alternates`): one question, the
    file is hashed, then silence — the mirror's config is in the reference
    and the child git runs there is covered."""
    src = _upstream(gw, tmp_path)
    mirror = tmp_path / "mirror.git"
    assert gw.git("clone", "-q", "--mirror", str(src), str(mirror)).rc == 0
    commit(gw, src, "ahead", "1")
    gw.git("remote", "add", "origin", f"file://{src}", cwd=repo)
    gw.trust(repo)
    (repo / ".git/objects/info/alternates").write_text(f"{mirror}/objects\n")
    r = gw.check(repo)
    assert r.blocked and "objects/info/alternates" in r.err, r.text
    gw.trust(repo)
    trace = _traced(gw, "fetch", "-q", "origin", cwd=repo)
    assert _enters(trace, mirror) and "gitwary:" not in trace, trace
    assert not gw.check(repo).blocked


def test_submodule_updated_with_a_reference(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[156] `submodule update --init --reference <mirror>`: the submodule's
    clone borrows from the mirror — a clone run by a child git, under its
    own marker — and so does every later fetch of the submodule, from the
    superproject or from its own tree."""
    src = make_source(gw, tmp_path)
    for i in range(3):
        commit(gw, src, f"s{i}", str(i))
    mirror = tmp_path / "submirror.git"
    assert gw.git("clone", "-q", "--mirror", str(src), str(mirror)).rc == 0
    add_submodule(gw, repo, tmp_path)
    # A URL, as for a submodule fetched over the network: git negotiates
    # (a plain path is copied, and nothing is asked of the mirror).
    assert gw.git("config", "-f", ".gitmodules", "submodule.sub.url", f"file://{src}", cwd=repo).rc == 0
    assert gw.git("commit", "-qam", "url", cwd=repo).rc == 0
    clone = tmp_path / "clone"
    assert gw.run("git", "clone", "-q", f"file://{repo}", str(clone), cwd=tmp_path).rc == 0
    allow = ["-c", "protocol.file.allow=always"]
    trace = _traced(gw, *allow, "submodule", "update", "-q", "--init", "--reference", str(mirror), cwd=clone)
    assert _enters(trace, mirror), f"the submodule's clone no longer enters the mirror\n{trace}"
    assert (clone / ".git/modules/sub/objects/info/alternates").is_file()
    assert _objects(clone / ".git/modules/sub") == 0, "the submodule's clone copied what it borrows"
    gw.trust(clone)
    commit(gw, src, "ahead", "1")
    trace = _traced(gw, *allow, "fetch", "-q", "--recurse-submodules=yes", cwd=clone)
    assert _enters(trace, mirror) and "gitwary:" not in trace, trace
    commit(gw, src, "ahead", "2")
    trace = _traced(gw, "fetch", "-q", cwd=clone / "sub")
    assert _enters(trace, mirror), trace


# -------------------- two repositories, one directory ([157], 2026-11-13)
def _named(gw: GW, gitdir: Path, tree: Path) -> GW:
    """gitwary as vcsh, yadm or a `git --git-dir=… --work-tree=…` alias
    runs git: the gitdir and the tree both named by the environment."""
    return GW({**gw.env, "GIT_DIR": str(gitdir), "GIT_WORK_TREE": str(tree)}, gw.state, gw.raw_exec)


def _dotfiles(gw: GW, tmp_path: Path) -> tuple[Path, Path, Path]:
    """vcsh's layout: `zsh.git` and `vim.git`, kept apart, each tracking
    its own files of one directory. Their configs differ."""
    tree = tmp_path / "home-tree"
    tree.mkdir()
    gitdirs = []
    for n in ("zsh", "vim"):
        g = tmp_path / f"{n}.git"
        w = [f"--git-dir={g}", f"--work-tree={tree}"]
        assert gw.git("init", "-q", "--bare", str(g)).rc == 0
        assert gw.git(*w, "config", "core.bare", "false").rc == 0
        (tree / f".{n}rc").write_text(n + "\n")
        assert gw.git(*w, "add", "-f", f".{n}rc").rc == 0
        assert gw.git(*w, "commit", "-qm", n).rc == 0
        gitdirs.append(g)
    assert gw.git(f"--git-dir={gitdirs[1]}", "config", "user.name", "vim").rc == 0
    return tree, gitdirs[0], gitdirs[1]


def test_two_gitdirs_on_one_tree_have_a_reference_each(gw: GW, tmp_path: Path) -> None:
    """[157] two repositories sharing a tree (vcsh) shared one state key,
    the tree's: the second was shown as "<tree>/.git has changed" — a
    `.git` that does not exist — with its difference from the first, each
    `y` replaced the other's reference, and the question came back at
    every switch. One reference each: trusted once, then silent, whatever
    the order; a change of one is that one's."""
    tree, zsh, vim = _dotfiles(gw, tmp_path)
    z, v = _named(gw, zsh, tree), _named(gw, vim, tree)
    r = z.run("git", "status", "--short", cwd=tree)
    assert r.blocked and "never trusted" in r.err and str(zsh) in r.err, r.text
    z.trust(tree)
    assert z.run("git", "status", "--short", cwd=tree).rc == 0
    r = v.run("git", "status", "--short", cwd=tree)
    assert r.blocked and "never trusted" in r.err and str(vim) in r.err, r.text
    assert "has changed" not in r.err, "a repository never trusted shown as a change of another"
    v.trust(tree)
    for g in (z, v, z, v):
        r = g.run("git", "status", "--short", cwd=tree)
        assert r.rc == 0 and not r.err, r.text
    with open(vim / "config", "a") as f:
        f.write("[core]\n\thooksPath = /nowhere\n")
    r = v.run("git", "status", "--short", cwd=tree)
    assert r.blocked and f"{vim} (work tree {tree}) has changed" in r.err, r.text
    assert f"{tree}/.git" not in r.err, "a gitdir that does not exist named as the one that changed"
    r = z.run("git", "status", "--short", cwd=tree)
    assert r.rc == 0 and not r.err, r.text


def test_list_forget_and_retrust_reach_a_gitdir_named_apart(gw: GW, tmp_path: Path) -> None:
    """[157] the management commands opened `<root>/.git` for every record:
    a repository of dotfiles (a bare gitdir, the home directory as its
    tree) was listed as `structure` and `retrust` skipped it. `forget
    <tree>` reaches every repository of that tree, `forget <gitdir>` its
    own."""
    tree, zsh, vim = _dotfiles(gw, tmp_path)
    z, v = _named(gw, zsh, tree), _named(gw, vim, tree)
    z.trust(tree)
    v.trust(tree)
    listing = gw.run("list").text
    for g in (zsh, vim):
        line = next(ln for ln in listing.splitlines() if str(g) in ln)
        assert line.startswith("ok") and str(tree) in line, listing
    r = gw.run("retrust")
    assert r.rc == 0 and "2 repository(ies) re-trusted, 0 skipped" in r.text, r.text
    r = gw.run("forget", str(vim))
    assert r.rc == 0 and str(vim) in r.text, r.text
    assert v.check(tree).blocked and not z.check(tree).blocked
    v.trust(tree)
    r = gw.run("forget", str(tree))
    assert r.text.count("forgotten") == 2, r.text
    assert z.check(tree).blocked and v.check(tree).blocked


def test_own_gitdir_named_by_the_environment_is_the_same_repository(gw: GW, repo: Path) -> None:
    """[157] GIT_DIR naming the gitdir the tree already has — what git
    exports to its hooks and children, what `git --git-dir=.git` spells —
    is that repository, under its reference."""
    assert _named(gw, repo / ".git", repo).run("git", "status", "--short", cwd=repo).rc == 0
    r = gw.run("git", "--git-dir=.git", "status", "--short", cwd=repo)
    assert r.rc == 0 and not r.err, r.text


def test_another_gitdir_named_from_a_trusted_tree_is_not_its_change(gw: GW, repo: Path, tmp_path: Path) -> None:
    """[157] `git --git-dir=<other>/.git` typed (or run by a child git) in
    a trusted repository: another repository, never trusted, said so and
    recorded so — it was compared with the reference of the directory it
    ran in, "<repo>/.git has changed" with the other's config as the
    diff, and a `y` there replaced the reference of `repo`."""
    other = make_source(gw, tmp_path, "other")
    r = gw.run("git", f"--git-dir={other / '.git'}", "log", "--oneline", cwd=repo)
    assert r.blocked and "never trusted" in r.err and str(other / ".git") in r.err, r.text
    assert "has changed" not in r.err, r.text
    assert not gw.check(repo).blocked
    pending = gw.run("pending").text
    assert str(other / ".git") in pending and "never" in pending, pending
    r = gw.run("pending", "-c", str(other / ".git"))
    assert "cleared" in r.text and "nothing pending" in gw.run("pending").text, r.text


# ------------- ordinary setups that still ask: the records (2026-11-13)
@pytest.mark.xfail(strict=True, reason="[160] accepted limitation (DESIGN.md, Known limitations): the file a "
                   "credential helper stores into is a word of a program's command line")
def test_credential_store_file_rewritten_by_git_is_silent(gw: GW, repo: Path) -> None:
    """[160] OPEN — `credential.helper = store --file <f>`: `<f>` holds
    data, and git rewrites it at every credential it approves or rejects.
    It is watched as any file a program key names (the helper is a command
    line, and nothing in it says which word is a script and which a data
    file), so each rewrite is a change. The way out: the helper's default
    file, which no config names (`credential.helper = store`)."""
    import subprocess
    creds = Path(gw.env["HOME"]) / "creds"
    creds.write_text("https://u:p@example.com\n")
    assert gw.git("config", "credential.helper", f"store --file {creds}", cwd=repo).rc == 0
    gw.trust(repo)
    r = subprocess.run(["git", "credential", "approve"], cwd=repo, env=gw.raw_env, text=True, capture_output=True,
                       input="protocol=https\nhost=other.example\nusername=u2\npassword=p2\n\n")
    assert r.returncode == 0 and "other.example" in creds.read_text(), r.stderr
    r = gw.run("git", "status", "--short", cwd=repo)
    assert not r.blocked and "gitwary:" not in r.err, r.text


@pytest.mark.xfail(strict=True, reason="[161] accepted limitation (DESIGN.md, Known limitations): an includeIf "
                   "is followed whatever its condition")
def test_clone_is_auto_trusted_despite_a_template_in_an_inactive_include(gw: GW, tmp_path: Path) -> None:
    """[161] OPEN — a global `includeIf "gitdir:~/work/"` whose file sets
    `init.templateDir`: git applies it to the repositories under that
    directory only; the gate of the auto-trust reads every include,
    whatever its condition (a superset, as the scan does: evaluating git's
    conditions is one more reader to hold to git), and withholds the
    auto-trust of every clone. One `gitwary trust` per clone."""
    home = Path(gw.env["HOME"])
    (tmp_path / "tpl/hooks").mkdir(parents=True)
    (home / "work.inc").write_text(f"[init]\n\ttemplateDir = {tmp_path / 'tpl'}\n")
    assert gw.git("config", "--global", "includeIf.gitdir:/nowhere/at/all/.path", str(home / "work.inc")).rc == 0
    src, dst = make_source(gw, tmp_path), tmp_path / "dst"
    r = gw.run("git", "clone", "-q", f"file://{src}", str(dst), cwd=tmp_path)
    assert r.rc == 0, r.text
    assert not gw.check(dst).blocked, r.text


def test_a_large_config_is_read_whole_whatever_it_costs(gw: GW, repo: Path) -> None:
    """[162] no ceiling on what a config may weigh: an included megabyte is
    read to its last line, and what that line names is watched. gitwary's
    reader is a port of git's, character by character, in Python: about
    3 MB a second where git reads a hundred; a ceiling was considered and
    left out — one more refusal of a repository git accepts, for a file
    whose change is refused anyway."""
    write_exec(repo / ".githooks/pre-commit", "#!/bin/sh\nexit 0\n")
    lines = "".join(f"\tkey{i:07d} = an ordinary value of forty characters\n" for i in range(20000))
    (repo / "big.inc").write_text(f"[section]\n{lines}[core]\n\thooksPath = .githooks\n")
    assert (repo / "big.inc").stat().st_size > 1_000_000
    assert gw.git("config", "include.path", "../big.inc", cwd=repo).rc == 0
    gw.trust(repo)
    assert not gw.check(repo).blocked
    write_exec(repo / ".githooks/pre-commit", "#!/bin/sh\ntouch /tmp/evil\n")
    r = gw.check(repo)
    assert r.blocked and ".githooks/pre-commit" in r.err, r.text
