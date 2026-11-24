"""Nested .git, fake submodules, redirected gitfiles. [6], [7], [9]"""
from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

from tests.attacks._helpers import add_submodule, plant_active_gitlink
from tests.conftest import GB


def attack_nested_git_undeclared(gb: GB, repo: Path, tmp_path: Path) -> None:
    """[14] undeclared nested repository: RCE as soon as a gitlink exists
    (proof: tests/nested_git_is_a_threat.sh)"""
    sub = repo / "vendor"
    sub.mkdir()
    gb.git("init", "-q", cwd=sub)
    (sub / "v").write_text("v\n")
    gb.git("add", "v", cwd=sub)
    gb.git("commit", "-qm", "v", cwd=sub)
    gb.git("config", "core.fsmonitor", "/tmp/evil", cwd=sub)


def attack_nested_git_in_pruned_dir_with_gitlink(gb: GB, repo: Path, tmp_path: Path) -> None:
    """[14] nested repository in a pruned directory, referenced by an index gitlink"""
    sub = repo / "node_modules" / "pkg"
    sub.mkdir(parents=True)
    gb.git("init", "-q", cwd=sub)
    (sub / "v").write_text("v\n")
    gb.git("add", "v", cwd=sub)
    gb.git("commit", "-qm", "v", cwd=sub)
    gb.git("config", "core.fsmonitor", "/tmp/evil", cwd=sub)
    gb.git("add", "-A", cwd=repo)        # creates the gitlink


def attack_index_namelen_desync_hides_gitlink(gb: GB, repo: Path, tmp_path: Path) -> None:
    """[14] forged index: name length in the flags != NUL position → gitblocker's
    parser desynchronises and misses the gitlink git honours (node_modules
    pruned → nested_gits blind too; .git/index excluded from the fingerprint)"""
    sub = repo / "node_modules" / "pkg"
    sub.mkdir(parents=True)
    gb.git("init", "-q", cwd=sub)
    (sub / "v").write_text("v\n")
    gb.git("add", "v", cwd=sub)
    gb.git("commit", "-qm", "v", cwd=sub)
    gb.git("config", "core.fsmonitor", "/tmp/evil", cwd=sub)
    gb.git("add", "-A", cwd=repo)        # forms the real gitlink node_modules/pkg
    idx = repo / ".git/index"
    d = bytearray(idx.read_bytes())
    # Entry 1 (file 'f', 64 bytes): announce a 16-byte name in the flags
    # (d[72:74]) but put a real NUL at offset 3 of the name. git consumes 16
    # bytes (→ correct next entry); gitblocker stops at the NUL and shifts its
    # offset by 8 bytes, landing in the middle of the real gitlink entry.
    header = bytes(d[0:12])
    fixed = bytes(d[12:72]) + (16).to_bytes(2, "big")
    body = fixed + b"abc\x00DEFGHIJKLMNO"
    body += b"\x00" * (((len(body) + 8) & ~7) - len(body))
    rest = bytes(d[76:-20])              # gitlink entry + extensions, intact
    new = header + body + rest
    idx.write_bytes(new + hashlib.sha1(new).digest())


def attack_nested_git_declared_but_directory(gb: GB, repo: Path, tmp_path: Path) -> None:
    """[6] .git directory declared in .gitmodules: declared != legitimate"""
    (repo / "evil").mkdir()
    gb.git("init", "-q", cwd=repo / "evil")
    gb.git("config", "core.fsmonitor", "/tmp/evil", cwd=repo / "evil")
    (repo / ".gitmodules").write_text('[submodule "evil"]\n\tpath = evil\n\turl = ./evil\n')


def attack_nested_git_in_pruned_dir_declared(gb: GB, repo: Path, tmp_path: Path) -> None:
    """[6] .git planted in a pruned directory (build/) but declared: git descends there"""
    (repo / "build").mkdir()
    gb.git("init", "-q", cwd=repo / "build")
    (repo / ".gitmodules").write_text('[submodule "build"]\n\tpath = build\n\turl = ./build\n')


def attack_second_fake_submodule_after_legit_one(gb: GB, repo: Path, tmp_path: Path) -> None:
    """[9] a legitimate submodule must not hide a second, fake, declared submodule"""
    add_submodule(gb, repo, tmp_path, "aaa")
    gb.trust(repo)
    (repo / "zzz").mkdir()
    gb.git("init", "-q", cwd=repo / "zzz")
    with (repo / ".gitmodules").open("a") as f:
        f.write('[submodule "zzz"]\n\tpath = zzz\n\turl = ./zzz\n')


def attack_submodule_gitfile_redirected(gb: GB, repo: Path, tmp_path: Path) -> None:
    """[7] submodule gitfile redirected to a controlled gitdir outside .git/modules"""
    add_submodule(gb, repo, tmp_path)
    gb.trust(repo)
    shutil.copytree(repo / ".git/modules/sub", repo / "evilgit")
    (repo / "sub/.git").write_text("gitdir: ../evilgit\n")


def attack_gitmodules_modified(gb: GB, repo: Path, tmp_path: Path) -> None:
    """.gitmodules modified (update = !cmd)"""
    add_submodule(gb, repo, tmp_path)
    gb.trust(repo)
    (repo / ".gitmodules").write_text('[submodule "sub"]\n\tpath = sub\n\turl = ./x\n\tupdate = !id\n')


def attack_root_gitfile_into_worktree(gb: GB, repo: Path, tmp_path: Path) -> None:
    """root .git file pointing inside the work tree"""
    (repo / ".git").rename(repo / "evil.git")
    (repo / ".git").write_text("gitdir: evil.git\n")


def attack_submodule_gitdir_volatile_name(gb: GB, repo: Path, tmp_path: Path) -> None:
    """[15] submodule named "lfs": .git/modules/lfs pruned as volatile"""
    add_submodule(gb, repo, tmp_path, "lfs")
    gb.trust(repo)
    with (repo / ".git/modules/lfs/config").open("a") as f:
        f.write("\tfsmonitor = /tmp/evil\n")


def attack_submodule_gitdir_volatile_name_refs(gb: GB, repo: Path, tmp_path: Path) -> None:
    """[15] submodule named "refs": same pruning by name"""
    add_submodule(gb, repo, tmp_path, "refs")
    gb.trust(repo)
    with (repo / ".git/modules/refs/config").open("a") as f:
        f.write("\tfsmonitor = /tmp/evil\n")


def attack_submodule_hook(gb: GB, repo: Path, tmp_path: Path) -> None:
    """hook in .git/modules/<sub>/hooks"""
    from tests.conftest import write_exec
    add_submodule(gb, repo, tmp_path)
    gb.trust(repo)
    write_exec(repo / ".git/modules/sub/hooks/post-checkout")


def attack_submodule_config(gb: GB, repo: Path, tmp_path: Path) -> None:
    """submodule config modified"""
    add_submodule(gb, repo, tmp_path)
    gb.trust(repo)
    gb.git("config", "core.fsmonitor", "/tmp/evil", cwd=repo / "sub")


def attack_bare_gitdir_planted_in_subdir(gb: GB, repo: Path, tmp_path: Path) -> None:
    """[23] bare gitdir (HEAD + objects/ + refs/) planted in src/: git discovers
    it before the parent's .git when git is run from src/"""
    bare = tmp_path / "bare.git"
    assert gb.git("clone", "-q", "--bare", str(repo), str(bare)).rc == 0
    shutil.copytree(bare, repo / "src")
    gb.git("config", "core.fsmonitor", "/tmp/evil", cwd=repo / "src")
    from tests.conftest import write_exec
    write_exec(repo / "src/hooks/reference-transaction")


def attack_gitfile_in_pruned_dir_redirected(gb: GB, repo: Path, tmp_path: Path) -> None:
    """[24] gitfile node_modules/pkg/.git → gitdir outside .git/modules + gitlink
    in the index: nested_gits does not enter node_modules, and the index loop
    only refused a .git directory"""
    sub = repo / "node_modules" / "pkg"
    sub.mkdir(parents=True)
    gb.git("init", "-q", cwd=sub)
    (sub / "v").write_text("v\n")
    gb.git("add", "v", cwd=sub)
    gb.git("commit", "-qm", "v", cwd=sub)
    evil = repo / "node_modules" / "evilgit"      # pruned: invisible to nested_gits
    (sub / ".git").rename(evil)
    (sub / ".git").write_text(f"gitdir: {evil}\n")
    gb.git("config", "core.fsmonitor", "/tmp/evil", cwd=sub)
    gb.git("add", "-A", cwd=repo)        # creates the gitlink


def attack_gitlink_in_submodule_index(gb: GB, repo: Path, tmp_path: Path) -> None:
    """[60] nested repository inside a submodule's tree, referenced by a
    gitlink of the submodule's index (`.git/modules/sub/index`): that index
    was parsed for forged names [55] but its gitlinks were dropped, and
    `git status` in the superproject recurses into sub, then into the nested
    repository, whose core.fsmonitor runs"""
    sub = add_submodule(gb, repo, tmp_path)
    gb.trust(repo)
    inner = sub / "inner"
    gb.git("init", "-q", str(inner))
    (inner / "i").write_text("i\n")
    gb.git("add", "i", cwd=inner)
    gb.git("commit", "-qm", "i", cwd=inner)
    gb.git("config", "core.fsmonitor", "/tmp/evil", cwd=inner)
    assert gb.git("add", "inner", cwd=sub).rc == 0          # the gitlink, in sub's index


def attack_nested_git_declared_in_submodule_gitmodules(gb: GB, repo: Path, tmp_path: Path) -> None:
    """[60] a nested .git directory declared in the submodule's own
    .gitmodules (no gitlink needed for the declaration to be read)"""
    sub = add_submodule(gb, repo, tmp_path)
    gb.trust(repo)
    inner = sub / "inner"
    gb.git("init", "-q", str(inner))
    gb.git("config", "core.fsmonitor", "/tmp/evil", cwd=inner)
    (sub / ".gitmodules").write_text('[submodule "inner"]\n\tpath = inner\n\turl = ./x\n')


def attack_gitlink_in_submodule_index_gitfile_outside(gb: GB, repo: Path, tmp_path: Path) -> None:
    """[60] the nested entry of the submodule's index is a gitfile pointing
    outside the submodule's modules/ (a gitdir the container controls)"""
    sub = add_submodule(gb, repo, tmp_path)
    gb.trust(repo)
    evil = tmp_path / "vol-evil"
    gb.git("init", "-q", str(evil))
    (evil / "e").write_text("e\n")
    gb.git("add", "e", cwd=evil)
    gb.git("commit", "-qm", "e", cwd=evil)
    gb.git("config", "core.fsmonitor", "/tmp/evil", cwd=evil)
    # only the volatile index and the tree: no watched file of .git changes
    sha = gb.git("rev-parse", "HEAD", cwd=evil).out.strip()
    assert gb.git("update-index", "--add", "--cacheinfo", f"160000,{sha},inner", cwd=sub).rc == 0
    (sub / "inner").mkdir()
    (sub / "inner/.git").write_text(f"gitdir: {evil / '.git'}\n")


def attack_sparse_index_hides_gitlink(gb: GB, repo: Path, tmp_path: Path) -> None:
    """[87] sparse index: the gitlink `vendor/evil` sits in a 040000
    directory entry (`sdir`) the index parser does not expand; git expands
    it once `vendor/` is on disk and `git status` runs the planted fsmonitor
    (positive control: test_commands)"""
    from tests.attacks._helpers import payload, plant_sparse_gitlink
    plant_sparse_gitlink(gb, repo, tmp_path, str(payload(tmp_path)))


def attack_gitdir_in_submodule_volatile_zone(gb: GB, repo: Path, tmp_path: Path) -> None:
    """[103] a gitdir planted in a volatile zone of a real submodule's gitdir
    (`.git/modules/sub/refs/p`: nobody hashes refs/), named by a gitlink of
    the submodule's index (volatile) through a gitfile: check_nested_git
    accepted anything under modules/, and `git status` recursed into it"""
    sub = add_submodule(gb, repo, tmp_path)
    gb.trust(repo)
    planted = tmp_path / "vol-planted"
    gb.git("init", "-q", str(planted))
    (planted / "p").write_text("p\n")
    gb.git("add", "p", cwd=planted)
    gb.git("commit", "-qm", "p", cwd=planted)
    gb.git("config", "core.fsmonitor", "/tmp/evil", cwd=planted)
    pg = repo / ".git/modules/sub/refs/p"
    shutil.move(str(planted / ".git"), str(pg))
    sha = gb.git("--git-dir", str(pg), "rev-parse", "HEAD").out.strip()
    assert gb.git("update-index", "--add", "--cacheinfo", f"160000,{sha},inner", cwd=sub).rc == 0
    (sub / "inner").mkdir()
    (sub / "inner/.git").write_text("gitdir: ../../.git/modules/sub/refs/p\n")


def attack_active_submodule_gitlink_in_head_runs_in_process(gb: GB, repo: Path,
                                                            tmp_path: Path) -> None:
    """[126] `submodule.active = .` (what `clone --recurse-submodules`
    writes, hence trusted) makes the sandbox's planted `vendor/x` an active
    submodule with only a gitlink committed to HEAD and a `.gitmodules`
    there — objects and refs are volatile, the index and the work tree hold
    no gitlink, so gitblocker's structural check (index gitlinks, `.gitmodules`
    on disk) sees nothing. `git grep --recurse-submodules s HEAD` reads the
    gitlink from the tree, finds the submodule active, and enters
    `vendor/x/.git` in-process (repo_submodule_init), running its
    core.fsmonitor: no child git stands between git and the planted gitdir,
    so the exec-path wrap never judges it. gitblocker does not refuse the
    repository; the payload runs."""
    plant_active_gitlink(gb, repo, tmp_path, planting="tree", gitfile=False)


def attack_embryonic_submodule_gitdir_config_planted(gb: GB, repo: Path, tmp_path: Path) -> None:
    """[146] a gitfile to `modules/<x>` that is no repository yet (no HEAD:
    what a failed recursive switch leaves) with a `config` planted there,
    which `submodule update --init` would keep: an added file, refused by
    the fingerprint, never accepted as structure"""
    d = repo / ".git/modules/libs/c"
    d.mkdir(parents=True)
    (d / "config").write_text("[core]\n\trepositoryformatversion = 0\n\thooksPath = /tmp/evil\n")
    (repo / "libs/c").mkdir(parents=True)
    (repo / "libs/c/.git").write_text("gitdir: ../../.git/modules/libs/c\n")
    (repo / ".gitmodules").write_text('[submodule "libs/c"]\n\tpath = libs/c\n\turl = ../c.git\n')


def attack_gitfile_copy_of_a_trusted_submodule(gb: GB, repo: Path, tmp_path: Path) -> None:
    """[154] a copy of a trusted submodule's gitfile planted in another
    directory: the gitdir is the superproject's, its `core.worktree` names
    the real tree — the planted one inherits nothing"""
    sub = add_submodule(gb, repo, tmp_path)
    gb.trust(repo)
    (repo / "src").mkdir()
    (repo / "src/.git").write_text(f"gitdir: {repo}/.git/modules/{sub.name}\n")


def attack_gitfile_copy_of_a_trusted_worktree(gb: GB, repo: Path, tmp_path: Path) -> None:
    """[154] a copy of a trusted linked worktree's gitfile planted in a
    directory of the main tree: `worktrees/<id>/gitdir` names the real
    worktree — git run from the planted one would work on another HEAD and
    index, unseen"""
    wt = tmp_path / "wt"
    assert gb.git("worktree", "add", "-q", str(wt), cwd=repo).rc == 0
    gb.trust(repo)
    assert gb.run("git", "status", "--short", cwd=wt).rc == 0      # the real one inherits
    (repo / "src").mkdir()
    (repo / "src/.git").write_text((wt / ".git").read_text())


def attack_worktree_gitdir_planted_in_a_volatile_zone(gb: GB, repo: Path, tmp_path: Path) -> None:
    """[154] a linked worktree's gitdir planted where nothing is hashed
    (`logs/`), its `commondir` the trusted repository: the main tree's
    check sees nothing, and none of it is in its reference"""
    adm = repo / ".git/logs/w"
    adm.mkdir(parents=True)
    (adm / "HEAD").write_text("ref: refs/heads/main\n")
    (adm / "commondir").write_text("../..\n")
    (adm / "gitdir").write_text(f"{repo}/src/.git\n")
    (repo / "src").mkdir()
    (repo / "src/.git").write_text(f"gitdir: {adm}\n")


def _submodule_config(gb: GB, repo: Path, tmp_path: Path, lines: str) -> None:
    """A trusted superproject whose submodule is in use; `lines` appended
    to the submodule's config, `modules/sub/config`."""
    sub = add_submodule(gb, repo, tmp_path)
    gb.trust(repo)
    assert gb.run("git", "status", "--short", cwd=sub).rc == 0     # the submodule took the trust
    with open(repo / ".git/modules/sub/config", "a") as f:
        f.write(lines)


def attack_submodule_config_filter_behind_branch_tracking(gb: GB, repo: Path, tmp_path: Path) -> None:
    """[166] [168] a filter added to a submodule's config beside the
    tracking of a branch the user created there: not tracking alone, and
    not one line `modified modules/sub/config` either"""
    _submodule_config(gb, repo, tmp_path, '[branch "feat"]\n\tremote = origin\n\tmerge = refs/heads/main\n'
                                          '[filter "x"]\n\tclean = sh evil.sh\n')


def attack_submodule_config_remote_to_a_path_of_the_volume(gb: GB, repo: Path, tmp_path: Path) -> None:
    """[166] a remote added to a submodule's config with a path of the
    volume as its URL: git runs that repository's hooks and config ([45]
    [61]), the list takes a network URL only"""
    _submodule_config(gb, repo, tmp_path, f'[remote "up"]\n\turl = {tmp_path}/evil\n'
                                          '\tfetch = +refs/heads/*:refs/remotes/up/*\n')


def attack_submodule_config_remote_through_a_helper(gb: GB, repo: Path, tmp_path: Path) -> None:
    """[166] a remote added to a submodule's config whose URL names a
    remote helper (`ext::` runs a command)"""
    _submodule_config(gb, repo, tmp_path, '[remote "up"]\n\turl = ext::sh -c evil.sh\n')


def attack_alias_in_a_submodule_config_beside_tracking_in_the_superproject(gb: GB, repo: Path,
                                                                         tmp_path: Path) -> None:
    """[166] two configs moved at once, the superproject's by branch
    tracking, the submodule's by an alias: accepted together or not at all"""
    sub = add_submodule(gb, repo, tmp_path)
    hub = tmp_path / "hub.git"
    gb.git("init", "-q", "--bare", str(hub))
    gb.git("remote", "add", "origin", str(hub), cwd=repo)
    gb.git("push", "-q", "origin", "main", cwd=repo)
    gb.trust(repo)
    assert gb.run("git", "status", "--short", cwd=sub).rc == 0     # the submodule took the trust
    with open(repo / ".git/modules/sub/config", "a") as f:
        f.write("[alias]\n\tst = !sh evil.sh\n")
    assert gb.git("checkout", "-q", "-b", "one", "origin/main", cwd=repo).rc == 0


def attack_submodule_tree_swapped_for_a_symlink(gb: GB, repo: Path, tmp_path: Path) -> None:
    """[171] a trusted submodule's directory replaced by a symlink to a
    directory the sandbox planted, its gitfile copied there: resolved,
    the path `core.worktree` names is the planted one — which took the
    superproject's trust, and whose commits and pushes went to the
    submodule's repository"""
    import os
    import shutil
    sub = add_submodule(gb, repo, tmp_path)
    gb.trust(repo)
    (repo / "src").mkdir()
    shutil.copy(sub / ".git", repo / "src/.git")
    shutil.rmtree(sub)
    os.symlink("src", sub)


def attack_worktree_tree_swapped_for_a_symlink(gb: GB, repo: Path, tmp_path: Path) -> None:
    """[171] a trusted linked worktree's directory replaced by a symlink
    to a directory of the main tree, its gitfile copied there: git run
    from that directory works on the worktree's HEAD and index"""
    import os
    import shutil
    wt = tmp_path / "wt"
    assert gb.run("git", "worktree", "add", "-q", str(wt), cwd=repo).rc == 0
    assert gb.run("git", "status", "--short", cwd=wt).rc == 0      # the real one took the trust
    (repo / "src").mkdir()
    shutil.copy(wt / ".git", repo / "src/.git")
    shutil.rmtree(wt)
    os.symlink(repo / "src", wt)
