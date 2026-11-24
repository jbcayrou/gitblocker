# gitblocker

[![tests](https://github.com/jbcayrou/gitblocker/actions/workflows/tests.yml/badge.svg)](https://github.com/jbcayrou/gitblocker/actions/workflows/tests.yml)

Refuses to run `git` on a repository whose trusted files (`.git/config`,
hooks, `.gitmodules`, gitfiles, every path the config makes git execute…)
have changed since you last looked at them.

One Python file, standard library only. Linux and macOS, Python ≥ 3.9,
git ≥ 2.39 (see [Supported versions](#supported-versions)).

## The problem

You run untrusted code in a container or VM with a host directory mounted
into it, and that directory holds git repositories. The sandbox may be a CI
job, a build of a project you just cloned, a third-party tool, an LLM coding
agent. Writing into the work tree is the whole point, and `.git/` sits
inside it. Malicious code there can drop a hook, add
`core.fsmonitor = /tmp/evil` to `.git/config`, redirect `.git` to a
booby-trapped directory, plant a nested repository… The next time *you* run
`git` on the host, that code runs with your rights: SSH keys, credentials,
shell. That is the sandbox-to-host pivot.

Sandboxing layers (AppArmor/seccomp profiles, a global `core.hooksPath`,
`safe.bareRepository=explicit`, rootless uid mapping) prevent some of it.
gitblocker **detects** the rest: it refuses to run git until you have looked.

## You are not the only one running git

An alias protects the `git` you type. It does not protect the git that runs
because you merely *looked* at the repository:

- **Shell prompts.** oh-my-zsh, powerlevel10k, Starship, `git-prompt.sh` run
  `git status`, `git rev-parse`, `git symbolic-ref` at every prompt, and
  oh-my-zsh does it with `command git`, which skips aliases by design. A
  `core.fsmonitor` planted in `.git/config` fires the moment you `cd` into
  the directory, before you have typed a single git command.
- **Editors.** VS Code's git extension runs `git status` every few seconds
  and `git fetch` periodically (`git.autofetch`); JetBrains, magit, lazygit,
  tig, fugitive do the same on their own schedule. Opening the folder is
  enough.
- **Build tooling.** Makefiles, `setuptools_scm`, `go build` with VCS
  stamping, npm `prepare` scripts, pre-commit, husky, git-lfs call `git` by
  name and never see your alias.

Which git each of these finds depends on the `PATH` it was started with, not
on your shell's aliases. That is why the install below puts gitblocker **as
`git`** in a directory ahead of the real one: everything that resolves `git`
through the `PATH` is then wrapped — prompts, `command git`, scripts, and
editors started from a shell (VS Code resolves your login shell's
environment at startup, even when launched from the Dock).

Still outside: a tool with a hardcoded `/usr/bin/git`, a GUI started by a
launcher with a minimal `PATH`, and the git that hooks or `rebase --exec`
run (the real git puts its own exec path first). For VS Code, set `git.path`
to the gitblocker symlink to remove the doubt. Tools built on libgit2 rather
than the git binary do not run hooks or config commands and are outside this
picture.

Cost: one check per invocation, ~33 ms, whatever the size of the tree
(see `PERF.md`). A prompt that calls git three times pays ~100 ms. In a
repository you have not trusted, or whose trusted files changed, those calls
are refused: the prompt shows no git information until you have decided.
That silence is the signal.

## How it works

`gitblocker trust` records a **fingerprint** of:

- everything in `.git/`, at any depth, `modules/` and `worktrees/` included,
  except what git rewrites in normal operation (objects, refs, logs, index,
  `*_HEAD`…). An unknown file is watched, not ignored;
- the tree files that drive git: `.gitmodules`, `.lfsconfig`, the gitfile of
  each submodule or linked worktree;
- every path the config makes git execute or read: `core.hooksPath`,
  `include.path` chains, scripts named in aliases, filters, drivers,
  `credential.helper`… — in the tree or outside it, as long as you could
  write there (a `core.hooksPath` resolving to the root of the tree is
  refused: every top-level file would be a hook);
- a local remote (`remote.*.url` = a path in the volume): the config and
  hooks of the repository `push` enters, opened as git opens it; `git push
  <path>` to a repository no remote names is refused;
- a repository yours borrows objects from (`clone --reference <mirror>`,
  `--shared`): its config and hooks too — git asks it what it holds at
  every fetch;
- the paths named by the system and global configs: a global
  `core.hooksPath` pointing into the mounted volume is a bypass otherwise
  (the files themselves are parsed, not hashed: the sandbox cannot write
  them). Files git reads as data — a signing key, `commit.template`,
  `core.excludesFile` — are not watched; a file outside the repository named
  by a program key is watched but never copied into the state directory.

Every later `git` invocation is checked against that fingerprint first. Any
deviation, structural anomaly (symlinked `.git`, bare gitdir planted in a
subdirectory, undeclared nested repository, `exec` lines injected into a
rebase todo, an index entry whose name escapes the work tree — `.git/hooks/x`,
`../x`, which `checkout -- .` and `restore` would write as is —, control
characters in names…) or unknown repository → git is not run. The config is parsed by a port of git's own parser, never by
calling `git config`: git would honour the config being judged.

The fingerprint lives in `~/.local/state/gitblocker/`, outside any mounted
volume, with a backup of the watched files so `gitblocker restore` can put
them back.

It is a fingerprint, not a blocklist of "dangerous" config keys: there is
nothing to keep up to date with git's CVEs, and no key it can miss. The
price is an explicit `gitblocker trust` when *you* change your hooks, remotes
or config; see "Day to day" for how much of that is automated.

## Install

Two things to wrap: the `git` you type, and the `git` every git runs its
children through — git's **exec path** (`git --exec-path`). A command
enters other repositories only through children (`git status` in a
submodule, `git pull` in a hook, the `index-pack` of a clone, a repository
planted in the work tree), and a child that is gitblocker judges the
repository it enters; a raw one does not (DESIGN-exec-path.md). Without
the second wrap gitblocker checks the repositories you run git in, as
before, and `gitblocker trust` says so.

### Per user (Linux, macOS)

```sh
install -m 755 gitblocker.py ~/bin/gitblocker
ln -s ~/bin/gitblocker ~/bin/git      # a directory ahead of the real git in your PATH
gitblocker exec-path                  # builds ~/.local/lib/gitblocker-exec (or the directory you give)
```

then, in your shell profile:

```sh
export GIT_EXEC_PATH=~/.local/lib/gitblocker-exec
```

gitblocker detects it is called `git` and switches to exec mode. `gitblocker
exec-path` links every entry of the real git's exec path into the
directory, `git` to gitblocker and `git.real` to the real binary, which
gitblocker runs before looking at the `PATH` (a GUI app's `PATH` may hold
another git). Run it again after a git upgrade; `gitblocker trust` tells
you when it is stale. The variable reaches what your login shell starts;
cron, systemd units and GUI apps need it set their own way (`launchctl
setenv GIT_EXEC_PATH …` on macOS, `Environment=` in a unit, the crontab)
— or the system-wide install below.

If you only want the `git` you type wrapped, an alias is enough, with the
limits described above:

```sh
alias git='gitblocker git'
```

### System-wide (Debian/Ubuntu)

To wrap every git on the machine, cron and GUIs included, gitblocker is
installed *as* `/usr/bin/git` and at the exec path, `/usr/lib/git-core/git`,
and the real binaries are diverted to `git.real` beside them. The package
does it:

```sh
ci/build-deb.sh                              # needs dpkg-deb; writes dist/gitblocker_<version>_all.deb
sudo apt install ./dist/gitblocker_*_all.deb
```

`apt upgrade git` then installs every new git at the diverted names, never
over gitblocker, and `sudo apt remove gitblocker` puts the real git back, byte
for byte. dpkg does not drop a diversion by itself: the package's `postrm`
does. Trust records live in each user's home and are left alone. The
whole cycle — install, an upgrade of git, an upgrade of gitblocker, remove,
purge, the removal of git itself — is replayed at every push on Debian 12,
Debian 13, Ubuntu 24.04 and Ubuntu 26.04 (`ci/test-deb.sh`).

The same by hand, which the package takes over if you install it later:

```sh
sudo install -m 755 gitblocker.py /usr/bin/gitblocker
sudo dpkg-divert --package gitblocker --add --rename --divert /usr/bin/git.real /usr/bin/git
sudo ln -s gitblocker /usr/bin/git
sudo dpkg-divert --package gitblocker --add --rename --divert /usr/lib/git-core/git.real /usr/lib/git-core/git
sudo ln -s /usr/bin/gitblocker /usr/lib/git-core/git
```

gitblocker runs a `git.real` found next to the name it was invoked by
before looking at the `PATH`, so no environment variable is needed (cron,
systemd and GUIs would not get one). The 160 dashed builtins of
`/usr/lib/git-core` (`git-status`, `git-receive-pack`…) are symlinks to
`git` and land on gitblocker too: invoked under a dashed name it runs that
command; under `git-receive-pack`, `git-upload-pack` and
`git-upload-archive` (sshd, for every push and fetch *to* the machine) it
passes straight to the real git, since they serve a repository named by
argument and run nothing of the caller's. Upgrading a hand-made install
is overwriting `/usr/bin/gitblocker`. To undo it — all three lines: with
`/usr/bin/gitblocker` deleted and the diversions left, `/usr/bin/git` links
to nothing, and reinstalling git does not repair it (dpkg keeps writing
the real one to `git.real`):

```sh
sudo rm /usr/bin/git /usr/lib/git-core/git /usr/bin/gitblocker
sudo dpkg-divert --package gitblocker --rename --remove /usr/bin/git
sudo dpkg-divert --package gitblocker --rename --remove /usr/lib/git-core/git
```

Other distributions have no `dpkg-divert`: renaming the two binaries by
hand (`git` → `git.real`, a symlink to gitblocker in its place, under
`/usr/bin` and `$(git --exec-path)`) works until the next package upgrade
puts the real git back, which `gitblocker trust` reports. Or build the exec
path once for everyone and set the variable system-wide:

```sh
sudo gitblocker exec-path /usr/local/lib/gitblocker-exec
echo 'GIT_EXEC_PATH=/usr/local/lib/gitblocker-exec' | sudo tee -a /etc/environment
```

### macOS

`/usr/bin/git` is protected by SIP and renaming Homebrew's git is undone
by `brew upgrade`: use the per-user install above. The `PATH` symlink
covers everything started from a login shell, VS Code included (set
`git.path` there); for GUI apps:

```sh
launchctl setenv GIT_EXEC_PATH ~/.local/lib/gitblocker-exec
```

`git.real` matters here: a GUI app's `PATH` holds only Apple's git, which
would become the real one without it. Run `gitblocker exec-path` again after
`brew upgrade git`.

### Check the install

In any repository:

```sh
gitblocker trust        # no warning about the exec path: children are wrapped
git --exec-path         # the directory whose `git` is gitblocker
```

`gitblocker trust`, `list` and `retrust` warn while the exec path does not
lead to gitblocker, or leads to a stale directory (a git upgrade added or
removed entries), and say what to run.

### First trust

Set git's own guard against bare repositories planted in subdirectories; it
works with or without gitblocker:

```sh
git config --global safe.bareRepository explicit
```

Then, in each existing repository, **look before you trust**: the whole
point is that no state is blessed unseen, so there is no trust-on-first-use.

```sh
cat .git/config; ls -la .git/hooks     # anything you did not put there?
gitblocker trust
```

`gitblocker list` shows every registered repository and its status. New
repositories need nothing: a successful `git clone` / `git init` through the
wrapper is trusted automatically (unless a template directory is involved,
or the target already held a gitdir, in which case it says so).

## Day to day

Commit, checkout, merge, rebase, stash, bisect and gc touch only volatile
files: nothing to do. `submodule add` and `submodule update --init` write
to the gitdir: the next command in the superproject asks once (typed in
the new submodule first, it is refused and names the superproject). `git
worktree add`, `move`, `remove` and `prune` run through gitblocker ask
nothing, in the main tree or in the other worktrees, started one by one or
several at once (a worktree created by another git, an IDE's bundled one,
is asked about once). One thing is refused there: a path that goes through
a symlink sitting in the repository or beside it (`.claude/worktrees →
…`) — git would check the branch out, or delete, wherever it leads; name
the real directory instead. A submodule or a
linked worktree needs no trust of its own: the first git run there takes
the trust of the repository that holds it, and says so (`trusted with …`),
and again whenever that repository's reference has moved. A branch created
in a submodule (`checkout -b`, `push -u`) asks nothing, there or in the
superproject.
When a command finds the repository changed, one of three things happens.

`git --version` is never checked: it reads no repository, and the tools
that run it first (lazygit, fugitive) took a refusal for an old git.

**Auto-accept: the change is one git or your editor made itself.**
gitblocker re-trusts on its own, prints one line and runs git. See the next
subsection for the exact rule.

**Anything else is shown and asked on the terminal.** A new remote, a hook,
an `include.path`: the diff is printed, then

```
Trust this state and run git? [y/N]
```

The question is read on `/dev/tty`, so git's own stdin (`git apply <
patch`) is untouched. The state recorded is the one you were shown, not
whatever the sandbox may have written in the meantime. No question, a plain
refusal, when stdout or stderr is not a terminal (a prompt's `$(git …)`,
`git log | head`), or with `GITBLOCKER_NO_PROMPT=1`.

**A git with no terminal waits for you.** An editor's polling, a build tool,
cron: nobody reads their stderr. On a changed repository that git records
what it saw, sends one desktop notification (`notify-send` on Linux,
`osascript` on macOS, at most one per repository per 10 minutes) and waits
up to `GITBLOCKER_WAIT` seconds (default 60; 0 = never) for your decision:

```
$ gitblocker pending
changed         4s  1 waiting  /home/user/work/api
  gitblocker pending <repo>   to see the diff and decide     -a: all
$ gitblocker pending ~/work/api
/home/user/work/api  [changed, since 6s]
    git waiting (pid 41250, 6s): code[40988] ← systemd[1]
      /usr/share/code/code --type=utility
────────────────────────────────────────────────────────
  added     hooks/pre-commit
────────────────────────────────────────────────────────
Allow: record this state and let the waiting git run? [y/N] n
! gitblocker: refused: the waiting git is not run; the record is cleared. If malicious:  gitblocker restore
```

Allowing records the state you were shown and lets the waiting git run.
Refusing makes it fail; `gitblocker restore` then puts the watched files back
and you inspect the rest by hand. If the files changed again between the
block and your review, the diff shown is the current one and says so. A
decision taken after the timeout applies to the next invocation (editors
poll again by themselves). A never-trusted repository or a structural
anomaly is recorded and refused at once: nothing can be allowed there
without `gitblocker trust` after inspection.

`gitblocker trust` on a changed repository shows the same diff and asks the
same way; in a script it prints the diff and records.

### Auto-accept

Not to be confused with **auto-trust**, which blesses a *new* repository
after a `clone` or `init` made through the wrapper. Auto-accept applies to
a repository already trusted that now differs from its reference, and
accepts the difference without asking when it is one of the few things git
and your editor write into `.git/config` by themselves in the course of a
normal day. The point is to keep the `[y/N]` question for the rare changes
you will actually read (a hook, an `include.path`, a remote to a local
path), instead of training a reflex `y`.

The rule: every file that changed is a `config` — the repository's, the
main repository's when working from a linked worktree, a submodule's
(`.git/modules/<x>/config`: a branch created in a submodule is accepted
from the submodule and from the superproject alike) — and the **semantic**
difference between the trusted config and the new one is limited, for
each, to added or removed lines of these keys (a config that only differs
by a comment has no semantic difference, and is not accepted either):

| Key | Written by | Accepted value | Why it cannot run anything |
|---|---|---|---|
| `branch.<x>.remote` | `push -u`, `branch -u`, `checkout -b` with `autoSetupMerge` | a remote already present in the trusted config, or `.` | names an existing `[remote]` section; a new remote is not accepted this way |
| `branch.<x>.merge` | same | `refs/heads/…` | a ref name git resolves, never executes |
| `branch.<x>.vscode-merge-base` | VS Code's git extension, when it opens a repository | a ref name: no leading `-`, no blank, no control character | git ignores the key; VS Code passes the value to `git merge-base` |
| `remote.<n>.url` | `remote add` | a URL git reaches over the network by itself: `http(s)://`, `ftp(s)://`, `git://`, `ssh://`, `user@host:path` | no path of the machine and no program is named; a local path or `file://` (git runs that repository's hooks) and `<helper>::…` (git runs the helper) are asked |
| `remote.<n>.fetch` | same | a refspec | names refs |

Anything outside this, a `branch.<x>.rebase` or a remote to a local path
for instance, goes through the question. It is a closed allowlist of
harmless keys, not a blocklist of dangerous ones: nothing enters it
without a demonstration that the key cannot make git execute anything.
Since git writes these lines *after* the check (`push -u` runs, then
records the tracking), it is the next command that accepts them.

A git run by another git — a hook, a tool a hook starts — is never asked a
question: it shares the terminal of the git that runs it. It applies this
list all the same. pre-commit fetches a hook repository into its cache
inside your first `git commit` (`init`, `remote add`, `fetch`): that
passes; anything else found changed there is refused at once.

One more thing is accepted without a question, on other grounds: the two
pointers `git worktree add`, `move`, `remove` and `prune` write under
`.git/worktrees/`, when gitblocker ran that command itself, in the main
repository, on a state it had just found trusted, and nothing else moved
meanwhile. The same files written by anything else are shown and asked.

### `gh`, `ssh -i`: a `-c` that names a file

A setting given on the command line (`git -c key=value …`) that names a
file you can rewrite puts that file in the fingerprint of that command
only. The command with the `-c` asks about the file ("added"), the next
one without it asks again ("removed"), and so on at every alternation.

`gh` does exactly that: every git it runs over the network gets `-c
credential.helper='!"/opt/homebrew/bin/gh" auth git-credential'`, and a
Homebrew install belongs to you (a `gh` from a distribution package,
owned by root, is silent). Make the setting permanent and the file is in
every command's fingerprint: one question per repository, then nothing,
with or without `gh`.

```sh
gh auth setup-git
```

Same for a script that runs `git -c core.sshCommand='ssh -i ~/.ssh/deploy'
…`: name the key in `~/.ssh/config` (`IdentityFile`) instead, or set
`core.sshCommand` in the repository's config once.

Two settings of your own that keep asking, and what settles them:

- `credential.helper = store --file <f>`: git rewrites `<f>` at every
  credential it saves, and a file the config names is watched. Use the
  helper's default file (`credential.helper = store`), which no config
  names, or a helper that keeps no file (`osxkeychain`, `libsecret`,
  `cache`).
- a global `includeIf "gitdir:~/work/"` whose file sets
  `init.templateDir`: no clone is trusted automatically any more, under
  `~/work/` or elsewhere — gitblocker does not evaluate the condition. Run
  `gitblocker trust` in the clone, as its message says.

Tried on Debian with the system-wide install, on a repository modified
behind the user's back: starship, oh-my-zsh, fish and `__git_ps1` prompts
go quiet with no delay (their git has the terminal: refused at once);
powerlevel10k keeps showing branch and status, since `gitstatusd` reads
`.git` directly and never runs git, which is harmless; lazygit exits with
gitblocker's message, tig says "Not a git repository"; fugitive's `:Git`
shows the refusal after `GITBLOCKER_WAIT` (its first git is a job without a
terminal, which waits); pre-commit's hook runs with the real git, and the
`pre-commit install` that rewrote the hook is what asks for a `trust`.

To try the waiting path by hand, start a git with no controlling terminal.
`nohup` and `&` keep the terminal; `setsid` detaches on Linux, and on macOS,
which has no `setsid`, Python's `start_new_session` does the same:

```sh
cd ~/work/api && printf '#!/bin/sh\necho pwned\n' > .git/hooks/pre-commit
GITBLOCKER_WAIT=300 python3 -c 'import subprocess, sys
subprocess.run(sys.argv[1:], start_new_session=True, stdin=subprocess.DEVNULL,
               stdout=open("/tmp/git.log", "w"), stderr=subprocess.STDOUT)' git status &
gitblocker pending ~/work/api      # decide; then read /tmp/git.log
```

### After upgrading gitblocker

A new version may change what the fingerprint contains; `gitblocker list`
then shows the repositories as "legacy". `gitblocker retrust` re-validates in
bulk the ones that are unchanged and skips the modified ones. Installed at
the same path, the new version is what the exec path's `git` already
links to; nothing else to redo.

### Dotfiles, vcsh, yadm: a gitdir kept apart from its tree

A repository run through `GIT_DIR` / `--git-dir` with a gitdir that is not
the tree's own `.git` — a bare repository of dotfiles with your home
directory as its tree, several vcsh repositories on that one directory —
has its own reference, named by the tree **and** the gitdir. Trust it the
way you run it:

```sh
GIT_DIR=~/.dotfiles.git GIT_WORK_TREE=~ gitblocker trust
```

`gitblocker list` shows it with its gitdir; `forget` and `pending` take the
tree (every repository on it) or the gitdir (that one). If you trusted
such a repository with an earlier version, trust it once more: its
reference was filed under the directory alone, shared by every
repository using that directory.

## Commands

| Command | What it does |
|---|---|
| `gitblocker` | Check the current repository. Exit 1 if suspect or never trusted. |
| `gitblocker trust` | Record the current state as the reference, with a backup of the watched files. Shows the diff first if the repository changed. |
| `gitblocker diff` | Show what differs from the reference. |
| `gitblocker restore [-y]` | Put the watched files back into the reference state. Refused when `.git` no longer leads to the git directory that state was taken from: nothing is written into another repository. |
| `gitblocker git <args>` | Check, then run the real git. Honours `-C`, `--git-dir`, `--work-tree`, `-c`. |
| `gitblocker list` | Registered repositories and their status (ok / modified / structure / missing / legacy / unknown). |
| `gitblocker pending [<repo>… \| -a \| -c <repo>…]` | Decisions waiting for a git blocked by a program: list, review and allow/refuse, or clear. |
| `gitblocker forget <repo>…` / `--missing` | Remove entries; the repository becomes "never trusted" again. `<repo>` is its directory, or its gitdir when kept apart. |
| `gitblocker prune` | Same as `forget --missing`. |
| `gitblocker retrust` | Re-validate unchanged repositories after an upgrade. |
| `gitblocker version` | The version, which is the package's. |
| `gitblocker exec-path [<dir>]` | Build or rebuild an exec path whose `git` is gitblocker, for `GIT_EXEC_PATH` (default `~/.local/lib/gitblocker-exec`). |

Management commands write to stdout (`gitblocker list | grep modified`
works); refusals and diagnostics go to stderr.

## Environment variables

| Variable | Effect |
|---|---|
| `GITBLOCKER_STATE` | State directory (default `$XDG_STATE_HOME/gitblocker`, i.e. `~/.local/state/gitblocker`). Never inside a mounted volume. |
| `GITBLOCKER_REAL_GIT` | Path to the real git (default: a `git.real` next to gitblocker, else the first `git` in the PATH that is not gitblocker itself). Changing the real git changes its system config, hence the fingerprint: one `trust`. |
| `GITBLOCKER_ALLOW_REBASE_EXEC=1` | Allow `exec` lines in rebase todo files, and a merge strategy that is not one of git's builtins (`rebase-merge/strategy`, `sequencer/opts`). |
| `GITBLOCKER_NO_PROMPT=1` | Never ask on the terminal; refuse directly. |
| `GITBLOCKER_WAIT` | Seconds a git without a terminal waits for `gitblocker pending` (default 60, 0 = never). |
| `GITBLOCKER_NO_NOTIFY=1` | No desktop notification. |
| `GITBLOCKER_KEEP_FSMONITOR=1` | Do not pin `core.fsmonitor=false` on the git gitblocker runs. By default gitblocker appends it to `GIT_CONFIG_PARAMETERS`, which outranks every repository's own config: a repository planted in the work tree that git reads in-process (an active submodule, `git grep --recurse-submodules <rev>`) cannot run its fsmonitor hook. Set this to keep a fsmonitor hook or daemon of your own; `trust` then warns when a `submodule.active` pathspec makes that reading possible. |
| `GITBLOCKER_DEBUG=1` | Full traceback on internal errors (otherwise a one-line message, exit 1, git not run). |
| `NO_COLOR` | Disable colours. |

Git's own `GIT_DIR`, `GIT_WORK_TREE`, `GIT_COMMON_DIR`, `GIT_INDEX_FILE`,
`GIT_CEILING_DIRECTORIES` and `GIT_CONFIG_*` are read as git reads them:
the repository checked is the one git opens. A relative `GIT_COMMON_DIR` is
refused (git itself reads it against two different directories in one run).

## What it does not do

- It only covers git invocations that resolve to the wrapper. A tool with a
  hardcoded path to the real git, or started with a `PATH` that does not
  contain the symlink, is not checked (see "You are not the only one running
  git"). A `-c key=value` or a `GIT_INDEX_FILE` given to such a git is
  invisible too.
- It cannot close the race between its check and git's execution if the
  sandbox is still writing. Stop the sandbox before running git on the host.
- It is no substitute for an up-to-date git. A repository you clone that
  exploits a bug of git itself acts inside the git you ran, where gitblocker
  sees nothing.
- `restore` only cleans the pivot vector: objects, commits and tree files
  dropped by the sandbox stay there for you to inspect. It never writes
  outside the repository: a watched file there (`../shared-hooks`) is named
  and left for you.
- Hooks tracked *in the tree* under `core.hooksPath` (husky, `.githooks`)
  are watched, but a `checkout`/`merge`/`pull` of a commit the sandbox
  created rewrites them after the check, and git runs the new version in
  the same command. `gitblocker trust` warns when that layout is in place;
  review incoming changes to those files.
- The `[y/N]` question needs stdout and stderr on a terminal. A shell
  prompt's `$(git …)` or a `git log | head` on a changed repository is
  refused, not asked: rerun without the pipe, or `gitblocker trust`.
- No desktop notification without a session (ssh, cron, systemd): the
  pending record is still written and the wait still times out; check
  `gitblocker pending` by hand.
- Your global config is read for the paths it names, not fingerprinted: a
  `git config --global` that names no file (an alias, a pager) is not seen.
  Whoever could write it could write gitblocker's state directory too.
- Bare repositories are refused, not managed. `core.splitIndex` is refused
  (the gitlinks it needs to read live in `sharedindex.*`).
- Parity with git is checked against git itself in `tests/test_git_parity.py`;
  a gap found there is marked as an expected failure until fixed (none open
  at the moment). Deliberate, fail-closed divergences: a NUL byte or a line
  git dies on in a config file is refused.

`DESIGN.md` holds the design notes, the review method and the catalogue of
the 99 bypasses and false positives found so far (`tests/attacks/`).

## Tests

```sh
python3 -m pytest
```

Needs `pytest` and `git`; `git` is the first one of the `PATH` that is not
gitblocker, or `GITBLOCKER_REAL_GIT`. The suite replays a corpus of attacks against a
trusted repository and checks that each one is refused, that ordinary git
operations are not, and that everything git reads (config syntax, includes,
discovery, index gitlinks) gitblocker reads the same way, with git as the
oracle.

### Supported versions

gitblocker reads a repository the way git does, and each of its readers is
held to git by the suite: a git is supported when the whole suite passes
against it. Every push runs it (`.github/workflows/tests.yml`) on Linux
and macOS against git 2.39, 2.43, 2.47, 2.50 and 2.56, built from
kernel.org by `ci/build-git.sh`; on Debian 12, Debian 13, Ubuntu 24.04
and Ubuntu 26.04 with the distribution's own git and python; and once on
Python 3.9. On the same four distributions it builds the package and
replays its life against the distribution's git (`ci/test-deb.sh`).

gitblocker never asks git its version. Where two supported gits read one
file two ways — a tab between two words of a config value is a space
before 2.45 — it watches what either reads. A git older than 2.39 is not
supported, and one newer than 2.56 is not known until its inventory is
classified (`DESIGN.md`, "Tests").

## License

MIT — see `LICENSE`.
