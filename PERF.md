# Performance

Overhead of `gitblocker git <cmd>` over a plain `git <cmd>`, measured on
2026-10-17 at commit `73b0d1c`.

Re-checked on 2026-10-19 with the current code (pending decisions, real git
resolved from the PATH): same overhead within 3 ms on the small repository,
head to head against the `73b0d1c` script on the same machine state. The
tables below are the original measurements.

Re-checked on 2026-10-25 after the fixes of [86]–[99] (global values read
again in each submodule, hard-link and FIFO checks, sparse directories):
`gitblocker` alone, median of 25, against the previous commit on the same
machine state — 39.4 → 40.4 ms on a one-file repository, 62.5 → 64.9 ms on
one with 10 submodules and a global config of 30 aliases and a config hook.

Where it stands now: **+50 ms per command** on the same machine
("2026-11-24: where the overhead stands", below), about 23 ms of it the
compilation of the script at every start. The dated sections say what
each change moved; the tables of 2026-10-17 are kept as measured.

## Child gits (DESIGN-exec-path.md)

With gitblocker at git's exec path, every child git is gitblocker too. On the
Debian VM (git 2.47.3, python 3.13), a trusted one-file repository, the
same gitblocker as parent and child, median of 15 (2026-10-26):

| command                          | raw children | wrapped children |
|----------------------------------|-------------:|-----------------:|
| `log -1` (no child)              | 26 ms        | 26 ms            |
| `commit` (one child: maintenance)| 26 ms        | 50 ms            |
| alias `!git log` (one child)     | 26 ms        | 50 ms            |
| alias with three children        | 27 ms        | 101 ms           |

About 25 ms per child on the VM: the interpreter's start (the inheriting
child skips the check itself). `pull` has two or three children, `status`
one per submodule, `submodule foreach` one per submodule plus the command's.

Re-measured on 2026-10-27 after the marker was redone ([101]–[112]: pid
lifetime through `/proc`, coverage by `gitdir_roots`, an `iterdir` of
`modules/` and `worktrees/` per child): 26 / 51 / 51 / 101 ms, the same
table within noise.

Taken again on 2026-11-24 on macOS (M4 Pro, git 2.50.0, python 3.14;
`children.py` below, median of 15):

| command                          | raw children | wrapped children |
|----------------------------------|-------------:|-----------------:|
| `log -1` (no child)              | 58 ms        | 59 ms            |
| `commit` (one child: maintenance)| 68 ms        | 119 ms           |
| alias `!git log` (one child)     | 69 ms        | 118 ms           |
| alias with three children        | 84 ms        | 234 ms           |

About 50 ms per child there: a child pays the interpreter's start and
the compilation of the script, as its parent does, and skips the check.

## Environment

- Apple M4 Pro, macOS (Darwin 27.0), APFS
- git 2.50.0 (Homebrew), used both directly and as `GITBLOCKER_REAL_GIT`
- Python 3.14 (Homebrew), gitblocker.py stdlib only
- Isolated state directory (`GITBLOCKER_STATE`), repository trusted before
  the measurements, `NO_COLOR=1`
- Median of N runs per command (`subprocess.run` from Python, process
  start included)

## Linux kernel (shallow clone)

`git clone --depth 1` of torvalds/linux from kernel.org: 96 080 tracked
files, 6 285 directories, ~10 MB index. N = 10.

| command          | git     | gitblocker git | overhead |
|------------------|--------:|-------------:|---------:|
| `status`         | 247 ms  | 293 ms       | +46 ms   |
| `log -1`         |   6 ms  |  52 ms       | +46 ms   |
| `rev-parse HEAD` |   4 ms  |  49 ms       | +45 ms   |
| `diff --stat`    | 125 ms  | 172 ms       | +48 ms   |
| `branch`         |   5 ms  |  50 ms       | +45 ms   |

`gitblocker` alone (check, no git): 49 ms.

Index cache invalidated (`<key>.idx` removed, i.e. right after a command
that rewrote the 10 MB index): check at 80–90 ms instead of 45 ms, once;
the next command is back to 45 ms. Since [55] the same parse also checks
every entry name (port of git's verify_path): +30 ms on 96k synthetic
kernel-like names (ten substring scans of the 2.6 MB joined names, the
full port only on the names they flag), so ~110–120 ms once after an
index rewrite, cached afterwards.

## Small repository (gitblocker itself)

~30 files. N = 15.

| command          | git   | gitblocker git | overhead |
|------------------|------:|-------------:|---------:|
| `status`         | 5 ms  | 48 ms        | +43 ms   |
| `log -1`         | 5 ms  | 46 ms        | +40 ms   |
| `rev-parse HEAD` | 4 ms  | 45 ms        | +41 ms   |
| `diff --stat`    | 4 ms  | 45 ms        | +41 ms   |
| `branch`         | 5 ms  | 45 ms        | +41 ms   |

`gitblocker` alone: 45 ms.

### Same on Linux (Debian 13, VM)

Debian 13 aarch64 in a VM on the same machine, ext4, Python 3.13.5
(system), git 2.47.3, system-wide install (`/usr/bin/git → gitblocker`, real
git at `git.real`). Small repository, N = 20, 2026-10-19.

| command          | git   | gitblocker git | overhead |
|------------------|------:|-------------:|---------:|
| `status`         | 1 ms  | 27 ms        | +26 ms   |
| `log -1`         | 0 ms  | 27 ms        | +26 ms   |
| `rev-parse HEAD` | 0 ms  | 26 ms        | +26 ms   |

`gitblocker` alone: 29 ms; Python floor 16 ms. Same shape as macOS: the
interpreter's startup is most of it, Linux starts it twice as fast.

## 2026-10-21: imports trimmed

Same machine, small repository, N = 60, `rev-parse HEAD`: overhead 44 ms →
33 ms. The modules only `trust`, `restore`, `pending` and the prompt need
(`subprocess`, `shutil`, `difflib`, `termios`, `fcntl`, `dataclasses` — the
last one pulls `inspect`) are imported where used; the four former
dataclasses are written out. Import floor of the top-level modules 34 → 22
ms (bare interpreter 16.5 ms).

What remains, measured apart: bare interpreter 16 ms, imports 6 ms,
**compiling gitblocker.py 15 ms** — a script run by path is compiled on every
run, only an imported module gets a cached `.pyc` —, gitblocker's own work
~2 ms. A two-file layout (a three-line launcher importing the module, whose
`.pyc` is cached) measured 25.6 ms against 37.3 ms for the script, i.e.
overhead 21 ms. `python3 -S` (no `site`) saves 5 ms on `python3 -c pass`
but under 1 ms on a gitblocker command: not worth an `env -S` shebang.

Re-measured on 2026-10-22, both versions head to head, small repository,
N = 30, all five commands within 0.5 ms of each other:

| machine                          | before  | after   | `python3 -c pass` |
|----------------------------------|--------:|--------:|------------------:|
| macOS, M4 Pro, Python 3.14.6     | +46 ms  | +35 ms  | 15 ms             |
| Debian 13 VM, aarch64, Python 3.13.5 | +27 ms | +20 ms | 4 ms             |

`gitblocker` alone: 50 → 37 ms on macOS, 30 → 22 ms on the VM.

## 2026-10-22: fixes [58]–[65]

`gitblocker` alone (plain check), before and after the fixes of [58]–[65],
head to head, N = 30, median; the A/B script is under "Reproducing":

| machine, repository                         | before  | after   |
|---------------------------------------------|--------:|--------:|
| macOS, small repository (gitblocker itself) | 38.0 ms | 39.5 ms |
| macOS, 40 shell aliases in the config       | 47.9 ms | 41.8 ms |
| Debian VM, small repository                 | 22.0 ms | 23.1 ms |
| Debian VM, 40 shell aliases in the config   | 28.5 ms | 26.1 ms |

The +1 ms on a small repository: a longer script to compile, the
repository format read once more for the index (`object_id_size`, [63]),
the submodules' trees ([60]). The sh readings of [58] add tokens, and
every token cost a `resolve()`: an alias-heavy config produced 1248
tokens for 35 distinct ones. Resolved once per base now, which more than
pays for the readings.

## 2026-10-23: fixes [66]–[70], [72], [73], [75], [76]

`gitblocker` alone (plain check), `ca23feb` (the previous measurement) against
`606c09e`, head to head, N = 60, median, two rounds each (the A/B script
under "Reproducing"):

| machine, repository                         | before  | after   |
|---------------------------------------------|--------:|--------:|
| macOS, small repository (gitblocker itself) | 40.4 ms | 41.4 ms |
| macOS, 40 shell aliases in the config       | 42.8 ms | 43.5 ms |
| Debian VM, small repository                 | 30.0 ms | 30.7 ms |
| Debian VM, 40 shell aliases in the config   | 29.9 ms | 30.7 ms |

+0.7 to +1 ms. Compiling the script accounts for most of it: 153 → 164 KB,
12.7 → 13.5 ms (macOS, median of 30 `compile()`). The rest is a handful
of `stat` calls: the remote's gitdir as a second base for global
`core.hooksPath` ([68]), the symlink chain of a config path ([75]), and
reading `alias.*` values for the command word ([66]) — shell aliases return
at the first character. Absolute figures differ from the 2026-10-22 table
(machine state, the VM's load); only the head-to-head column pair is
comparable.

## 2026-10-24: design review follow-ups ([84], [85], the default switch, ConfigScan)

`gitblocker` alone (plain check), `28309e3` (before the four commits of the
review) against the working tree after them, head to head, N = 60,
median, two rounds each, macOS, small repository (a clone of gitblocker):

| round | before  | after   |
|-------|--------:|--------:|
| 1     | 44.5 ms | 44.5 ms |
| 2     | 44.8 ms | 44.7 ms |

Unchanged. The script grew 177 → 180 KB (ConfigScan's and
_core_worktree's docstrings) and lost the Levenshtein port; the check
does the same stat calls as before, in the same order (`inspect` only
names the pipeline). Not measured on the Debian VM (down that day).

## 2026-11-02: eighteenth adversarial pass ([134]–[142])

`check_links_into_gitdir` now judges every `wt` and `ext` entry of the
manifest, not the `ext` ones only: one `os.stat` plus one `realpath` per
entry (the hooks of a `core.hooksPath`, the included files), the gitdir
walk still only when an entry has two names. Measured in isolation on
macOS: 100 entries (50 files, 50 symlinks) cost 3.7 ms, i.e. ~37 µs per
entry; a repository has a few to a few dozen such entries, under 1 ms.
The rest of the pass adds `try/except` around reads that already
happened and a presence test on two environment variables: nothing
measurable. Not re-measured end to end.

## 2026-11-13: alternates ([156])

Every check now looks for `objects/info/alternates` in each gitdir root
(one failed `open` where there is none, the common case) and, where a
repository borrows objects, hashes the mirror's `config` and `hooks/` as it
does a local remote's. A/B of the plain check (`ab.py` below, N = 40,
macOS, a clone of gitblocker, which has one local remote):

|                                             | before  | after   |
|---------------------------------------------|---------|---------|
| small repository                            | 52.0 ms | 52.9 ms |
| the same, `clone --reference <bare mirror>` | 49.8 ms | 52.3 ms |

Under 1 ms where nothing is borrowed, about half of it the longer script
to compile; +2.5 ms with one mirror (its config and the fourteen sample
hooks of a `clone --mirror`). What the fix gives back is not in the
table: the clone no longer downloads what the mirror holds.

The state key of [157] costs one `stat` and one `resolve` per check, to
tell whether the gitdir is the one `<directory>/.git` leads to: within
the noise of the same A/B (53.1–53.8 ms before, 53.7–53.8 ms after).

## 2026-11-13: a very large config ([162])

The config reader is a port of git's parser, character by character
(`_Src.get`, one Python call per character): it is the price of reading
every byte as git does. Plain check, macOS, an included file of 8 MB in
a small repository (40 ms with that file empty):

| the 8 MB are                      | gitblocker | git (`config --get-all`) |
|-----------------------------------|----------|--------------------------|
| `key = value` lines (150 000)     | 2.85 s   | 0.06 s                   |
| comment lines                     | 0.54 s   | 0.05 s                   |
| one comment line                  | 0.53 s   | 0.04 s                   |
| `[branch "…"]` sections (93 000)  | 3.49 s   | 0.05 s                   |

About 3 MB a second on ordinary lines. The sizes people have: 100 KB
(1 166 tracked branches) costs 50 ms more per command, 1 MB (11 651)
0.45 s. For the branch sections more than half of the time is not the
parser: `_local_remote` is asked once per `branch.<n>.remote = origin`,
a score of `stat` each for the same answer; memoised per URL in a
prototype, 1 166 branches go from 70 to 40 ms and 11 651 from 450 to
150 ms. Not done: kept for the next work on `ConfigScan`. No ceiling on
the size ([162], DESIGN.md, Known limitations).

## 2026-11-16: the marker of a clone ([163])

A child of a clone in progress is covered when its gitdir is a gitdir
root of the one the clone creates: an `iterdir` of that gitdir's
`modules/` per child, as for a judged repository, where the former rule
compared three paths. `git clone --recurse-submodules` of a superproject
with 30 submodules over `file://` (`clone.py` below, median of 7, macOS,
git 2.50):

|                    | before  | after   |
|--------------------|---------|---------|
| the real git alone | 2.27 s  |         |
| behind gitblocker  | 16.48 s | 16.55 s |

+0.07 s over some 220 child gits, a third of a millisecond each. The
14 s over the real git are those children's interpreter starts, before
as after ("Child gits" above): about seven per submodule.

## 2026-11-24: the global config is not read ([179])

The scan no longer parses the system and global config files, nor hashes
what they name (a global hooks directory, an include, an alias's
script). A/B of the plain check (`ab.py` below, N = 40, macOS, a clone of
gitblocker, `HOME` set to a directory holding the global config of each
row):

| the global config                                                      | before  | after   |
|------------------------------------------------------------------------|---------|---------|
| two keys (`user.name`, `user.email`)                                   | 52.4 ms | 52.8 ms |
| 47 keys: 40 shell aliases, a hooks directory of four hooks, an include | 58.1 ms | 53.0 ms |

+0.4 ms on a bare global config, the longer script to compile; about
5 ms less per command on a loaded one, the parse of its values and the
candidates each alias word was (a `resolve()` per distinct token, [58]).
The check no longer depends on what `~/.gitconfig` holds; the push
check and the auto-accept of a remote read it, on those commands only.

## 2026-11-24: where the overhead stands

The figure quoted by README.md and DESIGN.md (~33 ms) dated from
2026-10-21 and had not been taken again. The bench of "Reproducing" on
the machine of "Environment" (git 2.50.0, python 3.14.6), a clone of
gitblocker, N = 40:

| command          | git   | gitblocker git | overhead |
|------------------|------:|---------------:|---------:|
| `status`         | 5 ms  | 56 ms          | +50 ms   |
| `log -1`         | 5 ms  | 56 ms          | +51 ms   |
| `rev-parse HEAD` | 4 ms  | 54 ms          | +50 ms   |
| `diff --stat`    | 4 ms  | 54 ms          | +50 ms   |
| `branch`         | 5 ms  | 55 ms          | +50 ms   |

`gitblocker` alone: 51 ms; the floor that bench prints, 31 ms, is the one
of 2026-10-17 (it imports what the script imported at top level then).
Where the time goes now (`where.py` below, N = 40, each line the
difference with the one above; 52.1 ms in all):

| step                                                              | cost    |
|-------------------------------------------------------------------|--------:|
| bare interpreter (`python3 -c pass`)                              | 14.9 ms |
| the top-level imports                                             | 5.6 ms  |
| `gitblocker.py` compiled (6 431 lines) and its body run (`version`) | 25.1 ms |
| the check                                                         | 6.5 ms  |

The same code imported from a cached `.pyc` is there in 22.8 ms, where
the script run by path takes 45.6 ms before any check: about 23 ms of
compilation, paid at every start, by the command and by each child git
(the table of "Child gits": about 50 ms a child). On 2026-10-21 the
plain check took 37 ms: the script was 3 151 lines and 15 ms to compile,
it has doubled; its own work was put at ~2 ms then, ~6 ms now. The two-file
layout measured that day (a launcher importing the module, whose `.pyc`
is cached) saved 12 ms then and would save about 23 ms now.

## Where the time goes (2026-10-17 figures)

| component                                             | cost            |
|-------------------------------------------------------|----------------:|
| Python startup + stdlib imports (`python floor`)      | 32 ms           |
| gitblocker's own work on a small repository           | ~13 ms          |
| extra on the kernel (gitdir hashing, `.idx` read)     | ~4 ms           |
| index re-parse when the index changed (10 MB, cached) | +40 ms, once    |
| entry-name check on that re-parse (verify_path, [55])  | +30 ms, once    |
| config parser (port of git's config.c), 17 KB config  | ~2 ms           |

Conclusions:

- The overhead is a constant ~45 ms per command, independent of the
  repository size; 70 % of it is the interpreter's startup. A compiled
  rewrite would bring it to a few ms.
- The config parser is invisible at this scale.
- Nothing walks the work tree. An opt-in tree scan (`GITBLOCKER_SCAN_TREE`,
  looking for undeclared nested `.git`) existed when these measurements
  were taken: +210 ms on the kernel, +165 ms of it in `readdir` (APFS
  serialises it; a C `find` was slower, 8 threads 3× slower), for an early
  warning the gitlink check already gives. It was removed on 2026-10-18;
  see DESIGN.md, "Nested repositories".

## Reproducing

```python
"""Raw git vs gitblocker git on a repository. Median of N runs, ms."""
import os, statistics, subprocess, sys, time
repo, n = sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 15
GB = os.path.abspath("gitblocker.py")
GIT = "/opt/homebrew/bin/git"
state = os.path.abspath("bench-state")
env = dict(os.environ, GITBLOCKER_REAL_GIT=GIT, GITBLOCKER_STATE=state, NO_COLOR="1")

def run(cmd):
    ts = []
    for _ in range(n):
        t = time.perf_counter()
        r = subprocess.run(cmd, cwd=repo, env=env, capture_output=True)
        ts.append((time.perf_counter() - t) * 1000)
        assert r.returncode == 0, (cmd, r.stderr[-500:])
    return statistics.median(ts)

subprocess.run([sys.executable, GB, "trust"], cwd=repo, env=env, capture_output=True, check=True)
cases = [("status", ["status"]), ("log -1", ["log", "-1"]), ("rev-parse HEAD", ["rev-parse", "HEAD"]),
         ("diff --stat", ["diff", "--stat"]), ("branch", ["branch"])]
print(f"{'command':18} {'git':>10} {'gitblocker git':>14} {'overhead':>10}")
for name, args in cases:
    raw = run([GIT, *args])
    gb = run([sys.executable, GB, "git", *args])
    print(f"{name:18} {raw:8.0f}ms {gb:12.0f}ms {gb - raw:+8.0f}ms")
print(f"{'gitblocker (check)':18} {'':>10} {run([sys.executable, GB]):12.0f}ms")
floor = run([sys.executable, "-c", "import difflib,hashlib,json,os,re,shlex,shutil,stat,subprocess,sys,time,dataclasses,functools,pathlib"])
print(f"{'python floor':18} {'':>10} {floor:12.0f}ms")
```

Run from the gitblocker checkout: `python3 bench.py <repo> [N]`. A/B of two copies of the script (the "before
and after" tables), from the repository to measure:

```python
"""A/B of `gitblocker` (plain check) for two copies of gitblocker.py, in the cwd's
repository, isolated state. usage: ab.py old.py new.py [N]"""
import os, statistics, subprocess, sys, tempfile, time
old, new = sys.argv[1], sys.argv[2]
n = int(sys.argv[3]) if len(sys.argv) > 3 else 30
env = {**os.environ, "GITBLOCKER_STATE": tempfile.mkdtemp(), "GITBLOCKER_NO_NOTIFY": "1"}
for name, path in [("before", old), ("after", new)] * 2:
    subprocess.run([sys.executable, path, "trust"], env=env, capture_output=True)
    ts = []
    for _ in range(n):
        t = time.perf_counter()
        r = subprocess.run([sys.executable, path], env=env, capture_output=True)
        ts.append(time.perf_counter() - t)
    print(f"{name:7} rc={r.returncode} median {statistics.median(ts) * 1000:.1f} ms")
```

`old.py` from `git show <commit>:gitblocker.py` (the script had another
name before 2026-11-24: `git ls-tree --name-only <commit>` says which).
Where one check goes, from the repository to measure:

```python
"""Where one `gitblocker` check goes: the interpreter, the top-level imports, the script compiled and its
body run (`version`, which reads no repository), the check. Each line is a python started with one more
thing to do; a step costs the difference. Last line: the same code imported from a cached `.pyc`, i.e.
without the compilation. From the repository to measure. usage: where.py <gitblocker.py> [N]"""
import ast, os, shutil, statistics, subprocess, sys, tempfile, time
gb, n = os.path.abspath(sys.argv[1]), int(sys.argv[2]) if len(sys.argv) > 2 else 40
env = {**os.environ, "GITBLOCKER_STATE": tempfile.mkdtemp(), "GITBLOCKER_NO_NOTIFY": "1"}
body = ast.parse(open(gb).read()).body      # module level: what every command imports
mods = sorted({a.name for node in body if isinstance(node, ast.Import) for a in node.names}
              | {node.module for node in body if isinstance(node, ast.ImportFrom) and node.module != "__future__"})
cached = tempfile.mkdtemp()
shutil.copy(gb, os.path.join(cached, "gbmod.py"))

def run(*cmd, cwd=None):
    ts = []
    for _ in range(n):
        t = time.perf_counter()
        subprocess.run([sys.executable, *cmd], env=env, cwd=cwd, capture_output=True, check=True)
        ts.append((time.perf_counter() - t) * 1000)
    return statistics.median(ts)

subprocess.run([sys.executable, gb, "trust"], env=env, capture_output=True, check=True)
run("-c", "import gbmod", cwd=cached)       # writes the .pyc
steps = [("bare interpreter", run("-c", "pass")), ("+ top-level imports", run("-c", "import " + ",".join(mods))),
         ("+ script compiled, body run", run(gb, "version")), ("+ the check", run(gb))]
prev = 0.0
for name, t in steps:
    print(f"{name:30} {t - prev:6.1f} ms")
    prev = t
print(f"{'= gitblocker (check)':30} {prev:6.1f} ms")
print(f"{'imported from a cached .pyc':30} {run('-c', 'import gbmod', cwd=cached):6.1f} ms   (against {steps[2][1]:.1f})")
```

The "Child gits" table, with a copy of the script (it is made executable):

```python
"""The "Child gits" table: a trusted one-file repository, the same gitblocker as parent and child, raw
children against wrapped ones (an exec path whose `git` is the script, as tests/conftest.py builds it).
usage: children.py <scratch dir> <gitblocker.py> [N]"""
import os, statistics, subprocess, sys, time
from pathlib import Path
work, gb = Path(sys.argv[1]).resolve(), os.path.abspath(sys.argv[2])
n = int(sys.argv[3]) if len(sys.argv) > 3 else 15
GIT = "/opt/homebrew/bin/git"
core = Path(subprocess.run([GIT, "--exec-path"], capture_output=True, text=True).stdout.strip())
os.chmod(gb, 0o755)      # the exec path's `git` is run by git

def exec_path(name, git, real=None):
    d = work / f"exec-{name}"
    d.mkdir(parents=True)
    for e in os.listdir(core):
        if e != "git":
            os.symlink("git" if (core / e).resolve() == (core / "git").resolve() else core / e, d / e)
    os.symlink(git, d / "git")
    if real:
        os.symlink(real, d / "git.real")
    return str(d)

raw, wrapped = exec_path("raw", core / "git"), exec_path("wrapped", gb, core / "git")
env = {"PATH": os.environ["PATH"], "HOME": str(work), "GIT_CONFIG_NOSYSTEM": "1", "GITBLOCKER_REAL_GIT": GIT,
       "GITBLOCKER_STATE": str(work / "state"), "GITBLOCKER_NO_NOTIFY": "1", "GIT_EXEC_PATH": raw}
repo = work / "repo"
subprocess.run([GIT, "init", "-q", str(repo)], env=env, check=True, capture_output=True)
for args in (["config", "user.email", "t@t"], ["config", "user.name", "t"], ["config", "alias.l", "!git log -1"],
             ["config", "alias.three", "!git log -1 && git log -1 && git log -1"],
             ["commit", "-q", "--allow-empty", "-m", "init"]):
    subprocess.run([GIT, *args], cwd=repo, env=env, check=True, capture_output=True)
subprocess.run([sys.executable, gb, "trust"], cwd=repo, env=env, check=True, capture_output=True)

def run(args, ep):
    ts = []
    for _ in range(n):
        t = time.perf_counter()
        subprocess.run([sys.executable, gb, "git", *args], cwd=repo, env={**env, "GIT_EXEC_PATH": ep},
                       check=True, capture_output=True)
        ts.append((time.perf_counter() - t) * 1000)
    return statistics.median(ts)

for name, args in [("log -1 (no child)", ["log", "-1"]),
                   ("commit (one child: maintenance)", ["commit", "-q", "--allow-empty", "-m", "x"]),
                   ("alias !git log (one child)", ["l"]), ("alias with three children", ["three"])]:
    print(f"{name:34} raw {run(args, raw):4.0f} ms   wrapped {run(args, wrapped):4.0f} ms")
```

A recursive clone, the
real git alone then behind each copy, child gits included:

```python
"""Wall time of `git clone --recurse-submodules` of a superproject with N submodules over file://: the
real git alone, then behind each gitblocker.py given, its children too (an exec path whose `git` is that
script, as tests/conftest.py builds it). usage: clone.py <scratch dir> <N> <rounds> <label=gitblocker.py>..."""
import os, shutil, statistics, subprocess, sys, time
from pathlib import Path
work, n, rounds = Path(sys.argv[1]).resolve(), int(sys.argv[2]), int(sys.argv[3])
GIT = "/opt/homebrew/bin/git"
core = Path(subprocess.run([GIT, "--exec-path"], capture_output=True, text=True).stdout.strip())
base = {"PATH": os.environ["PATH"], "HOME": str(work), "GIT_CONFIG_NOSYSTEM": "1"}

def exec_path(name, git):
    d = work / f"exec-{name}"
    d.mkdir(parents=True)
    for e in os.listdir(core):
        if e != "git":
            os.symlink("git" if (core / e).resolve() == (core / "git").resolve() else core / e, d / e)
    os.symlink(git, d / "git")
    return {**base, "GIT_EXEC_PATH": str(d)}

raw = exec_path("raw", GIT)
def git(*args, cwd=None):
    subprocess.run([GIT, *args], cwd=cwd, env=raw, check=True, capture_output=True)
for k, v in [("user.email", "t@t"), ("user.name", "t"), ("protocol.file.allow", "always")]:
    git("config", "--global", k, v)
top = work / "top"
git("init", "-q", str(top))
for i in range(n):
    s = work / f"s{i}"
    git("init", "-q", str(s))
    git("commit", "-q", "--allow-empty", "-m", "s", cwd=s)
    git("submodule", "add", "-q", f"file://{s}", f"libs/s{i}", cwd=top)
git("commit", "-qm", "top", cwd=top)
runs = {"git": ([GIT], raw)}
for label, gb in (a.split("=", 1) for a in sys.argv[4:]):
    gb = os.path.abspath(gb)
    os.chmod(gb, 0o755)      # the exec path's `git` is run by git: not executable, the children are the PATH's git
    runs[label] = ([sys.executable, gb, "git"], {**exec_path(label, gb), "GITBLOCKER_REAL_GIT": GIT,
                   "GITBLOCKER_STATE": str(work / f"state-{label}"), "GITBLOCKER_NO_NOTIFY": "1"})
times = {k: [] for k in runs}
for _ in range(rounds):
    for label, (argv, env) in runs.items():
        t = time.perf_counter()
        subprocess.run([*argv, "clone", "-q", "--recurse-submodules", f"file://{top}", str(work / "dst")],
                       env=env, check=True, capture_output=True)
        times[label].append(time.perf_counter() - t)
        shutil.rmtree(work / "dst")
for label, ts in times.items():
    print(f"{label:8} median {statistics.median(ts):6.2f} s")
```

For the
kernel: `git clone --depth 1
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git`
(a few minutes, 2 GB; the GitHub mirror may hang on `info/refs`).
