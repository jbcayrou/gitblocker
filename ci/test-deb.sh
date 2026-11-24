#!/bin/sh
# The life of the package on a machine, replayed against the distribution's
# own git: install, an upgrade of git, an upgrade of gitblocker, remove,
# purge, the take-over of the README's hand-made install, the removal of
# git itself. After each: either git is wrapped at both names with the
# distribution's binaries intact beside them, or the machine is as if the
# package had never been there — same bytes, no diversion left.
#
# It installs and removes git, as root: in a throwaway container only.
#
#   docker run --rm -v "$PWD":/src:ro debian:13 sh -c \
#       'cp -r /src /w && cd /w && GITBLOCKER_DEB_TEST=throwaway ci/test-deb.sh'
#
# GITBLOCKER_DEB=<file> replays the life of that package instead of one
# built here: the workflow builds the .deb once and hands the same file to
# every distribution, then to the release.
set -eu
if [ "${GITBLOCKER_DEB_TEST:-}" != throwaway ] || [ "$(id -u)" != 0 ]; then
    echo "ci/test-deb.sh installs and removes git: run it as root in a throwaway" >&2
    echo "container, with GITBLOCKER_DEB_TEST=throwaway (see its header)." >&2
    exit 2
fi
here=$(cd "$(dirname "$0")/.." && pwd)
export DEBIAN_FRONTEND=noninteractive
BIN=/usr/bin/git CORE=/usr/lib/git-core/git

say() { printf '\n== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
sum() { sha256sum "$1" | cut -d' ' -f1; }
apt() { apt-get -qy -o Dpkg::Use-Pty=0 "$@" >/tmp/apt.log 2>&1 || { cat /tmp/apt.log >&2; fail "apt-get $*"; }; }
diversions() { dpkg-divert --list | grep -c gitblocker || true; }
as_user() { su user -c "cd /home/user && export GITBLOCKER_STATE=/home/user/state GITBLOCKER_WAIT=0 GITBLOCKER_NO_NOTIFY=1 && $1"; }

wrapped() {      # git is gitblocker at both names, the distribution's binaries beside them
    [ "$(readlink $BIN)" = gitblocker ] || fail "$BIN is not the package's link"
    [ "$(readlink -f $CORE)" = /usr/bin/gitblocker ] || fail "$CORE does not lead to gitblocker"
    [ "$(sum $BIN.real)" = "$real_bin" ] || fail "$BIN.real is not the distribution's git"
    [ "$(sum $CORE.real)" = "$real_core" ] || fail "$CORE.real is not the distribution's git"
    [ "$(diversions)" = 2 ] || fail "expected two diversions: $(dpkg-divert --list)"
    git --version | grep -q '^git version' || fail "git --version"
    # It guards, as a user: a new repository is trusted, a hook planted
    # behind its back refuses the next git, under the dashed name of the
    # exec path too, and `trust` has nothing to say about the exec path.
    rm -rf /home/user/r /home/user/state
    as_user 'git init -q r' 2>&1 | grep -q 'new repository trusted' || fail "git init did not go through gitblocker"
    as_user 'printf "#!/bin/sh\n" > r/.git/hooks/pre-commit && chmod +x r/.git/hooks/pre-commit'
    for g in git /usr/lib/git-core/git-status; do
        if as_user "cd r && $g status" >/tmp/out 2>&1; then fail "$g ran on a changed repository"; fi
        grep -q 'has changed since the last trust' /tmp/out || { cat /tmp/out >&2; fail "$g: not gitblocker's refusal"; }
    done
    as_user 'cd r && gitblocker trust' >/tmp/out 2>&1 || { cat /tmp/out >&2; fail "gitblocker trust"; }
    if grep -q 'does not lead to gitblocker\|stale exec path' /tmp/out; then cat /tmp/out >&2; fail "exec path not wrapped"; fi
    as_user 'cd r && git status' >/dev/null 2>&1 || fail "git refused a trusted repository"
}

pristine() {     # as if the package had never been installed
    for f in $BIN $CORE; do
        [ -f $f ] && [ ! -L $f ] || fail "$f is not a regular file"
        [ ! -e $f.real ] && [ ! -L $f.real ] || fail "$f.real left behind"
    done
    [ "$(sum $BIN)" = "$real_bin" ] && [ "$(sum $CORE)" = "$real_core" ] || fail "git is not the distribution's bytes"
    [ ! -e /usr/bin/gitblocker ] || fail "/usr/bin/gitblocker left behind"
    [ "$(diversions)" = 0 ] || fail "diversion left behind: $(dpkg-divert --list)"
    rm -rf /home/user/r
    if as_user 'git init -q r' 2>&1 | grep -q gitblocker; then fail "git is still gitblocker"; fi
}

say "the distribution's git"
apt update
apt install --no-install-recommends git python3
id user >/dev/null 2>&1 || useradd -m user
[ -f $BIN ] && [ ! -L $BIN ] && [ -f $CORE ] && [ ! -L $CORE ] || fail "expected two regular files: $BIN, $CORE"
real_bin=$(sum $BIN) real_core=$(sum $CORE)
git --version
if [ -n "${GITBLOCKER_DEB:-}" ]; then
    [ -f "$GITBLOCKER_DEB" ] || fail "GITBLOCKER_DEB: no such file: $GITBLOCKER_DEB"
    # A copy apt can read as its unprivileged user, under a name of the
    # form apt takes for a file (a `/` in it).
    mkdir -p /tmp/deb
    cp "$GITBLOCKER_DEB" /tmp/deb/
    deb=/tmp/deb/$(basename "$GITBLOCKER_DEB")
else
    deb=$("$here/ci/build-deb.sh" /tmp/deb)
fi
[ "$(python3 "$here/gitblocker.py" version)" = "gitblocker $(dpkg-deb -f "$deb" Version)" ] || fail "the package's version is not gitblocker's"
next=$(DEB_VERSION=99.0.0 "$here/ci/build-deb.sh" /tmp/deb)
dpkg-deb --info "$deb" | sed -n 's/^ \(Package\|Version\|Depends\|Maintainer\)/\1/p'

say "install"
apt install "$deb"
wrapped

say "git reinstalled by apt (an upgrade of git): dpkg writes at the diverted names"
apt install --reinstall git
wrapped

say "upgrade of gitblocker: the diversions stay"
apt install "$next"
[ "$(dpkg-query -W -f '${Version}' gitblocker)" = 99.0.0 ] || fail "not upgraded"
wrapped

say "remove"
apt remove gitblocker
pristine

say "install, purge"
apt install "$deb"
wrapped
apt purge gitblocker
pristine

say "the README's hand-made install, taken over by the package, then removed"
dpkg-deb --fsys-tarfile "$deb" | tar -xO ./usr/bin/gitblocker > /usr/bin/gitblocker
chmod 755 /usr/bin/gitblocker
dpkg-divert --package gitblocker --add --rename --divert $BIN.real $BIN >/dev/null
ln -s gitblocker $BIN
dpkg-divert --package gitblocker --add --rename --divert $CORE.real $CORE >/dev/null
ln -s /usr/bin/gitblocker $CORE
apt install "$deb"
wrapped
apt remove gitblocker
pristine

say "git removed while gitblocker is installed: both go, nothing is left"
apt install "$deb"
apt remove git
for f in $BIN $BIN.real $CORE $CORE.real /usr/bin/gitblocker; do
    [ ! -e $f ] && [ ! -L $f ] || fail "$f left behind"
done
[ "$(diversions)" = 0 ] || fail "diversion left behind: $(dpkg-divert --list)"
apt install --no-install-recommends git
pristine

say "ok"
