#!/bin/sh
# Build the Debian/Ubuntu package of the system-wide install (README):
# gitblocker as /usr/bin/git and as /usr/lib/git-core/git, the real ones
# diverted by the maintainer scripts of packaging/deb/.
#
#   ci/build-deb.sh [<outdir>]              default: dist/
#
# A binary package assembled with dpkg-deb, no debhelper: one script, two
# symlinks, two maintainer scripts. The version is gitblocker.py's VERSION
# (DEB_VERSION overrides it: ci/test-deb.sh builds a "next" one to upgrade
# to). DEB_MAINTAINER sets the Maintainer field.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-$here/dist}
version=${DEB_VERSION:-$(sed -n 's/^VERSION = "\([0-9.]*\)".*/\1/p' "$here/gitblocker.py")}
[ -n "$version" ] || { echo "no VERSION in gitblocker.py" >&2; exit 1; }
maintainer=${DEB_MAINTAINER:-gitblocker <gitblocker@gitblocker.invalid>}

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
chmod 755 "$stage"
mkdir -p "$stage/DEBIAN" "$stage/usr/bin" "$stage/usr/lib/git-core" "$stage/usr/share/doc/gitblocker"

# The system's python, not the first one of whoever runs git (a pyenv, a
# virtualenv, a PATH directory in a mounted volume).
[ "$(head -n 1 "$here/gitblocker.py")" = '#!/usr/bin/env python3' ] \
    || { echo "gitblocker.py: unexpected first line" >&2; exit 1; }
{ echo '#!/usr/bin/python3'; tail -n +2 "$here/gitblocker.py"; } > "$stage/usr/bin/gitblocker"
chmod 755 "$stage/usr/bin/gitblocker"
# The two names git is run by: the user's, and the one every git runs its
# children through (DESIGN-exec-path.md). gitblocker finds `git.real` next to
# the name it was invoked by.
ln -s gitblocker "$stage/usr/bin/git"
ln -s ../../bin/gitblocker "$stage/usr/lib/git-core/git"
install -m 644 "$here/README.md" "$stage/usr/share/doc/gitblocker/README.md"
install -m 644 "$here/LICENSE" "$stage/usr/share/doc/gitblocker/copyright"

size=$(du -sk "$stage/usr" | cut -f1)
sed -e "s|@VERSION@|$version|" -e "s|@MAINTAINER@|$maintainer|" -e "s|@SIZE@|$size|" \
    "$here/packaging/deb/control" > "$stage/DEBIAN/control"
install -m 755 "$here/packaging/deb/preinst" "$here/packaging/deb/postrm" "$stage/DEBIAN/"

mkdir -p "$out"
# xz, named: Ubuntu's dpkg-deb compresses with zstd by default, which a dpkg
# older than 1.21.18 cannot unpack. The package is the same file whatever
# distribution builds it.
dpkg-deb -Zxz --root-owner-group --build "$stage" "$out/gitblocker_${version}_all.deb" >/dev/null
echo "$out/gitblocker_${version}_all.deb"
