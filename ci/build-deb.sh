#!/bin/sh
# Build the Debian/Ubuntu package of the system-wide install (README):
# gitwary as /usr/bin/git and as /usr/lib/git-core/git, the real ones
# diverted by the maintainer scripts of packaging/deb/.
#
#   ci/build-deb.sh [<outdir>]              default: dist/
#
# A binary package assembled with dpkg-deb, no debhelper: one script, two
# symlinks, two maintainer scripts. The version is gitwary.py's VERSION
# (DEB_VERSION overrides it: ci/test-deb.sh builds a "next" one to upgrade
# to). DEB_MAINTAINER sets the Maintainer field.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-$here/dist}
version=${DEB_VERSION:-$(sed -n 's/^VERSION = "\([0-9.]*\)".*/\1/p' "$here/gitwary.py")}
[ -n "$version" ] || { echo "no VERSION in gitwary.py" >&2; exit 1; }
maintainer=${DEB_MAINTAINER:-gitwary <gitwary@gitwary.invalid>}

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
chmod 755 "$stage"
mkdir -p "$stage/DEBIAN" "$stage/usr/bin" "$stage/usr/lib/git-core" "$stage/usr/share/doc/gitwary"

# The system's python, not the first one of whoever runs git (a pyenv, a
# virtualenv, a PATH directory in a mounted volume).
[ "$(head -n 1 "$here/gitwary.py")" = '#!/usr/bin/env python3' ] \
    || { echo "gitwary.py: unexpected first line" >&2; exit 1; }
{ echo '#!/usr/bin/python3'; tail -n +2 "$here/gitwary.py"; } > "$stage/usr/bin/gitwary"
chmod 755 "$stage/usr/bin/gitwary"
# The two names git is run by: the user's, and the one every git runs its
# children through (DESIGN-exec-path.md). gitwary finds `git.real` next to
# the name it was invoked by.
ln -s gitwary "$stage/usr/bin/git"
ln -s ../../bin/gitwary "$stage/usr/lib/git-core/git"
install -m 644 "$here/README.md" "$stage/usr/share/doc/gitwary/README.md"
install -m 644 "$here/LICENSE" "$stage/usr/share/doc/gitwary/copyright"

size=$(du -sk "$stage/usr" | cut -f1)
sed -e "s|@VERSION@|$version|" -e "s|@MAINTAINER@|$maintainer|" -e "s|@SIZE@|$size|" \
    "$here/packaging/deb/control" > "$stage/DEBIAN/control"
install -m 755 "$here/packaging/deb/preinst" "$here/packaging/deb/postrm" "$stage/DEBIAN/"

mkdir -p "$out"
dpkg-deb --root-owner-group --build "$stage" "$out/gitwary_${version}_all.deb" >/dev/null
echo "$out/gitwary_${version}_all.deb"
