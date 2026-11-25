#!/bin/sh
# Prepare a release: set the version, commit and tag. Pushing the tag
# makes GitHub build the RPM and deb and publish them as a release.
# Usage: tools/release.sh 0.2.0
set -eu
cd "$(dirname "$0")/.."
VERSION=${1:?usage: tools/release.sh VERSION (for example 0.2.0)}
META=data/io.github.subsite.Lanscan.metainfo.xml

case "$VERSION" in
    [0-9]*.[0-9]*.[0-9]*) ;;
    *) echo "Version must look like 1.2.3" >&2; exit 1 ;;
esac
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    echo "Commit or stash your changes first" >&2; exit 1
fi
if git rev-parse -q --verify "refs/tags/v$VERSION" >/dev/null; then
    echo "Tag v$VERSION already exists" >&2; exit 1
fi
python3 -m unittest discover -s tests

sed -i "s/^__version__ = .*/__version__ = \"$VERSION\"/" \
    lanscan/__init__.py
sed -i "s/^version = .*/version = \"$VERSION\"/" pyproject.toml
if ! grep -q "release version=\"$VERSION\"" "$META"; then
    sed -i "s|<releases>|<releases>\n    <release version=\"$VERSION\" date=\"$(date +%F)\"/>|" \
        "$META"
fi
git add lanscan/__init__.py pyproject.toml "$META"
git commit -m "Release $VERSION"
git tag -a "v$VERSION" -m "LAN Scan $VERSION"

echo
echo "Tagged v$VERSION. Publish it with:"
echo "  git push origin $(git branch --show-current) v$VERSION"
