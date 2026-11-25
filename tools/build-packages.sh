#!/bin/sh
# Build installable packages into dist/. Usage:
#   tools/build-packages.sh rpm     needs rpm-build
#   tools/build-packages.sh deb     needs dpkg-deb
set -eu
cd "$(dirname "$0")/.."
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' pyproject.toml)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p dist

build_rpm() {
    top=$WORK/rpm
    mkdir -p "$top/SOURCES" "$top/tmp"
    tar --exclude=__pycache__ --transform "s,^,lanscan-$VERSION/," \
        -czf "$top/SOURCES/lanscan-$VERSION.tar.gz" \
        Makefile README.md LICENSE pyproject.toml lanscan data packaging
    rpmbuild -bb --define "_topdir $top" \
        --define "_tmppath $top/tmp" \
        --define "version $VERSION" packaging/lanscan.spec
    cp "$top"/RPMS/noarch/*.rpm dist/
}

build_deb() {
    root=$WORK/deb
    make install DESTDIR="$root" \
        PYDIR=/usr/lib/python3/dist-packages
    mkdir -p "$root/DEBIAN" "$root/usr/share/doc/lanscan"
    printf '%s\n' "LAN Scan, by SubSite" \
        "Source: https://github.com/subsite/lanscan" \
        "License: GPL-3.0-or-later" \
        "See /usr/share/common-licenses/GPL-3 for the full text." \
        > "$root/usr/share/doc/lanscan/copyright"
    sed "s/@VERSION@/$VERSION/" packaging/control.in \
        > "$root/DEBIAN/control"
    dpkg-deb --root-owner-group --build "$root" \
        "dist/lanscan_${VERSION}_all.deb"
}

case "${1:-}" in
    rpm) build_rpm ;;
    deb) build_deb ;;
    *) echo "usage: $0 rpm|deb" >&2; exit 1 ;;
esac
ls -l dist/
