# Installs LAN Scan into a system tree. Used by the RPM and deb builds:
#   make install DESTDIR=/tmp/root PYDIR=/usr/lib/python3/dist-packages
PREFIX ?= /usr
PYTHON ?= python3
PYDIR ?= $(shell $(PYTHON) -c \
	"import sysconfig; print(sysconfig.get_path('purelib'))")
ID = io.github.subsite.Lanscan
SHARE = $(DESTDIR)$(PREFIX)/share

.PHONY: install test

test:
	$(PYTHON) -m unittest discover -s tests

install:
	install -d $(DESTDIR)$(PYDIR)/lanscan/icons
	install -m644 lanscan/*.py $(DESTDIR)$(PYDIR)/lanscan
	install -m644 lanscan/icons/*.svg $(DESTDIR)$(PYDIR)/lanscan/icons
	install -Dm755 packaging/lanscan $(DESTDIR)$(PREFIX)/bin/lanscan
	install -Dm644 data/$(ID).desktop -t $(SHARE)/applications
	install -Dm644 data/$(ID).metainfo.xml -t $(SHARE)/metainfo
	install -Dm644 data/$(ID).svg -t $(SHARE)/icons/hicolor/scalable/apps
	install -Dm644 data/$(ID).policy -t $(SHARE)/polkit-1/actions
