# Built by tools/build-packages.sh, which passes the version.
%{!?version: %global version 0.0.0}
%global app_id io.github.subsite.Lanscan

Name:           lanscan
Version:        %{version}
# No distribution tag: the one package is meant for any RPM system.
Release:        1
Summary:        Graphical overview of the devices on your networks
License:        GPL-3.0-or-later
URL:            https://github.com/subsite/lanscan
Source0:        %{name}-%{version}.tar.gz
BuildArch:      noarch

BuildRequires:  make
BuildRequires:  desktop-file-utils

Requires:       python3 >= 3.10
Requires:       python3-gobject
# Where package names differ, the first is Fedora's (and its
# relatives'), the second openSUSE's.
Requires:       (python3-cairo or python3-gobject-cairo)
Requires:       (gtk4 or typelib(Gtk) = 4.0)
Requires:       (libadwaita >= 1.6 or typelib(Adw) = 1)
Requires:       nmap
Requires:       (iproute or iproute2)
Requires:       iputils
Requires:       polkit
Requires:       hicolor-icon-theme
Recommends:     (avahi-tools or avahi-utils)
# Wi-Fi scanning
Recommends:     NetworkManager
Recommends:     iw
Recommends:     hwdata

%description
LAN Scan shows every device on the networks this computer is connected
to, in a list grouped by network and on a map. Devices are found with
nmap, ping, mDNS and UPnP, and identified by vendor, model, type and
operating system.

%prep
%autosetup

%build

%install
%make_install PREFIX=%{_prefix}

%check
desktop-file-validate %{buildroot}%{_datadir}/applications/%{app_id}.desktop

%files
%license LICENSE
%doc README.md
%{_bindir}/lanscan
%{_datadir}/lanscan/
%{_datadir}/applications/%{app_id}.desktop
%{_datadir}/metainfo/%{app_id}.metainfo.xml
%{_datadir}/icons/hicolor/scalable/apps/%{app_id}.svg
%{_datadir}/polkit-1/actions/%{app_id}.policy
