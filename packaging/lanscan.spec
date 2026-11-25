# Built by tools/build-packages.sh, which passes the version.
%{!?version: %global version 0.0.0}
%global app_id io.github.subsite.Lanscan

Name:           lanscan
Version:        %{version}
Release:        1%{?dist}
Summary:        Graphical overview of the devices on your networks
License:        GPL-3.0-or-later
URL:            https://github.com/subsite/lanscan
Source0:        %{name}-%{version}.tar.gz
BuildArch:      noarch

BuildRequires:  make
BuildRequires:  python3-rpm-macros
BuildRequires:  desktop-file-utils

Requires:       python3 >= 3.10
Requires:       python3-gobject
Requires:       python3-cairo
Requires:       gtk4
Requires:       libadwaita >= 1.6
Requires:       nmap
Requires:       iproute
Requires:       iputils
Requires:       polkit
Requires:       hicolor-icon-theme
Recommends:     avahi-tools
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
%make_install PREFIX=%{_prefix} PYDIR=%{python3_sitelib}

%check
desktop-file-validate %{buildroot}%{_datadir}/applications/%{app_id}.desktop

%files
%license LICENSE
%doc README.md
%{_bindir}/lanscan
%{python3_sitelib}/lanscan/
%{_datadir}/applications/%{app_id}.desktop
%{_datadir}/metainfo/%{app_id}.metainfo.xml
%{_datadir}/icons/hicolor/scalable/apps/%{app_id}.svg
%{_datadir}/polkit-1/actions/%{app_id}.policy
