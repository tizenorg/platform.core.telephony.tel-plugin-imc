%define major 0
%define minor 1
%define patchlevel 89

Name:             tel-plugin-imc
Version:          %{major}.%{minor}.%{patchlevel}
Release:          1
License:          Apache-2.0
Summary:          imc-plugin for Telephony
Group:            Development/Libraries
Source0:          tel-plugin-imc-%{version}.tar.gz
BuildRequires:    cmake
BuildRequires:    pkgconfig(glib-2.0)
BuildRequires:    pkgconfig(dlog)
BuildRequires:    pkgconfig(tcore)
BuildRequires:    pkgconfig(db-util)
BuildRequires:    pkgconfig(vconf)
BuildRequires:    pkgconfig(libxml-2.0)
BuildRequires:    pkgconfig(key-manager)
Requires(post):   /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description
IMC plugin for telephony

%prep
%setup -q

%build
%cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix} \
	-DLIB_INSTALL_DIR=%{_libdir}
make %{?_smp_mflags}

%post
/sbin/ldconfig

%postun -p /sbin/ldconfig

%install
%make_install
mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}

%files
%defattr(644,system,system,-)
%{_libdir}/telephony/plugins/modems/*
/usr/share/license/%{name}
