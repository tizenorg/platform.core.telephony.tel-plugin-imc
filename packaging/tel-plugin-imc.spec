%define major 0
%define minor 1
%define patchlevel 69


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
Requires(post):   /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description
IMC plugin for telephony

%prep
%setup -q

%build
%cmake .
make %{?_smp_mflags}

%post
/sbin/ldconfig
mkdir -p /opt/dbspace

if [ ! -f /opt/dbspace/.mcc_mnc_oper_list.db ]
then
	sqlite3 /opt/dbspace/.mcc_mnc_oper_list.db < /tmp/mcc_mnc_oper_list.sql
fi

rm -f /tmp/mcc_mnc_oper_list.sql

if [ -f /opt/dbspace/.mcc_mnc_oper_list.db ]
then
	chmod 600 /opt/dbspace/.mcc_mnc_oper_list.db
fi
if [ -f /opt/dbspace/.mcc_mnc_oper_list.db-journal ]
then
	chmod 644 /opt/dbspace/.mcc_mnc_oper_list.db-journal
fi

%postun -p /sbin/ldconfig

%install
%make_install
mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}

%files

%defattr(-,root,root,-)

%{_libdir}/telephony/plugins/modems/*
/tmp/mcc_mnc_oper_list.sql
/usr/share/license/%{name}
