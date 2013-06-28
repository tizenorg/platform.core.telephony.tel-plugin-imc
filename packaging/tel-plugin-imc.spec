#sbs-git:slp/pkgs/t/tel-plugin-imc
Name:		tel-plugin-imc
Summary:	imc plugin for telephony
Version:	0.1.38
Release:	1
Group:		Development/Libraries
License:	Apache
Source0:	tel-plugin-imc-%{version}.tar.gz
Source1001: 	tel-plugin-imc.manifest
Requires(post):	/sbin/ldconfig
Requires(postun):/sbin/ldconfig
BuildRequires:	cmake
BuildRequires:	pkgconfig(glib-2.0)
BuildRequires:	pkgconfig(dlog)
BuildRequires:	pkgconfig(tcore)
BuildRequires:	pkgconfig(db-util)
BuildRequires:	pkgconfig(libxml-2.0)

%description
IMC plugin for telephony

%prep
%setup -q
cp %{SOURCE1001} .

%build
%cmake .
make %{?jobs:-j%jobs}

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
rm -rf %{buildroot}
%make_install
mkdir -p %{buildroot}/usr/share/license

%files
%manifest %{name}.manifest

%defattr(-,root,root,-)

%{_libdir}/telephony/plugins/modems/*
/tmp/mcc_mnc_oper_list.sql
/usr/share/license/tel-plugin-imc
