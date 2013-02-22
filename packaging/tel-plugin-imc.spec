#sbs-git:slp/pkgs/t/tel-plugin-imc
Name:		tel-plugin-imc
Summary:	imc plugin for telephony
Version:	0.1.36
Release:	2
Group:		Development/Libraries
License:	Apache
Source0:	tel-plugin-imc-%{version}.tar.gz
Requires(post):	/sbin/ldconfig
Requires(postun):/sbin/ldconfig
BuildRequires:	cmake
BuildRequires:	pkgconfig(glib-2.0)
BuildRequires:	pkgconfig(dlog)
BuildRequires:	pkgconfig(tcore)
BuildRequires:	pkgconfig(db-util)
BuildRequires:	pkgconfig(libxml-2.0)
BuildRequires:  pkgconfig(vconf)
%ifarch %ix86
%if "%{simulator}" != "1"
patch0: 0001-desc-CP-name-is-imc-pr3-for-Intel-device.patch
patch1: 0002-s_modem-CGMR-response-parsing-is-compatible-with-IMC.patch
patch2: 0003-s-modem-Cleanup.patch
patch3: 0004-s-modem-Add-notification-hook-for-SIM-status.patch
patch4: 0005-s-sim-Query-SIM-state-when-modem-is-powered-up.patch
patch5: 0006-common-Fix-warning-errors.patch
patch6: 0007-s_sim-Get-the-SIM-type-when-SIM-is-ready.patch
patch7: 0008-Fix-SCA-service-center-address-length-checking-error.patch
patch8: 0009-s_modem-Add-XGENDATA-query-to-get-firmware-informati.patch
patch9: 0010-s_sim-Extend-XSIMSTATE-parsing-to-get-SMS-service-st.patch
patch10: 0011-set-modem-power-saving-mode.patch
patch11: 0012-Fix-EFsmsp-size-error.patch
patch12: 0013-s_call-use-hal-set-sound-path-function.patch
patch13: 0014-Add-core-objects-and-link-them-to-HAL.patch
patch14: 0015-Change-the-way-imc-plugin-is-initialized.patch
patch15: 0016-s_ps-Remove-plateform-dependencies-to-setup-pdp-cont.patch
patch16: 0017-Fix-the-issue-that-system-is-waken-up-by-modem-frequ.patch
patch17: 0018-Configure-modem-I2s1-to-8khz-mono-if-routing-to-blue.patch
patch18: 0019-s_sat.c-Fix-envelope-cmd-and-enable-Setup-Event-List.patch
patch19: 0020-s_sim.c-Fix-get-lock-info.patch
patch20: 0021-s_sim-Fix-multiple-sim-facility-status-query.patch
patch21: 0023-s_network.c-By-default-display-the-plmn-in-case-SPN-.patch
patch22: 0024-Use-plugin-mfld-blackbay.patch 
patch23: 0025-Fix-integration-issue.patch
%endif
%endif

%description
IMC plugin for telephony

%prep
%setup -q
%ifarch %ix86
%if "%{simulator}" != "1"
%patch0 -p1
%patch1 -p1
%patch2 -p1
%patch3 -p1
%patch4 -p1
%patch5 -p1
%patch6 -p1
%patch7 -p1
%patch8 -p1
%patch9 -p1
%patch10 -p1
%patch11 -p1
%patch12 -p1
%patch13 -p1
%patch14 -p1
%patch15 -p1
%patch16 -p1
%patch17 -p1
%patch18 -p1
%patch19 -p1
%patch20 -p1
%patch21 -p1
%patch22 -p1
%patch23 -p1
%endif
%endif

%build
cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix}
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

%defattr(-,root,root,-)

%{_libdir}/telephony/plugins/*
/tmp/mcc_mnc_oper_list.sql
/usr/share/license/tel-plugin-imc
