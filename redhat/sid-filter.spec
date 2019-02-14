Summary: An SSL-encrypting socket wrapper
Name: sid-milter
Version: 1.0.0
Release: 1%{?dist}
License: GPLv2
Group: Applications/Internet

%global srcname sid-milter
%global gittag  1.0.0

URL: https://sourceforge.net/projects/sid-milter/
Source0: https://github.com/iav/sid-milter/archive/%{gittag}.zip


%global binname sid-filter

# Use systemd from F-15 / EL-7, else sysvinit
%if 0%{?fedora} > 14 || 0%{?rhel} > 6
%global use_systemd 1
%global rundir /run
%else
%global use_systemd 0
%global rundir %{_localstatedir}/run
%endif

Provides:        %{srcname} = %{version}-%{release}
Obsoletes:       %{srcname} < %{version}-%{release}

Requires:        sendmail-milter

BuildRequires: binutils, gcc, make, util-linux
BuildRequires: m4, sendmail-devel

%if %{use_systemd}
Requires(post):     /bin/systemctl
Requires(preun):    /bin/systemctl
Requires(postun):   /bin/systemctl
%else
Requires(post):     /sbin/chkconfig
Requires(preun):    /sbin/chkconfig
Requires(preun):    initscripts
Requires(postun):   initscripts
%endif

Buildroot: %{_tmppath}/%{name}-root


%description
This package contains an Open Source plug-in, for use with
Open Source or commercial sendmail MTAs, which implements and enforces the
merged Caller-ID/SPF specification from the IETF MARID working group,
currently dubbed "Sender-ID".

%prep
%setup -q -n %{srcname}-%{gittag}

%build
CFLAGS="$RPM_OPT_FLAGS -fPIC"; export CFLAGS

%{__make} %{?_smp_mflags}

%install

%{__rm} -rf %{buildroot}
%{__install} -d -m 755 %{buildroot}{%{rundir},%{_initrddir},%{_bindir},%{_mandir}/man{3,8},%{_sysconfdir}/mail,%{_sysconfdir}/sysconfig}

%{__make} install DESTDIR=%{buildroot}

# Initscript

%if %{use_systemd}
	%{__install} -d -m 755 %{buildroot}%{_unitdir}
	%{__install} -D -p -m 0644 %{_builddir}/%buildsubdir/redhat/sid-milter.systemd.service %{buildroot}%{_unitdir}/%{name}.service
	%{__install} -D -p -m 0644 %{_builddir}/%buildsubdir/redhat/sid-milter.env %{buildroot}%{_sysconfdir}/sysconfig/%{name}
%else
	%{__install} -D -p -m 0644 %{_builddir}/%buildsubdir/redhat/sid-milter.env %{buildroot}%{_sysconfdir}/sysconfig/%{binname}
	%{__install} -D -p -m  755 %{_builddir}/%buildsubdir/redhat/sid-filter.rc  %{buildroot}%{_initrddir}/%{binname}
	touch %{buildroot}%{rundir}/%{binname}.pid
%endif


%clean
%{__rm} -rf $RPM_BUILD_ROOT


%post
%if %{use_systemd}
	/bin/systemctl daemon-reload >/dev/null || 2>&1 :
%endif
if [ $1 -eq 1 ]; then
	# Initial installation
	%if ! %{use_systemd}
		/sbin/chkconfig --add %{binname} || :
	%endif
	%if 0%{?fedora} >= 18 || 0%{?rhel} >= 7
		/bin/systemctl preset milter-greylist.service >/dev/null 2>&1 || :
	%endif
	
fi


%preun
%if %{use_systemd}
	%systemd_preun %{name}.service
%else
	%{_initrddir}/%{binname} stop >/dev/null || :
	/sbin/chkconfig --del %{binname} || :
%endif

%postun
%if %{use_systemd}
	%systemd_postun_with_restart %{name}.service
%endif


%files
%defattr(-,root,root)
%doc FEATURES KNOWNBUGS README RELEASE_NOTES rfc4408.txt rfc4406.txt rfc4407.txt LICENSE README-SenderID
%doc redhat/sid-whitelist-sample
%{_bindir}/sid-filter
%{_mandir}/man3/ar.3*
%{_mandir}/man8/sid-filter.8*
%ghost %{rundir}/%{binname}.pid
%if %{use_systemd}
	%config %{_unitdir}/%{name}.service
	%config(noreplace) %{_sysconfdir}/sysconfig/%{name}
%else
	%{_initrddir}/%{binname}
	%config(noreplace) %{_sysconfdir}/sysconfig/%{binname}
%endif


%changelog
* Tue Aug 23 2016 iav@iav.lv
- Initial RPMification
