%define  rellevel 1
%define  relbase std.%{rellevel}
%define  rhrel %([ -f /etc/redhat-release ] && (sed -e 's/^Red Hat Linux release //' -e 's/ .*$//' -e 's/\\./_/g' -e 's/^.*$/.rh&/' < /etc/redhat-release))
%define  blddate %(date -u +"%Y%m%d%H%M")
%define  release %{relbase}%{rhrel}.%{blddate}

%define  initdir /etc/rc.d/init.d

Summary: tor: The Onion Router; patent-free Onion Routing
Name: tor
Version: 0.0.2pre20
Vendor: R. Dingledine <arma@seul.org>
Release: %{release}
License: BSD-like
Group: Applications/Internet
URL: http://freehaven.net/tor

Source0: http://freehaven.net/tor/dist/tor-0.0.2pre19.tar.gz

Requires(pre): shadow-utils, /usr/bin/id, /bin/date, /bin/sh
Requires(pre): %{_sbindir}/useradd, %{_sbindir}/groupadd

BuildRoot: %{_tmppath}/%{name}-%{version}-%{relbase}-root

%description
tor is a system which attempts to conceal the sources of TCP connections
by relaying those connections through multiple independently administered
forwarding nodes; it is a "cascaded mix" system. Among older systems,
tor is most similar to Onion Routing. The basic concept of tor is also
similar to that of the Zero Knowledge Freedom system or the Java Anonymous
Proxy. The "onions" used in tor are similar in concept to the reply blocks
used with type I "cypherpunks" anonymous remailers. Feeding phrases
from this paragraph into search engines should give you more background
information than you really want.

This package provides the "tor" program, which serves as both a client
and a relay node. Scripts will automatically create a "tor" user and
group, set tor up to run as a daemon, and automatically start it at
installation time.

%prep
%setup -q

# Patch the startup script to use the right user and group IDs, store
# the PID in a subdirectory of /var/run (so tor doesn't have to start
# as root) and add in a control line for chkconfig. This (BSD? Debian?)
# script will work, but doesn't use all the weird Red Hat macros to make
# the boot sequence look pretty.
ed -s tor.sh.in << '/EOF/' > /dev/null
# Change the PID file location
,s/^TORPID=\(.*\)\/run\/tor.pid/TORPID=\1\/run\/tor\/tor.pid/
#
# Set user to "tor" before starting tor
,s/^\([ 	]*\)\(\$TORBIN.*\)$/\1\/bin\/su -s \/bin\/sh -c "\2" tor/
#
# Add user and group to command line. Suspenders and belt.
,s/^TORARGS="\(.*\)"/TORARGS="\1 --user tor --group tor"/
#
# Add control lines for chkconfig
1a
# chkconfig: 2345 90 10
# description: Onion router
.
#
# Save and exit ed
w
q
/EOF/

%build
%configure
%__make

%install
%makeinstall

# Install init script.
%__mkdir_p ${RPM_BUILD_ROOT}%{initdir}
%__install -m 755 tor.sh ${RPM_BUILD_ROOT}%{initdir}/tor

# Directories that don't have any preinstalled files
%__mkdir_p -m 700 ${RPM_BUILD_ROOT}/var/lib/tor
%__mkdir_p -m 755 ${RPM_BUILD_ROOT}/var/run/tor
%__mkdir_p -m 755 ${RPM_BUILD_ROOT}/var/log/tor

%clean
[ "${RPM_BUILD_ROOT}" != "/" ] && rm -rf ${RPM_BUILD_ROOT}

%pre
[ -f %{initdir}/tor  ] && /sbin/service tor stop
if [ ! -n "`/usr/bin/id -g tor 2>/dev/null`" ]; then
    # One would like to default the GID, but doing that properly would
    # require thought.
    %{_sbindir}/groupadd tor 2> /dev/null
fi
if [ ! -n "`/usr/bin/id -u tor 2>/dev/null`" ]; then
    # One would also like to default the UID, but doing that properly would
    # also require thought.
    if [ -x /sbin/nologin ]; then
        %{_sbindir}/useradd -g tor -d / -s /sbin/nologin tor 2> /dev/null
    else
        %{_sbindir}/useradd -g tor -d / -s /bin/false tor 2> /dev/null
    fi
fi

%post
/sbin/chkconfig --add tor
/sbin/service tor start

%preun
/sbin/service tor stop
/sbin/chkconfig --del tor

%files
%defattr(-,root,root)
%doc AUTHORS INSTALL LICENSE README
%{_mandir}/man*/*
%{_bindir}/tor
%{initdir}/tor
%dir %{_sysconfdir}/tor/
%config(noreplace) %{_sysconfdir}/tor/torrc
%config(noreplace) %{_sysconfdir}/tor/dirservers
%attr(-,tor,tor) %dir /var/lib/tor
%attr(-,tor,tor) %dir /var/run/tor
%attr(-,tor,tor) %dir /var/log/tor

%changelog
* Sat Jan 17 2004 John Bashinski <jbash@velvet.com>
- Basic spec file; tested with Red Hat 9.
