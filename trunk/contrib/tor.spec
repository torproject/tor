# TODO:
# Add /etc/logrotate.d/tor
# 

%define  blddate %(date -u +"%Y%m%d%H%M")

%define  version       0.0.7
%define  version_extra rc2
%define  vepoch        0.1
%define  tor_version   %{version}%{version_extra}
# not quite right XXXXX
%define  release 0.std.%{vepoch}.%{version_extra}

Name: tor
Version: %{version}
Release: %{release}
Summary: Anonymizing overlay network for TCP
Vendor: R. Dingledine <arma@seul.org>
Packager: Nick Mathewson <nickm@seul.org>
License: BSD-like
Group: Applications/Internet
URL: http://freehaven.net/tor/

Source0: http://freehaven.net/tor/dist/tor-%{tor_version}.tar.gz

Requires: openssl >= 0.9.6
BuildRequires: openssl-devel >= 0.9.6
Requires(pre): shadow-utils, /usr/bin/id, /bin/date, /bin/sh
Requires(pre): %{_sbindir}/useradd, %{_sbindir}/groupadd

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%description
Tor is a connection-based low-latency anonymous communication system which
addresses many flaws in the original onion routing design.

In brief, Onion Routing is a connection-oriented anonymizing communication
service. Users choose a source-routed path through a set of nodes, and
negotiate a "virtual circuit" through the network, in which each node
knows its predecessor and successor, but no others. Traffic flowing down
the circuit is unwrapped by a symmetric key at each node, which reveals
the downstream node.

Basically Tor provides a distributed network of servers ("onion
routers"). Users bounce their tcp streams (web traffic, ftp, ssh, etc)
around the routers, and recipients, observers, and even the routers
themselves have difficulty tracking the source of the stream.

Note that Tor does no protocol cleaning.  That means there is a danger that
application protocols and associated programs can be induced to reveal
information about the initiator.  Tor depends on Privoxy and similar protocol
cleaners to solve this problem.

Client applications can use the Tor network by connecting to the local
onion proxy.  If the application itself does not come with socks support
you can use a socks client such as tsocks.  Some web browsers like mozilla
and web proxies like privoxy come with socks support, so you don't need an
extra socks client if you want to use Tor with them.

Remember that this is alpha code, and the network is very small -- Tor will
not provide anonymity currently.

This package provides the "tor" program, which serves as both a client
and a relay node. Scripts will automatically create a "tor" user and
group, set tor up to run as a daemon, and automatically start it at
installation time.

%prep
%setup -q -n tor-%{tor_version}

# Patch the startup script to use the right user and group IDs. Force
# the use of /bin/sh as the shell for the "tor" account.
ed -s contrib/tor.sh.in << '/EOF/' > /dev/null
,s/^TORUSER=$/TORUSER=tor/
,s/^TORGROUP=$/TORGROUP=tor/
,s:/bin/su:/bin/su -s /bin/sh:
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
%__mkdir_p ${RPM_BUILD_ROOT}%{_initrddir}
%__install -p -m 755 contrib/tor.sh ${RPM_BUILD_ROOT}%{_initrddir}/tor

# Directories that don't have any preinstalled files
%__mkdir_p -m 700 ${RPM_BUILD_ROOT}%{_localstatedir}/lib/tor
%__mkdir_p -m 755 ${RPM_BUILD_ROOT}%{_localstatedir}/run/tor
%__mkdir_p -m 755 ${RPM_BUILD_ROOT}%{_localstatedir}/log/tor

%clean
[ "${RPM_BUILD_ROOT}" != "/" ] && rm -rf ${RPM_BUILD_ROOT}

%pre
[ -f %{_initrddir}/tor  ] && /sbin/service tor stop
if [ ! -n "`/usr/bin/id -g tor 2>/dev/null`" ]; then
    # One would like to default the GID, but doing that properly would
    # require thought.
    %{_sbindir}/groupadd tor 2> /dev/null
fi
if [ ! -n "`/usr/bin/id -u tor 2>/dev/null`" ]; then
    # One would also like to default the UID, but doing that properly would
    # also require thought.
    if [ -x /sbin/nologin ]; then
        %{_sbindir}/useradd -r -g tor -d / -s /sbin/nologin tor 2> /dev/null
    else
        %{_sbindir}/useradd -r -g tor -d / -s /bin/false tor 2> /dev/null
    fi
fi

%post
/sbin/chkconfig --add tor
/sbin/chkconfig tor && /sbin/service tor start

%preun
/sbin/chkconfig tor && /sbin/service tor stop
/sbin/chkconfig --del tor

%files
%defattr(-,root,root)
%doc AUTHORS INSTALL LICENSE README ChangeLog doc/HACKING doc/TODO doc/FAQ
#%{_mandir}/man1/tor.1.gz
#%{_mandir}/man1/torify.1.gz
%{_mandir}/man*/*
%{_bindir}/tor
%{_bindir}/torify
%config %{_initrddir}/tor
%dir %{_sysconfdir}/tor/
%config(noreplace) %{_sysconfdir}/tor/torrc.sample
%config(noreplace) %{_sysconfdir}/tor/dirservers
%config(noreplace) %{_sysconfdir}/tor/tor-tsocks.conf
%attr(0700,tor,tor) %dir %{_localstatedir}/lib/tor
%attr(0755,tor,tor) %dir %{_localstatedir}/run/tor
%attr(0755,tor,tor) %dir %{_localstatedir}/log/tor

%changelog
* Mon Jun 06 2004 Nick Mathewson <nickm@freehaven.net> 0.0.7-0.std.0.1.rc2
- Make spec file more happy with fc2 packaging 

* Sat Jan 17 2004 John Bashinski <jbash@velvet.com>
- Basic spec file; tested with Red Hat 9.

