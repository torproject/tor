%define  rellevel 1
%define  relbase std.%{rellevel}
%define  rhrel %([ -f /etc/redhat-release ] && (sed -e 's/^Red Hat Linux release //' -e 's/ .*$//' -e 's/\\./_/g' -e 's/^.*$/.rh&/' < /etc/redhat-release))
%define  blddate %(date -u +"%Y%m%d%H%M")
%define  release %{relbase}%{rhrel}.%{blddate}

%define  initdir /etc/rc.d/init.d

Summary: tor: anonymizing overlay network for TCP
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
