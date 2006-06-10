#!/usr/bin/perl -w

require 5.005;
use strict;
use IO::Socket;
use Getopt::Std;

# Checks routers for open socks-ports and socks5
# Successful connects go to STDOUT, failed ones to STDERR.
# We only do one check per loop in -d mode, so it takes some time.

# Contributed by Peter Kornherr <peter at wuschelpuschel dot org>, and
# cleaned up by Peter Palfrader <peter at palfrader dot org>.

our($opt_i,$opt_p,$opt_d,$opt_h,$opt_l);
getopts('i:p:dhl:');

if ($opt_h || !($opt_d||$opt_i||$opt_l)) {
    print "Usage: $0 -d < file_with_routers_in_it\n";
    print "or:    $0 -i IP -p Port\n";
    print "or:    $0 -l IP:Port\n";
    exit;
}

if ($opt_d) {
    open (IN,"<-") or die $!;
    while (<IN>) {
        next unless /^router /;
        (my $routername,my $checkip,my $checkport) = (split(" "))[1,2,4];
        &do_check($checkip,$checkport,$routername);
    }
} elsif ($opt_i && $opt_p) {
    &do_check($opt_i,$opt_p);
} elsif ($opt_l) {
    &do_check(split(":",$opt_l));
}

sub do_check {
    (my $checkip, my $checkport,my $routername) = @_;
    # as socksports may not be published (therefore "0") here,
    # let's try 9050, the default port:
    if ($checkport == 0) { $checkport = 9050; }
    # print "Checking $checkip:$checkport\n";
    my $s5socket = IO::Socket::INET->new(PeerAddr => $checkip,
        PeerPort => $checkport, Proto => "tcp", Type => SOCK_STREAM,
        Timeout => "20");
    if ($s5socket) {
        my @got;
        print $s5socket pack("CCC",'5','1','0');
        eval {
            local $SIG{ALRM} = sub { die "alarm\n" };
            alarm 10;
            read ($s5socket,$got[0],1);
            read ($s5socket,$got[1],1);
            alarm 0;
        };
        if ($@) {
            return; # die unless $@ eq "alarm\n";
        }
        if ($got[0] eq pack('C','5')) {
            if(defined($routername)) {
                print "Found SOCKS5 at $routername ($checkip:$checkport)\n";
            } else {
                print "Found SOCKS5 at $checkip:$checkport\n";
            }
        } else {
            if(defined($routername)) {
                print "$routername ($checkip:$checkport) answers - " .
                      "but not SOCKS5.\n";
            } else {
                print "$checkip:$checkport answers - but not SOCKS5.\n";
            }
        }
    } else {
        if(defined($routername)) {
            print STDERR "Can't connect to $routername " .
                         "($checkip:$checkport) ($!)\n";
        } else {
            print STDERR "Can't connect to $checkip:$checkport ($!)\n";
        }
    }
}

