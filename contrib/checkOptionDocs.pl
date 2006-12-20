#!/usr/bin/perl -w
# $Id
use strict;

my %options = ();
my %descOptions = ();
my %torrcSampleOptions = ();
my %torrcCompleteOptions = ();
my %manPageOptions = ();

# Load the canonical list as actually accepted by Tor.
my $mostRecentOption;
open(F, "./src/or/tor --list-torrc-options |") or die;
while (<F>) {
    next if m!/\[notice\] Tor v0\.!;
    if (m!^([A-Za-z0-9_]+)!) {
        $mostRecentOption = lc $1;
        $options{$mostRecentOption} = 1;
    } elsif (m!^    !) {
        $descOptions{$mostRecentOption} = 1;
    } else {
        print "Unrecognized output> ";
        print;
    }
}
close F;

# Load the contents of torrc.sample and torrc.complete
sub loadTorrc {
    my ($fname, $options) = @_;
    local *F;
    open(F, "$fname") or die;
    while (<F>) {
        next if (m!##+!);
        if (m!#([A-Za-z0-9_]+)!) {
            $options->{lc $1} = 1;
        }
    }
    close F;
    0;
}

loadTorrc("./src/config/torrc.sample.in", \%torrcSampleOptions);
loadTorrc("./src/config/torrc.complete.in", \%torrcCompleteOptions);

# Try to figure out what's in the man page.

my $considerNextLine = 0;
open(F, "./doc/tor.1.in") or die;
while (<F>) {
    if ($considerNextLine and
        m!^\\fB([A-Za-z0-9_]+)!) {
        $manPageOptions{lc $1} = 1;
    }

    if (m!^\.(?:SH|TP)!) {
        $considerNextLine = 1; next;
    } else {
        $considerNextLine = 0;
    }
}
close F;

# Now, display differences:

sub subtractHashes {
    my ($s, $a, $b) = @_;
    my @lst = ();
    for my $k (keys %$a) {
        push @lst, $k unless (exists $b->{$k});
    }
    print "$s: ", join(' ', sort @lst), "\n\n";
    0;
}

subtractHashes("No online docs", \%options, \%descOptions);
# subtractHashes("Orphaned online docs", \%descOptions, \%options);

subtractHashes("Not in torrc.complete.in", \%options, \%torrcCompleteOptions);
subtractHashes("Orphaned in torrc.complete.in", \%torrcCompleteOptions, \%options);
subtractHashes("Orphaned in torrc.sample.in", \%torrcSampleOptions, \%options);

subtractHashes("Not in man page", \%options, \%manPageOptions);
subtractHashes("Orphaned in man page", \%manPageOptions, \%options);


