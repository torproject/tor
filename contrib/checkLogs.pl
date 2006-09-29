#!/usr/bin/perl -w

use strict;

my %count = ();
my $more = 0;
my $last = "";

while (<>) {
    if ($more) {
        if (/\s*(?:LD_[A-Z]*,)?\"((?:[^\"\\]+|\\.*)+)\"(.*)/) {
            $last .= $1;
            if ($2 !~ /[,\)]/) {
                $more = 1;
            } else {
                $count{$last}++;
                $more = 0;
            }
        } elsif (/[,\)]/) {
            $count{$last}++;
            $more = 0;
        } elsif ($more == 2) {
            print "SKIPPED more\n";
        }
    } elsif (/log_(?:warn|err|notice)\([^\"]*\"((?:[^\"\\]+|\\.)*)\"(.*)/) {
        my $s = $1;
        if ($2 =~ /[,\)]/ ) {
            $count{$s}++;
        } else {
            $more = 1;
            $last = $s;
        }
    } elsif (/log_(?:warn|err|notice)\((?:LD_[A-Z]*,)?(.*)/) {
        my $extra = $1;
        chomp $extra;
        $last = "";
        $more = 2 if ($extra eq '');
    }
}

while ((my $phrase, my $count) = each %count) {
    if ($count > 1) {
        print "$count\t$phrase\n";
    }
}
