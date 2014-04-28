#!/usr/bin/perl -w

use strict;

my %count = ();
my $more = 0;
my $last = "";

while (<>) {
    if ($more) {
        if (/LD_BUG/) {
            $more = 0;
            next;
        }
        if (/\"((?:[^\"\\]+|\\.*)+)\"(.*)/) {
            $last .= $1;
            if ($2 !~ /[,\)]/) {
                $more = 1;
            } else {
                $count{lc $last}++;
                $more = 0;
            }
        } elsif (/[,\)]/) {
            $count{lc $last}++;
            $more = 0;
        } elsif ($more == 2) {
            print "SKIPPED more\n";
        }
    } elsif (/log_(?:warn|err|notice)\(\s*(LD_[A-Z_]*)\s*,\s*\"((?:[^\"\\]+|\\.)*)\"(.*)/) {
        next if ($1 eq 'LD_BUG');
        my $s = $2;
        if ($3 =~ /[,\)]/ ) {
            $count{lc $s}++;
        } else {
            $more = 1;
            $last = $s;
        }
    } elsif (/log_(?:warn|err|notice)\(\s*((?:LD_[A-Z_]*)?)(.*)/) {
        next if ($1 eq 'LD_BUG');
        my $extra = $2;
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
